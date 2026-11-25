"""Evaluate the candidate + verifier pipeline on the held-out apps.

  python eval/verify_harness.py --name loose-grep --no-model
  python eval/verify_harness.py --name verifier-base-f16 --gguf models/gguf/base-F16.gguf --prompt full
  python eval/verify_harness.py --name verifier-v1-Q8_0 --gguf models/gguf/tuned-verifier-v1-Q8_0.gguf

Findings = candidates the verifier confirms (class from the scanner, lines from the candidate).
Scored with the same matching as the finder (eval/metrics.py) plus per-candidate verdict accuracy.
Writes results/runs/<name>/{predictions.jsonl, metrics.json}.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT), str(ROOT / "data")]

from apkscan.candidates import find_candidates, verifier_messages  # noqa: E402
from apkscan.infer import LlamaServer  # noqa: E402
from apkscan.schema import class_ids  # noqa: E402
from build_verifier import match  # noqa: E402
from eval.harness import RssSampler, test_apps  # noqa: E402
from eval.metrics import prf, score  # noqa: E402

SCAN = ROOT / "data" / "scan"
TRUE_ID = None  # filled from the server tokenizer when a bias is requested


def parse_verdict(text: str):
    t = text.strip()
    try:
        obj = json.loads(t)
        if isinstance(obj, dict) and isinstance(obj.get("real"), bool):
            return obj, True
    except json.JSONDecodeError:
        pass
    m = re.search(r'"real"\s*:\s*(true|false)', t)
    if m:
        return {"real": m.group(1) == "true"}, False
    return None, False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--gguf")
    ap.add_argument("--no-model", action="store_true", help="every candidate is a finding (loose grep alone)")
    ap.add_argument("--prompt", choices=["short", "full"], default="short")
    ap.add_argument("--split", default="test")
    ap.add_argument("--true-bias", type=float, default=0.0, help="logit bias on the ' true' token (calibrated on validation)")
    ap.add_argument("--max-tokens", type=int, default=320)
    args = ap.parse_args()
    out_dir = ROOT / "results" / "runs" / args.name
    out_dir.mkdir(parents=True, exist_ok=True)

    apps = test_apps(args.split)
    work = []
    ceiling = Counter()
    for lab in apps:
        root = SCAN / lab["app"]
        files = {p.relative_to(root).as_posix(): p.read_text(errors="replace") for p in sorted(root.rglob("*")) if p.is_file()}
        cands = [c for f, t in files.items() for c in find_candidates(f, t)]
        for g in lab.get("findings", []):
            ceiling[any(match(c, [g], [])[0] == "real" for c in cands)] += 1
        for c in cands:
            work.append((lab, c, files[c.file], match(c, lab.get("findings", []), lab.get("ignore", []))[0]))

    rows, preds_by_app = [], {lab["app"]: [] for lab in apps}
    perf = {"prompt_tokens": 0, "completion_tokens": 0, "prompt_ms": 0.0, "gen_ms": 0.0, "wall_s": 0.0}
    n_json = n_parsed = 0
    verdicts = Counter()
    server = sampler = None
    bias = None
    t0 = time.time()
    try:
        if not args.no_model:
            server = LlamaServer(args.gguf, log=out_dir / "server.log").__enter__()
            sampler = RssSampler(server.pid)
            sampler.start()
            if args.true_bias:
                import urllib.request
                req = urllib.request.Request(server.url + "/tokenize", data=json.dumps({"content": " true"}).encode(),
                                             headers={"Content-Type": "application/json"})
                tid = json.loads(urllib.request.urlopen(req).read())["tokens"][0]
                bias = {tid: args.true_bias}
        for i, (lab, c, text, truth) in enumerate(work):
            if args.no_model:
                real, raw, obj = True, None, None
                n_json += 1; n_parsed += 1
            else:
                g = server.chat(verifier_messages(c, text, args.prompt), max_tokens=args.max_tokens, logit_bias=bias)
                for k in perf:
                    perf[k] += getattr(g, k)
                raw = g.text
                obj, strict = parse_verdict(raw)
                n_json += strict
                n_parsed += obj is not None
                real = bool(obj and obj.get("real"))
            if truth != "skip":
                verdicts[(truth == "real", real)] += 1
            if real:
                p = {"vuln_class": c.vuln_class, "file": c.file, "line_range": [c.start, c.end]}
                if obj:
                    p.update({k: obj.get(k) for k in ("severity", "cwe", "evidence", "why_exploitable", "fix") if k in obj})
                preds_by_app[lab["app"]].append(p)
            rows.append({"app": lab["app"], "candidate": c.key, "truth": truth, "pred_real": real, "raw": raw})
            if (i + 1) % 25 == 0:
                print(f"[{args.name}] {i + 1}/{len(work)} candidates, {time.time() - t0:.0f}s", flush=True)
    finally:
        if sampler:
            sampler.stop = True
        if server:
            server.__exit__(None, None, None)

    gold = [g for lab in apps for g in lab.get("findings", [])]
    ignore = [ig for lab in apps for ig in lab.get("ignore", [])]
    allp = [p for v in preds_by_app.values() for p in v]
    sc = score(gold, ignore, allp, class_ids())
    tp, fp = verdicts[(True, True)], verdicts[(False, True)]
    fn, tn = verdicts[(True, False)], verdicts[(False, False)]
    n = len(work)
    metrics = {
        "name": args.name, "split": args.split, "pipeline": "verifier", "gguf": args.gguf, "prompt_style": args.prompt,
        "true_bias": args.true_bias, "candidates": n, "gold_findings": len(gold),
        "candidate_recall_ceiling": round(ceiling[True] / max(1, sum(ceiling.values())), 3),
        "verdict": {**prf(tp, fp, fn), "tn": tn, "accuracy": round((tp + tn) / max(1, tp + fp + fn + tn), 3)},
        "json_valid_strict": round(n_json / n, 3) if n else 0, "json_parsed": round(n_parsed / n, 3) if n else 0,
        "overall": sc["overall"], "per_class": sc["per_class"],
        "per_app": {lab["app"]: score(lab.get("findings", []), lab.get("ignore", []), preds_by_app[lab["app"]], class_ids())["overall"] for lab in apps},
        "outcome_counts": {k: sum(1 for o in sc["match"]["outcomes"] if o[0] == k) for k in ("tp", "fp", "dup", "ignored")},
        "wall_s": round(time.time() - t0, 1),
    }
    if not args.no_model:
        metrics["perf"] = {
            "prompt_tok_per_s": round(perf["prompt_tokens"] / (perf["prompt_ms"] / 1000), 1) if perf["prompt_ms"] else None,
            "gen_tok_per_s": round(perf["completion_tokens"] / (perf["gen_ms"] / 1000), 1) if perf["gen_ms"] else None,
            "avg_s_per_candidate": round(perf["wall_s"] / n, 2) if n else None,
            "scan_s_per_app": round(perf["wall_s"] / len(apps), 1),
            "peak_rss_mb": round(sampler.peak / 1e6) if sampler else None,
            "gguf_mb": round(os.path.getsize(args.gguf) / 1e6),
        }
    with (out_dir / "predictions.jsonl").open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    o, v = metrics["overall"], metrics["verdict"]
    print(json.dumps({"name": args.name, "F1": o["f1"], "P": o["precision"], "R": o["recall"], "tp": o["tp"], "fp": o["fp"], "fn": o["fn"],
                      "candidates": n, "ceiling": metrics["candidate_recall_ceiling"], "verdict_acc": v["accuracy"],
                      "verdict_P": v["precision"], "verdict_R": v["recall"], "json": metrics["json_valid_strict"],
                      "s_per_cand": (metrics.get("perf") or {}).get("avg_s_per_candidate")}))


if __name__ == "__main__":
    main()
