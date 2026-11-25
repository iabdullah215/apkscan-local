"""Evaluate a model variant (or the grep baseline) on the held-out test apps.

Usage:
  python eval/harness.py --name grep --grep
  python eval/harness.py --name base-f16-zeroshot --gguf models/gguf/base-F16.gguf
  python eval/harness.py --name base-f16-fewshot --gguf models/gguf/base-F16.gguf --few-shot 2
  python eval/harness.py --name tuned-q4 --gguf models/gguf/tuned-Q4_K_M.gguf

Writes results/runs/<name>/{predictions.jsonl, metrics.json}. Deterministic: temperature 0, seed 0.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import threading
import time
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

from apkscan.chunking import chunk_file  # noqa: E402
from apkscan.infer import EMPTY_TOKEN_ID, LlamaServer  # noqa: E402
from apkscan.prompts import PROMPT_VERSION, messages  # noqa: E402
from apkscan.schema import class_ids, parse_output  # noqa: E402
from eval.metrics import score  # noqa: E402

LABELS = ROOT / "data" / "labels"
SCAN = ROOT / "data" / "scan"


def test_apps(split: str = "test") -> list[dict]:
    apps = []
    for lp in sorted(LABELS.glob("*.yaml")):
        lab = yaml.safe_load(lp.read_text())
        if lab.get("split") == split:
            apps.append(lab)
    return apps


def app_chunks(app: str):
    root = SCAN / app
    out = []
    for p in sorted(root.rglob("*")):
        if p.is_file():
            out += chunk_file(p.relative_to(root).as_posix(), p.read_text(errors="replace"))
    return out


def few_shot_examples(k: int) -> list[tuple[str, str]]:
    """First k suitable examples from the training file: alternate one-finding and empty answers."""
    if k <= 0:
        return []
    rows = [json.loads(l) for l in (ROOT / "data" / "processed" / "train.jsonl").open()]
    with_f = [r for r in rows if r["messages"][2]["content"].count('"vuln_class"') == 1 and len(r["messages"][1]["content"]) < 1400]
    empty = [r for r in rows if r["messages"][2]["content"] == "[]" and len(r["messages"][1]["content"]) < 1000]
    picked = []
    for i in range(k):
        r = (with_f if i % 2 == 0 else empty)[i // 2]
        picked.append((r["messages"][1]["content"], r["messages"][2]["content"]))
    return picked


class RssSampler(threading.Thread):
    def __init__(self, pid):
        super().__init__(daemon=True)
        import psutil
        self.proc = psutil.Process(pid)
        self.peak = 0
        self.stop = False

    def run(self):
        while not self.stop:
            try:
                self.peak = max(self.peak, self.proc.memory_info().rss)
            except Exception:
                return
            time.sleep(0.2)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--name", required=True)
    ap.add_argument("--gguf")
    ap.add_argument("--grep", action="store_true")
    ap.add_argument("--few-shot", type=int, default=0)
    ap.add_argument("--max-tokens", type=int, default=1024)
    ap.add_argument("--prompt", choices=["full", "short"], default="full", help="system prompt style")
    ap.add_argument("--empty-bias", type=float, default=0.0, help="logit bias on the '[]' token, calibrated on validation (eval/calibrate.py)")
    ap.add_argument("--split", default="test", help="test (jadx output of the APKs) or test_src (same apps, GitHub source)")
    ap.add_argument("--limit", type=int, default=0, help="debug: only first N chunks")
    args = ap.parse_args()

    out_dir = ROOT / "results" / "runs" / args.name
    out_dir.mkdir(parents=True, exist_ok=True)
    apps = test_apps(args.split)
    work = [(lab, c) for lab in apps for c in app_chunks(lab["app"])]
    if args.limit:
        work = work[: args.limit]
    shots = few_shot_examples(args.few_shot)

    rows, preds_by_app = [], {lab["app"]: [] for lab in apps}
    perf = {"prompt_tokens": 0, "completion_tokens": 0, "prompt_ms": 0.0, "gen_ms": 0.0, "wall_s": 0.0}
    n_strict = n_parsed = n_schema = 0
    server = sampler = None
    t_start = time.time()
    try:
        if not args.grep:
            server = LlamaServer(args.gguf, log=out_dir / "server.log").__enter__()
            sampler = RssSampler(server.pid)
            sampler.start()
        for i, (lab, c) in enumerate(work):
            if args.grep:
                from eval.baselines.grep_baseline import predict
                preds = predict(c)
                raw, pr = None, None
                n_strict += 1; n_parsed += 1; n_schema += 1
            else:
                g = server.chat(messages(c, shots, args.prompt), max_tokens=args.max_tokens,
                                logit_bias={EMPTY_TOKEN_ID: args.empty_bias} if args.empty_bias else None)
                for k in perf:
                    perf[k] += getattr(g, k)
                raw = g.text
                pr = parse_output(raw)
                n_strict += pr.strict_json
                n_parsed += pr.parsed
                n_schema += pr.schema_valid
                preds = [{**f, "file": c.file} for f in pr.findings]
            preds_by_app[lab["app"]] += preds
            rows.append({"app": lab["app"], "chunk": c.key, "raw": raw, "preds": preds,
                         "strict_json": None if pr is None else pr.strict_json,
                         "schema_errors": None if pr is None else pr.schema_errors[:5]})
            if (i + 1) % 10 == 0:
                print(f"[{args.name}] {i + 1}/{len(work)} chunks, {time.time() - t_start:.0f}s", flush=True)
    finally:
        if sampler:
            sampler.stop = True
        if server:
            server.__exit__(None, None, None)

    classes = class_ids()
    gold = [g for lab in apps for g in lab.get("findings", [])]
    ignore = [ig for lab in apps for ig in lab.get("ignore", [])]
    allpreds = [p for a in preds_by_app.values() for p in a]
    sc = score(gold, ignore, allpreds, classes)
    per_app = {lab["app"]: score(lab.get("findings", []), lab.get("ignore", []), preds_by_app[lab["app"]], classes)["overall"] for lab in apps}
    n = len(work)
    metrics = {
        "name": args.name, "split": args.split, "gguf": args.gguf, "few_shot": args.few_shot, "prompt_version": PROMPT_VERSION, "prompt_style": args.prompt, "empty_bias": args.empty_bias,
        "chunks": n, "gold_findings": len(gold),
        "json_valid_strict": round(n_strict / n, 3) if n else 0, "json_parsed": round(n_parsed / n, 3) if n else 0,
        "schema_valid": round(n_schema / n, 3) if n else 0,
        "overall": sc["overall"], "per_class": sc["per_class"], "per_app": per_app,
        "outcome_counts": {k: sum(1 for o in sc["match"]["outcomes"] if o[0] == k) for k in ("tp", "fp", "dup", "ignored")},
        "wall_s": round(time.time() - t_start, 1),
    }
    if not args.grep:
        metrics["perf"] = {
            "prompt_tok_per_s": round(perf["prompt_tokens"] / (perf["prompt_ms"] / 1000), 1) if perf["prompt_ms"] else None,
            "gen_tok_per_s": round(perf["completion_tokens"] / (perf["gen_ms"] / 1000), 1) if perf["gen_ms"] else None,
            "prompt_tokens": perf["prompt_tokens"], "completion_tokens": perf["completion_tokens"],
            "avg_s_per_chunk": round(perf["wall_s"] / n, 2) if n else None,
            "peak_rss_mb": round(sampler.peak / 1e6) if sampler else None,
            "gguf_mb": round(os.path.getsize(args.gguf) / 1e6),
        }
    with (out_dir / "predictions.jsonl").open("w") as fh:
        for r in rows:
            fh.write(json.dumps(r, ensure_ascii=False) + "\n")
    fns = [{"file": g["file"], "vuln_class": g["vuln_class"], "line_range": g["line_range"]} for g in sc["match"]["fn"]]
    fps = [{"file": p["file"], "vuln_class": p["vuln_class"], "line_range": p["line_range"]} for k, p, _ in sc["match"]["outcomes"] if k == "fp"]
    (out_dir / "errors.json").write_text(json.dumps({"false_negatives": fns, "false_positives": fps}, indent=1))
    (out_dir / "metrics.json").write_text(json.dumps(metrics, indent=2))
    o = metrics["overall"]
    print(json.dumps({"name": args.name, "P": o["precision"], "R": o["recall"], "F1": o["f1"], "macroF1": o["macro_f1"],
                      "tp": o["tp"], "fp": o["fp"], "fn": o["fn"], "json_strict": metrics["json_valid_strict"],
                      "perf": metrics.get("perf")}))


if __name__ == "__main__":
    main()
