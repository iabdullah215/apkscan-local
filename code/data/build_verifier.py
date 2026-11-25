"""Build verifier training data automatically: run the loose candidate scanner over labelled code and
mark each candidate real (overlaps a labelled finding of the same class) or false alarm.

  python data/build_verifier.py --stats train      # candidate recall / volume on training sources
  python data/build_verifier.py                    # write data/processed_verifier/{train,valid}.jsonl

Candidates overlapping an `ignore` region (real issue outside the 8 classes) are left out of training.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import random
import sys
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT), str(ROOT / "data" / "synth"), str(ROOT / "data")]

from apkscan.candidates import find_candidates, verifier_messages  # noqa: E402
from apkscan.chunking import normalize_xml  # noqa: E402
from apkscan.schema import load_classes  # noqa: E402
from eval.metrics import _overlap, _ranges, _tol  # noqa: E402

LABELS = ROOT / "data" / "labels"
SCAN = ROOT / "data" / "scan"
OUT = ROOT / "data" / "processed_verifier"
SEED = 4321


def sources(split: str):
    """Yield (name, files, gold, ignore) for every labelled app/demo in a split."""
    for lp in sorted(LABELS.glob("*.yaml")):
        lab = yaml.safe_load(lp.read_text())
        if lab.get("split") != split:
            continue
        if lab.get("kind") == "mastg":
            base = ROOT / lab["base"]
            for d in lab["demos"]:
                files = {k: (normalize_xml if k.endswith(".xml") else str)((base / d["dir"] / v).read_text(errors="replace"))
                         for k, v in d["files"].items()}
                yield f"mastg-{d['id']}", files, d.get("findings", []), d.get("ignore", [])
            continue
        root = SCAN / lab["app"]
        names = lab.get("reviewed_files") or sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
        yield lab["app"], {n: (root / n).read_text(errors="replace") for n in names}, lab.get("findings", []), lab.get("ignore", [])


def synthetic_sources(seed: int, n_java: int, n_man: int, n_net: int):
    import generator
    for i, s in enumerate(generator.generate(seed, n_java, n_man, n_net)):
        yield f"synthetic-{i}", {s.file: s.text}, s.findings, []


def match(cand, gold, ignore):
    """'real' with the matched label, 'skip' (ignore region), or 'false'."""
    cr = [cand.start, cand.end]
    for g in gold:
        if g["file"] == cand.file and g["vuln_class"] == cand.vuln_class and any(_overlap(cr, r, _tol(g["file"])) for r in _ranges(g)):
            return "real", g
    if any(ig["file"] == cand.file and _overlap(cr, ig["line_range"], 0) for ig in ignore):
        return "skip", None
    return "false", None


def label_all(srcs):
    rows, recall = [], Counter()
    for name, files, gold, ignore in srcs:
        cands = [c for f, t in files.items() for c in find_candidates(f, t)]
        for g in gold:
            hit = any(c.file == g["file"] and c.vuln_class == g["vuln_class"] and any(_overlap([c.start, c.end], r, _tol(g["file"])) for r in _ranges(g))
                      for c in cands)
            recall[(g["vuln_class"], hit)] += 1
            if not hit and not name.startswith("synthetic"):
                print(f"   MISS {name} {g['vuln_class']} {g['file']}:{g['line_range']} {g.get('evidence', '')[:70]}")
        for c in cands:
            verdict, g = match(c, gold, ignore)
            rows.append((name, c, files[c.file], verdict, g))
    return rows, recall


def answer(cand, g) -> str:
    if g is None:
        return json.dumps({"real": False})
    from builder import DEFAULTS
    spec = load_classes()["classes"][cand.vuln_class]
    why, fix = DEFAULTS[cand.vuln_class]
    return json.dumps({"real": True, "severity": g["severity"], "cwe": g.get("cwe") or spec["cwe"][0],
                       "evidence": g["evidence"], "why_exploitable": g.get("why") or g.get("why_exploitable") or why,
                       "fix": g.get("fix") or fix}, ensure_ascii=False)


def report(rows, recall, title):
    print(f"== {title}")
    v = Counter(r[3] for r in rows)
    print(f"candidates {len(rows)}: real {v['real']}, false {v['false']}, skipped {v['skip']}")
    for c in load_classes()["classes"]:
        hit, miss = recall[(c, True)], recall[(c, False)]
        cc = Counter(r[3] for r in rows if r[1].vuln_class == c)
        print(f"  {c:<20} label recall {hit}/{hit + miss}   candidates real {cc['real']:4d} false {cc['false']:4d}")
    misses = [(n, g) for n, *_ in []]
    return v


def to_record(name, cand, text, verdict, g):
    return {"messages": verifier_messages(cand, text) + [{"role": "assistant", "content": answer(cand, g)}],
            "meta": {"source": name, "file": cand.file, "class": cand.vuln_class, "lines": [cand.start, cand.end], "real": verdict == "real"}}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stats", choices=["train", "test", "test_src"])
    ap.add_argument("--max-false-per-real", type=float, default=1.5)
    a = ap.parse_args()
    if a.stats:
        rows, rec = label_all(sources(a.stats))
        report(rows, rec, a.stats)
        if a.stats == "train":
            srows, srec = label_all(synthetic_sources(SEED, 300, 40, 20))
            report(srows, srec, "synthetic sample")
        return

    rng = random.Random(SEED)
    real_rows, _ = label_all(sources("train"))
    syn_rows, _ = label_all(synthetic_sources(SEED, 450, 60, 30))
    val_rows, _ = label_all(synthetic_sources(SEED + 1, 60, 8, 4))

    def balance(rows, repeat_real=1):
        pos = [r for r in rows if r[3] == "real"]
        neg = [r for r in rows if r[3] == "false"]
        rng.shuffle(neg)
        neg = neg[: int(len(pos) * a.max_false_per_real)]
        return pos * repeat_real + neg

    train = [to_record(*r) for r in balance(real_rows, repeat_real=2) + balance(syn_rows)]
    valid = [to_record(*r) for r in balance(val_rows)]
    rng.shuffle(train)
    OUT.mkdir(parents=True, exist_ok=True)
    stats = {}
    for name, recs in (("train", train), ("valid", valid)):
        p = OUT / f"{name}.jsonl"
        with p.open("w") as fh:
            for r in recs:
                fh.write(json.dumps({"messages": r["messages"]}, ensure_ascii=False) + "\n")
        with (OUT / f"{name}.meta.jsonl").open("w") as fh:
            for r in recs:
                fh.write(json.dumps(r["meta"]) + "\n")
        stats[name] = {"records": len(recs), "real": sum(r["meta"]["real"] for r in recs),
                       "by_class_real": dict(Counter(r["meta"]["class"] for r in recs if r["meta"]["real"])),
                       "by_class_false": dict(Counter(r["meta"]["class"] for r in recs if not r["meta"]["real"])),
                       "sha256": hashlib.sha256(p.read_bytes()).hexdigest()}
    stats["seed"] = SEED
    (OUT / "manifest.json").write_text(json.dumps(stats, indent=2))
    print(json.dumps({k: (v if k == "seed" else {kk: vv for kk, vv in v.items() if kk != "sha256"}) for k, v in stats.items()}, indent=1))


if __name__ == "__main__":
    main()
