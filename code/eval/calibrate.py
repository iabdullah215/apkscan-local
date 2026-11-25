"""Calibrate the empty-vs-findings decision threshold on the VALIDATION set only.

For each validation record we take d = logit('[') - logit('[]') at the first answer token.
The model answers "findings" when d > tau. We pick tau that maximizes F1 of the
"has findings" decision on validation, then apply it at inference as a logit bias of tau on the '[]' token
(llama-server logit_bias; tau < 0 lowers '[]'), so the test set never influences the choice.

  python eval/calibrate.py models/adapters/v2 results/calibration-v2.json
"""
import json
import math
import sys
from pathlib import Path

import mlx.core as mx
from mlx_lm import load
from mlx_lm.tuner.datasets import ChatDataset

ROOT = Path(__file__).resolve().parents[1]
adapter, out = sys.argv[1], Path(sys.argv[2])
model, tok = load(str(ROOT / "models/base/Qwen2.5-Coder-1.5B-Instruct"), adapter_path=adapter)
open_id, empty_id = tok.encode("[")[0], tok.encode("[]")[0]
rows = [json.loads(l) for l in (ROOT / "data/processed/valid.jsonl").open()]
ds = ChatDataset(rows, tok, mask_prompt=True)
pts = []
for r in rows:
    t, o = ds.process(r)
    lg = model(mx.array(t[:o])[None])[0, -1].astype(mx.float32)
    pts.append((lg[open_id].item() - lg[empty_id].item(), r["messages"][2]["content"] != "[]"))
best = None
for tau in sorted({round(d, 2) for d, _ in pts} | {0.0}):
    tp = sum(1 for d, y in pts if d > tau - 1e-9 and y)
    fp = sum(1 for d, y in pts if d > tau - 1e-9 and not y)
    fn = sum(1 for d, y in pts if d <= tau - 1e-9 and y)
    f1 = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
    acc = sum(1 for d, y in pts if (d > tau - 1e-9) == y) / len(pts)
    if best is None or f1 > best["f1"] or (f1 == best["f1"] and acc > best["acc"]):
        best = {"tau": tau, "f1": round(f1, 3), "acc": round(acc, 3), "tp": tp, "fp": fp, "fn": fn}
greedy_acc = sum(1 for d, y in pts if (d > 0) == y) / len(pts)
res = {"adapter": adapter, "n_valid": len(pts), "empty_token_id": empty_id, "open_token_id": open_id,
       "greedy_acc": round(greedy_acc, 3), "best": best,
       "logit_bias_on_empty_token": round(best["tau"], 2),
       "d_findings": sorted(round(d, 2) for d, y in pts if y), "d_empty": sorted(round(d, 2) for d, y in pts if not y)}
out.write_text(json.dumps(res, indent=1))
print(json.dumps({k: v for k, v in res.items() if not k.startswith("d_")}, indent=1))
print("d (findings):", res["d_findings"][:8], "...", res["d_findings"][-4:])
print("d (empty):   ", res["d_empty"][:4], "...", res["d_empty"][-6:])
