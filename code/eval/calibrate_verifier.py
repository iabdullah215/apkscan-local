"""Calibrate the verifier's true/false decision on the VALIDATION set only.

For each validation record, d = logit(' true') - logit(' false') at the decision position
({"real": <here>). The verifier says real when d > tau; tau maximizing F1 on validation is
applied at inference as logit bias -tau on ' true' (eval/verify_harness.py --true-bias).

  python eval/calibrate_verifier.py models/adapters/verifier-v1 results/calibration-verifier-v1.json
"""
import json
import sys
from pathlib import Path

import mlx.core as mx
from mlx_lm import load
from mlx_lm.tuner.datasets import ChatDataset

ROOT = Path(__file__).resolve().parents[1]
model, tok = load(str(ROOT / "models/base/Qwen2.5-Coder-1.5B-Instruct"), adapter_path=sys.argv[1])
t_id, f_id = tok.encode(" true")[0], tok.encode(" false")[0]
rows = [json.loads(l) for l in (ROOT / "data/processed_verifier/valid.jsonl").open()]
ds = ChatDataset(rows, tok, mask_prompt=True)
pts = []
for r in rows:
    t, o = ds.process(r)
    pos = next(i for i in range(o, len(t)) if t[i] in (t_id, f_id))
    lg = model(mx.array(t[:pos])[None])[0, -1].astype(mx.float32)
    pts.append((lg[t_id].item() - lg[f_id].item(), t[pos] == t_id))
best = None
for tau in sorted({round(d, 2) for d, _ in pts} | {0.0}):
    tp = sum(1 for d, y in pts if d > tau - 1e-9 and y); fp = sum(1 for d, y in pts if d > tau - 1e-9 and not y)
    fn = sum(1 for d, y in pts if d <= tau - 1e-9 and y)
    f1 = 2 * tp / (2 * tp + fp + fn) if tp else 0.0
    acc = sum(1 for d, y in pts if (d > tau - 1e-9) == y) / len(pts)
    if best is None or f1 > best["f1"] or (f1 == best["f1"] and abs(tau) < abs(best["tau"])):
        best = {"tau": tau, "f1": round(f1, 3), "acc": round(acc, 3), "tp": tp, "fp": fp, "fn": fn}
greedy = sum(1 for d, y in pts if (d > 0) == y) / len(pts)
res = {"adapter": sys.argv[1], "n_valid": len(pts), "greedy_acc": round(greedy, 3), "best": best,
       "true_bias": round(-best["tau"], 2)}
Path(sys.argv[2]).write_text(json.dumps(res, indent=1))
print(json.dumps(res, indent=1))
