"""Diagnose the empty-vs-findings decision of an adapter on validation data (never the test set).

Prints mean P('[') (findings follow) and P('[]') (clean) on the first answer token, split by the
gold answer, plus the accuracy of the greedy decision. Run v1 failed here (P('[[]') ~0.83 for
every input), which is why v2 trains with a decision-weighted loss.

  python eval/decision_probe.py models/adapters/v2 [checkpoint_prefix] [n]
"""
import json
import shutil
import sys
import tempfile
from pathlib import Path

import mlx.core as mx
from mlx_lm import load
from mlx_lm.tuner.datasets import ChatDataset

ROOT = Path(__file__).resolve().parents[1]
adapter_dir = Path(sys.argv[1])
ckpt = sys.argv[2] if len(sys.argv) > 2 else ""
n = int(sys.argv[3]) if len(sys.argv) > 3 else 60
tmp = Path(tempfile.mkdtemp())
shutil.copy(adapter_dir / "adapter_config.json", tmp)
shutil.copy(adapter_dir / (f"{ckpt}_adapters.safetensors" if ckpt else "adapters.safetensors"), tmp / "adapters.safetensors")
model, tok = load(str(ROOT / "models/base/Qwen2.5-Coder-1.5B-Instruct"), adapter_path=str(tmp))
open_id, empty_id = tok.encode("[")[0], tok.encode("[]")[0]
rows = [json.loads(l) for l in (ROOT / "data/processed/valid.jsonl").open()][:n]
ds = ChatDataset(rows, tok, mask_prompt=True)
stats = {True: [], False: []}
correct = 0
for r in rows:
    t, o = ds.process(r)
    p = mx.softmax(model(mx.array(t[:o])[None])[0, -1].astype(mx.float32))
    empty_gold = r["messages"][2]["content"] == "[]"
    stats[empty_gold].append((p[open_id].item(), p[empty_id].item()))
    correct += (p[empty_id].item() > p[open_id].item()) == empty_gold
for gold, xs in stats.items():
    if xs:
        print(f"gold {'empty   ' if gold else 'findings'} n={len(xs):3d}  P('[')={sum(x[0] for x in xs)/len(xs):.3f}  P('[]')={sum(x[1] for x in xs)/len(xs):.3f}")
print(f"greedy decision accuracy {correct}/{len(rows)} = {correct/len(rows):.2f}")
