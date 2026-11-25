"""Recompute metrics for every saved run from its predictions.jsonl (after a metrics or label change)."""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]
from apkscan.schema import class_ids  # noqa: E402
from eval.harness import test_apps  # noqa: E402
from eval.metrics import score  # noqa: E402

for mp in sorted((ROOT / "results" / "runs").glob("*/metrics.json")):
    m = json.loads(mp.read_text())
    if "overall" not in m:
        continue
    apps = test_apps(m.get("split", "test"))
    rows = [json.loads(l) for l in (mp.parent / "predictions.jsonl").open()]
    by_app = {a["app"]: [p for r in rows if r["app"] == a["app"] for p in r["preds"]] for a in apps}
    gold = [g for a in apps for g in a.get("findings", [])]
    ign = [i for a in apps for i in a.get("ignore", [])]
    sc = score(gold, ign, [p for v in by_app.values() for p in v], class_ids())
    old = m["overall"]["f1"]
    m["overall"], m["per_class"] = sc["overall"], sc["per_class"]
    m["per_app"] = {a["app"]: score(a.get("findings", []), a.get("ignore", []), by_app[a["app"]], class_ids())["overall"] for a in apps}
    m["outcome_counts"] = {k: sum(1 for o in sc["match"]["outcomes"] if o[0] == k) for k in ("tp", "fp", "dup", "ignored")}
    mp.write_text(json.dumps(m, indent=2))
    print(f"{mp.parent.name:<28} F1 {old:.3f} -> {m['overall']['f1']:.3f}")
