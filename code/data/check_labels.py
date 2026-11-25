"""Print the labelled lines for every real-code label so a human can confirm each one."""
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from apkscan.chunking import normalize_xml  # noqa: E402


def show(files, labels, tag):
    for g in labels:
        lines = files[g["file"]].splitlines()
        a, b = g["line_range"]
        seg = " | ".join(l.strip() for l in lines[a - 1:b])[:170]
        print(f"[{tag}] {g['vuln_class']:<19} {g['file'].split('/')[-1]}:{a}-{b}  {seg}")


for lp in sorted((ROOT / "data" / "labels").glob("*.yaml")):
    if len(sys.argv) > 1 and lp.stem not in sys.argv[1:]:
        continue
    lab = yaml.safe_load(lp.read_text())
    if lab.get("kind") == "mastg":
        base = ROOT / lab["base"]
        for d in lab["demos"]:
            files = {k: (normalize_xml if k.endswith(".xml") else str)((base / d["dir"] / v).read_text()) for k, v in d["files"].items()}
            show(files, d.get("findings", []), "mastg-" + d["id"])
    else:
        root = ROOT / "data" / "scan" / lab["app"]
        files = {p.relative_to(root).as_posix(): p.read_text() for p in root.rglob("*") if p.is_file()}
        show(files, lab.get("findings", []), lab["app"])
