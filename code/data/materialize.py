"""Write the exact files the scanner sees for each dataset app to data/scan/<app>/ (labels refer to these)."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from apkscan.decompile import collect_jadx, collect_source_tree  # noqa: E402

ROOT = Path(__file__).resolve().parent
JADX_APPS = {"ovaa": "decompiled/ovaa", "insecurebankv2": "decompiled/insecurebankv2"}
SOURCE_APPS = {"diva": "raw/diva", "allsafe": "raw/allsafe", "injuredandroid": "raw/injuredandroid/InjuredAndroid",
               # test apps in source form (test_src split): same apps as the jadx test set, read from GitHub source
               "ovaa-src": "raw/ovaa/app", "insecurebankv2-src": "raw/insecurebankv2/InsecureBankv2/app"}


def write(app, files):
    out = ROOT / "scan" / app
    for rel, txt in files.items():
        p = out / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(txt)
    print(f"{app}: {len(files)} files, {sum(t.count(chr(10)) for t in files.values())} lines")


if __name__ == "__main__":
    for app, d in JADX_APPS.items():
        write(app, collect_jadx(ROOT / d))
    for app, d in SOURCE_APPS.items():
        write(app, collect_source_tree(ROOT / d))
