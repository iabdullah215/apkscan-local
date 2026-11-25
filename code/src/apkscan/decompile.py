"""APK -> jadx -> the set of files we scan (app code, normalized manifest, network config).

Everything runs locally. No network access.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from .chunking import normalize_xml

LIB_PREFIXES = ("android.", "androidx.", "com.google.", "kotlin.", "kotlinx.", "okhttp3.", "okio.", "retrofit2.",
                "org.apache.", "org.json.", "com.squareup.", "io.reactivex.", "dagger.", "javax.", "java.")
SKIP_FILE = re.compile(r"(^|/)(R|R\$\w+|BuildConfig|Manifest|Manifest\$\w+)\.java$")


def run_jadx(apk: Path, out_dir: Path, jadx: str = "jadx") -> Path:
    if shutil.which(jadx) is None:
        raise RuntimeError("jadx not found on PATH (brew install jadx)")
    out_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run([jadx, "-q", "--show-bad-code", "-d", str(out_dir), str(apk)],
                   check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if not (out_dir / "sources").exists():
        raise RuntimeError(f"jadx produced no sources for {apk}")
    return out_dir


def app_prefixes(manifest_xml: str) -> list[str]:
    pkg = re.search(r'\bpackage="([\w.]+)"', manifest_xml)
    prefixes = set()
    if pkg:
        prefixes.add(pkg.group(1) + ".")
    for m in re.finditer(r'<(?:activity|service|receiver|provider|application)\b[^>]*?android:name="([\w.$]+)"', manifest_xml):
        name = m.group(1)
        if name.startswith("."):
            continue
        if name.startswith(LIB_PREFIXES):
            continue
        parts = name.split(".")
        if len(parts) >= 3:
            prefixes.add(".".join(parts[:2]) + ".")
    return sorted(prefixes)


def network_config_name(manifest_xml: str) -> str | None:
    m = re.search(r'android:networkSecurityConfig="@xml/([\w]+)"', manifest_xml)
    return m.group(1) if m else None


def collect_jadx(out_dir: Path) -> dict[str, str]:
    """Return {relative_path: text} for the files the scanner looks at."""
    files: dict[str, str] = {}
    res = out_dir / "resources"
    man_path = res / "AndroidManifest.xml"
    manifest = normalize_xml(man_path.read_text(errors="replace")) if man_path.exists() else ""
    if manifest:
        files["AndroidManifest.xml"] = manifest
        nc = network_config_name(manifest)
        if nc and (res / "res" / "xml" / f"{nc}.xml").exists():
            files[f"res/xml/{nc}.xml"] = normalize_xml((res / "res" / "xml" / f"{nc}.xml").read_text(errors="replace"))
    prefixes = app_prefixes(manifest)
    src = out_dir / "sources"
    for p in sorted(src.rglob("*.java")):
        rel = p.relative_to(src).as_posix()
        dotted = rel.replace("/", ".")
        if SKIP_FILE.search(rel):
            continue
        if prefixes and not any(dotted.startswith(px) for px in prefixes):
            continue
        files[rel] = p.read_text(errors="replace")
    return files


def collect_source_tree(app_dir: Path) -> dict[str, str]:
    """Same output shape for an open-source app checkout (training apps).

    Java/Kotlin paths are made relative to their java/ or kotlin/ source root so they
    look like jadx package paths.
    """
    files: dict[str, str] = {}
    manifests = [m for m in app_dir.rglob("src/main/AndroidManifest.xml")]
    for m in manifests[:1]:
        txt = m.read_text(errors="replace")
        try:
            files["AndroidManifest.xml"] = normalize_xml(txt)
        except Exception:
            files["AndroidManifest.xml"] = txt
        nc = network_config_name(txt)
        if nc:
            cand = m.parent / "res" / "xml" / f"{nc}.xml"
            if cand.exists():
                files[f"res/xml/{nc}.xml"] = normalize_xml(cand.read_text(errors="replace"))
    for p in sorted(list(app_dir.rglob("*.java")) + list(app_dir.rglob("*.kt"))):
        s = p.as_posix()
        if "/test/" in s or "/androidTest/" in s or "/build/" in s:
            continue
        m = re.search(r"/(?:java|kotlin)/(.+)$", s)
        rel = m.group(1) if m else p.name
        if SKIP_FILE.search(rel):
            continue
        files[rel] = p.read_text(errors="replace")
    return files
