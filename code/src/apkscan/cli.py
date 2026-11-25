"""apkscan-local: offline Android vulnerability triage with a local fine-tuned Qwen model.

  apkscan-local scan app.apk --model models/gguf/tuned-v1-Q4_K_M.gguf
  apkscan-local scan --dir path/to/jadx_output --model ...
  apkscan-local scan --src path/to/android/project   (source code, no decompilation)

No network access: jadx and llama-server run locally, llama-server binds 127.0.0.1 only.
"""

from __future__ import annotations

import argparse
import json
import sys
import tempfile
import time
from pathlib import Path

from .chunking import chunk_file
from .decompile import collect_jadx, collect_source_tree, run_jadx
from .infer import EMPTY_TOKEN_ID, LlamaServer
from .prompts import messages
from .report import dedupe, to_markdown
from .schema import parse_output

MODELS = Path(__file__).resolve().parents[2] / "models" / "gguf"
DEFAULT_MODEL = MODELS / "tuned-v2-Q8_0.gguf"  # finder mode (whole chunks)
DEFAULT_VERIFIER = MODELS / "tuned-verifier-v1-Q8_0.gguf"  # verify mode (default)
DEFAULT_EMPTY_BIAS = -1.69  # calibrated on the validation set for v2 (results/calibration-v2.json)


def scan(files: dict[str, str], model: str, log=None, progress=True, empty_bias: float = DEFAULT_EMPTY_BIAS) -> tuple[list[dict], dict]:
    chunks = [c for rel, txt in files.items() for c in chunk_file(rel, txt)]
    found, bad = [], 0
    t0 = time.time()
    with LlamaServer(model, log=log) as srv:
        for i, c in enumerate(chunks, 1):
            g = srv.chat(messages(c, style="short"), max_tokens=1024,
                         logit_bias={EMPTY_TOKEN_ID: empty_bias} if empty_bias else None)
            pr = parse_output(g.text)
            bad += not pr.parsed
            for f in pr.findings:
                found.append({**f, "file": c.file})
            if progress:
                print(f"\r  scanned {i}/{len(chunks)} chunks, {len(found)} raw findings", end="", file=sys.stderr, flush=True)
    if progress:
        print(file=sys.stderr)
    meta = {"model": Path(model).name, "files": len(files), "chunks": len(chunks), "unparsed_chunks": bad,
            "seconds": round(time.time() - t0, 1)}
    return dedupe(found), meta


def scan_verify(files: dict[str, str], model: str, log=None, progress=True, true_bias: float = 0.0) -> tuple[list[dict], dict]:
    """Loose pattern scan for candidates, then the fine-tuned verifier confirms and explains each one."""
    import json
    import re
    import urllib.request
    from .candidates import find_candidates, verifier_messages
    from .schema import load_classes
    cands = [(c, files[c.file]) for rel, txt in files.items() for c in find_candidates(rel, txt)]
    found, bad = [], 0
    t0 = time.time()
    with LlamaServer(model, log=log) as srv:
        bias = None
        if true_bias:
            req = urllib.request.Request(srv.url + "/tokenize", data=json.dumps({"content": " true"}).encode(),
                                         headers={"Content-Type": "application/json"})
            bias = {json.loads(urllib.request.urlopen(req).read())["tokens"][0]: true_bias}
        for i, (c, text) in enumerate(cands, 1):
            g = srv.chat(verifier_messages(c, text), max_tokens=320, logit_bias=bias)
            try:
                obj = json.loads(g.text.strip())
            except json.JSONDecodeError:
                m = re.search(r'"real"\s*:\s*(true|false)', g.text)
                obj = {"real": m.group(1) == "true"} if m else None
                bad += 1
            if isinstance(obj, dict) and obj.get("real") is True:
                spec = load_classes()["classes"][c.vuln_class]
                found.append({"vuln_class": c.vuln_class, "cwe": obj.get("cwe", spec["cwe"][0]), "masvs": spec["masvs"],
                              "severity": obj.get("severity", "medium"), "file": c.file, "line_range": [c.start, c.end],
                              "evidence": obj.get("evidence", c.hits[0]), "why_exploitable": obj.get("why_exploitable", ""),
                              "fix": obj.get("fix", "")})
            if progress:
                print(f"\r  verified {i}/{len(cands)} candidates, {len(found)} confirmed", end="", file=sys.stderr, flush=True)
    if progress:
        print(file=sys.stderr)
    meta = {"model": Path(model).name, "mode": "verify", "files": len(files), "candidates": len(cands),
            "unparsed": bad, "seconds": round(time.time() - t0, 1)}
    return dedupe(found), meta


def main(argv=None):
    ap = argparse.ArgumentParser(prog="apkscan-local", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scan an APK (or an existing jadx output directory)")
    s.add_argument("apk", nargs="?")
    s.add_argument("--dir", help="existing jadx output directory (contains sources/ and resources/)")
    s.add_argument("--src", help="Android project source directory (finds src/main/AndroidManifest.xml and java/kotlin sources)")
    s.add_argument("--mode", choices=["verify", "finder"], default="verify",
                   help="verify: pattern candidates checked by the fine-tuned verifier (default); finder: model reads whole chunks")
    s.add_argument("--model", help="GGUF model path (default depends on --mode)")
    s.add_argument("--true-bias", type=float, default=0.0, help="verify mode: decision calibration (logit bias on ' true')")
    s.add_argument("--empty-bias", type=float, default=DEFAULT_EMPTY_BIAS, help="decision calibration (logit bias on '[]')")
    s.add_argument("--out", help="write JSON report here")
    s.add_argument("--md", help="write Markdown report here")
    s.add_argument("--keep", help="keep the decompiled output in this directory")
    a = ap.parse_args(argv)

    a.model = a.model or str(DEFAULT_VERIFIER if a.mode == "verify" else DEFAULT_MODEL)
    if not Path(a.model).exists():
        ap.error(f"model not found: {a.model}")
    if a.src:
        target, files = a.src, collect_source_tree(Path(a.src))
    elif a.dir:
        target, files = a.dir, collect_jadx(Path(a.dir))
    elif a.apk:
        target = a.apk
        work = Path(a.keep) if a.keep else Path(tempfile.mkdtemp(prefix="apkscan-"))
        print(f"decompiling {a.apk} with jadx ...", file=sys.stderr)
        files = collect_jadx(run_jadx(Path(a.apk), work))
    else:
        ap.error("give an APK path, --dir or --src")
    print(f"{len(files)} app files selected (libraries skipped)", file=sys.stderr)
    if a.mode == "verify":
        findings, meta = scan_verify(files, a.model, true_bias=a.true_bias)
    else:
        findings, meta = scan(files, a.model, empty_bias=a.empty_bias)
    meta["target"] = Path(target).name
    report = {"meta": meta, "findings": findings}
    if a.out:
        Path(a.out).write_text(json.dumps(report, indent=2, ensure_ascii=False))
    md = to_markdown(meta, findings)
    if a.md:
        Path(a.md).write_text(md)
    if not a.out and not a.md:
        print(md)
    else:
        print(f"{len(findings)} findings; reports written", file=sys.stderr)


if __name__ == "__main__":
    main()
