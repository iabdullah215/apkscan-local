"""Pretty-printing helpers for demo/video_demo.sh. Reads only local files; no network.

  python demo/video_helpers.py count   report.json
  python demo/video_helpers.py seconds report.json
  python demo/video_helpers.py table   report.json
  python demo/video_helpers.py detail  report.json FILE_SUBSTRING LINE_START
  python demo/video_helpers.py results
  python demo/video_helpers.py fails   report.json
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "results" / "runs"

RESET, BOLD, DIM = "\033[0m", "\033[1m", "\033[2m"
RED, GREEN, YELLOW, BLUE, MAGENTA, CYAN = (f"\033[{c}m" for c in (31, 32, 33, 34, 35, 36))
SEV = {"high": RED + BOLD, "medium": YELLOW, "low": DIM}


def load(path: str) -> dict:
    return json.loads(Path(path).read_text())


def metrics(name: str) -> dict:
    return json.loads((RUNS / name / "metrics.json").read_text())


def cmd_count(path: str) -> None:
    print(len(load(path)["findings"]))


def cmd_seconds(path: str) -> None:
    print(load(path)["meta"].get("seconds", "?"))


def cmd_table(path: str) -> None:
    findings = load(path)["findings"]
    if not findings:
        print(f"  {DIM}(no findings){RESET}")
        return
    print(f"  {BOLD}{'#':>2}  {'severity':<8}  {'class':<20}  location{RESET}")
    for i, f in enumerate(findings, 1):
        a, b = f["line_range"]
        loc = f"{f['file'].split('/')[-1]}:{a}-{b}"
        sev = f["severity"]
        print(f"  {i:>2}  {SEV.get(sev, '')}{sev:<8}{RESET}  {CYAN}{f['vuln_class']:<20}{RESET}  {loc}")


def _show(f: dict) -> None:
    a, b = f["line_range"]
    print(f"  {BOLD}{f['file']}  lines {a}-{b}{RESET}")
    print(f"    class     : {CYAN}{f['vuln_class']}{RESET}  ({f['cwe']}, {f['masvs']})")
    print(f"    severity  : {SEV.get(f['severity'], '')}{f['severity']}{RESET}")
    print(f"    evidence  : {f['evidence']}")
    print(f"    why       : {f['why_exploitable']}")
    print(f"    fix       : {GREEN}{f['fix']}{RESET}")


def cmd_detail(path: str, file_sub: str, line: str) -> None:
    for f in load(path)["findings"]:
        if file_sub in f["file"] and f["line_range"][0] == int(line):
            _show(f)
            return
    print(f"  {DIM}(finding {file_sub}:{line} not in this run){RESET}")


def cmd_fails(path: str) -> None:
    hits = [f for f in load(path)["findings"] if f["vuln_class"] == "hardcoded_secret" and "PASSWORD_KEY" in f["evidence"]]
    if not hits:
        print(f"  {DIM}(the PASSWORD_KEY false alarm did not appear in this run){RESET}")
        return
    _show(hits[0])


def cmd_results() -> None:
    rows = [
        ("grep baseline (strict regex rules)", "grep", DIM),
        ("Base Qwen2.5-Coder-1.5B, F16", "verifier-base-F16", RED),
        ("Base Qwen2.5-Coder-1.5B, Q4_K_M", "verifier-base-Q4_K_M", RED),
        ("Fine-tuned verifier, F16 (calibrated)", "verifier-v1-F16", GREEN),
        ("Fine-tuned verifier, Q8_0 (CLI default)", "verifier-v1-Q8_0-greedy", GREEN),
        ("Fine-tuned verifier, Q4_K_M (calibrated)", "verifier-v1-Q4_K_M", GREEN),
    ]
    print(f"  {BOLD}{'variant':<42} {'F1':>5} {'found':>7} {'false alarms':>13} {'GGUF':>8} {'peak RAM':>9} {'tok/s':>6}{RESET}")
    for label, run, color in rows:
        m = metrics(run)
        o, p = m["overall"], m.get("perf", {})
        size = f"{p['gguf_mb'] / 1000:.1f} GB" if p.get("gguf_mb") else "-"
        ram = f"{p['peak_rss_mb'] / 1000:.1f} GB" if p.get("peak_rss_mb") else "-"
        tps = f"{p['gen_tok_per_s']:.0f}" if p.get("gen_tok_per_s") else "-"
        found = f"{o['tp']}/{o['tp'] + o['fn']}"
        print(f"  {color}{label:<42}{RESET} {BOLD}{o['f1']:>5.2f}{RESET} {found:>7} {o['fp']:>13} {size:>8} {ram:>9} {tps:>6}")


if __name__ == "__main__":
    cmd, *args = sys.argv[1:]
    {"count": cmd_count, "seconds": cmd_seconds, "table": cmd_table, "detail": cmd_detail,
     "fails": cmd_fails, "results": cmd_results}[cmd](*args)
