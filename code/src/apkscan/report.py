"""Merge per-chunk findings into one report (JSON and Markdown)."""

from __future__ import annotations

SEV_ORDER = {"high": 0, "medium": 1, "low": 2}


def dedupe(findings: list[dict]) -> list[dict]:
    """Drop findings of the same class in the same file whose line ranges overlap."""
    out: list[dict] = []
    for f in sorted(findings, key=lambda x: (x["file"], x["line_range"][0], SEV_ORDER.get(x.get("severity"), 3))):
        dup = any(o["file"] == f["file"] and o["vuln_class"] == f["vuln_class"]
                  and o["line_range"][0] <= f["line_range"][1] and f["line_range"][0] <= o["line_range"][1] for o in out)
        if not dup:
            out.append(f)
    return sorted(out, key=lambda x: (SEV_ORDER.get(x.get("severity"), 3), x["file"], x["line_range"][0]))


def to_markdown(meta: dict, findings: list[dict]) -> str:
    lines = [f"# apkscan-local report: {meta.get('target', '')}", "",
             f"Model: `{meta.get('model', '')}` ({meta.get('mode', 'finder')} mode). Scanned {meta.get('files', 0)} files"
             + (f", {meta['candidates']} pattern candidates verified" if 'candidates' in meta else f" in {meta.get('chunks', 0)} chunks")
             + f" in {meta.get('seconds', 0)} s, fully offline.", ""]
    if not findings:
        lines.append("No findings in the v1 classes.")
        return "\n".join(lines) + "\n"
    counts = {}
    for f in findings:
        counts[f.get("severity", "?")] = counts.get(f.get("severity", "?"), 0) + 1
    lines.append("Findings: " + ", ".join(f"{counts.get(s, 0)} {s}" for s in ("high", "medium", "low")))
    lines += ["", "| Severity | Class | Location | Evidence |", "|---|---|---|---|"]
    for f in findings:
        ev = str(f.get("evidence", "")).replace("|", "\\|")[:110]
        lines.append(f"| {f.get('severity')} | {f['vuln_class']} ({f.get('cwe', '')}) | `{f['file']}:{f['line_range'][0]}-{f['line_range'][1]}` | {ev} |")
    lines.append("")
    for i, f in enumerate(findings, 1):
        lines += [f"## {i}. {f['vuln_class']} in `{f['file']}` lines {f['line_range'][0]}-{f['line_range'][1]}", "",
                  f"- Severity: {f.get('severity')}, {f.get('cwe', '')}, {f.get('masvs', '')}",
                  f"- Evidence: `{f.get('evidence', '')}`",
                  f"- Why it matters: {f.get('why_exploitable', '')}",
                  f"- Fix: {f.get('fix', '')}", ""]
    lines.append("Model output; verify each finding before acting on it.")
    return "\n".join(lines) + "\n"
