"""Matching and precision/recall/F1 for findings.

A prediction is a true positive when vuln_class and file are equal and its line range
overlaps (within TOL lines for code, exactly for XML) the label's line_range or one of its alt_ranges. Each label
matches once; further predictions on an already matched label are duplicates and are not
counted. Unmatched predictions overlapping an ignore region (real issue outside the v1
classes) are not counted. All other predictions are false positives.
"""

from __future__ import annotations

from collections import defaultdict

TOL = 2


def _overlap(a, b, tol=TOL) -> bool:
    return a[0] <= b[1] + tol and b[0] <= a[1] + tol


def _tol(file: str) -> int:
    """XML elements are discrete (one component per line), so no line tolerance there."""
    return 0 if file.endswith(".xml") else TOL


def _ranges(g) -> list:
    return [g["line_range"], *g.get("alt_ranges", [])]


def match(gold: list[dict], ignore: list[dict], preds: list[dict]) -> dict:
    """gold/preds carry file, vuln_class, line_range. Returns per-item outcomes."""
    matched = [False] * len(gold)
    outcomes = []
    for p in preds:
        pr = p["line_range"]
        hit = None
        for i, g in enumerate(gold):
            if not matched[i] and g["file"] == p["file"] and g["vuln_class"] == p["vuln_class"] and any(
                    _overlap(pr, r, _tol(g["file"])) for r in _ranges(g)):
                hit = i
                break
        if hit is not None:
            matched[hit] = True
            outcomes.append(("tp", p, gold[hit]))
            continue
        dup = any(matched[i] and g["file"] == p["file"] and g["vuln_class"] == p["vuln_class"] and any(
            _overlap(pr, r, _tol(g["file"])) for r in _ranges(g)) for i, g in enumerate(gold))
        if dup:
            outcomes.append(("dup", p, None))
            continue
        if any(ig["file"] == p["file"] and _overlap(pr, ig["line_range"], 0) for ig in ignore):
            outcomes.append(("ignored", p, None))
            continue
        outcomes.append(("fp", p, None))
    fns = [g for i, g in enumerate(gold) if not matched[i]]
    return {"outcomes": outcomes, "fn": fns}


def prf(tp: int, fp: int, fn: int) -> dict:
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f = 2 * p * r / (p + r) if p + r else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "precision": round(p, 3), "recall": round(r, 3), "f1": round(f, 3)}


def score(gold: list[dict], ignore: list[dict], preds: list[dict], classes: list[str]) -> dict:
    m = match(gold, ignore, preds)
    counts = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0})
    for kind, p, _ in m["outcomes"]:
        if kind in ("tp", "fp"):
            counts[p["vuln_class"]][kind] += 1
    for g in m["fn"]:
        counts[g["vuln_class"]]["fn"] += 1
    per_class = {c: prf(**counts[c]) for c in classes}
    tot = {k: sum(counts[c][k] for c in classes) for k in ("tp", "fp", "fn")}
    present = [c for c in classes if counts[c]["tp"] + counts[c]["fn"] > 0]
    macro_f1 = round(sum(per_class[c]["f1"] for c in present) / len(present), 3) if present else 0.0
    return {"overall": {**prf(**tot), "macro_f1": macro_f1}, "per_class": per_class, "match": m}
