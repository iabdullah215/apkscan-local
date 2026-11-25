"""Finding schema, class registry and tolerant parsing of model output."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]
CLASSES_PATH = ROOT / "configs" / "classes.yaml"
FIELDS = ["vuln_class", "cwe", "masvs", "severity", "file", "line_range", "evidence", "why_exploitable", "fix"]


@lru_cache(maxsize=1)
def load_classes(path: str | None = None) -> dict:
    data = yaml.safe_load(Path(path or CLASSES_PATH).read_text())
    return data


def class_ids() -> list[str]:
    return list(load_classes()["classes"].keys())


def severities() -> list[str]:
    return list(load_classes()["severities"])


@dataclass
class ParseResult:
    findings: list[dict]
    strict_json: bool  # whole output is a JSON array, nothing else
    parsed: bool  # a JSON array could be recovered (fences or prose stripped)
    schema_errors: list[str] = field(default_factory=list)

    @property
    def schema_valid(self) -> bool:
        return self.parsed and not self.schema_errors


_FENCE = re.compile(r"^```(?:json)?\s*|\s*```$", re.S)


def _recover_array(text: str):
    t = _FENCE.sub("", text.strip())
    try:
        return json.loads(t)
    except json.JSONDecodeError:
        pass
    start, end = t.find("["), t.rfind("]")
    if start != -1 and end > start:
        try:
            return json.loads(t[start : end + 1])
        except json.JSONDecodeError:
            return None
    return None


def _is_json(text: str) -> bool:
    try:
        json.loads(text.strip())
        return True
    except json.JSONDecodeError:
        return False


def validate_finding(f: dict) -> list[str]:
    errs = []
    if not isinstance(f, dict):
        return ["finding is not an object"]
    for k in FIELDS:
        if k not in f:
            errs.append(f"missing {k}")
    if f.get("vuln_class") not in class_ids():
        errs.append(f"unknown vuln_class {f.get('vuln_class')!r}")
    if f.get("severity") not in severities():
        errs.append(f"bad severity {f.get('severity')!r}")
    lr = f.get("line_range")
    if not (isinstance(lr, list) and len(lr) == 2 and all(isinstance(x, int) for x in lr) and lr[0] <= lr[1]):
        errs.append(f"bad line_range {lr!r}")
    return errs


def parse_output(text: str) -> ParseResult:
    strict = False
    try:
        obj = json.loads(text.strip())
        strict = isinstance(obj, (list, dict))
    except json.JSONDecodeError:
        t = _FENCE.sub("", text.strip())
        obj = json.loads(t) if _is_json(t) else _recover_array(text)
    if isinstance(obj, dict) and set(obj) <= set(class_ids()):
        # by-class form {"weak_crypto": [{...}], "insecure_network": [], ...}
        flat = []
        for cls, items in obj.items():
            for f in items if isinstance(items, list) else []:
                if isinstance(f, dict):
                    flat.append({"vuln_class": cls, **f})
        obj = flat
    elif isinstance(obj, dict):
        strict = False
    if not isinstance(obj, list):
        return ParseResult([], strict_json=False, parsed=False, schema_errors=["no JSON array"])
    errors, findings = [], []
    for f in obj:
        e = validate_finding(f)
        errors.extend(e)
        if isinstance(f, dict) and f.get("vuln_class") in class_ids():
            lr = f.get("line_range")
            if isinstance(lr, list) and len(lr) == 2 and all(isinstance(x, int) for x in lr):
                findings.append(f)
    return ParseResult(findings, strict_json=strict, parsed=True, schema_errors=errors)


def make_finding(vuln_class: str, severity: str, file: str, line_range: list[int], evidence: str,
                 why: str, fix: str, cwe: str | None = None) -> dict:
    spec = load_classes()["classes"][vuln_class]
    return {
        "vuln_class": vuln_class,
        "cwe": cwe or spec["cwe"][0],
        "masvs": spec["masvs"],
        "severity": severity,
        "file": file,
        "line_range": [int(line_range[0]), int(line_range[1])],
        "evidence": evidence,
        "why_exploitable": why,
        "fix": fix,
    }
