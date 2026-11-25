"""Build train/valid JSONL (chat format for MLX-LM) from synthetic samples and labelled real apps.

Splits:
- test: whole held-out apps (labels/*.yaml with split: test). Never written to training files.
- train/valid: labelled training apps and MASTG demos (split by app/demo) plus synthetic samples
  (valid gets a separate generator seed; it only monitors loss).

Run: python data/builder.py   (deterministic; writes data/processed/ and a manifest with hashes)
"""

from __future__ import annotations

import hashlib
import json
import random
import re
import sys
from collections import Counter
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "data" / "synth")]

from apkscan.chunking import chunk_file  # noqa: E402
from apkscan.prompts import PROMPT_VERSION, system_prompt, user_prompt  # noqa: E402
from apkscan.schema import FIELDS, make_finding  # noqa: E402
import generator  # noqa: E402

OUT = ROOT / "data" / "processed"
LABELS = ROOT / "data" / "labels"
SCAN = ROOT / "data" / "scan"
SEED = 1234
REAL_REPEAT = 2
PROMPT_STYLE = "short"  # the fine-tuned model is trained on the compact prompt

# Rule checks: the labelled lines of a synthetic finding must contain a signal for its class.
RULES = {
    "insecure_webview": r"addJavascriptInterface|setAllow\w*Access\w*\(true\)|loadUrl|endsWith|contains|startsWith",
    "hardcoded_secret": r'=\s*"[^"]{8,}"',
    "weak_crypto": r'getInstance\("(AES|DES|DESede)(/ECB[^"]*)?"\)|IvParameterSpec|byte\[\] iv = \{|MD5|SHA-?1|new Random\(\)',
    "insecure_network": r'http://|checkServerTrusted|-> true|return true|proceed\(\)|cleartextTrafficPermitted="true"|usesCleartextTraffic="true"',
    "insecure_storage": r"putString|MODE_WORLD|, [12]\)|External|FileWriter",
    "provider_sqli": r"rawQuery|selection|sortOrder|\+ id",
    "intent_redirection": r"getParcelableExtra|setResult|sendBroadcast|putExtra|PendingIntent|\.equals\(intent\.getAction|startActivity|startService",
    "exported_component": r'exported="true"|<intent-filter>',
}


def check_sample(text: str, findings: list[dict]) -> list[str]:
    lines = text.splitlines()
    errs = []
    for f in findings:
        a, b = f["line_range"]
        seg = "\n".join(lines[a - 1:b + 1 if f["vuln_class"] == "exported_component" else b])
        if not re.search(RULES[f["vuln_class"]], seg):
            errs.append(f"{f['vuln_class']} rule failed on lines {a}-{b}: {seg[:120]!r}")
    return errs


def assign(chunks, findings):
    """Map each finding to the chunk that holds most of its line range."""
    per = {c.key: [] for c in chunks}
    for f in findings:
        a, b = f["line_range"]
        best, best_ov = None, -1
        for c in chunks:
            ov = min(b, c.end) - max(a, c.start)
            if ov > best_ov:
                best, best_ov = c, ov
        if best is not None and best_ov >= 0:
            per[best.key].append(f)
    return per


TARGET_STYLE = "list"  # list: [{...}]; byclass: {"<class>": [{...}], ...} with every class key present


def target(findings: list[dict]) -> str:
    fs = sorted(findings, key=lambda f: (f["line_range"][0], f["vuln_class"]))
    if TARGET_STYLE == "byclass":
        from apkscan.schema import class_ids
        out = {c: [{k: f[k] for k in FIELDS if k != "vuln_class"} for f in fs if f["vuln_class"] == c] for c in class_ids()}
        return json.dumps(out, ensure_ascii=False)
    return json.dumps([{k: f[k] for k in FIELDS} for f in fs], ensure_ascii=False)


def to_records(file: str, text: str, findings: list[dict], source: str) -> list[dict]:
    chunks = chunk_file(file, text)
    per = assign(chunks, findings)
    recs = []
    for c in chunks:
        recs.append({"messages": [{"role": "system", "content": system_prompt(PROMPT_STYLE)},
                                  {"role": "user", "content": user_prompt(c)},
                                  {"role": "assistant", "content": target(per[c.key])}],
                     "meta": {"source": source, "file": file, "lines": [c.start, c.end], "n": len(per[c.key])}})
    return recs


DEFAULTS = {
    "exported_component": ("Any app on the device can start or call this component directly with crafted intents or queries, bypassing the app's own flow.",
                           'Set android:exported="false" unless other apps need it; otherwise protect it with a signature-level android:permission.'),
    "insecure_webview": ("Attacker-controlled content loaded in this WebView can run script with the app's WebView privileges.",
                         "Load only allowlisted https origins, keep JavaScript and file access disabled unless required, and validate URLs by exact host."),
    "hardcoded_secret": ("The value ships inside every APK and can be extracted with a decompiler, so it is not secret.",
                         "Remove it from the app; keep secrets server-side or generate keys in the Android Keystore."),
    "weak_crypto": ("This algorithm or mode is broken or deterministic, so encrypted data can be recovered or patterns leak.",
                    'Use AES/GCM/NoPadding with a random IV and a Keystore key, SecureRandom for random values, and a slow salted KDF for passwords.'),
    "insecure_network": ("Traffic can be read or modified by anyone on the network path because transport security is missing or disabled.",
                         "Use HTTPS with default certificate and hostname validation; disallow cleartext in network_security_config.xml."),
    "insecure_storage": ("Sensitive data is stored where other apps, backups or anyone with device access can read it.",
                         "Avoid storing it, or encrypt it with a Keystore-backed key (EncryptedSharedPreferences/EncryptedFile) in internal storage."),
    "provider_sqli": ("Caller-controlled input becomes part of the SQL statement, so another app can read or change data it should not access.",
                      "Use parameterized selections with selectionArgs, a strict projection map and qb.setStrict(true), and require a permission."),
    "intent_redirection": ("Untrusted intent data is acted on or sensitive data leaves through an intent other apps can intercept.",
                           "Validate incoming intents, never launch nested intents from extras, and use explicit intents or permissions for sensitive data."),
}


def label_to_finding(g: dict) -> dict:
    """Turn a training label entry into a full target finding (class defaults for missing why/fix)."""
    why, fix = DEFAULTS[g["vuln_class"]]
    return make_finding(g["vuln_class"], g["severity"], g["file"], g["line_range"], g["evidence"],
                        g.get("why", why), g.get("fix", fix), g.get("cwe"))


def _records_for_files(files: dict[str, str], labels: list[dict], source: str) -> list[dict]:
    by_file: dict[str, list] = {}
    for g in labels:
        by_file.setdefault(g["file"], []).append(label_to_finding(g))
    unknown = set(by_file) - set(files)
    if unknown:
        raise SystemExit(f"{source}: labels reference missing files {unknown}")
    recs = []
    for f, text in files.items():
        recs += to_records(f, text, by_file.get(f, []), source)
    return recs


def real_app_records(split: str) -> list[dict]:
    from apkscan.chunking import normalize_xml
    recs = []
    for lp in sorted(LABELS.glob("*.yaml")):
        lab = yaml.safe_load(lp.read_text())
        if lab.get("split") != split:
            continue
        if lab.get("kind") == "mastg":
            base = ROOT / lab["base"]
            for d in lab["demos"]:
                files = {}
                for scan_name, src in d["files"].items():
                    txt = (base / d["dir"] / src).read_text(errors="replace")
                    files[scan_name] = normalize_xml(txt) if scan_name.endswith(".xml") else txt
                recs += _records_for_files(files, d.get("findings", []), f"mastg-{d['id']}")
            continue
        root = SCAN / lab["app"]
        names = lab.get("reviewed_files") or sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
        files = {n: (root / n).read_text(errors="replace") for n in names}
        recs += _records_for_files(files, lab.get("findings", []), lab["app"])
    return recs


def synth_records(seed: int, n_java: int, n_man: int, n_net: int) -> tuple[list[dict], Counter]:
    recs, tids = [], Counter()
    for s in generator.generate(seed, n_java, n_man, n_net):
        errs = check_sample(s.text, s.findings)
        if errs:
            raise SystemExit(f"synthetic rule check failed for {s.file}: {errs}")
        recs += to_records(s.file, s.text, s.findings, "synthetic")
        tids.update(s.tids)
    return recs, tids


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main(n_java=500, n_man=70, n_net=30):
    OUT.mkdir(parents=True, exist_ok=True)
    train_syn, tids = synth_records(SEED, n_java, n_man, n_net)
    valid_syn, _ = synth_records(SEED + 1, n_java // 10, n_man // 10, n_net // 10)
    real_train = real_app_records("train")
    train = train_syn + real_train * REAL_REPEAT  # real code is scarce; repeat it so it is not drowned out
    valid = valid_syn + real_app_records("valid")
    rng = random.Random(SEED)
    rng.shuffle(train)
    rng.shuffle(valid)
    stats = {}
    for name, rows in (("train", train), ("valid", valid)):
        p = OUT / f"{name}.jsonl"
        with p.open("w") as fh:
            for r in rows:
                fh.write(json.dumps({"messages": r["messages"]}, ensure_ascii=False) + "\n")
        with (OUT / f"{name}.meta.jsonl").open("w") as fh:
            for r in rows:
                fh.write(json.dumps(r["meta"]) + "\n")
        cls = Counter()
        for r in rows:
            for f in json.loads(r["messages"][2]["content"]):
                cls[f["vuln_class"]] += 1
        stats[name] = {"records": len(rows), "empty": sum(1 for r in rows if r["meta"]["n"] == 0), "target_style": TARGET_STYLE,
                       "by_source": dict(Counter(r["meta"]["source"] for r in rows)), "findings_by_class": dict(cls),
                       "sha256": sha(p)}
    stats["prompt_version"] = PROMPT_VERSION
    stats["prompt_style"] = PROMPT_STYLE
    stats["seed"] = SEED
    stats["real_repeat"] = REAL_REPEAT
    stats["real_train_unique_records"] = len(real_train)
    stats["synthetic_template_counts"] = dict(sorted(tids.items()))
    (OUT / "manifest.json").write_text(json.dumps(stats, indent=2))
    print(json.dumps({k: v for k, v in stats.items() if k != "synthetic_template_counts"}, indent=2))


if __name__ == "__main__":
    main()
