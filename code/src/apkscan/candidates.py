"""Loose, high-recall candidate scanner and verifier prompts.

Stage 1 (this file): broad per-class patterns flag candidate lines. Most are false alarms.
Stage 2 (verifier model): sees a small window around each candidate and answers whether it is a
real vulnerability of that class, with severity, explanation and fix.

The patterns were written to maximize recall on the TRAINING apps (DIVA, allsafe, InjuredAndroid,
MASTG demos, synthetic); the held-out test apps were not used to tune them.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .chunking import _CLASS_DECL, _DROP, clean_line, kind_for

JAVA = {
    "insecure_webview": [r"addJavascriptInterface", r"setJavaScriptEnabled\(\s*true|javaScriptEnabled\s*=\s*true",
                         r"setAllow\w*Access\w*\(", r"allow\w*Access\w*\s*=\s*true", r"\.loadUrl\(", r"\.loadData(WithBaseURL)?\(",
                         r"shouldOverrideUrlLoading", r"\.getHost\(\)"],
    "hardcoded_secret": [r'(?i)\b\w*(key|secret|pass|pwd|token|auth|api|cred|pin)\w*\s*=\s*"[^"]{4,}"', r'"[^"]{4,}"\.getBytes\(',
                         r'"[A-Za-z0-9+/=_\-]{16,}"', r'Base64\.decode\(\s*"', r"byte\[\]\s*\w+\s*=\s*\{\s*-?\d",
                         r'\.equals\(\s*"[^"]{4,}"\s*\)', r'(?i)"[^"]*(api.?key|password|secret)[^"]*:\s*[^"]+"',
                         r"<\w*(Password|Token)\w*[^>]*>[^<]{4,}<"],
    "weak_crypto": [r"Cipher\.getInstance", r"MessageDigest\.getInstance", r"IvParameterSpec", r"SecretKeySpec",
                    r"new Random\(|Math\.random\(|\bRandom\(\)", r"DES(ede)?KeySpec|SecretKeyFactory", r"KeyGenerator",
                    r"byte\[\]\s*\w*[iI][vV]\w*\s*=", r"new Date\(\)\.getTime\(\)"],
    "insecure_network": [r'"http://', r'scheme\(\s*"http"', r"TrustManager", r"checkServerTrusted", r"[Hh]ostname[Vv]erifier",
                         r"onReceivedSslError|\.proceed\(\)", r"SSLSocket|setSSLSocketFactory|SSLContext", r"ALLOW_ALL",
                         r'protocol\s*=\s*"'],
    "insecure_storage": [r"getSharedPreferences|getDefaultSharedPreferences", r"\.putString\(", r"MODE_WORLD_\w+",
                         r"openFileOutput|openOrCreateDatabase", r"getExternal\w*(Dir|Directory|Dirs)\(", r"new FileWriter|new FileOutputStream",
                         r"createTempFile|setReadable\(|setWritable\(", r'execSQL\(\s*"INSERT'],
    "intent_redirection": [r"getParcelableExtra", r"setResult\(", r"sendBroadcast\(|sendOrderedBroadcast\(", r"PendingIntent\.get",
                           r"getQueryParameter\(", r'new Intent\(\s*"', r"\.setAction\(", r"void onReceive\(",
                           r"get(String|Boolean|Int)Extra\(|getExtras\(\)", r"startActivity\(\s*\w+\s*\)|startService\(",
                           r"registerReceiver\("],
}
PROVIDER_ONLY = {"provider_sqli": [r"rawQuery\(|execSQL\(", r"\.query\(", r"appendWhere\(", r"\.delete\(|\.update\(",
                                   r"public\s+Cursor\s+query\("]}
MANIFEST_COMPONENT = re.compile(r"^\s*<(activity|activity-alias|service|receiver|provider)\b")
NETCONFIG = [r'cleartextTrafficPermitted="true"', r'usesCleartextTraffic="true"', r"<certificates\b"]

MERGE_GAP = 3  # same-class hits within this many lines become one candidate
CONTEXT = 10  # lines of context on each side of a candidate in the verifier window


@dataclass
class Candidate:
    file: str
    kind: str
    vuln_class: str
    start: int
    end: int
    hits: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return f"{self.file}:{self.vuln_class}:{self.start}-{self.end}"


def _merge(hits: list[tuple[int, str]], cls: str, file: str, kind: str) -> list[Candidate]:
    out: list[Candidate] = []
    for n, text in sorted(hits):
        if out and n - out[-1].end <= MERGE_GAP:
            out[-1].end = n
            out[-1].hits.append(text)
        else:
            out.append(Candidate(file, kind, cls, n, n, [text]))
    return out


def _manifest_candidates(rel: str, lines: list[str]) -> list[Candidate]:
    out = []
    i = 0
    while i < len(lines):
        m = MANIFEST_COMPONENT.match(lines[i])
        if m:
            tag = m.group(1)
            end = i
            if not lines[i].rstrip().endswith("/>"):
                close = f"</{tag}>"
                while end < len(lines) - 1 and close not in lines[end]:
                    end += 1
            block = "\n".join(lines[i:end + 1])
            if 'exported="true"' in block or "<intent-filter" in block:
                out.append(Candidate(rel, "manifest", "exported_component", i + 1, end + 1, [lines[i].strip()]))
            i = end + 1
            continue
        if re.search(r'usesCleartextTraffic="true"', lines[i]):
            out.append(Candidate(rel, "manifest", "insecure_network", i + 1, i + 1, [lines[i].strip()]))
        i += 1
    return out


def find_candidates(rel: str, text: str) -> list[Candidate]:
    kind = kind_for(rel)
    lines = text.splitlines()
    if kind == "manifest":
        return _manifest_candidates(rel, lines)
    if kind == "netconfig":
        hits = [(i + 1, l.strip()) for i, l in enumerate(lines) if any(re.search(p, l) for p in NETCONFIG)]
        return _merge(hits, "insecure_network", rel, kind)
    rules = dict(JAVA)
    if re.search(r"extends\s+ContentProvider|:\s*ContentProvider\(|Cursor\s+query\(\s*(@\w+\s+)?Uri", text):
        rules.update(PROVIDER_ONLY)
    compiled = {c: [re.compile(p) for p in ps] for c, ps in rules.items()}
    per_class: dict[str, list[tuple[int, str]]] = {c: [] for c in compiled}
    for i, raw in enumerate(lines):
        if _DROP.match(raw):
            continue
        s = raw.strip()
        if not s or s.startswith(("//", "*", "/*", "import ", "package ")):
            continue
        for c, pats in compiled.items():
            if any(p.search(raw) for p in pats):
                per_class[c].append((i + 1, s))
    out = []
    for c, hits in per_class.items():
        out += _merge(hits, c, rel, kind)
    return out


def window(text: str, cand: Candidate, context: int = CONTEXT) -> tuple[str, str]:
    """Numbered lines around the candidate (flagged lines marked with '>'), plus the enclosing declaration."""
    lines = text.splitlines()
    lo, hi = max(1, cand.start - context), min(len(lines), cand.end + context)
    out = []
    for n in range(lo, hi + 1):
        raw = lines[n - 1]
        if cand.kind in ("java", "kotlin") and _DROP.match(raw):
            continue
        t = clean_line(raw) if cand.kind in ("java", "kotlin") else raw.rstrip()
        mark = ">" if cand.start <= n <= cand.end else " "
        out.append(f"{mark}{n:>4}| {t}")
    decl = ""
    if cand.kind in ("java", "kotlin"):
        decl = next((l.strip() for l in lines[: cand.start] if _CLASS_DECL.match(l)), "")
    elif cand.kind == "manifest":
        decl = next((l.strip() for l in lines if "<uses-sdk" in l), "")
    return "\n".join(out), decl


VERIFIER_SHORT = ("You are apkscan-local's verifier. A pattern scanner flagged the lines marked '>' in this Android code as a "
                  "possible {cls} issue. Decide whether it is a real, exploitable {cls} vulnerability. Answer with JSON only: "
                  '{{"real": false}} if not, or {{"real": true, "severity": ..., "cwe": ..., "evidence": ..., '
                  '"why_exploitable": ..., "fix": ...}} if it is. Never write exploit code.')


def verifier_messages(cand: Candidate, text: str, style: str = "short") -> list[dict]:
    from .schema import load_classes
    body, decl = window(text, cand)
    spec = load_classes()["classes"][cand.vuln_class]
    system = VERIFIER_SHORT.format(cls=cand.vuln_class)
    if style == "full":
        system += f"\n\nDefinition of {cand.vuln_class}: {spec['definition']}\nMost flagged lines are false alarms; answer real only when the code is actually vulnerable."
    head = f"File: {cand.file}\nSuspected class: {cand.vuln_class}\nFlagged lines: {cand.start}-{cand.end}"
    if decl:
        head += f"\nContext: {decl}"
    return [{"role": "system", "content": system}, {"role": "user", "content": f"{head}\n\n{body}"}]
