"""Regex baseline: one pattern list per class, applied line by line to each chunk.

It sees exactly the same chunks as the model and reports one finding per matching line.
Written to be a fair, reasonably strong pattern baseline (the kind of thing a quick
grep-based audit would use), not a strawman.
"""

from __future__ import annotations

import re

from apkscan.chunking import Chunk

JAVA_RULES = {
    "insecure_webview": [r"addJavascriptInterface\(", r"setAllow(File|Content|UniversalAccess|FileAccess)\w*\(\s*true\s*\)",
                         r"setAllowUniversalAccessFromFileURLs\(\s*true", r"setAllowFileAccessFromFileURLs\(\s*true",
                         r"\.loadUrl\(\s*(getIntent|intent|url|uri|data)", r"shouldOverrideUrlLoading"],
    "hardcoded_secret": [r'(?i)(key|secret|passw(or)?d|token|api_?key|pwd|pin)\w*\s*=\s*"[^"]{6,}"',
                         r'"(AIza[0-9A-Za-z_\-]{30,}|sk_live_[0-9A-Za-z]{10,}|AKIA[0-9A-Z]{16})"'],
    "weak_crypto": [r'Cipher\.getInstance\(\s*"(AES|DES|DESede|RC4|Blowfish)"\s*\)', r'Cipher\.getInstance\(\s*"[^"]*/ECB/',
                    r'Cipher\.getInstance\(\s*"(DES|DESede|RC4)/', r'MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"',
                    r"new IvParameterSpec\(\s*new byte\[", r"byte\[\]\s+\w*[iI][vV]\w*\s*=\s*\{", r"new Random\(\)"],
    "insecure_network": [r'"http://(?!localhost|127\.0\.0\.1|schemas\.android\.com|www\.w3\.org)', r"checkServerTrusted\([^)]*\)\s*\{\s*\}?$",
                         r"ALLOW_ALL_HOSTNAME_VERIFIER", r"\.proceed\(\)", r'scheme\(\s*"http"\s*\)', r"hostnameVerifier\(\s*\(.*\)\s*->\s*true"],
    "insecure_storage": [r'putString\(\s*"[^"]*(pass|pwd|token|pin|secret|card)', r"MODE_WORLD_(READABLE|WRITEABLE)",
                         r"getSharedPreferences\([^,]+,\s*[12]\s*\)", r"getExternalStorage(Directory|PublicDirectory)\(",
                         r"getExternal(Files|Cache)Dir\("],
    "provider_sqli": [r"rawQuery\(\s*\"[^\"]*\"\s*\+", r"execSQL\(\s*\"[^\"]*\"\s*\+", r"appendWhere\([^)]*\+",
                      r"\.query\(\s*\w+\s*,\s*projection\s*,\s*selection"],
    "intent_redirection": [r"getParcelableExtra\([^)]*\)\s*\)?\s*;?.*", r"startActivity\(\s*\(?Intent\)?\s*\w*\.?getParcelableExtra",
                           r"setResult\([^,]+,\s*getIntent\(\)\s*\)", r"PendingIntent\.get\w+\([^)]*FLAG_MUTABLE",
                           r"sendBroadcast\(\s*\w+\s*\)"],
}
MANIFEST_RULES = {
    "exported_component": [r'<(activity|service|receiver|provider)\b(?![^>]*android:permission=)[^>]*android:exported="true"'],
    "insecure_network": [r'usesCleartextTraffic="true"', r'cleartextTrafficPermitted="true"'],
}
_LINE = re.compile(r"^\s*(\d+)\| (.*)$")


def predict(chunk: Chunk) -> list[dict]:
    rules = MANIFEST_RULES if chunk.kind in ("manifest", "netconfig") else JAVA_RULES
    compiled = {c: [re.compile(p) for p in ps] for c, ps in rules.items()}
    preds = []
    for raw in chunk.body.splitlines():
        m = _LINE.match(raw)
        if not m:
            continue
        n, text = int(m.group(1)), m.group(2)
        if chunk.kind == "manifest" and "android.intent.category.LAUNCHER" in chunk.body:
            pass
        for cls, pats in compiled.items():
            if any(p.search(text) for p in pats):
                if cls == "exported_component" and ("MAIN" in text or "LAUNCHER" in text):
                    continue
                preds.append({"vuln_class": cls, "file": chunk.file, "line_range": [n, n], "evidence": text.strip()[:120]})
    return preds
