"""Turn decompiled files into model-sized chunks with original line numbers.

Line numbers shown to the model always refer to the file on disk (after manifest
normalization), so predicted line ranges can be checked against labels.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
MAX_CHARS = 3800  # about 1.1k Qwen tokens of code per chunk

_DROP = re.compile(r"^\s*(import\s+[\w.*]+;|/\* JADX INFO: [^*]*\*/|/\* (?:compiled|loaded) from: [^*]*\*/|@Metadata\(.*\)|@SourceDebugExtension\(.*\))\s*$")
_NOISE = [
    (re.compile(r"\s*// from class: [\w.$]+.*$"), ""),
    (re.compile(r"(@Override)\s*//.*$"), r"\1"),
    (re.compile(r"^(\s*)/\* JADX INFO: [^*]*\*/\s*"), r"\1"),
]
_MEMBER = re.compile(r"^ {4}(?:@|public |private |protected |static |final |abstract |synchronized |class |interface |enum |[\w<>\[\], ]+\s+\w+\s*\()")
_CLASS_DECL = re.compile(r"^\s*(?:public |private |protected |static |final |abstract |data |open |internal )*(class|interface|object|enum)\s+\w+")


@dataclass
class Chunk:
    file: str  # path relative to the scan root, e.g. "AndroidManifest.xml" or "com/x/Foo.java"
    kind: str  # java | kotlin | manifest | netconfig
    start: int
    end: int
    body: str  # numbered lines
    context: str = ""  # extra line such as the enclosing class declaration

    @property
    def key(self) -> str:
        return f"{self.file}:{self.start}-{self.end}"


NAMESPACES = {ANDROID_NS: "android:", "{http://schemas.android.com/tools}": "tools:",
              "{http://schemas.android.com/apk/res-auto}": "app:"}


def _attr_name(k: str) -> str:
    for ns, prefix in NAMESPACES.items():
        if k.startswith(ns):
            return prefix + k[len(ns):]
    return k


def normalize_xml(text: str) -> str:
    """Re-serialize Android XML with one element per line (stable, compact line numbers)."""
    root = ET.fromstring(text.encode("utf-8") if isinstance(text, str) else text)
    out = ['<?xml version="1.0" encoding="utf-8"?>']

    def esc(v: str) -> str:
        return v.replace("&", "&amp;").replace('"', "&quot;").replace("<", "&lt;")

    def emit(el, depth):
        attrs = "".join(f' {_attr_name(k)}="{esc(v)}"' for k, v in el.attrib.items())
        tag = _attr_name(el.tag)
        pad = "    " * depth
        children = list(el)
        if children:
            out.append(f"{pad}<{tag}{attrs}>")
            for c in children:
                emit(c, depth + 1)
            out.append(f"{pad}</{tag}>")
        else:
            out.append(f"{pad}<{tag}{attrs}/>")

    emit(root, 0)
    s = "\n".join(out) + "\n"
    if root.tag == "manifest":
        s = s.replace("<manifest", '<manifest xmlns:android="http://schemas.android.com/apk/res/android"', 1)
    return s


def clean_line(line: str) -> str:
    for pat, rep in _NOISE:
        line = pat.sub(rep, line)
    return line.rstrip()


def number(lines: list[tuple[int, str]]) -> str:
    return "\n".join(f"{n:>4}| {t}" for n, t in lines)


def kind_for(path: str) -> str:
    if path.endswith("AndroidManifest.xml"):
        return "manifest"
    if path.endswith(".xml"):
        return "netconfig"
    if path.endswith(".kt"):
        return "kotlin"
    return "java"


def chunk_file(rel_path: str, text: str, max_chars: int = MAX_CHARS) -> list[Chunk]:
    kind = kind_for(rel_path)
    raw = text.splitlines()
    if kind in ("manifest", "netconfig"):
        kept = [(i + 1, l.rstrip()) for i, l in enumerate(raw) if l.strip()]
    else:
        kept = [(i + 1, clean_line(l)) for i, l in enumerate(raw) if not _DROP.match(l)]
        kept = [(n, l) for n, l in kept if l.strip() or True]
        # trim leading/trailing blank lines and collapse blank runs
        out, prev_blank = [], True
        for n, l in kept:
            blank = not l.strip()
            if blank and prev_blank:
                continue
            out.append((n, l))
            prev_blank = blank
        while out and not out[-1][1].strip():
            out.pop()
        kept = out
    if not kept:
        return []

    decl = next((l.strip() for _, l in kept if _CLASS_DECL.match(l)), "")
    chunks: list[list[tuple[int, str]]] = []
    cur: list[tuple[int, str]] = []
    size = 0
    last_boundary = 0
    for n, l in kept:
        ln = len(l) + 7
        if cur and size + ln > max_chars:
            cut = last_boundary if last_boundary > len(cur) * 0.3 else len(cur)
            chunks.append(cur[:cut])
            cur = cur[cut:]
            size = sum(len(x[1]) + 7 for x in cur)
            last_boundary = 0
        is_boundary = (not l.strip()) or (kind in ("java", "kotlin") and _MEMBER.match(l)) or (
            kind in ("manifest", "netconfig") and re.match(r"^\s{4,8}<(activity|service|receiver|provider|application|domain-config|base-config)\b", l))
        if is_boundary and cur:
            last_boundary = len(cur)
        cur.append((n, l))
        size += ln
    if cur:
        chunks.append(cur)

    result = []
    for c in chunks:
        while c and not c[0][1].strip():
            c = c[1:]
        if not c:
            continue
        body = number(c)
        ctx = "" if (not decl or decl in body) else decl
        result.append(Chunk(rel_path, kind, c[0][0], c[-1][0], body, ctx))
    return result
