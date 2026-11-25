"""Prompt construction shared by training, evaluation and the CLI (one definition, no drift)."""

from __future__ import annotations

from .chunking import Chunk
from .schema import load_classes

PROMPT_VERSION = "v2"  # v1 = full prompt only; v2 adds the short prompt used for fine-tuning


SHORT = ("You are apkscan-local, an offline Android security reviewer. Report real vulnerabilities in this chunk of "
         "decompiled Android code or XML, limited to: exported_component, insecure_webview, hardcoded_secret, weak_crypto, "
         "insecure_network, insecure_storage, provider_sqli, intent_redirection. Answer with a JSON array only: one object "
         "per finding with vuln_class, cwe, masvs, severity, file, line_range, evidence, why_exploitable, fix; or [] if there "
         "is none. Never write exploit code.")


def system_prompt(style: str = "full") -> str:
    """full: detailed instructions (used for the base model); short: compact prompt the fine-tuned model is trained on."""
    if style == "short":
        return SHORT
    cls = load_classes()["classes"]
    lines = [
        "You are apkscan-local, an offline Android security reviewer. You read decompiled Android code, "
        "AndroidManifest.xml and network_security_config.xml and report real, exploitable vulnerabilities. "
        "You explain issues and fixes. You never write exploit code.",
        "",
        "Report only these classes:",
    ]
    for cid, c in cls.items():
        lines.append(f"- {cid} ({c['cwe'][0]}, {c['masvs']}): {c['definition']}")
    lines += [
        "",
        "Answer with a JSON array only, no prose and no code fences. One object per finding with keys: "
        'vuln_class, cwe, masvs, severity (high|medium|low), file, line_range ([start, end] using the line numbers shown), '
        "evidence (the vulnerable code, short), why_exploitable (one or two sentences), fix (one or two sentences).",
        "If the code has none of these issues, answer [] .",
    ]
    return "\n".join(lines)


def user_prompt(chunk: Chunk) -> str:
    head = f"File: {chunk.file}\nKind: {chunk.kind}\nLines: {chunk.start}-{chunk.end}"
    if chunk.context:
        head += f"\nEnclosing declaration: {chunk.context}"
    return f"{head}\n\n{chunk.body}"


def messages(chunk: Chunk, few_shot: list[tuple[str, str]] | None = None, style: str = "full") -> list[dict]:
    msgs = [{"role": "system", "content": system_prompt(style)}]
    for u, a in few_shot or []:
        msgs += [{"role": "user", "content": u}, {"role": "assistant", "content": a}]
    msgs.append({"role": "user", "content": user_prompt(chunk)})
    return msgs
