"""Collect results/runs/*/metrics.json into results/results.md and results/chart.png."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from apkscan.schema import class_ids  # noqa: E402

RUNS = ROOT / "results" / "runs"
ORDER = ["grep", "base-f16-zeroshot", "base-f16-fewshot", "base-q4-zeroshot", "tuned-v1-Q4_K_M-greedy",
         "tuned-v2-Q4_K_M-greedy", "tuned-v2-F16", "tuned-v2-Q8_0", "tuned-v2-Q4_K_M"]
LABELS = {"grep": "grep baseline", "base-f16-zeroshot": "Base Qwen2.5-Coder-1.5B, zero-shot (F16)",
          "base-f16-fewshot": "Base, few-shot k=2 (F16)", "base-q4-zeroshot": "Base, zero-shot (Q4_K_M)"}


def label(name):
    if name.startswith("src-"):
        return label(name[4:])
    if name in LABELS:
        return LABELS[name]
    if name.startswith("tuned-"):
        parts = name.split("-")
        run, q = parts[1], parts[2]
        how = "greedy" if name.endswith("-greedy") else "calibrated"
        return f"Fine-tuned {run} ({q}, {how})"
    return name


def load(split="test"):
    runs = {}
    for p in sorted(RUNS.glob("*/metrics.json")):
        m = json.loads(p.read_text())
        if m.get("split", "test") == split and m.get("pipeline", "finder") == "finder":
            runs[p.parent.name] = m
    key = (lambda n: n[4:]) if split == "test_src" else (lambda n: n)
    names = [n for o in ORDER for n in runs if key(n) == o] + sorted(n for n in runs if key(n) not in ORDER)
    return [(n, runs[n]) for n in names]


def main():
    runs = load()
    out = ["# Results", "",
           "Held-out test apps: OVAA 1.0.0 and InsecureBankv2 (whole apps never seen in training), "
           f"{runs[0][1]['chunks']} chunks, {runs[0][1]['gold_findings']} labelled findings. "
           "Hardware: Apple M4 (10 cores), 16 GB unified memory, macOS 27.2.1, llama.cpp b10210 (Metal). "
           "Decoding: temperature 0, seed 0, no grammar constraint.", "",
           "## Overall", "",
           "| Variant | Precision | Recall | F1 | Macro F1 | TP / FP / FN | Strict JSON | Gen tok/s | Prompt tok/s | s/chunk | Peak RSS MB | GGUF MB |",
           "|---|---:|---:|---:|---:|---|---:|---:|---:|---:|---:|---:|"]
    for n, m in runs:
        o, pf = m["overall"], m.get("perf") or {}
        out.append(f"| {label(n)} | {o['precision']:.2f} | {o['recall']:.2f} | **{o['f1']:.2f}** | {o['macro_f1']:.2f} | "
                   f"{o['tp']} / {o['fp']} / {o['fn']} | {m['json_valid_strict']:.0%} | {pf.get('gen_tok_per_s', '-')} | "
                   f"{pf.get('prompt_tok_per_s', '-')} | {pf.get('avg_s_per_chunk', '-')} | {pf.get('peak_rss_mb', '-')} | {pf.get('gguf_mb', '-')} |")
    out += ["", "Peak RSS is the llama-server process and includes memory-mapped weights.", "",
            "## F1 per class", "", "| Class | gold | " + " | ".join(label(n) for n, _ in runs) + " |",
            "|---|---:|" + "---:|" * len(runs)]
    for c in class_ids():
        gold = runs[0][1]["per_class"][c]["tp"] + runs[0][1]["per_class"][c]["fn"]
        cells = []
        for _, m in runs:
            pc = m["per_class"][c]
            cells.append(f"{pc['f1']:.2f} ({pc['tp']}/{pc['fp']}/{pc['fn']})")
        out.append(f"| {c} | {gold} | " + " | ".join(cells) + " |")
    out += ["", "Cells: F1 (TP/FP/FN). With small per-class counts, read the raw counts, not only F1.", ""]
    src = load("test_src")
    if src:
        out += ["## Same apps from source code instead of the APK", "",
                "Same two apps and the same 36 findings, labelled at source line numbers (GitHub source of OVAA and "
                "InsecureBankv2). Same models, prompts and calibration.", "",
                "| Variant | F1 on APK (jadx) | F1 on source | Precision (src) | Recall (src) | TP / FP / FN (src) | Strict JSON (src) | s/chunk (src) |",
                "|---|---:|---:|---:|---:|---|---:|---:|"]
        apk = dict(runs)
        for n, m in src:
            o, pf = m["overall"], m.get("perf") or {}
            a = apk.get(n[4:])
            out.append(f"| {label(n)} | {a['overall']['f1']:.2f} | **{o['f1']:.2f}** | {o['precision']:.2f} | {o['recall']:.2f} | "
                       f"{o['tp']} / {o['fp']} / {o['fn']} | {m['json_valid_strict']:.0%} | {pf.get('avg_s_per_chunk', '-')} |"
                       if a else f"| {label(n)} | - | **{o['f1']:.2f}** | {o['precision']:.2f} | {o['recall']:.2f} | {o['tp']} / {o['fp']} / {o['fn']} | {m['json_valid_strict']:.0%} | {pf.get('avg_s_per_chunk', '-')} |")
        out.append("")
    ver = [(p.parent.name, json.loads(p.read_text())) for p in sorted(RUNS.glob("*/metrics.json"))]
    ver = [(n, m) for n, m in ver if m.get("pipeline") == "verifier" and m.get("split", "test") == "test"]
    if ver:
        vorder = ["loose-grep", "verifier-base-F16", "verifier-base-Q4_K_M", "verifier-v1-Q8_0-greedy", "verifier-v1-F16", "verifier-v1-Q8_0", "verifier-v1-Q4_K_M"]
        ver.sort(key=lambda x: vorder.index(x[0]) if x[0] in vorder else 99)
        g = dict(runs).get("grep")
        out += ["## Verifier pipeline (loose pattern scan, then a model confirms each candidate)", "",
                f"Same held-out apps and labels. The loose scanner raises {ver[0][1]['candidates']} candidates and covers "
                f"{ver[0][1]['candidate_recall_ceiling']:.0%} of the labelled findings; the verifier decides which are real.", "",
                "| Variant | F1 | Precision | Recall | TP / FP / FN | Verdict accuracy | Strict JSON | s/candidate |",
                "|---|---:|---:|---:|---|---:|---:|---:|"]
        if g:
            o = g["overall"]
            out.append(f"| strict grep baseline (for reference) | {o['f1']:.2f} | {o['precision']:.2f} | {o['recall']:.2f} | {o['tp']} / {o['fp']} / {o['fn']} | - | - | - |")
        names = {"loose-grep": "loose scanner alone (every candidate reported)", "verifier-base-F16": "base model as verifier (F16)",
                 "verifier-base-Q4_K_M": "base model as verifier (Q4_K_M)", "verifier-v1-Q8_0-greedy": "fine-tuned verifier v1 (Q8_0, greedy)",
                 "verifier-v1-F16": "fine-tuned verifier v1 (F16, calibrated)", "verifier-v1-Q8_0": "fine-tuned verifier v1 (Q8_0, calibrated)", "verifier-v1-Q4_K_M": "fine-tuned verifier v1 (Q4_K_M, calibrated)"}
        for n, m in ver:
            o, v, pf = m["overall"], m["verdict"], m.get("perf") or {}
            out.append(f"| {names.get(n, n)} | **{o['f1']:.2f}** | {o['precision']:.2f} | {o['recall']:.2f} | {o['tp']} / {o['fp']} / {o['fn']} | "
                       f"{v['accuracy']:.2f} | {m['json_valid_strict']:.0%} | {pf.get('avg_s_per_candidate', '-')} |")
        out.append("")
    (ROOT / "results" / "results.md").write_text("\n".join(out) + "\n")

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    names = [label(n) for n, _ in runs]
    f1 = [m["overall"]["f1"] for _, m in runs]
    p = [m["overall"]["precision"] for _, m in runs]
    r = [m["overall"]["recall"] for _, m in runs]
    fig, ax = plt.subplots(figsize=(10, 0.6 * len(runs) + 1.5))
    y = range(len(runs))
    ax.barh([i + 0.27 for i in y], p, height=0.25, label="precision", color="#9db4d6")
    ax.barh([i for i in y], f1, height=0.25, label="F1", color="#2b5ea7")
    ax.barh([i - 0.27 for i in y], r, height=0.25, label="recall", color="#c9a26b")
    for i, v in enumerate(f1):
        ax.text(v + 0.01, i, f"{v:.2f}", va="center", fontsize=9)
    ax.set_yticks(list(y))
    ax.set_yticklabels(names, fontsize=9)
    ax.invert_yaxis()
    ax.set_xlim(0, 1.05)
    ax.set_xlabel("score on held-out apps (OVAA + InsecureBankv2)")
    ax.legend(loc="lower right", fontsize=8)
    ax.spines[["top", "right"]].set_visible(False)
    fig.tight_layout()
    fig.savefig(ROOT / "results" / "chart.png", dpi=150)
    print((ROOT / "results" / "results.md").read_text())


if __name__ == "__main__":
    main()
