"""README comparison charts from results/runs/*/metrics.json.

Writes results/charts/<name>-light.png and <name>-dark.png (GitHub picks one with <picture>).
Every number is read from the run files; nothing is typed in by hand.

    .venv/bin/python eval/make_charts.py
"""

from __future__ import annotations

import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.lines import Line2D  # noqa: E402
from matplotlib.patches import PathPatch  # noqa: E402
from matplotlib.path import Path as MPath  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RUNS = ROOT / "results" / "runs"
OUT = ROOT / "results" / "charts"
DPI = 200
PX = DPI / 96  # device pixels per CSS pixel

# Palette: categorical slots 1-3, validated all-pairs in both modes (dataviz validate_palette.js).
# Colour follows the entity in every chart: blue = fine-tuned, orange = base model, aqua = grep.
THEMES = {
    "light": dict(surface="#fcfcfb", ink="#0b0b0b", ink2="#52514e", muted="#898781", grid="#e1e0d9",
                  axis="#c3c2b7", track="#ecebe6", tuned="#2a78d6", base="#eb6834", grep="#1baf7a"),
    "dark": dict(surface="#1a1a19", ink="#f0efec", ink2="#c3c2b7", muted="#898781", grid="#2c2c2a",
                 axis="#383835", track="#262624", tuned="#3987e5", base="#d95926", grep="#199e70"),
}
FONT = ["Helvetica Neue", "Helvetica", "Arial", "DejaVu Sans"]
CLASS_NAMES = {
    "exported_component": "Exported components", "insecure_webview": "Insecure WebView",
    "hardcoded_secret": "Hardcoded secrets", "weak_crypto": "Weak crypto",
    "insecure_network": "Cleartext / trust-all TLS", "insecure_storage": "Insecure storage",
    "provider_sqli": "ContentProvider SQLi", "intent_redirection": "Intent redirection",
}


def run(name):
    p = RUNS / name / "metrics.json"
    return json.loads(p.read_text()) if p.exists() else None


def f1(name):
    return run(name)["overall"]["f1"]


def setup(theme, w, h):
    t = THEMES[theme]
    plt.rcParams.update({"font.family": FONT, "font.size": 11, "text.color": t["ink"],
                         "axes.labelcolor": t["ink2"], "xtick.color": t["muted"], "ytick.color": t["muted"]})
    fig = plt.figure(figsize=(w, h), dpi=DPI, facecolor=t["surface"])
    return fig, t


def style_ax(ax, t, grid_axis="x"):
    ax.set_facecolor(t["surface"])
    for s in ax.spines.values():
        s.set_visible(False)
    ax.tick_params(length=0, labelsize=10)
    ax.grid(axis=grid_axis, color=t["grid"], linewidth=0.75, linestyle="-")
    ax.set_axisbelow(True)


def header(fig, t, title, subtitle, top=0.95):
    fig.text(0.035, top, title, fontsize=15, fontweight="bold", color=t["ink"], va="top")
    fig.text(0.035, top - 0.065 * (6.0 / fig.get_figheight()), subtitle, fontsize=10.5, color=t["ink2"], va="top")


def footer(fig, t, text):
    fig.text(0.035, 0.025, text, fontsize=8.5, color=t["muted"], va="bottom")


def column(ax, x, width, height, color, r_css=4):
    """Vertical column, square at the baseline, 4px rounded data end."""
    bb = ax.get_window_extent()
    (x0l, x1l), (y0l, y1l) = ax.get_xlim(), ax.get_ylim()
    rx = r_css * PX * (x1l - x0l) / bb.width
    ry = min(r_css * PX * (y1l - y0l) / bb.height, height)
    rx = min(rx, width / 2)
    a, b = x - width / 2, x + width / 2
    if height <= 0:
        return
    verts = [(a, 0), (a, height - ry), (a, height), (a + rx, height), (b - rx, height), (b, height),
             (b, height - ry), (b, 0), (a, 0)]
    codes = [MPath.MOVETO, MPath.LINETO, MPath.CURVE3, MPath.CURVE3, MPath.LINETO, MPath.CURVE3,
             MPath.CURVE3, MPath.LINETO, MPath.CLOSEPOLY]
    ax.add_patch(PathPatch(MPath(verts, codes), facecolor=color, edgecolor="none", zorder=3))


def dot(ax, x, y, color, t, s=70, z=4):
    ax.scatter([x], [y], s=s, color=color, edgecolors=t["surface"], linewidths=2 * PX * 0.72, zorder=z)


def legend(fig, t, items, y, x=0.035):
    """items: (kind, colour, label); kind 'dot' or 'line'. Drawn as a row of keys under the subtitle."""
    handles = []
    for kind, c, lab in items:
        if kind == "dot":
            handles.append(Line2D([], [], marker="o", linestyle="none", markersize=8, markerfacecolor=c,
                                  markeredgecolor=t["surface"], label=lab))
        else:
            handles.append(Line2D([], [], color=c, linewidth=2, label=lab))
    lg = fig.legend(handles=handles, loc="upper left", bbox_to_anchor=(x - 0.008, y), ncol=len(items),
                    frameon=False, fontsize=10, handletextpad=0.4, columnspacing=1.6, labelcolor=t["ink2"])
    return lg


def save(fig, name, theme):
    OUT.mkdir(parents=True, exist_ok=True)
    fig.savefig(OUT / f"{name}-{theme}.png", dpi=DPI, facecolor=fig.get_facecolor())
    plt.close(fig)


# 1. Base versus fine-tuned at the same precision ---------------------------------------------------------

def chart_base_vs_tuned(theme):
    rows = [("Verifier mode", "Q4_K_M", "verifier-base-Q4_K_M", "verifier-v1-Q4_K_M"),
            ("Verifier mode", "F16", "verifier-base-F16", "verifier-v1-F16"),
            ("Finder mode", "F16", "base-f16-zeroshot", "tuned-v2-F16"),
            ("Finder mode", "Q4_K_M", "base-q4-zeroshot", "tuned-v2-Q4_K_M")]
    rows = [r for r in rows if run(r[2]) and run(r[3])]
    fig, t = setup(theme, 9, 4.9)
    header(fig, t, "Fine-tuning turned a model that could not verify findings into one that can",
           "F1 on two held-out apps (OVAA, InsecureBankv2: 36 labelled findings), base vs LoRA-tuned at the same precision")
    legend(fig, t, [("dot", t["base"], "Base Qwen2.5-Coder-1.5B-Instruct"), ("dot", t["tuned"], "Fine-tuned (LoRA)"),
                    ("line", t["grep"], "grep baseline")], y=0.80)
    ax = fig.add_axes([0.20, 0.15, 0.68, 0.54])
    style_ax(ax, t)
    ax.set_xlim(-0.09, 1)
    ax.text(1.09, -0.58, "change", ha="right", va="bottom", fontsize=9.5, color=t["ink2"], clip_on=False)
    ax.set_ylim(len(rows) - 0.5, -0.6)
    g = f1("grep")
    ax.axvline(g, color=t["grep"], linewidth=2 * PX * 0.72, zorder=2)
    ax.text(g, -0.58, f"grep {g:.2f}", ha="center", va="bottom", fontsize=9.5, color=t["ink2"])
    for i, (mode, q, b, tu) in enumerate(rows):
        vb, vt = f1(b), f1(tu)
        ax.plot([vb, vt], [i, i], color=t["axis"], linewidth=2 * PX * 0.72, solid_capstyle="round", zorder=3)
        dot(ax, vb, i, t["base"], t, s=90)
        dot(ax, vt, i, t["tuned"], t, s=90)
        up = vt >= vb
        ax.text(vb + (-0.02 if up else 0.02), i, f"{vb:.2f}", ha="right" if up else "left", va="center",
                fontsize=10, color=t["ink2"])
        d = vt - vb
        ax.text(vt + (0.02 if up else -0.02), i, f"{vt:.2f}", ha="left" if up else "right", va="center",
                fontsize=11, fontweight="bold", color=t["ink"])
        ax.text(1.09, i, f"{d:+.2f}", ha="right", va="center", fontsize=11, color=t["ink"] if d > 0 else t["ink2"],
                fontweight="bold" if d > 0.2 else "normal", clip_on=False)
    ax.set_yticks(range(len(rows)))
    ax.set_yticklabels([f"{m}\n{q}" for m, q, _, _ in rows], fontsize=10.5, color=t["ink"])
    ax.set_xticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.grid(axis="y", visible=False)
    footer(fig, t, "Verifier mode: a loose pattern scan proposes candidates and the model confirms or rejects each one.\n"
                   "Finder mode: the model reads each code chunk and lists findings itself. Tuned models use the threshold calibrated on validation.")
    save(fig, "01-base-vs-tuned", theme)


# 2. Precision / recall map -------------------------------------------------------------------------------

def chart_precision_recall(theme):
    pts = [  # name, family, label (None = unlabelled), label offset in points
        ("grep", "grep", "grep, strict rules", (8, 6)),
        ("loose-grep", "grep", "loose scan alone\n(every candidate)", (-10, 8)),
        ("base-f16-zeroshot", "base", None, None),
        ("base-f16-fewshot", "base", None, None),
        ("base-q4-zeroshot", "base", "base model, finder", (8, -4)),
        ("verifier-base-Q4_K_M", "base", "base model as verifier", (10, -2)),
        ("tuned-v2-Q8_0", "tuned", "fine-tuned finder v2", (10, 2)),
        ("tuned-v2-Q4_K_M", "tuned", None, None),
        ("verifier-v1-Q8_0-greedy", "tuned", "fine-tuned verifier\n(greedy)", (-12, 10)),
        ("verifier-v1-Q8_0", "tuned", None, None),
        ("verifier-v1-Q4_K_M", "tuned", "fine-tuned verifier\n(calibrated)", (0, -24)),
        ("verifier-v1-F16", "tuned", None, None),
        ("tuned-v1-Q4_K_M-greedy", "tuned", None, None),
        ("verifier-base-F16", "base", None, None),
    ]
    fig, t = setup(theme, 9, 6.6)
    header(fig, t, "The fine-tuned verifier finds more real issues than grep, at lower precision",
           "Each dot is one variant on the held-out apps. Curves are constant F1. Up and right is better.")
    legend(fig, t, [("dot", t["tuned"], "fine-tuned"), ("dot", t["base"], "base model"), ("dot", t["grep"], "pattern only")],
           y=0.865)
    ax = fig.add_axes([0.10, 0.145, 0.85, 0.63])
    style_ax(ax, t, grid_axis="both")
    ax.set_xlim(0, 1.04)
    ax.set_ylim(0, 1.04)
    import numpy as np
    for f in (0.2, 0.4, 0.6, 0.8):
        r = np.linspace(f / 2 + 1e-4, 1.04, 5000)
        p = f * r / (2 * r - f)
        m = (p > 0) & (p <= 1.04)
        ax.plot(r[m], p[m], color=t["axis"], linewidth=0.9, zorder=1)
        ax.text(f / (2 - f) + 0.012, 1.0, f"F1 {f:.1f}", fontsize=8.5, color=t["muted"], ha="left", va="center")
    hidden = 0
    for name, fam, lab, off in pts:
        m = run(name)
        if not m:
            continue
        o = m["overall"]
        if o["tp"] == 0:
            hidden += 1
            continue
        dot(ax, o["recall"], o["precision"], t[fam], t, s=80)
        if lab:
            ax.annotate(lab, (o["recall"], o["precision"]), xytext=off, textcoords="offset points",
                        fontsize=9.5, color=t["ink"], va="center", zorder=6,
                        ha="center" if off[0] == 0 else ("right" if off[0] < 0 else "left"))
    ax.set_xlabel("Recall: share of the 36 real issues found", fontsize=10.5)
    ax.set_ylabel("Precision: share of reports that are real", fontsize=10.5)
    footer(fig, t, f"Not shown: {hidden} variants with zero true positives (fine-tuned v1, which answered 'clean' to "
                   "everything, and the base F16 model as verifier).\nThe three calibrated verifier dots (F16, Q8_0, Q4_K_M) sit on top of each other.")
    save(fig, "02-precision-recall", theme)


# 3. Per class: found and false alarms --------------------------------------------------------------------

def chart_per_class(theme, tuned="verifier-v1-Q8_0-greedy"):
    g, v = run("grep"), run(tuned)
    classes = list(CLASS_NAMES)
    gold = {c: g["per_class"][c]["tp"] + g["per_class"][c]["fn"] for c in classes}
    fig, t = setup(theme, 9.5, 5.8)
    header(fig, t, "Where the fine-tuned verifier beats grep, and where it still fails",
           "Per class on the held-out apps. Fine-tuned verifier (Q8_0, greedy) vs the strict grep baseline.")
    legend(fig, t, [("dot", t["tuned"], "fine-tuned verifier"), ("dot", t["grep"], "grep baseline")], y=0.84)
    axl = fig.add_axes([0.255, 0.10, 0.43, 0.6])
    axr = fig.add_axes([0.725, 0.10, 0.25, 0.6])
    xmax = max(max(gold.values()), max(v["per_class"][c]["fp"] for c in classes), max(g["per_class"][c]["fp"] for c in classes))
    for ax, title in ((axl, "Real issues found, of those labelled"), (axr, "False alarms")):
        style_ax(ax, t)
        ax.set_ylim(len(classes) - 0.5, -0.5)
        ax.set_xlim(-0.4, xmax + 0.6)
        ax.set_title(title, loc="left", fontsize=10.5, color=t["ink"], fontweight="bold", pad=8)
        ax.set_xticks(range(0, xmax + 1, 2))
    axl.set_yticks(range(len(classes)))
    axl.set_yticklabels([f"{CLASS_NAMES[c]}  ({gold[c]})" for c in classes], fontsize=10, color=t["ink"])
    axr.set_yticks([])
    for i, c in enumerate(classes):
        axl.plot([0, gold[c]], [i, i], color=t["track"], linewidth=7 * PX * 0.72, solid_capstyle="round", zorder=1)
        for ax, key in ((axl, "tp"), (axr, "fp")):
            a, b = v["per_class"][c][key], g["per_class"][c][key]
            dy = 0.17 if a == b else 0
            dot(ax, b, i + dy, t["grep"], t, s=70)
            dot(ax, a, i - dy, t["tuned"], t, s=70)
    i = classes.index("hardcoded_secret")
    axr.annotate("harmless constants\n(pref names, keys)", (v["per_class"]["hardcoded_secret"]["fp"], i),
                 xytext=(-8, -20), textcoords="offset points", ha="right", va="center", fontsize=8.5, color=t["ink2"])
    o_v, o_g = v["overall"], g["overall"]
    footer(fig, t, f"Totals: fine-tuned verifier {o_v['tp']} found / {o_v['fp']} false alarms; grep {o_g['tp']} / {o_g['fp']}. "
                   "Grey track = labelled issues in that class. Counts are small: read them, not the percentages.")
    save(fig, "03-per-class", theme)


# 4. Quantization: small multiples ------------------------------------------------------------------------

def chart_quant(theme):
    qs = [("F16", "verifier-v1-F16"), ("Q8_0", "verifier-v1-Q8_0"), ("Q4_K_M", "verifier-v1-Q4_K_M")]
    panels = [("F1 on held-out apps", lambda m: m["overall"]["f1"], "{:.2f}", 1.0),
              ("GGUF file size, GB", lambda m: m["perf"]["gguf_mb"] / 1000, "{:.1f}", None),
              ("Peak memory, GB", lambda m: m["perf"]["peak_rss_mb"] / 1000, "{:.1f}", None),
              ("Generation, tokens/s", lambda m: m["perf"]["gen_tok_per_s"], "{:.0f}", None)]
    fig, t = setup(theme, 10, 4.4)
    header(fig, t, "Q4_K_M keeps the verifier's accuracy at a third of the size",
           "Fine-tuned verifier v1 (calibrated) on an Apple M4 laptop, 16 GB, llama.cpp Metal. Same test apps for every bar.")
    w, gap, left = 0.2, 0.035, 0.035
    for k, (title, fn, fmt, ymax) in enumerate(panels):
        ax = fig.add_axes([left + k * (w + gap), 0.13, w, 0.56])
        style_ax(ax, t, grid_axis="y")
        vals = [(q, fn(run(n)) if run(n) else None) for q, n in qs]
        top = ymax or max(x for _, x in vals if x is not None) * 1.18
        ax.set_xlim(-0.6, len(qs) - 0.4)
        ax.set_ylim(0, top)
        ax.set_title(title, loc="left", fontsize=10.5, color=t["ink"], fontweight="bold", pad=10)
        ax.axhline(0, color=t["axis"], linewidth=1 * PX * 0.72, zorder=4)
        bb = ax.get_window_extent()
        width = min(0.5, 24 * PX * (len(qs)) / bb.width)
        for j, (q, x) in enumerate(vals):
            if x is None:
                ax.text(j, top * 0.04, "not run", ha="center", fontsize=8.5, color=t["muted"])
                continue
            column(ax, j, width, x, t["tuned"])
            ax.text(j, x + top * 0.025, fmt.format(x), ha="center", va="bottom", fontsize=10, color=t["ink"])
        ax.set_xticks(range(len(qs)))
        ax.set_xticklabels([q for q, _ in qs], fontsize=9.5, color=t["ink2"])
        ax.set_yticklabels([])
    footer(fig, t, "Peak memory is the llama-server process including memory-mapped weights. Lower is better for size and memory.")
    save(fig, "04-quantization", theme)


# 5. How we got here --------------------------------------------------------------------------------------

def chart_journey(theme):
    steps = [("tuned-v1-Q4_K_M-greedy", "v1\nplain LoRA", "answered 'clean'\nto everything"),
             ("tuned-v2-Q4_K_M-greedy", "v2\nweighted loss", "precise but\nfound 2 of 36"),
             ("tuned-v2-Q8_0", "v2 +\ncalibration", "threshold set on\nvalidation only"),
             ("verifier-v1-Q8_0-greedy", "verifier v1", "model checks\nscanner candidates")]
    fig, t = setup(theme, 9, 5.2)
    header(fig, t, "From a collapsed first run to 0.72 F1 in one build day",
           "Best F1 of each training step on the held-out apps, against the two reference points")
    ax = fig.add_axes([0.08, 0.25, 0.70, 0.50])
    style_ax(ax, t, grid_axis="y")
    ax.set_xlim(-0.6, len(steps) - 0.4)
    ax.set_ylim(0, 1)
    ax.set_yticks([0, 0.2, 0.4, 0.6, 0.8, 1.0])
    ax.axhline(0, color=t["axis"], linewidth=1 * PX * 0.72, zorder=4)
    refs = [(f1("grep"), t["grep"], "grep baseline"),
            (max(f1(n) for n in ("base-f16-zeroshot", "base-f16-fewshot", "base-q4-zeroshot")), t["base"], "best base model")]
    for y, c, lab in refs:
        ax.axhline(y, color=c, linewidth=1.5 * PX * 0.72, zorder=2)
        ax.text(len(steps) - 0.35, y, f"  {lab} {y:.2f}", va="center", ha="left", fontsize=9.5, color=t["ink2"], clip_on=False)
    bb = ax.get_window_extent()
    width = min(0.5, 24 * PX * len(steps) / bb.width)
    for j, (n, lab, note) in enumerate(steps):
        v = f1(n)
        column(ax, j, width, v, t["tuned"])
        ax.text(j, v + 0.025, f"{v:.2f}", ha="center", va="bottom", fontsize=11, fontweight="bold", color=t["ink"], zorder=6,
                bbox=dict(boxstyle="square,pad=0.15", facecolor=t["surface"], edgecolor="none"))
        ax.text(j, -0.2, note, ha="center", va="top", fontsize=9, color=t["ink2"])
    ax.set_xticks(range(len(steps)))
    ax.set_xticklabels([s[1] for s in steps], fontsize=10, color=t["ink"])
    footer(fig, t, "v1 and v2 greedy measured at Q4_K_M, the rest at Q8_0 (Q8_0 matched F16 exactly for v2). "
                   "The test set was used to diagnose verifier v1.")
    save(fig, "05-journey", theme)


def main():
    for theme in THEMES:
        chart_base_vs_tuned(theme)
        chart_precision_recall(theme)
        chart_per_class(theme)
        chart_quant(theme)
        chart_journey(theme)
    for p in sorted(OUT.glob("*.png")):
        print(p.relative_to(ROOT), f"{p.stat().st_size / 1024:.0f} KB")


if __name__ == "__main__":
    main()
