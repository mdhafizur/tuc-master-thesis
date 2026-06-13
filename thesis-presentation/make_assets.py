"""Generate chart/diagram images for defense_slides_v3.pptx.

Outputs PNGs into assets/ at 1600x900 px (16:9, suitable for 10" wide slides at 160 dpi).
"""
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch, Rectangle
import matplotlib.patches as mpatches
import os

OUT = os.path.join(os.path.dirname(__file__), "assets")
os.makedirs(OUT, exist_ok=True)

# design tokens — match deck
NAVY = "#14213D"
NAVY_DARK = "#0B1428"
ACCENT = "#FCA311"
RED = "#C9184A"
GREEN = "#2E8B57"
LIGHT_BG = "#F6F7FB"
CARD_BG = "#FFFFFF"
CARD_BORDER = "#E2E6EE"
TEXT_DARK = "#1A1F36"
TEXT_MUTED = "#5B657A"

plt.rcParams.update({
    "font.family": "DejaVu Sans",
    "axes.spines.right": False,
    "axes.spines.top": False,
    "axes.edgecolor": "#9AA3B5",
    "axes.labelcolor": TEXT_DARK,
    "xtick.color": TEXT_MUTED,
    "ytick.color": TEXT_MUTED,
})


def save(name, fig):
    p = os.path.join(OUT, name)
    fig.savefig(p, dpi=160, bbox_inches="tight", facecolor=LIGHT_BG)
    plt.close(fig)
    print(f"wrote {p}")


# -----------------------------------------------------------------------------
# Chart 1 — slide 15: F1 Code Guardian vs SAST baselines
# -----------------------------------------------------------------------------
def chart_f1_baselines():
    labels = ["Code Guardian\n(qwen3:8b + RAG)", "Semgrep", "CodeQL", "ESLint-security"]
    values = [71.43, 20.22, 10.85, 0.00]
    colors = [NAVY, TEXT_MUTED, TEXT_MUTED, TEXT_MUTED]

    fig, ax = plt.subplots(figsize=(7.5, 4.2))
    bars = ax.barh(labels, values, color=colors, edgecolor="none", height=0.55)
    # highlight Code Guardian
    bars[0].set_color(ACCENT)
    bars[0].set_edgecolor(NAVY)
    bars[0].set_linewidth(1.2)

    for bar, v in zip(bars, values):
        ax.text(v + 1.5, bar.get_y() + bar.get_height() / 2,
                f"{v:.2f}%", va="center", fontsize=12,
                color=NAVY_DARK, fontweight="bold")

    ax.set_xlim(0, 85)
    ax.set_xlabel("F1 Score (%)  ·  higher is better", fontsize=10)
    ax.invert_yaxis()
    ax.tick_params(axis="y", labelsize=11)
    ax.set_facecolor(LIGHT_BG)
    fig.patch.set_facecolor(LIGHT_BG)
    ax.grid(axis="x", color="#D0D6E2", linewidth=0.6)
    ax.set_axisbelow(True)
    save("chart_15_f1_baselines.png", fig)


# -----------------------------------------------------------------------------
# Chart 2 — slide 16: ΔF1 from no-RAG → RAG per model
# -----------------------------------------------------------------------------
def chart_rag_ablation():
    # canonical taxonomy ΔF1 (RAG - no-RAG)
    rows = [
        ("qwen3:8b",   +3.91, NAVY),
        ("gemma3:4b",  -0.16, TEXT_MUTED),
        ("gemma3:1b",  -0.63, TEXT_MUTED),
        ("qwen3:4b",   -5.22, RED),
        ("codellama",  -29.89, RED),
    ]
    labels = [r[0] for r in rows]
    deltas = [r[1] for r in rows]
    colors = [GREEN if d > 0 else RED if d < -5 else TEXT_MUTED for _, d, _ in rows]

    fig, ax = plt.subplots(figsize=(7.5, 4.5))
    bars = ax.barh(labels, deltas, color=colors, height=0.55, edgecolor="none")

    for bar, d in zip(bars, deltas):
        x = bar.get_width()
        label = f"{d:+.2f}"
        cy = bar.get_y() + bar.get_height() / 2
        # long bars get the label *inside* the bar (white) so it never spills
        # off the left edge into the axis tick labels; short bars sit outside.
        if d <= -8:
            ax.text(x + 0.7, cy, label, va="center", ha="left",
                    fontsize=12, color="white", fontweight="bold")
        else:
            ha = "left" if d >= 0 else "right"
            offset = 0.7 if d >= 0 else -0.7
            ax.text(x + offset, cy, label, va="center", ha=ha,
                    fontsize=12, color=NAVY_DARK, fontweight="bold")

    ax.axvline(0, color=NAVY_DARK, linewidth=1.2)
    ax.set_xlim(-33, 8)
    ax.invert_yaxis()
    ax.set_xlabel("ΔF1 (RAG − no-RAG), percentage points", fontsize=10)
    ax.tick_params(axis="y", labelsize=11)
    ax.set_facecolor(LIGHT_BG)
    fig.patch.set_facecolor(LIGHT_BG)
    ax.grid(axis="x", color="#D0D6E2", linewidth=0.6)
    ax.set_axisbelow(True)
    save("chart_16_rag_ablation.png", fig)


# -----------------------------------------------------------------------------
# Chart 3 — slide 18: latency horizontal bars with band markers
# -----------------------------------------------------------------------------
def chart_latency_bands():
    # (label, median latency ms, F1 %, bar colour)
    rows = [
        ("Semgrep (SAST)",          63,   20, TEXT_MUTED),
        ("CodeQL (SAST)",          182,   11, TEXT_MUTED),
        ("gemma3:1b + RAG",       1019,   36, ACCENT),
        ("qwen3:4b + RAG",        1328,   61, ACCENT),
        ("gemma3:4b + RAG",       2077,   57, ACCENT),
        ("qwen3:8b + RAG",        2216,   71, NAVY),
        ("codellama + RAG",       3529,   23, RED),
    ]
    rows = sorted(rows, key=lambda r: r[1])
    labels = [r[0] for r in rows]
    values = [r[1] for r in rows]
    f1s = [r[2] for r in rows]
    colors = [r[3] for r in rows]

    fig, ax = plt.subplots(figsize=(8.4, 4.7))

    # shaded latency bands (drawn first, behind the bars)
    bands = [(0, 500, "Real-time\n≤ 0.5 s", "#2E8B57"),
             (500, 1500, "Interactive\n≤ 1.5 s", "#FCA311"),
             (1500, 5000, "On-demand\n≤ 5 s", "#5B657A")]
    for lo, hi, name, col in bands:
        ax.axvspan(lo, hi, color=col, alpha=0.08, zorder=0)
        ax.axvline(hi, color="#9AA3B5", linestyle="--", linewidth=0.7, alpha=0.6, zorder=0)
        ax.text((lo + min(hi, 4400)) / 2, -0.55, name,
                va="bottom", ha="center", fontsize=8.5,
                color=TEXT_MUTED, fontweight="bold")

    bars = ax.barh(labels, values, color=colors, height=0.55,
                   edgecolor="none", zorder=3)

    # value + F1 so speed is never read without quality
    for bar, v, f in zip(bars, values, f1s):
        ax.text(v + 90, bar.get_y() + bar.get_height() / 2,
                f"{v:,} ms  ·  F1 {f}%", va="center", fontsize=9.5,
                color=NAVY_DARK, fontweight="bold")

    # highlight headline configuration
    for bar, lbl in zip(bars, labels):
        if lbl == "qwen3:8b + RAG":
            bar.set_edgecolor(NAVY_DARK)
            bar.set_linewidth(1.8)

    ax.set_xlim(0, 4700)
    ax.set_ylim(-0.6, len(rows) + 0.2)
    ax.invert_yaxis()
    ax.set_xlabel("Median end-to-end latency (ms)  ·  lower is better, F1 higher is better", fontsize=10)
    ax.tick_params(axis="y", labelsize=10)
    ax.set_facecolor(LIGHT_BG)
    fig.patch.set_facecolor(LIGHT_BG)
    ax.grid(axis="x", color="#D0D6E2", linewidth=0.6, zorder=0)
    ax.set_axisbelow(True)
    save("chart_18_latency_bands.png", fig)


# -----------------------------------------------------------------------------
# Diagram — slide 11: system architecture
# -----------------------------------------------------------------------------
def diagram_architecture():
    """Slide-11 system architecture.

    Laid out on a 200x80 canvas (2.5:1) so it fills the deck's content box
    without horizontal stretch (add_picture forces width AND height). The slide
    chrome supplies the "System Architecture" title, so none is drawn here.

    Layout: a left-to-right request pipeline on the top lane
    (Client UI -> Extension Core -> Analyzer -> Ollama) with supporting stores
    on two lower lanes snapped to shared columns, so connectors stay straight.
    The optional outbound path forms a clean vertical chain on the right
    (Vulnerability Data -> Egress Gate -> Public Security Feeds).
    """
    from matplotlib.patches import Ellipse, Polygon

    fig, ax = plt.subplots(figsize=(15, 6.0))
    ax.set_xlim(0, 200)
    ax.set_ylim(0, 80)
    ax.axis("off")
    fig.patch.set_facecolor("white")
    # full-bleed white background — also locks the tight-bbox to 2.5:1
    ax.add_patch(Rectangle((0, 0), 200, 80, facecolor="white",
                           edgecolor="none", zorder=0))

    STORE_FILL = "#E9EEF8"
    CREAM = "#FFF6E2"
    TS = 0.88  # global text scale — shrinks every label uniformly

    # ---- helpers ----------------------------------------------------------
    def box(cx, cy, w, h, title, sub=None, fill=NAVY, text_color="white",
            border=None, lw=1.5, title_fs=12.5, sub_fs=9.0, sub_color=None):
        """Rounded card with centered bold title + optional sub-label.
        Returns (left, bottom, w, h) for edge-point lookups."""
        if border is None:
            border = fill
        x0, y0 = cx - w / 2, cy - h / 2
        ax.add_patch(FancyBboxPatch((x0, y0), w, h,
                     boxstyle="round,pad=0,rounding_size=1.1",
                     linewidth=lw, edgecolor=border, facecolor=fill, zorder=4))
        if sub:
            sc = sub_color or ("#C7D0E4" if text_color == "white" else TEXT_MUTED)
            ax.text(cx, cy + h * 0.17, title, ha="center", va="center",
                    fontsize=title_fs * TS, fontweight="bold", color=text_color,
                    zorder=5)
            ax.text(cx, cy - h * 0.24, sub, ha="center", va="center",
                    fontsize=sub_fs * TS, color=sc, zorder=5)
        else:
            ax.text(cx, cy, title, ha="center", va="center",
                    fontsize=title_fs * TS, fontweight="bold",
                    color=text_color, zorder=5)
        return (x0, y0, w, h)

    def cylinder(cx, cy, w, h, title, sub):
        """Database cylinder. Returns (left, bottom, w, h, top_rim, bot_rim)
        so connectors land on the rims rather than the bounding box."""
        eh = h * 0.20
        top_rim = cy + h / 2 - eh / 2
        bot_rim = cy - h / 2 + eh / 2
        left, right = cx - w / 2, cx + w / 2
        ax.add_patch(Polygon([(left, bot_rim), (left, top_rim),
                              (right, top_rim), (right, bot_rim)],
                             closed=True, facecolor=STORE_FILL,
                             edgecolor="none", zorder=4))
        ax.add_patch(Ellipse((cx, bot_rim), w, eh, facecolor=STORE_FILL,
                             edgecolor=NAVY, linewidth=1.5, zorder=4))
        ax.plot([left, left], [bot_rim, top_rim], color=NAVY, lw=1.5, zorder=5)
        ax.plot([right, right], [bot_rim, top_rim], color=NAVY, lw=1.5, zorder=5)
        ax.add_patch(Ellipse((cx, top_rim), w, eh, facecolor="#F4F7FD",
                             edgecolor=NAVY, linewidth=1.5, zorder=6))
        ax.text(cx, cy + h * 0.10, title, ha="center", va="center",
                fontsize=10.5 * TS, fontweight="bold", color=NAVY, zorder=7)
        ax.text(cx, cy - h * 0.21, sub, ha="center", va="center",
                fontsize=8.0 * TS, color=TEXT_MUTED, zorder=7)
        return (left, cy - h / 2, w, h, top_rim, bot_rim)

    def ep(b, side):
        """Edge midpoint of a box/cylinder tuple."""
        x0, y0, w, h = b[0], b[1], b[2], b[3]
        if side == "top":
            return (x0 + w / 2, b[4] if len(b) > 4 else y0 + h)
        if side == "bottom":
            return (x0 + w / 2, b[5] if len(b) > 5 else y0)
        if side == "left":
            return (x0, y0 + h / 2)
        return (x0 + w, y0 + h / 2)               # right

    def arrow(p0, p1, color=NAVY, lw=2.0, dashed=False, mut=15, zorder=4):
        ax.add_patch(FancyArrowPatch(
            p0, p1, arrowstyle="-|>", mutation_scale=mut, linewidth=lw,
            color=color, zorder=zorder, shrinkA=0, shrinkB=0,
            joinstyle="round", capstyle="round",
            linestyle=(0, (5, 4)) if dashed else "-"))

    def seg(x0, y0, x1, y1, color=NAVY, lw=2.0, dashed=False, zorder=4):
        ax.plot([x0, x1], [y0, y1], color=color, lw=lw, zorder=zorder,
                solid_capstyle="round", dash_capstyle="round",
                linestyle=(0, (5, 4)) if dashed else "-")

    def label(x, y, text, color=TEXT_DARK, fs=9.0, weight="bold", pad=0.18):
        ax.text(x, y, text, ha="center", va="center", fontsize=fs * TS,
                color=color, fontweight=weight, zorder=9,
                bbox=dict(boxstyle=f"round,pad={pad}", fc="white", ec="none",
                          alpha=0.95))

    # ---- privacy boundary -------------------------------------------------
    ax.add_patch(FancyBboxPatch((4, 4.5), 178, 62.5,
                 boxstyle="round,pad=0,rounding_size=2.4",
                 linewidth=2.2, edgecolor=NAVY, facecolor="#FBFCFE",
                 linestyle=(0, (6, 4)), zorder=1))
    ax.text(7, 64.6, "CODE GUARDIAN", ha="left", va="center", fontsize=12.0 * TS,
            fontweight="bold", color=NAVY_DARK, zorder=3)
    ax.text(7, 61.7, "runs entirely on your laptop", ha="left", va="center",
            fontsize=9.0 * TS, color=TEXT_MUTED, fontstyle="italic", zorder=3)

    # ---- column / lane grid ----------------------------------------------
    C_CLIENT, C_CORE, C_ANALYZER, C_OLLAMA = 24, 63, 111, 159
    C_CACHE, C_RAG, C_EGRESS = 63, 111, 159       # lower lane 1, aligned to top
    C_KB, C_VULN = 111, 159                        # lower lane 2
    TOP_Y, LANE1_Y, LANE2_Y = 53, 33, 14
    RED_X = 176                                    # sole outbound channel

    # ---- top lane: request pipeline --------------------------------------
    b_client = box(C_CLIENT, TOP_Y, 26, 12, "Client UI", "VS Code · 4 workflows")
    b_core = box(C_CORE, TOP_Y, 26, 12, "Extension Core", "orchestration")

    AN_W, AN_H = 48, 20.5
    an_x0, an_y0 = C_ANALYZER - AN_W / 2, TOP_Y - AN_H / 2
    ax.add_patch(FancyBboxPatch((an_x0, an_y0), AN_W, AN_H,
                 boxstyle="round,pad=0,rounding_size=1.4",
                 linewidth=1.6, edgecolor=NAVY, facecolor="#EEF2FA", zorder=2))
    ax.text(C_ANALYZER, an_y0 + AN_H - 2.4, "Analyzer — two-stage",
            ha="center", va="center", fontsize=10.5 * TS, fontweight="bold",
            color=NAVY_DARK, zorder=6)
    b_s1 = box(C_ANALYZER - 11.5, 49.5, 20, 11, "Stage 1 · Detect",
               "consensus · JSON", title_fs=8.8, sub_fs=7.8)
    b_s2 = box(C_ANALYZER + 11.5, 49.5, 20, 11, "Stage 2 · Repair",
               "Babel-validated", title_fs=8.8, sub_fs=7.8)
    arrow(ep(b_s1, "right"), ep(b_s2, "left"), color=ACCENT, lw=1.8, mut=10,
          zorder=7)
    an_box = (an_x0, an_y0, AN_W, AN_H)

    b_ollama = box(C_OLLAMA, TOP_Y, 28, 12, "Ollama", "local · codellama / qwen3",
                   sub_fs=8.6)

    # ---- lower lanes ------------------------------------------------------
    b_cache = cylinder(C_CACHE, LANE1_Y, 30, 11, "Analysis Cache",
                       "LRU · 100 · 30 min")
    b_rag = box(C_RAG, LANE1_Y, 30, 11, "RAG Manager", "context retrieval",
                title_fs=11.5, sub_fs=8.6)
    b_egress = box(C_EGRESS, LANE1_Y, 28, 11, "Egress Gate",
                   "loopback-only · off by default", title_fs=11.0, sub_fs=7.6)
    b_kb = cylinder(C_KB, LANE2_Y, 32, 11, "Knowledge Base",
                    "HNSWlib · Ed25519-signed")
    b_vuln = cylinder(C_VULN, LANE2_Y, 30, 11, "Vulnerability Data",
                      "24 h cache · 7 sources")

    # ---- external feed (outside boundary, top-right) ---------------------
    b_feeds = box(RED_X, 73, 42, 9, "Public Security Feeds",
                  "NVD · OWASP · CWE · GitHub", fill="white", text_color=NAVY_DARK,
                  border=NAVY, lw=1.8, title_fs=11.5, sub_fs=8.6,
                  sub_color=TEXT_MUTED)
    ax.text(RED_X, 78.9, "outside the privacy boundary", ha="center",
            va="center", fontsize=8.0 * TS, color=TEXT_MUTED, fontstyle="italic")

    # ---- privacy callout (bottom-left, free corner) ----------------------
    PC_X, PC_Y, PC_W, PC_H = 8, 5.5, 38, 23
    ax.add_patch(FancyBboxPatch((PC_X, PC_Y), PC_W, PC_H,
                 boxstyle="round,pad=0,rounding_size=1.3",
                 linewidth=1.8, edgecolor=ACCENT, facecolor=CREAM, zorder=3))
    ax.text(PC_X + PC_W / 2, PC_Y + PC_H - 3.0, "Privacy by construction",
            ha="center", va="center", fontsize=11.0 * TS, fontweight="bold",
            color=NAVY_DARK, zorder=5)
    for i, c in enumerate(["all local execution", "no code leaves machine",
                           "no telemetry", "egress off by default",
                           "signed corpus"]):
        ay = PC_Y + PC_H - 6.6 - i * 3.1
        ax.text(PC_X + 3.0, ay, "✓", ha="left", va="center", fontsize=10.5 * TS,
                color=GREEN, fontweight="bold", zorder=5)
        ax.text(PC_X + 6.2, ay, c, ha="left", va="center", fontsize=9.4 * TS,
                color=TEXT_DARK, zorder=5)

    # ---- connectors -------------------------------------------------------
    OFF = 1.6   # separates a forward/return pair on a shared axis

    # Client UI -> Extension Core : analyze (+ dashed return)
    cl_r, co_l = ep(b_client, "right")[0], ep(b_core, "left")[0]
    arrow((cl_r, TOP_Y + OFF), (co_l, TOP_Y + OFF), lw=2.2)
    arrow((co_l, TOP_Y - OFF), (cl_r, TOP_Y - OFF), lw=1.5, dashed=True)
    label((cl_r + co_l) / 2, TOP_Y + OFF + 2.6, "analyze", color=NAVY)

    # Extension Core -> Analyzer : on miss
    arrow((ep(b_core, "right")[0], TOP_Y), (an_x0, TOP_Y), lw=2.2)
    label((ep(b_core, "right")[0] + an_x0) / 2, TOP_Y + 2.6, "on miss",
          color=NAVY, fs=8.6)

    # Analyzer <-> Ollama : prompt (JSON) (+ dashed return)
    an_r, ol_l = an_x0 + AN_W, ep(b_ollama, "left")[0]
    arrow((an_r, TOP_Y + OFF), (ol_l, TOP_Y + OFF), lw=2.2)
    arrow((ol_l, TOP_Y - OFF), (an_r, TOP_Y - OFF), lw=1.5, dashed=True)
    label((an_r + ol_l) / 2, TOP_Y + OFF + 2.7, "prompt (JSON)", color=NAVY,
          fs=8.0)

    # Extension Core <-> Analysis Cache : check (down) / hit (up)
    cache_t = ep(b_cache, "top")[1]
    core_b = ep(b_core, "bottom")[1]
    arrow((C_CORE - 2, core_b), (C_CORE - 2, cache_t), lw=2.2)
    arrow((C_CORE + 2, cache_t), (C_CORE + 2, core_b), lw=1.5, dashed=True)
    label(C_CORE - 8.5, (core_b + cache_t) / 2, "check", color=NAVY)
    label(C_CORE + 8.0, (core_b + cache_t) / 2, "hit", color=TEXT_MUTED)

    # Analyzer -> Analysis Cache : store on miss (Manhattan elbow, lands on the
    # cache top right of the check/hit pair so the three arrows stay separated)
    sx, ey, lx = 100, 40.5, 73
    seg(sx, an_y0, sx, ey)
    seg(sx, ey, lx, ey)
    arrow((lx, ey), (lx, cache_t))
    label((sx + lx) / 2, ey + 1.4, "store on miss", color=NAVY, fs=8.6)

    # Analyzer -> RAG Manager : RAG enrich
    rag_t = ep(b_rag, "top")[1]
    arrow((C_ANALYZER, an_y0), (C_RAG, rag_t), lw=2.2)
    label(C_ANALYZER + 11, (an_y0 + rag_t) / 2, "RAG enrich", color=NAVY, fs=8.6)

    # RAG Manager -> Knowledge Base : top-k 3
    rag_b, kb_t = ep(b_rag, "bottom")[1], ep(b_kb, "top")[1]
    arrow((C_RAG, rag_b), (C_KB, kb_t), lw=2.2)
    label(C_RAG + 9, (rag_b + kb_t) / 2, "top-k 3", color=NAVY, fs=8.6)

    # Vulnerability Data -> Knowledge Base : sync (dashed)
    vd_l, kb_r = ep(b_vuln, "left"), ep(b_kb, "right")
    arrow(vd_l, kb_r, lw=1.8, dashed=True)
    label((vd_l[0] + kb_r[0]) / 2, vd_l[1] + 2.3, "sync", color=TEXT_MUTED)

    # Vulnerability Data -> Egress Gate : egress req (straight up)
    arrow(ep(b_vuln, "top"), ep(b_egress, "bottom"), lw=2.2)
    label(C_VULN - 11, (ep(b_vuln, "top")[1] + ep(b_egress, "bottom")[1]) / 2,
          "egress req", color=NAVY, fs=8.6)

    # Egress Gate -> Public Security Feeds : RED dashed, sole boundary crossing
    eg_r = ep(b_egress, "right")
    feed_b = ep(b_feeds, "bottom")[1]
    seg(eg_r[0], eg_r[1], RED_X, eg_r[1], color=RED, lw=2.0, dashed=True)
    arrow((RED_X, eg_r[1]), (RED_X, feed_b), color=RED, lw=2.0, dashed=True,
          mut=17)
    ax.text(RED_X - 2.4, 44.2, "optional fetch", ha="right", va="center",
            fontsize=8.8 * TS, fontweight="bold", color=RED, zorder=9,
            bbox=dict(boxstyle="round,pad=0.16", fc="white", ec="none", alpha=0.95))
    ax.text(RED_X - 2.4, 41.0, "off by default", ha="right", va="center",
            fontsize=8.2 * TS, color=RED, zorder=9,
            bbox=dict(boxstyle="round,pad=0.16", fc="white", ec="none", alpha=0.95))

    # ---- legend -----------------------------------------------------------
    arrow((60, 2.4), (67, 2.4), color=NAVY, lw=2.4, mut=13)
    ax.text(68.5, 2.4, "local data flow", ha="left", va="center",
            fontsize=9.4 * TS, color=TEXT_DARK)
    arrow((112, 2.4), (119, 2.4), color=RED, lw=2.0, dashed=True, mut=13)
    ax.text(120.5, 2.4, "optional outbound — public metadata, off by default",
            ha="left", va="center", fontsize=9.4 * TS, color=TEXT_DARK)

    save("diagram_11_architecture.png", fig)


# -----------------------------------------------------------------------------
# Diagram — slide 29 (A5): threat-model boundary
# -----------------------------------------------------------------------------
def diagram_threat_model():
    fig, ax = plt.subplots(figsize=(6.6, 6.2))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 100)
    ax.axis("off")
    fig.patch.set_facecolor("white")
    GREEN_LINE = "#2E8B57"

    def badge(cx, cy, glyph, col):
        ax.add_patch(mpatches.Circle((cx, cy), 2.6, facecolor=col,
                                     edgecolor="none", zorder=6))
        ax.text(cx, cy + 0.1, glyph, ha="center", va="center",
                fontsize=11, color="white", fontweight="bold", zorder=7)

    def card(x, y, w, h, title, sub, *, fill=CARD_BG, edge=NAVY,
             tcol=NAVY_DARK, scol=TEXT_MUTED, mark=None, mark_col=None,
             lw=1.6, ts=11.5):
        ax.add_patch(FancyBboxPatch((x, y), w, h,
                     boxstyle="round,pad=0.4,rounding_size=1.4",
                     linewidth=lw, edgecolor=edge, facecolor=fill, zorder=4))
        tx = x + w / 2 + (2.5 if mark else 0)
        ax.text(tx, y + h * 0.62, title, ha="center", va="center",
                fontsize=ts, color=tcol, fontweight="bold", zorder=5)
        ax.text(tx, y + h * 0.27, sub, ha="center", va="center",
                fontsize=8.5, color=scol, zorder=5)
        if mark:
            badge(x + 6, y + h / 2, mark, mark_col)

    # ---- privacy boundary ----
    ax.add_patch(FancyBboxPatch((2, 17), 66, 77,
                 boxstyle="round,pad=1.2,rounding_size=2.5",
                 linewidth=2.0, edgecolor=GREEN_LINE, facecolor="#EAF6EE",
                 linestyle=(0, (6, 4)), alpha=0.6, zorder=1))
    ax.text(35, 90, "YOUR LAPTOP  ·  privacy boundary", ha="center",
            va="center", fontsize=10, color=GREEN_LINE, fontweight="bold")

    # ---- inside: everything that stays local (green ✓) ----
    card(7, 70, 52, 13, "Code Guardian", "local LLM + RAG",
         fill=NAVY, edge=NAVY, tcol="white", scol="#C2CBDD",
         mark="✓", mark_col=GREEN_LINE)
    card(7, 53, 52, 13, "Local SAST baselines", "Semgrep · CodeQL · ESLint",
         mark="✓", mark_col=GREEN_LINE)
    card(7, 36, 52, 13, "Your code & prompts", "source · embeddings · context",
         mark="✓", mark_col=GREEN_LINE)
    card(7, 23, 52, 8, "Only outbound: signed corpus updates", "",
         fill="#F3E9D8", edge=TEXT_MUTED, tcol=TEXT_MUTED, ts=9.5, lw=1.2)

    # ---- outside: the excluded cloud baseline (red ✗) ----
    card(73, 36, 25, 13, "Cloud LLM", "Copilot · GPT-4\nClaude · Cursor",
         fill="#FDE9EE", edge=RED, tcol=RED, scol=RED, ts=11,
         mark="✗", mark_col=RED)

    # ---- the egress that using a cloud baseline would require ----
    ax.add_patch(FancyArrowPatch((59, 42.5), (73, 42.5),
                 arrowstyle="-|>", color=RED, mutation_scale=15,
                 linewidth=1.8, linestyle=(0, (5, 3)), shrinkA=0, shrinkB=0,
                 zorder=3))
    ax.text(66, 47.5, "requires\ncode egress", color=RED, fontsize=8,
            ha="center", va="center", fontweight="bold", fontstyle="italic",
            zorder=8)

    ax.text(50, 10, "Cloud baselines can't be run without breaking the threat model.",
            ha="center", va="center", fontsize=8.5, color=RED, fontweight="bold")

    fig.tight_layout(pad=0.4)
    save("diagram_29_threat_model.png", fig)


# -----------------------------------------------------------------------------
# Illustration — slide 2: developer's dilemma
# -----------------------------------------------------------------------------
def illustration_dilemma():
    fig, ax = plt.subplots(figsize=(10.5, 5.6))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 55)
    ax.axis("off")
    fig.patch.set_facecolor(LIGHT_BG)

    # Developer figure — simple stylized silhouette behind a laptop
    # Head
    ax.add_patch(mpatches.Circle((50, 22), 4.2, facecolor=NAVY,
                                 edgecolor=NAVY_DARK, linewidth=1.2, zorder=3))
    # Shoulders (torso trapezoid)
    torso = mpatches.FancyBboxPatch((42, 6), 16, 12,
                                    boxstyle="round,pad=0.1,rounding_size=2.5",
                                    facecolor=NAVY, edgecolor=NAVY_DARK,
                                    linewidth=1.2, zorder=2)
    ax.add_patch(torso)
    # Laptop screen (front of body)
    screen = mpatches.FancyBboxPatch((39, 8), 22, 9,
                                     boxstyle="round,pad=0.2,rounding_size=0.8",
                                     facecolor=NAVY_DARK, edgecolor="#445",
                                     linewidth=1.2, zorder=4)
    ax.add_patch(screen)
    # Code lines on screen
    for i, w in enumerate([10, 14, 8, 12, 6]):
        ax.add_patch(Rectangle((41, 14.5 - i * 1.1), w, 0.5,
                               facecolor=("#FCA311" if i == 2 else "#8aa1c2"),
                               edgecolor="none", zorder=5))
    # Laptop base
    base = mpatches.FancyBboxPatch((37, 5), 26, 2,
                                   boxstyle="round,pad=0.1,rounding_size=0.5",
                                   facecolor="#445", edgecolor=NAVY_DARK,
                                   linewidth=0.8, zorder=3)
    ax.add_patch(base)

    # Three thought bubbles around the developer
    def bubble(cx, cy, w, h, icon, title, body, color):
        # Main rounded rect
        rect = mpatches.FancyBboxPatch((cx - w / 2, cy - h / 2), w, h,
                                       boxstyle="round,pad=0.6,rounding_size=1.8",
                                       facecolor=CARD_BG, edgecolor=color,
                                       linewidth=2.2, zorder=5)
        ax.add_patch(rect)
        # Top accent strip
        strip = Rectangle((cx - w / 2, cy + h / 2 - 1.2), w, 1.2,
                          facecolor=color, edgecolor="none", zorder=6)
        ax.add_patch(strip)
        # Icon (text-based)
        ax.text(cx - w / 2 + 2.5, cy + h / 2 - 4.5, icon,
                fontsize=18, color=color, fontweight="bold", zorder=7,
                va="center")
        # Title
        ax.text(cx - w / 2 + 6, cy + h / 2 - 4.5, title,
                fontsize=11, color=NAVY_DARK, fontweight="bold", zorder=7,
                va="center")
        # Body
        ax.text(cx, cy - h / 2 + 3.5, body,
                fontsize=10, color=TEXT_DARK, ha="center", va="center",
                zorder=7, wrap=True)

    # Bubble 1 (top-left) — privacy
    bubble(18, 44, 28, 12, "✗", "Can't paste this",
           "it's proprietary,\nregulated code", RED)

    # Bubble 2 (top-right) — SAST coverage
    bubble(82, 44, 28, 12, "✗", "Semgrep missed it",
           "again, only catches\npattern matches", "#A68000")

    # Bubble 3 (bottom-left, below dev) — repair gap
    bubble(20, 12, 28, 12, "?", "I need a fix",
           "not just a warning\nin the squiggle", NAVY)

    # Bubble 4 (bottom-right) — the question
    bubble(82, 12, 28, 12, "!", "What's the alternative?",
           "Privacy + coverage + repair\nin one tool: does it exist?",
           "#2E8B57")

    # Connector lines from bubbles toward developer
    for x, y in [(28, 38), (72, 38), (28, 18), (72, 18)]:
        ax.plot([x, 50], [y, 22], color=TEXT_MUTED, linewidth=0.8,
                linestyle=(0, (2, 2)), alpha=0.45, zorder=1)

    # Sub-caption
    ax.text(50, 1.5,
            "Privacy, coverage, and repair quality: pick at most two.",
            fontsize=12, color=TEXT_MUTED, ha="center", va="center",
            fontstyle="italic", fontweight="bold")

    fig.tight_layout(pad=0.5)
    save("illustration_2_dilemma.png", fig)


if __name__ == "__main__":
    chart_f1_baselines()
    chart_rag_ablation()
    chart_latency_bands()
    diagram_architecture()
    diagram_threat_model()
    illustration_dilemma()
    print("done")
