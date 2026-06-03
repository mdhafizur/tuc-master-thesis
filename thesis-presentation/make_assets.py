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
    from matplotlib.patches import Ellipse
    fig, ax = plt.subplots(figsize=(12.5, 6.8))
    ax.set_xlim(0, 100)
    ax.set_ylim(0, 68)
    ax.axis("off")
    fig.patch.set_facecolor("white")

    STORE_FILL = "#E9EEF8"
    GREEN_LINE = "#2E8B57"

    def card(x, y, w, h, title, sub=None, fill=NAVY, edge=NAVY,
             title_color="white", sub_color="#C2CBDD", fontsize=11, lw=1.6):
        ax.add_patch(FancyBboxPatch((x, y), w, h,
                     boxstyle="round,pad=0.45,rounding_size=1.0",
                     linewidth=lw, edgecolor=edge, facecolor=fill, zorder=4))
        if sub:
            ax.text(x + w / 2, y + h * 0.63, title, ha="center", va="center",
                    fontsize=fontsize, color=title_color, fontweight="bold", zorder=5)
            ax.text(x + w / 2, y + h * 0.30, sub, ha="center", va="center",
                    fontsize=8, color=sub_color, zorder=5)
        else:
            ax.text(x + w / 2, y + h / 2, title, ha="center", va="center",
                    fontsize=fontsize, color=title_color, fontweight="bold", zorder=5)

    def cylinder(x, y, w, h, title, sub):
        cx = x + w / 2
        eh = h * 0.13
        ax.add_patch(Rectangle((x, y + eh), w, h - 2 * eh, facecolor=STORE_FILL,
                               edgecolor=NAVY, linewidth=1.5, zorder=4))
        ax.add_patch(Ellipse((cx, y + eh), w, 2 * eh, facecolor=STORE_FILL,
                             edgecolor=NAVY, linewidth=1.5, zorder=4))
        ax.add_patch(Ellipse((cx, y + h - eh), w, 2 * eh, facecolor=STORE_FILL,
                             edgecolor=NAVY, linewidth=1.5, zorder=5))
        ax.text(cx, y + h * 0.64, title, ha="center", va="center",
                fontsize=10, color=NAVY_DARK, fontweight="bold", zorder=6)
        ax.text(cx, y + h * 0.42, sub, ha="center", va="center",
                fontsize=7.5, color=TEXT_MUTED, zorder=6)

    def conn(points, color=NAVY_DARK, lw=1.7, style="-|>", alpha=1.0,
             dashed=False, label=None, label_xy=None, label_color=TEXT_MUTED):
        ls = (0, (5, 3)) if dashed else "solid"
        for i in range(len(points) - 1):
            a, b = points[i], points[i + 1]
            st = style if i == len(points) - 2 else "-"
            ax.add_patch(FancyArrowPatch(a, b, arrowstyle=st, color=color,
                                         linewidth=lw, alpha=alpha,
                                         mutation_scale=15, linestyle=ls,
                                         shrinkA=0, shrinkB=0, zorder=2))
        if label:
            ax.text(label_xy[0], label_xy[1], label, fontsize=8,
                    color=label_color, ha="center", va="center", zorder=12,
                    fontstyle="italic")

    # ---- backend boundary (everything local) ----
    ax.add_patch(FancyBboxPatch((3, 5), 94, 47,
                 boxstyle="round,pad=1.0,rounding_size=2.0",
                 linewidth=1.8, edgecolor=NAVY, facecolor="#F7F9FD",
                 linestyle=(0, (6, 4)), zorder=1))
    ax.text(7, 8.5, "CODE GUARDIAN", ha="left", va="center",
            fontsize=15, color=NAVY_DARK, fontweight="bold", zorder=3)
    ax.text(7, 5.9, "runs entirely on your laptop", ha="left", va="center",
            fontsize=8.5, color=TEXT_MUTED, fontstyle="italic", zorder=3)

    # ---- external provider (outside, top) ----
    FEED = (60, 58, 33, 7)
    card(*FEED, "Public Security Feeds", "NVD · OWASP · CWE · GitHub",
         fill="white", edge=NAVY, title_color=NAVY_DARK, sub_color=TEXT_MUTED,
         fontsize=10.5, lw=1.4)

    # ---- nodes (bottom-left x, y, w, h) ----
    CUI = (9, 38, 17, 9)     # client UI
    EXT = (31, 38, 17, 9)    # extension core
    ANA = (53, 38, 17, 9)    # analyzer (accent)
    OL  = (74, 38, 19, 9)    # ollama
    CH  = (31, 23, 17, 8)    # cache (cyl)
    RAGM = (53, 23, 17, 8)   # rag manager
    VD  = (74, 23, 19, 8)    # vuln data (cyl)
    VEC = (53, 9, 17, 8)     # vector index (cyl)

    def cx(n): return n[0] + n[2] / 2
    def top(n): return n[1] + n[3]
    def vmid(n): return n[1] + n[3] / 2

    # ---- connectors (drawn first; cards overlay endpoints) ----
    # client request / response — the green path
    conn([(CUI[0] + CUI[2], vmid(CUI) + 1.5), (EXT[0], vmid(CUI) + 1.5)],
         color=GREEN_LINE, label="analyze", label_xy=(28.5, 49.0),
         label_color=GREEN_LINE)
    conn([(EXT[0], vmid(EXT) - 1.5), (CUI[0] + CUI[2], vmid(EXT) - 1.5)],
         color=GREEN_LINE, dashed=True, label="results", label_xy=(28.5, 36.0),
         label_color=GREEN_LINE)
    # extension → analyzer
    conn([(EXT[0] + EXT[2], vmid(EXT)), (ANA[0], vmid(EXT))],
         label="on miss", label_xy=(50.5, 49.0))
    # extension ↓ cache  (and cache ↑ back)
    conn([(cx(EXT) - 1.6, EXT[1]), (cx(EXT) - 1.6, top(CH))],
         label="cache\ncheck", label_xy=(35.0, 35.0))
    conn([(cx(EXT) + 1.6, top(CH)), (cx(EXT) + 1.6, EXT[1])],
         dashed=True, style="-|>")
    # analyzer ↓ rag manager  /  rag ↑ analyzer
    conn([(cx(ANA) - 1.6, ANA[1]), (cx(ANA) - 1.6, top(RAGM))],
         label="query", label_xy=(57.0, 35.0))
    conn([(cx(RAGM) + 1.6, top(RAGM)), (cx(RAGM) + 1.6, ANA[1])],
         dashed=True, label="context", label_xy=(67.0, 35.0))
    # rag manager ↓ vector index  /  vector ↑ rag
    conn([(cx(RAGM) - 1.6, RAGM[1]), (cx(RAGM) - 1.6, top(VEC))],
         label="embed", label_xy=(57.0, 20.6))
    conn([(cx(VEC) + 1.6, top(VEC)), (cx(VEC) + 1.6, RAGM[1])],
         dashed=True, label="top-k", label_xy=(66.5, 20.6))
    # analyzer → ollama  /  ollama → analyzer
    conn([(ANA[0] + ANA[2], vmid(ANA) + 1.5), (OL[0], vmid(ANA) + 1.5)],
         label="prompt (JSON)", label_xy=(72.0, 49.0))
    conn([(OL[0], vmid(OL) - 1.5), (ANA[0] + ANA[2], vmid(OL) - 1.5)],
         dashed=True, label="completion", label_xy=(72.0, 36.0))
    # vuln data → rag manager (CVE context)
    conn([(VD[0], vmid(VD)), (RAGM[0] + RAGM[2], vmid(VD))],
         label="CVE context", label_xy=(72.0, 33.0))
    # external feeds ⇢ vuln data  (the only line crossing the boundary,
    # routed down the right margin so it never touches the Ollama card)
    conn([(cx(FEED), FEED[1]), (cx(FEED), 54.5), (95.5, 54.5),
          (95.5, vmid(VD)), (VD[0] + VD[2], vmid(VD))],
         color=RED, dashed=True, lw=1.7,
         label="fetch (24 h)\noutbound only", label_xy=(70.5, 55.4),
         label_color=RED)

    # ---- nodes ----
    card(*CUI, "Client UI", "VS Code editor", edge=GREEN_LINE, lw=2.2)
    card(*EXT, "Extension Core", "orchestration")
    card(*ANA, "Analyzer", "detect + repair", fill=ACCENT, edge=ACCENT,
         title_color=NAVY_DARK, sub_color="#5A4410")
    card(*OL, "Ollama", "local LLM")
    card(*RAGM, "RAG Manager", "context retrieval", fontsize=10)
    cylinder(*CH, "Cache", "LRU 95–98%")
    cylinder(*VD, "Vulnerability Data", "24 h cache")
    cylinder(*VEC, "Vector Index", "HNSWlib")

    ax.text(50, 1.4, "Only public vulnerability look-ups (red) ever leave the machine — your code never does.",
            ha="center", va="center", fontsize=8.5, color=RED, fontweight="bold")

    fig.tight_layout(pad=0.4)
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
    card(7, 70, 54, 13, "Code Guardian", "local LLM + RAG",
         fill=NAVY, edge=NAVY, tcol="white", scol="#C2CBDD",
         mark="✓", mark_col=GREEN_LINE)
    card(7, 53, 54, 13, "Local SAST baselines", "Semgrep · CodeQL · ESLint",
         mark="✓", mark_col=GREEN_LINE)
    card(7, 36, 54, 13, "Your code & prompts", "source · embeddings · context",
         mark="✓", mark_col=GREEN_LINE)
    card(7, 23, 54, 8, "Only outbound: signed corpus updates", "",
         fill="#F3E9D8", edge=TEXT_MUTED, tcol=TEXT_MUTED, ts=9.5, lw=1.2)

    # ---- outside: the excluded cloud baseline (red ✗) ----
    card(73, 36, 25, 13, "Cloud LLM", "Copilot · GPT-4\nClaude · Cursor",
         fill="#FDE9EE", edge=RED, tcol=RED, scol=RED, ts=11,
         mark="✗", mark_col=RED)

    # ---- the egress that using a cloud baseline would require ----
    ax.add_patch(FancyArrowPatch((61, 42.5), (73, 42.5),
                 arrowstyle="-|>", color=RED, mutation_scale=15,
                 linewidth=1.8, linestyle=(0, (5, 3)), shrinkA=0, shrinkB=0,
                 zorder=3))
    ax.text(64, 54, "requires\ncode egress", color=RED, fontsize=8.5,
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
           "again — only catches\npattern matches", "#A68000")

    # Bubble 3 (bottom-left, below dev) — repair gap
    bubble(20, 12, 28, 12, "?", "I need a fix",
           "not just a warning\nin the squiggle", NAVY)

    # Bubble 4 (bottom-right) — the question
    bubble(82, 12, 28, 12, "!", "What's the alternative?",
           "Privacy + coverage + repair\nin one tool — does it exist?",
           "#2E8B57")

    # Connector lines from bubbles toward developer
    for x, y in [(28, 38), (72, 38), (28, 18), (72, 18)]:
        ax.plot([x, 50], [y, 22], color=TEXT_MUTED, linewidth=0.8,
                linestyle=(0, (2, 2)), alpha=0.45, zorder=1)

    # Sub-caption
    ax.text(50, 1.5,
            "Privacy, coverage, and repair quality — pick at most two.",
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
