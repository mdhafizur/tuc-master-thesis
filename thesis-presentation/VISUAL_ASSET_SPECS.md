# Visual Asset Specifications — defense_slides_v2.pptx

The pptx has six placeholder rectangles labelled with what they need. This doc tells you how to produce each one. Order is roughly highest-leverage-first.

## Asset checklist

| # | Slide | Asset                                              | Source / tool                              | Difficulty |
|---|-------|----------------------------------------------------|--------------------------------------------|------------|
| 1 | 10    | VS Code extension screenshot                       | Live recording on your laptop              | Easy       |
| 2 | 11    | System architecture diagram                        | Excalidraw / draw.io                       | Medium     |
| 3 | 15    | F1 bar chart — Code Guardian vs SAST baselines     | Excel / Numbers / Python matplotlib        | Easy       |
| 4 | 16    | RAG ablation bar chart — 5 models, ΔF1            | Excel / Numbers / Python matplotlib        | Easy       |
| 5 | 18    | Latency bar chart with band lines                  | Excel / Numbers / Python matplotlib        | Medium     |
| 6 | 2     | Problem-framing illustration                       | DALL-E / Midjourney / stock with overlay   | Easy       |
| 7 | 10    | QR code (demo / GitHub release)                    | qrcode.monster or `qrencode`               | Trivial    |
| A | A2    | Confusion matrix numbers                           | Cell-fill, no chart                        | Trivial    |
| A | A5    | Threat-model diagram (small)                       | Excalidraw                                 | Easy       |

---

## 1. VS Code Extension Screenshot (slide 10)

The most important addition to the entire deck. The thesis ships a product. Show the product.

### Shot list
You want **one composed screenshot** with all of the following visible:
- A JS or TS file open with a vulnerable line (use one of your curated cases — pick a SQL injection or XSS, since they're visually obvious to non-experts)
- A **red squiggle** under the vulnerable line
- The **Code Guardian side panel** on the right showing: category, severity, CWE id, evidence
- The **Quick Fix menu** floating on or near the squiggle, showing the structured repair option
- VS Code title bar visible (so the audience knows it's VS Code, not an IDE you invented)
- A **clean, recognizable code editor theme** — One Dark Pro, GitHub Dark, or VS Code default dark. Avoid eye-strain themes.

### Setup
- Resolution: at least **2560 × 1440** so it stays sharp when projected
- Font size in editor: bump to **16 pt** so the audience in the back can read it
- Hide unrelated UI: collapse the file explorer / extensions sidebar that isn't relevant
- Close other tabs (audiences read what's on screen — even tab names)

### How to capture
1. Open the project, pick a vulnerable case
2. Trigger the diagnostic (save the file)
3. Open the Code Guardian panel
4. Click the Quick Fix lightbulb to expand the menu
5. Take a full-window screenshot: **macOS** ⌘ + Shift + 5 → window capture; **Windows** Win + Shift + S → window
6. Crop the screenshot in Preview / Snip & Sketch to remove the OS title bar if it has personal info
7. Save as PNG, drop onto the slide-10 placeholder

### Annotations to add over the screenshot (in PowerPoint, after dropping it in)
- A small numbered callout "①" near the red squiggle
- "②" near the side panel
- "③" near the Quick Fix
- A tiny legend box at the bottom of the screenshot: "① detection · ② structured finding · ③ Quick-Fix repair"

This makes the screenshot self-documenting in the appendix PDF you'll publish post-defense.

---

## 2. System Architecture Diagram (slide 11)

You currently have `code-guardian-thesis-report/images/privacy_boundary.drawio.pdf` and `c4_container.drawio.pdf` — start from those and simplify for projector.

### Required elements

```
                          ┌─ INTERNET ────────────────────────────────┐
                          │   NVD     OWASP     CWE     (public,       │
                          │                              metadata only)│
                          └────┬──────────────────────────────────────┘
                               │  24h cache refresh, public metadata
                               │  (no user code, ever)
                               ▼
┌─── PRIVACY BOUNDARY  ·  developer's laptop ──────────────────────────┐
│                                                                       │
│   ┌────────────────────────┐                                          │
│   │     VS Code            │                                          │
│   │    Extension Host      │◀───── developer interacts                │
│   └───┬────────┬────────┬──┘                                          │
│       │        │        │                                             │
│       ▼        ▼        ▼                                             │
│   ┌────────┐ ┌─────┐ ┌──────────────┐                                 │
│   │ Ollama │ │ RAG │ │ Vuln. Data   │                                 │
│   │ 127.0..│ │HNSW │ │ Manager      │                                 │
│   │ ::1    │ │     │ │ (24h cache)  │                                 │
│   └────────┘ └─────┘ └──────────────┘                                 │
│      ↑signed manifest verified at load                                │
└───────────────────────────────────────────────────────────────────────┘
```

### Rules
- Draw the **privacy boundary as a dashed rectangle** containing everything that runs on the laptop
- The **only** arrow that crosses the boundary is the vulnerability-data refresh (outbound, public metadata only, 24h cache). Label that arrow explicitly.
- Use **two colors total**: navy for components, accent (orange/gold) for the boundary itself
- **No icons unless they're consistent.** A diagram with three different icon styles looks slapdash.

### Tool recommendation
- **Excalidraw** (excalidraw.com) — fastest, looks hand-drawn-clean, exports SVG
- **draw.io** if you want to reuse your existing `.drawio.pdf` source

### Sizing
Export as PNG at **300 DPI** or as SVG. PNG aim for ~3500 pixels wide.

---

## 3. F1 Bar Chart — Code Guardian vs SAST Baselines (slide 15)

### Data
Pull the actual numbers from `evaluation/results/`. If specific cells are still blank, leave them as `n/a` rather than fake them.

| System                    | F1     | Precision | Recall |
|---------------------------|--------|-----------|--------|
| **qwen3:8b + RAG (gated)**| **74.07** | **78.13** | 70.42  |
| qwen3:8b + RAG (ungated)  | 71.43  | 72.46     | 70.42  |
| Semgrep                   | ~14    | n/a       | 12.68  |
| CodeQL                    | n/a    | n/a       | n/a    |
| ESLint-security           | n/a    | n/a       | n/a    |

### Chart spec
- **Horizontal bar chart**, F1 on x-axis
- Sort descending by F1
- Highlight the Code Guardian bar in **accent color (orange/gold)**; baselines in muted gray
- X-axis: 0 to 100 %, gridline every 20 %
- Label each bar with its numeric value at the end of the bar
- Title: "F1 vs SAST baselines · canonical taxonomy · n = 101"
- No legend needed (single series)

### Tool
**matplotlib** is fastest. Snippet you can run:

```python
# rough sketch — adjust numbers
import matplotlib.pyplot as plt

systems = ["qwen3:8b + RAG (gated)", "qwen3:8b + RAG", "Semgrep", "CodeQL", "ESLint-sec"]
f1     = [74.07, 71.43, 14, 0, 0]  # use real values
colors = ["#FCA311", "#FCA311", "#94A3B8", "#94A3B8", "#94A3B8"]

fig, ax = plt.subplots(figsize=(8, 3.5))
ax.barh(systems[::-1], f1[::-1], color=colors[::-1])
ax.set_xlim(0, 100)
ax.set_xlabel("F1 (%)")
ax.set_title("F1 vs SAST baselines · canonical taxonomy · n = 101")
for i, v in enumerate(f1[::-1]):
    ax.text(v + 1, i, f"{v:.1f}%", va="center", fontsize=10)
plt.tight_layout()
plt.savefig("slide15_f1_bar.png", dpi=300, bbox_inches="tight")
```

Drop the PNG onto slide 15 placeholder.

---

## 4. RAG Ablation Bar Chart (slide 16)

### Data
From `evaluation/results/` Phase 1-b3 (2026-04-28 canonical run):

| Model        | F1 no-RAG | F1 RAG | ΔF1     | Bonferroni |
|--------------|-----------|--------|---------|------------|
| qwen3:8b     | 67.52     | 71.43  | **+3.91**  | n.s.       |
| gemma3:4b    | n/a       | n/a    | ≈ 0     | n.s.       |
| gemma3:1b    | n/a       | n/a    | ≈ 0     | n.s.       |
| qwen3:4b     | n/a       | n/a    | **−5.22**  | n.s.       |
| codellama    | 53.06     | 23.17  | **−29.89** | **p = 0.0013** ✓ |

### Chart spec
- **Horizontal divergent bar chart** — positive ΔF1 to the right, negative to the left
- Center line at 0
- Bars in green (positive) / red (negative)
- **Highlight codellama's bar with a "✓ Bonferroni" badge** to flag the significance
- X-axis label: "Δ F1 (RAG − no RAG), percentage points"
- Title: "RAG impact per model — only codellama survives Bonferroni"

### Important
Get the gemma3 and qwen3:4b numbers from the actual evaluation logs before publishing — don't ship the `n/a`s.

---

## 5. Latency Bar Chart with Band Lines (slide 18)

### Data

| Model               | Median p50 (ms) | p95 (ms) | Band               |
|---------------------|-----------------|----------|--------------------|
| qwen3:8b + RAG      | 2,216           | 4,327    | on-demand ✅       |
| qwen3:4b            | 1,328           | n/a      | interactive ✅     |
| gemma3:1b + RAG     | 1,019           | n/a      | interactive ✅     |
| codellama           | 2,024           | n/a      | on-demand ✅       |
| codellama + RAG     | 3,529           | n/a      | on-demand ✅       |
| Semgrep             | ~300            | n/a      | real-time ✅       |

### Chart spec
- **Horizontal bar chart**, median p50 latency on x-axis (linear ms, 0–6000)
- Three **vertical dashed reference lines** at 500 ms, 1500 ms, 5000 ms — label them at the top: "real-time", "interactive", "on-demand"
- Sort ascending by p50
- Color bars by band: SAST = green; interactive-qualifying models = blue; on-demand-only = navy
- The **headline qwen3:8b + RAG bar should be highlighted** in accent color, with a "headline" annotation

### Why this matters
This chart sells R4 in three seconds: the audience sees that you've named the bands, fit different models into different bands, and that the headline configuration sits inside the band you claimed it would.

---

## 6. Problem-Framing Illustration (slide 2)

### Concept
Single image, full-width. A developer at a laptop (any style — vector illustration, isometric, photographic). Three speech bubbles or thought clouds around them:

1. **Left bubble** (red border): "Can't paste this to ChatGPT — it's customer data"
2. **Top-right bubble** (yellow border): "Semgrep missed this again"
3. **Bottom-right bubble** (orange border): "I need a fix, not just a warning"

### Style
- Mirror Huzefa's slide 2 — flat illustration, dark navy and orange/yellow palette
- Avoid AI-art telltales (six fingers, glitched text) — fix in post if you use Midjourney/DALL-E
- If you can't get a good illustration in 10 minutes, **use a stock photo of a developer at a laptop and overlay the three speech bubbles in PowerPoint** — that's faster and reads cleanly

### Sources
- DALL-E 3 prompt: "Flat illustration of a software developer at a laptop in a dark room, viewed from the side, navy and orange color palette, isometric perspective, no text, vector style, clean simple shapes"
- unDraw (undraw.co) — free SVG illustrations in a clean flat style; search "developer," "coding," "security"
- Storyset (storyset.com) — same vibe, free for non-commercial

### Important
**Drop the speech bubbles in PowerPoint as separate shapes**, not as part of the image. Then you can edit the text on the day if your supervisor wants different framing.

---

## 7. QR Code (slide 10)

```bash
# install: brew install qrencode  (macOS)
qrencode -o slide10_qr.png -s 12 "https://github.com/<your-handle>/code-guardian"
# or
qrencode -o slide10_qr.png -s 12 "https://marketplace.visualstudio.com/items?itemName=<your-publisher>.code-guardian"
```

Or use any online QR generator (qrcode.monster, qr-code-generator.com). **Test the QR code by scanning it with your phone before the defense.**

---

## A2. Confusion Matrix Cells (appendix A2)

The pptx puts in placeholder cell values. Replace with the actual canonical-taxonomy figures from `evaluation/results/evaluation-phase1-b3-2026-04-28-qwen3-8b-rag.json`.

Formulae:
- F1 = 71.43 %, precision = 72.46 %, recall = 70.42 %, FPR = 10 %
- 71 vulnerable cases, 30 secure
- TP + FN = 71; FP + TN = 30
- Recall = TP / (TP + FN) → TP ≈ 50, FN ≈ 21
- FPR = FP / (FP + TN) → FP ≈ 3, TN ≈ 27

So full corpus should be approximately:
```
              Predicted: Vuln    Predicted: Safe
Actual Vuln:        50                21        (TP, FN)
Actual Safe:         3                27        (FP, TN)
```

The numbers currently in the pptx are placeholders — replace with these.

For the held-out 30-case split: F1 61.11 %, FPR 0 %. Solve similarly with the test-split case counts (typically 21 vulnerable + 9 secure in a 71/30 split that proportionally samples each class).

---

## A5. Threat-Model Diagram (appendix A5)

Small diagram showing why a cloud-LLM baseline doesn't fit the threat model:

```
        [ Cloud LLM ]              ← outside boundary  ❌
              ✗
              |
              |
┌─ Privacy boundary (dashed) ────────────────────┐
│                                                 │
│   [ Developer's code ]                          │
│   [ Code Guardian (local) ]   ✅                │
│   [ Semgrep, CodeQL, ESLint ] ✅ (baselines)    │
│                                                 │
└─────────────────────────────────────────────────┘
```

Excalidraw, ~5 minutes. Export as PNG.

---

## Sanity check before defense

Before you walk in:

- [ ] Open `defense_slides_v2.pptx` on the projector laptop — verify all 6 placeholders have been replaced with the real assets
- [ ] Open in *both* PowerPoint and Keynote — font substitutions sometimes ruin a card layout
- [ ] Export to PDF as a backup (`File → Export → PDF`) — projector apps fail
- [ ] On the projector laptop, set the resolution to 1080p — if you authored at higher DPI assets will down-sample
- [ ] Scan the QR code with your phone — confirms the link is right
- [ ] Sanity-check the numbers on slide 14, 15, 16, 17 against `thesis_defense_anchors.md` — these must match the thesis text exactly
- [ ] The R-badge in the corner of slides 15, 16, 17, 18, 19 must match the requirement being shown — not R6 (which doesn't exist anymore)

## Stylistic notes — what to avoid

- **No clip-art icons.** If you use icons, use a single set (e.g., Lucide, Phosphor). Mixing styles is the #1 tell of a rushed deck.
- **No 3D charts.** Ever. Flat bars only.
- **No drop shadows on cards.** The pptx ships flat; keep it flat.
- **No animations.** Cards appearing one at a time wastes seconds of your 28-minute budget.
- **No "the end" or "any questions?" slides.** Slide 24 is the Q&A landing already.
