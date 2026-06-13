# Defense Slide Redesign — Code Guardian

**Target:** 30 min total = ~28 min talk + 2 min Q&A
**Slide budget:** 24 main slides at ~70 s each + 6 appendix held for Q&A
**Design language:** dark-navy header band, white body, two-tone cards with icons (mirroring Huzefa's INVOX deck). Footer on every slide: `Md Hafizur Rahman · Code Guardian · TU Chemnitz · 11.05.2026 · X / 24`.

Each slide below specifies: title, layout, content, and a one-line *speaking anchor* — what you actually say to bridge to the next slide.

---

## ACT I — THE PROBLEM (slides 1–5, ~5 min)

### Slide 1 — Title
**Layout:** Full-bleed dark navy. White title.
**Content:**
- Title: **Privacy-Preserving Source Code Vulnerability Detection and Repair using Retrieval-Augmented LLMs**
- Subtitle: *Code Guardian — A local-only assistant for JavaScript / TypeScript*
- Three small columns at the bottom: Presented by · Supervisors/Examiner · Date
**Speaking anchor:** "Today I'll show why this assistant exists, what it does, and what the numbers say."

### Slide 2 — The Problem: A Developer's Dilemma
**Layout:** Single image, centered. *Make or commission an illustration* of a developer at a terminal with three speech bubbles: "Can't paste this to ChatGPT — it's customer data", "Semgrep missed it again", "I need a fix, not just a warning". (Huzefa's slide 2 is this same trick with a furnace worker.)
**Content:** Just the image + title.
**Speaking anchor:** "Here's the real situation."

### Slide 3 — Concrete Example: What "Privacy" Costs Today
**Layout:** Two side-by-side cards.
- LEFT card "❌ Cloud LLM (Copilot/ChatGPT)": shows a code snippet leaving the laptop with a red arrow to a cloud icon. Caption: *Code crosses the network — blocked in finance, healthcare, defence, air-gapped environments.*
- RIGHT card "❌ Local SAST (Semgrep/CodeQL)": shows the same snippet staying local but a tool emoji says "no fix". Caption: *Stays local but cannot reason across context or generate repairs. **Semgrep canonical recall: 12.68 %** on our JS/TS corpus.*
**Speaking anchor:** "Neither half of the existing market gives you all three things at once."

### Slide 4 — The Gap: Three Things, No Existing Tool
**Layout:** Three icon-headed cards in a row (mirror Huzefa slide 4 "Fragile/Opaque/Rigid").
- 🔒 **Local Inference** — code never leaves the developer's machine
- 📚 **Retrieval-Augmented Reasoning** — grounded in CWE/OWASP knowledge
- 🛠️ **Developer-Controlled Repair** — structured fix, opt-in via Quick Fix

Below: *"No existing tool combines all three. This thesis builds and evaluates one."*
**Speaking anchor:** "That gap defines what we built and how we measured it."

### Slide 5 — Research Questions and Requirements
**Layout:** Left column = 3 RQ cards. Right column = 5 R-cards (each with the metric it maps to). Bottom bar: "All R1–R5 are operationalised against fixed four-level threshold scales — set in Chapter 2 **before** evaluation."
- **RQ1** Can a local LLM on consumer hardware reach acceptable detection quality under a strict privacy envelope?
- **RQ2** Does grounding the LLM in retrieved CWE/OWASP knowledge improve detection?
- **RQ3** Is in-IDE latency acceptable for developer workflows?
- **R1** Detection accuracy *(precision, recall, F1)*
- **R2** Consistency *(JSON parse, inter-run)*
- **R3** Repair quality *(manual + auto-applicable)*
- **R4** Usability *(latency, IDE integration)*
- **R5** Privacy *(zero exfiltration, signed corpus)*
**Speaking anchor:** "These five requirements appear as badges on every results slide from here on."

---

## ACT II — STATE OF THE ART (slides 6–7, ~2.5 min)

### Slide 6 — Existing Approaches
**Layout:** Three-column table (mirror Huzefa slide 7). Columns: **Cloud LLM Assistants** · **Local SAST** · **Academic LLM-for-Sec**. Each column lists 3–4 representative tools with year and a one-line characterization (Copilot 2021 / Cursor 2023 / ChatGPT 2022 — Semgrep / CodeQL / ESLint — SecurityEval / VulnBench / CodeBERT-Sec).
**Speaking anchor:** "Now mapped against the five requirements."

### Slide 7 — Critical Gap Matrix
**Layout:** Matrix exactly like Huzefa slide 8. Rows = representative tools. Columns = R1 R2 R3 R4 R5. Cells = ✅ / 🟡 / ❌ / —.
- Copilot: R1 ✅, R2 🟡, R3 ✅, R4 ✅, **R5 ❌**
- Semgrep: R1 ❌, R2 ✅, R3 ❌, R4 ✅, R5 ✅
- CodeQL: similar to Semgrep
- SecurityEval (academic): R1 🟡, R2 🟡, R3 🟡, R4 ❌, R5 ✅
- *Code Guardian (this work):* all ✅ / 🟡 (cells filled at the end as a reveal)

Right side callout: **"No existing tool satisfies privacy + repair + IDE-latency together."**
**Speaking anchor:** "That's the gap. Now the system."

---

## ACT III — THE SYSTEM (slides 8–12, ~6 min)

### Slide 8 — Code Guardian at a Glance
**Layout:** Four icon cards in a row labelling the four developer workflows (mirror Huzefa slide 9 pipeline). Real-time diagnostics · On-demand file scan · Interactive Q&A panel · Workspace audit.
**Speaking anchor:** "All four workflows hit the same two-stage pipeline."

### Slide 9 — Two-Stage Local Pipeline
**Layout:** Horizontal flow diagram.
- Stage 1: **Detection** — JSON-mode LLM call → optional RAG context → consensus filter (3 runs).
- Stage 2: **Repair** — separate structured call → returns `{code, language}` → developer applies via Quick Fix.
- Below: "Privacy-by-construction — Ollama bound to loopback, embeddings local, no telemetry."
**Speaking anchor:** "Here's what it actually looks like running."

### Slide 10 — Live: VS Code Extension
**Layout:** Full-width screenshot of the extension in action — show a JS file with a red squiggle, the Code Guardian panel open with a finding, and the Quick Fix menu visible. QR code in the bottom corner linking to the GitHub release / demo video. (Mirror Huzefa slide 18.)
**Speaking anchor:** "Behind that UI sits the architecture."

### Slide 11 — System Architecture
**Layout:** Full-width architecture diagram (you must draw this). Boxes: VS Code Extension Host → Ollama (loopback) → RAG store (HNSWlib) → Vulnerability Data Manager → NVD/OWASP/CWE feeds. Show the privacy boundary as a dashed rectangle around everything that stays on the laptop.
**Speaking anchor:** "Privacy isn't a feature — it's a boundary."

### Slide 12 — Privacy by Construction
**Layout:** Four cards.
- 🔒 **Loopback only** — Ollama bound to 127.0.0.1
- 🧬 **Signed corpus** — RAG manifest signed with Ed25519
- 📦 **Pinned container** — Node 20.19.0-alpine, `npm ci`, seed = 42
- 🛡️ **Prompt-injection harness** — 12 cases, **leakFreeRate 100 %**
**Speaking anchor:** "Now the evaluation."

---

## ACT IV — EVALUATION SETUP (slides 13–14, ~2.5 min)

### Slide 13 — Evaluation Setup
**Layout:** Three cards.
- **Corpus** — Curated JS/TS · **101 cases** (71 vulnerable + 30 secure) · 20 CWE categories. External: 15 cases from NodeGoat, Juice Shop, 3 named CVEs. Whole-project scan on OWASP NodeGoat.
- **Configurations** — 5 Ollama models × {LLM-only, LLM+RAG} = 10 configurations + 3 SAST baselines. 3 runs each → **303 invocations per configuration.**
- **Statistical discipline** — Held-out 71/30 test split · McNemar with Bonferroni · exact-binomial CIs.
**Speaking anchor:** "Now the numbers."

### Slide 14 — Headline Numbers (Hero Slide)
**Layout:** Four giant number cards in a 2×2 grid (mirror Huzefa slide 24 "What We Learned" big-number style).
- **F1 = 71.43 %** *qwen3:8b + RAG · precision 72.46 % · recall 70.42 %*
- **Repair = 89.5 % semantic / 90.32 % auto-applicable**
- **Latency = 2,216 ms median** *p95 4,327 ms · inside on-demand band*
- **leakFreeRate = 100 %** *prompt-injection harness · zero non-loopback transmission*

Bottom bar: "Each detailed in the next four slides."
**Speaking anchor:** "Each number gets its own slide."

---

## ACT V — RESULTS (slides 15–19, ~8 min)

### Slide 15 — R1 Detection Accuracy
**Layout:** Top: big card with the headline F1 (71.43 %) and the confidence-gated improvement (74.07 %, precision 78.13 %) and held-out test (61.11 %, FPR 0 %). Bottom: bar chart, *Code Guardian vs three SAST baselines* on F1.
- Code Guardian (qwen3:8b + RAG): 71.43 %
- Semgrep: ~14 %
- CodeQL: …
- ESLint: …
Badge "R1" in the corner.
**Speaking anchor:** "But does RAG actually help?"

### Slide 16 — R1 Continued: RAG is Not a Uniform Win
**Layout:** Horizontal bar chart of RAG ablation across 5 models, ΔF1 from no-RAG → RAG. Plus/minus colours.
- qwen3:8b      **+3.91**
- gemma3:1b    ≈0
- gemma3:4b    ≈0
- qwen3:4b      **−5.22**
- codellama   **−29.89** *(only one surviving Bonferroni)*

Big callout: **"Treat RAG as a per-model design choice, not a default."**
Badge "R1 / RQ2" in the corner.
**Speaking anchor:** "On repair quality."

### Slide 17 — R3 Repair Quality
**Layout:** Two columns.
- LEFT "**Manual review** (n = 25)" — semantic correctness **89.5 %**, combined correctness **68 %**.
- RIGHT "**Auto-applicable rate** (fully automated)" — on issued fixes **90.32 %** (n = 279), on all stage-2 calls **84.85 %** (n = 297).

Bottom: Stage 2 returns `{code, language}` + 18 explicit abstentions. Repair is opt-in via Quick Fix.
Badge "R3" in the corner.
**Speaking anchor:** "On usability and privacy."

### Slide 18 — R4 Usability: Latency Bands
**Layout:** Horizontal bar chart, models on Y axis, median latency on X axis. Vertical dashed lines at 500 ms (real-time), 1.5 s (interactive), 5 s (on-demand).
- qwen3:8b + RAG: 2,216 ms ← headline
- gemma3:1b + RAG: 1,019 ms ✅ interactive
- qwen3:4b: 1,328 ms ✅ interactive
- SAST baselines: <500 ms ✅ real-time

Callout: "Stage 2 repair adds ~1.5× stage-1 cost. **Recommended deployment band: on-demand.**"
Badge "R4" in the corner.
**Speaking anchor:** "And privacy."

### Slide 19 — R5 Privacy: Empirically Verified
**Layout:** Four cards.
- ✅ **Zero non-loopback transmission** across the full corpus run
- ✅ **leakFreeRate 100 %** on 12-case prompt-injection harness
- ✅ **Ed25519-signed RAG manifest** verified at load
- ✅ **Reproducible** — Node 20.19.0-alpine, npm ci, seed = 42

Footer: "Resource footprint — harness CPU 3 ms median, RSS 87 MB. Ollama dominates at 6–8 GB RAM for an 8B-q4 model."
Badge "R5" in the corner.
**Speaking anchor:** "What does this all mean?"

---

## ACT VI — TAKEAWAYS (slides 20–23, ~4 min)

### Slide 20 — What We Learned
**Layout:** Four insight cards in a 2×2 grid (mirror Huzefa slide 24).
- 🏆 **A local 8B model is enough** for ~71 % F1 on JS/TS — within the on-demand latency band on a developer laptop.
- 📚 **RAG is model-dependent**, not a universal win. The largest paired effect we measured is a RAG-induced *degradation* (codellama −29.89).
- 🛠️ **Repair is the real product gap.** Auto-applicable 90 % means the developer can act, not just be warned — that's where SAST falls flat.
- 🔒 **Privacy as a boundary, not a setting.** Loopback + signed corpus + container pin makes the privacy claim verifiable, not aspirational.
**Speaking anchor:** "Now the honest limitations."

### Slide 21 — Limitations
**Layout:** Four cards (icon + one line each).
- 👤 **Single-reviewer manual review** (n = 25) — inter-rater agreement is future work
- 🎯 **Curated corpus** — mitigated by held-out split + 15-case external set + NodeGoat whole-project run
- 🌐 **One real-world project** (NodeGoat) for end-to-end
- 🔁 **Consensus filter inert under deterministic decoding** — needs seed rotation
**Speaking anchor:** "Future work."

### Slide 22 — Future Work
**Layout:** Five compact rows.
- 🎲 Seed rotation → genuine consensus signal
- 👥 Inter-rater agreement on the manual-review subset
- 🏗️ Multi-project real-world validation (more than NodeGoat)
- ⚡ Streaming partial results → break the real-time band
- 🎯 Adaptive top-k retrieval + per-model RAG gating *(directly motivated by slide 16)*
**Speaking anchor:** "Contributions."

### Slide 23 — Contributions
**Layout:** Five cards in a column.
- 🛠️ **Working VS Code extension** — local LLM + RAG + signed corpus + container
- 🔗 **Two-stage pipeline** with structured JSON contracts (detection + repair)
- 📊 **Empirical study** — 5 models × 2 modes + 3 SAST baselines on a CWE-mapped JS/TS corpus
- 🔁 **Reproducibility infrastructure** — byte-identical runs, signed manifest, pinned container
- 📐 **Statistical discipline** — Bonferroni-corrected, exact-binomial CIs, held-out split
**Speaking anchor:** "Thank you — questions?"

---

## Slide 24 — Thank You / Q&A
**Layout:** Same as Huzefa slide 27. Big "Questions & Discussion". Headline numbers strip at the bottom: `F1 71.43 % · repair 90.32 % · latency 2.2 s · leakFreeRate 100 %`.

---

## APPENDIX (held for Q&A, not advanced sequentially)

These replace your current text-essay backup slides. **Each appendix slide must be a single visual artefact you can land on in <5 seconds** — table, chart, or matrix. No paragraphs.

### A1 — Full Per-Model Results Table
A table: rows = 5 models × 2 modes (10 rows) + 3 SAST baselines. Columns = Precision / Recall / F1 / FPR / Latency p50 / Latency p95 / VRAM. Highlight the headline row. (Mirror Huzefa appendix tables on slides 28–30.)

### A2 — Detection Confusion Matrices
2×2 grid of small confusion matrices for the headline configuration, on (a) full corpus, (b) held-out test split. Numbers in cells.

### A3 — Why the Single-Reviewer Manual Review Is Bounded
Single visual: a four-quadrant rubric (semantic correctness · strategy alignment · executability · conciseness), each quadrant showing the rate on the n = 25 sample. Footer: "Inter-rater on 10-sample subset = future work. Headline R3 metric is auto-applicable (90.32 %, n = 279) — fully objective."

### A4 — Why a Curated Corpus
Single visual: a bar showing why other corpora don't fit — Juliet (C/C++/Java only), OWASP Benchmark (Java only), SecurityEval (small, inconsistent CWE labels). Right side: the four selection-bias mitigations as a vertical list. Bottom: "Provenance bound into Ed25519 manifest."

### A5 — Why No Cloud-LLM Baseline
Single visual: threat-model diagram showing the privacy boundary, with a red ✗ where a cloud baseline would sit. One-line caption: "Cloud-LLM is the problem statement — including it as a baseline contradicts the threat model. Floor provided by 3 SAST baselines."

### A6 — Why R2 Reports 100 % Inter-Run Agreement
Single visual: three identical JSON blobs side by side with the decoding settings underneath (`temperature=0, seed=42, format=JSON`). One-line caption: "Byte-identical under locked decoding — consensus signal requires seed rotation (future work)."

---

## What you must produce (in order of impact)

1. **Slide 10 screenshot** — the single most important addition. The deck currently never shows the product.
2. **Slide 11 architecture diagram** — replaces your current text-only slide 4.
3. **Slide 14 hero number cards** — surfaces the four headline numbers from a sub-bullet on slide 10.
4. **Slides 15, 16, 18 bar charts** — replaces text bullets with the kind of chart Huzefa uses on slides 21–23.
5. **Slide 2 illustration** — a single image that sets the stakes in 10 seconds.
6. **Appendix conversion** — rewrite your 4 text-essay backups as 6 single-visual reference slides.

## Pacing check

- Act I (problem): 5 slides × ~60 s = 5 min
- Act II (gap): 2 slides × ~75 s = 2.5 min
- Act III (system): 5 slides × ~75 s = 6 min
- Act IV (setup): 2 slides × ~75 s = 2.5 min
- Act V (results): 5 slides × ~95 s = 8 min
- Act VI (takeaway): 4 slides × ~60 s = 4 min
- Total: **28 min** → leaves 2 min for Q&A buffer. ✅
