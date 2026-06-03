# Speaker Notes — Code Guardian Defense

**Total budget:** 28 minutes talk + 2 minutes Q&A
**Per-slide budget:** ~70 s on main slides, longer on results (~95 s) to let numbers land.
**Voice:** flowing prose, no first person, plain English, short sentences. Avoid filler ("um," "so," "basically").
**Posture:** never read the slide aloud. The slide is the *artefact*, your voice is the *narrative*.

Each entry shows:
- **[Time]** approximate budget for that slide
- **VOICE** — the rough spoken text
- **TRANSITION** — the one sentence that lands on the next slide

The transitions matter. They are what makes the talk feel like one argument rather than 24 separate ones.

---

## Slide 1 — Title  ·  [60 s]

**VOICE**
"Good afternoon. The thesis is *Privacy-Preserving Source Code Vulnerability Detection and Repair using Retrieval-Augmented Local LLMs for Visual Studio Code*. The system is called Code Guardian. I'll first explain why a tool like this is needed, then show what it does, then go through what the numbers say. Total talk: about 28 minutes."

*(Pause. Look at the panel. Move to next slide.)*

**TRANSITION** — "I'll start with the problem the tool addresses."

---

## Slide 2 — The Developer's Dilemma  ·  [40 s]

**VOICE**
"A working developer today, writing JavaScript or TypeScript for a regulated industry, faces three problems at once. They can't paste sensitive code into a cloud LLM — that's a compliance breach. Their existing static-analysis tool keeps missing things. And when it does flag something, it gives a warning but no fix. This is the gap the thesis addresses."

*(Let the image breathe. Don't list the bubbles aloud — they're on screen.)*

**TRANSITION** — "Let me make the cost concrete."

---

## Slide 3 — Today You Pick: Send Code Away — or Get No Help  ·  [80 s]

**VOICE**
"There are two existing options. On the left, cloud LLM assistants — Copilot, ChatGPT, Cursor. They give strong reasoning, but every request crosses the network. That's blocked outright in finance, healthcare, defence, and any air-gapped environment.

On the right, local static-analysis tools — Semgrep, CodeQL, ESLint. These stay on the developer's machine, which is the right privacy posture. But their coverage is poor. On the JavaScript and TypeScript corpus used in this thesis, **Semgrep's canonical recall is 12.68 percent**. They also cannot generate fixes — only warnings.

So today the developer chooses: send code away, or get almost no help. Neither is acceptable."

**TRANSITION** — "Code Guardian is built to fill the gap between these two columns."

---

## Slide 4 — No Tool Combines All Three  ·  [60 s]

**VOICE**
"The thesis claims three properties must hold together. **Local inference** — code never leaves the machine, and that boundary is verifiable. **Retrieval-augmented reasoning** — the LLM is grounded in CWE and OWASP knowledge, not just pattern matching. **Developer-controlled repair** — a structured fix is returned, and the developer applies it via a Quick Fix. No silent rewrites.

No existing tool combines all three. This thesis builds and evaluates one."

**TRANSITION** — "Before showing the system, here are the research questions and the five requirements I commit to."

---

## Slide 5 — Research Questions and Requirements  ·  [90 s]

**VOICE**
"Three research questions. **RQ1** — can a local LLM on consumer hardware reach acceptable detection quality under a strict privacy envelope. **RQ2** — does grounding the LLM in retrieved CWE and OWASP knowledge improve detection. **RQ3** — is in-IDE latency acceptable for developer workflows.

To answer them I commit to five requirements before evaluating anything. **R1** accuracy — precision, recall, F1. **R2** consistency — JSON parse rate, inter-run agreement. **R3** repair quality — both manual and automated. **R4** usability — latency, IDE integration. **R5** privacy — zero exfiltration, signed corpus.

Each requirement has a four-level threshold scale fixed in Chapter 2. That's the commitment device — I can't move the goalposts after seeing the numbers."

**TRANSITION** — "Where do existing systems sit against R1 to R5?"

---

## Slide 6 — Three Existing Approaches  ·  [60 s]

**VOICE**
"The related work groups into three columns. **Cloud LLM assistants** — Copilot, ChatGPT, Cursor, Claude Code — strong on R1, R3, R4, but they fail R5 by construction. **Local SAST** — Semgrep, CodeQL, ESLint — strong on R2, R5, but weak on R1 and R3. **Academic LLM-for-security work** — IRIS, SecRepair, LLMSecGuard, RESCUE — varies, but none of them deliver everything together."

**TRANSITION** — "When I map them against R1 to R5 in a matrix, the gap is unambiguous."

---

## Slide 7 — No Tool Satisfies R1 + R3 + R5 Together  ·  [75 s]

**VOICE**
"Reading across each row — Copilot satisfies R1, R3, R4, but fails R5. Semgrep and CodeQL satisfy R5 but fail R1 and R3. IRIS, even using GPT-4, fails on R3, R4, and R5 because it's a whole-repo batch tool. SecRepair is fine-tuning-based, batch, primarily C and C++.

The bottom row is Code Guardian — and that's the claim this talk defends. No existing tool delivers privacy, repair quality, and IDE-grade latency together."

**TRANSITION** — "Now the system itself."

---

## Slide 8 — One Pipeline, Four Developer Workflows  ·  [60 s]

**VOICE**
"The extension supports four developer workflows. Real-time inline diagnostics — squiggles as you save. On-demand file scan — right-click. Interactive Q&A — a side panel for asking about a finding. And workspace audit — batch scanning the whole project.

All four hit the same two-stage pipeline. Detection, then optional repair. Everything in the dashed area runs on the developer's machine."

**TRANSITION** — "The two stages in detail."

---

## Slide 9 — Two-Stage Local Pipeline  ·  [85 s]

**VOICE**
"**Stage one is detection.** A JSON-mode LLM call with a pinned schema. Optional RAG context — the top-k retrieved CWE or OWASP snippets. Three deterministic runs, seed 42, temperature zero. An inter-run confidence gate — two of three runs must agree before a finding is surfaced. The output is structured: category, severity, line range, evidence.

**Stage two is repair.** A separate call, invoked only when something was detected. Returns a structured object with code and language. The output is parsed with @babel/parser — prose answers are rejected. The repair is surfaced as a VS Code Quick Fix. The developer applies the patch — there are no silent rewrites.

Privacy is by construction. Ollama is bound to loopback. Embeddings are local. There's no telemetry."

**TRANSITION** — "What does this actually look like running?"

---

## Slide 10 — Live in VS Code  ·  [75 s]

**VOICE** *(pointing at the screenshot)*
"This is the extension on a vulnerable Express route. Red squiggle on the line with the SQL injection. The side panel shows the finding — category, severity, CWE, the evidence. The Quick Fix menu lists the structured repair. The developer accepts it, the patch lands as a diff, the developer reviews and saves.

The QR code links to the demo video and the published Marketplace listing. The extension is open source."

**TRANSITION** — "Behind that UI sits the architecture."

---

## Slide 11 — System Architecture  ·  [75 s]

**VOICE** *(walk the diagram)*
"Inside the dashed rectangle is everything on the developer's laptop. The VS Code extension host orchestrates the four workflows. It talks to Ollama on loopback only — that's the privacy boundary. Ollama loads an 8B-class quantised model — qwen3:8b by default. The RAG store is HNSWlib, local. The vulnerability data manager refreshes public NVD, OWASP, and CWE metadata on a 24-hour cache — that's the only outbound call, and it never includes user code.

Privacy isn't a feature here. It's a topological boundary."

**TRANSITION** — "Four ways the privacy claim is enforced."

---

## Slide 12 — Privacy by Construction  ·  [75 s]

**VOICE**
"Four arms, each independently verifiable. Loopback-only Ollama — bound to 127.0.0.1 — that's the network isolation arm. Ed25519-signed RAG corpus — the provenance arm, verified at load. Pinned container — Node 20.19.0-alpine, npm ci, seed 42 — the reproducibility arm. And a prompt-injection harness — 12 cases attempting to exfiltrate via the model — that produced a **leakFreeRate of 100 percent**.

Each arm fails differently. A single failure doesn't silently break the contract."

**TRANSITION** — "Now the evaluation."

---

## Slide 13 — Evaluation Setup  ·  [85 s]

**VOICE**
"Three things to commit to before showing numbers. The **corpus** — a curated JavaScript and TypeScript set, 101 cases, 71 vulnerable and 30 secure, across 14 CWE categories. An external 15-case set drawn from OWASP NodeGoat, Juice Shop, and three named CVEs. And a whole-project NodeGoat scan for end-to-end validation.

The **configurations** — 5 Ollama models, two modes each — LLM-only and LLM-plus-RAG — gives 10 configurations. Three SAST baselines: Semgrep, CodeQL, and ESLint. Three runs per sample under deterministic decoding — that's 303 invocations per configuration.

The **statistical discipline** — a held-out 71/30 test split keeps threshold tuning off the headline. McNemar with Bonferroni correction across paired model comparisons. Exact-binomial confidence intervals for small-n rates."

**TRANSITION** — "Four headline numbers, one per requirement."

---

## Slide 14 — Headline Numbers  ·  [70 s]

**VOICE** *(briefly land each number, save detail for the next four slides)*
"Detection — **F1 71.43 percent**, qwen3:8b plus RAG. With the confidence gate, **74.07 percent F1**, **78.13 percent precision**. Repair — **90.32 percent auto-applicable**. Latency — **2.2 seconds median**, comfortably inside the on-demand band. Privacy — **leakFreeRate 100 percent** on the harness, zero non-loopback transmission across the corpus run. And the strip at the bottom is R2 — consistency — **JSON parse 100 percent across three thousand inferences**, zero schema rejections.

Each of the four headline numbers gets its own slide; R2 is detailed in the appendix."

**TRANSITION** — "R1, detection accuracy."

---

## Slide 15 — R1 Detection Accuracy  ·  [95 s]

**VOICE**
"Headline configuration: qwen3:8b plus RAG, canonical taxonomy, full 101 cases. F1 71.43 percent, precision 72.46 percent, recall 70.42, false-positive rate 10 percent.

With the inter-run confidence gate at 0.67 — that's two of three runs in agreement — F1 rises to 74.07 percent and precision to 78.13 percent. The trade-off is exposed, not hidden — both numbers are in the thesis.

On the held-out 71/30 test split the configuration shows F1 61.11 percent at false-positive rate zero. Lower recall, higher precision — that's what a held-out split is for.

Compared to the SAST baselines on the bar chart — Code Guardian's F1 71.43 percent beats every one of them on recall-driven F1. Semgrep's canonical recall is 12.68 percent."

**TRANSITION** — "But the second research question — does RAG actually help — is more interesting than I expected."

---

## Slide 16 — RAG Is Not a Uniform Win  ·  [90 s]

**VOICE**
"This is the most honest slide in the deck. Five models, two modes each, paired comparison: delta F1 from no-RAG to RAG.

qwen3:8b — **plus 3.91 F1** with RAG, the largest positive effect. The gemma3 family — essentially zero, around the noise floor. qwen3:4b — **minus 5.22** with RAG. codellama — **minus 29.89 F1 with RAG**. That's the largest paired effect in the dataset, and it goes the wrong way.

**Only codellama's drop survives Bonferroni correction at alpha 0.01** — McNemar p equals 0.0013. The other effects don't.

The disciplined finding is: RAG is a per-model design choice. Treating it as a default is wrong. That's exactly what the field has reported — RESCUE in 2025 documents the same pattern."

**TRANSITION** — "R3, repair quality."

---

## Slide 17 — R3 Repair Quality  ·  [95 s]

**VOICE**
"Two complementary metrics. On the left, the **manual review** at n equals 25. A fix was provided in 76 percent of samples. Of the fixes issued, 89.5 percent are semantically correct — they address the CWE — and 94.7 percent are strategy-aligned. Only 42.1 percent are directly executable; the rest give correct prose guidance. Combined correctness — fix-rate times semantic correctness — is 68 percent. The executability bar is low because a knowledgeable reviewer can recognise an intended fix even when the patch isn't perfectly runnable.

On the right, the **fully automated auto-applicable rate**. The validator parses the fix with @babel/parser. On the 279 issued fixes — **90.32 percent are auto-applicable**. Across all 297 stage-two calls including no-fix abstentions — 84.85 percent.

The two-tier metric is deliberate. Manual is the decision-support reading. Auto-applicable is the deployment reading. The thesis reports both."

**TRANSITION** — "R4, usability — what latency band does this actually live in."

---

## Slide 18 — R4 Usability: Latency Bands  ·  [80 s]

**VOICE**
"Three bands committed to before evaluation. **Real-time, under 500 milliseconds** — SAST baselines only. **Interactive, under 1.5 seconds** — gemma3:1b plus RAG at 1,019 milliseconds qualifies, and qwen3:4b at 1,328 milliseconds qualifies. **On-demand, under 5 seconds** — the headline qwen3:8b plus RAG at 2,216 milliseconds, p95 at 4,327 milliseconds, comfortably inside.

A real product would pick the band per workflow. Inline-diagnostic mode goes to a 4B model. On-demand and audit modes use the 8B."

**TRANSITION** — "R5, privacy."

---

## Slide 19 — R5 Privacy: Empirically Verified  ·  [70 s]

**VOICE**
"Four arms, each empirically verified rather than asserted. Zero non-loopback traffic across the full corpus run, observed via host firewall logs. leakFreeRate 100 percent on the 12-case prompt-injection harness. The RAG corpus manifest signature verified at load. And the whole pipeline reproducible from a pinned container — Node 20.19.0-alpine, npm ci, seed 42.

The resource footprint is acceptable: the harness itself uses 87 megabytes of RAM. Ollama dominates at 6 to 8 gigabytes for an 8B-q4 model."

**TRANSITION** — "What does all of this actually mean."

---

## Slide 20 — What We Learned  ·  [90 s]

**VOICE**
"Four takeaways.

**A local 8B model is enough.** qwen3:8b plus RAG reaches roughly 71 percent F1 on JavaScript and TypeScript, well inside the on-demand latency band on a developer laptop. You don't pay for privacy in quality.

**RAG is model-dependent**, not a universal win. The largest paired effect in the dataset is a RAG-induced *degradation* — codellama loses 29.89 F1 points. That finding alone justifies the per-model calibration stance.

**Repair is the real product gap.** 90 percent auto-applicable means the developer can act, not just be warned. This is exactly where SAST falls flat — they detect, they don't fix.

**Privacy as a verifiable boundary.** Loopback plus signed corpus plus container pin makes privacy testable, not aspirational. leakFreeRate 100 is a measurement, not a slogan.

And to close the loop on the three research questions from the start — the strip at the bottom answers them directly. **RQ1**, yes: 71.43 percent F1 under the privacy envelope. **RQ2**, yes but per-model — RAG is not a default. **RQ3**, yes: 2.2 seconds median, inside the on-demand band."

**TRANSITION** — "The honest limitations."

---

## Slide 21 — Limitations  ·  [80 s]

**VOICE**
"Five limitations, transparent.

Single-reviewer manual review at n equals 25 — inter-rater agreement on a 10-sample subset is the obvious next step.

Curated 101-case corpus — selection bias mitigated four ways: held-out split, external 15-case set, NodeGoat whole-project run, and the signed-manifest provenance.

One real-world project end-to-end — NodeGoat. Multi-project validation is future work.

Consensus filter inert under deterministic decoding — three runs at seed 42 are byte-identical. Real consensus signal requires seed rotation.

No cloud-LLM baseline — excluded by the privacy threat model. The floor is provided by three SAST baselines."

**TRANSITION** — "And the directions those limitations point to."

---

## Slide 22 — Future Work  ·  [60 s]

**VOICE**
"Five directions. Seed rotation for genuine consensus signal. Inter-rater agreement on the manual-review subset. Multi-project real-world validation. Streaming partial results to break the real-time band. And adaptive per-model RAG gating — directly motivated by slide 16."

**TRANSITION** — "The contributions."

---

## Slide 23 — Contributions of This Thesis  ·  [70 s]

**VOICE**
"Five contributions.

A **working VS Code extension** — local LLM, RAG, signed corpus, pinned container, published.

A **two-stage pipeline** with structured JSON contracts at every boundary — detection and repair.

An **empirical study** — 5 models, 2 modes, plus 3 SAST baselines, 303 invocations per configuration, on a CWE-mapped JavaScript and TypeScript corpus.

**Reproducibility infrastructure** — byte-identical runs, signed manifest, pinned Node container.

And **statistical discipline** — Bonferroni-corrected McNemar, exact-binomial confidence intervals, held-out test split."

**TRANSITION** — "Those are the contributions; the key references are on the next slide."

---

## Slide 24 — References  ·  [10 s]

**VOICE**
"These are the primary sources — the foundation models and RAG, the academic LLM-for-security comparators, and the standards the corpus is mapped against. I'll leave this up briefly."

*(Do not read the list. Advance once the panel has had a moment.)*

**TRANSITION** — "Thank you. I'd be glad to take questions."

---

## Slide 25 — Thank You  ·  [Q&A — 2 min]

**VOICE**
"Thank you. The headline strip at the bottom is the four numbers — F1 71.43, repair 90.32, latency 2.2 seconds, leakFreeRate 100. I'd be glad to take questions."

*(Stop talking. Look at the panel. Wait.)*

**During Q&A:**
- Restate the question briefly in your reframe (5 seconds — confirms you understood)
- If the question routes to an appendix slide, navigate to it before answering
- Don't apologise. Don't say "good question." Just answer.
- One question, one anchor number, max ~30 s per answer

---

## Pacing checkpoints

If you're behind schedule at these slides, you need to trim:

| Checkpoint     | Slide | Time elapsed should be |
|----------------|-------|------------------------|
| End of Act I   | 5     | ~5 min                 |
| End of Act III | 12    | ~13 min                |
| End of Act IV  | 14    | ~16 min                |
| End of Act V   | 19    | ~23 min                |
| End of Act VI  | 23    | ~28 min                |

If you're at slide 19 and the clock says 25 minutes, **drop slide 22 and condense slide 23 to 30 seconds**. Never run over.

## Voice / tone notes

- **Pause** after every number. The audience needs a beat to absorb a percentage.
- **Don't read the slide aloud.** The slide carries the artefact; you carry the argument.
- **Plain English.** "Stage one is detection," not "the first stage performs the detection task."
- **No first person plural.** Say "the thesis" or "Code Guardian," not "we built."
- **Don't apologise.** Don't say "this might not be perfect, but…" Anchor a limitation in a future-work item instead.
- **Land each requirement.** When you say "R1" on a results slide, point at the badge in the corner.

## Pre-defense checklist

- [ ] Rehearse slides 14–19 (the results block) standalone — these are where Q&A traction lives
- [ ] Walk through QA_PREP.md anchors verbally — the anchor stats must be muscle memory
- [ ] Verify the architecture diagram, screenshot, and three bar charts are dropped into the placeholders
- [ ] Print QA_PREP.md "quick reference card" and tape it inside your binder
- [ ] Hard-reload the deck on the projector laptop the morning of — fonts can be substituted
- [ ] Have a backup PDF export — projector apps fail
- [ ] Bring water. Sip between slides, not during them.
