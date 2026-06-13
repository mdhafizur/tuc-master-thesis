# Speaker Notes — Code Guardian Defense

**Total budget:** 30 minutes talk + 20 minutes Q&A
**Pace:** this script is written for **slow delivery — about 115 words per minute**, with deliberate pauses after every headline number. The whole spoken script is ~3,000 words ≈ **28 minutes including transitions and pauses**, leaving a 1–2 minute buffer inside the 30-minute slot. Do not speed up to "fit more in" — the fitting has already been done on paper.
**Per-slide budget:** printed in each slide header as **seconds and words**. The seconds include the transition sentence. If a slide runs long in rehearsal, cut connective words — never numbers.
**Pause cues:** *(pause)* = one slow breath, about two seconds. *(slow)* = drop to dictation speed for that one sentence. The pauses are content, not dead air — at a slow pace, silence after a number reads as confidence.
**Voice:** warm but measured spoken prose — plain English, short complete sentences (see STORYTELLING_STYLE.md §2: not fragments, not run-ons). First-person singular is fine ("I checked," "I ran"); avoid first-person plural ("we built"). Avoid filler ("um," "so," "basically").
**Posture:** never read the slide aloud. The slide is the *artefact*; your voice is the *story*.

Each entry shows:
- **[Time · words]** — the budget for that slide, transition included
- **VOICE** — the spoken text, with *(pause)* / *(slow)* cues in place
- **TRANSITION** — the one sentence that lands on the next slide

The transitions matter. They are what make the talk feel like one argument instead of 25 separate ones.

**Pre-empts are already folded in.** Earlier versions kept PRE-EMPT lines as separate asides to weave in live. They are now written **inside the VOICE text** at the right spot, so the script is linear — just speak it. A tag under each block says which QA_PREP entry the folded sentence defuses. Don't say it twice. A choice you volunteer reads as confidence; the same choice defended under questioning reads as damage control.

**Reserves are not spoken.** LIT-ANCHOR / RESERVE / SOURCE-NOTE lines are ammunition for Q&A only — drop them if (and only if) the matching challenge comes.

**Tell it as one connected argument** (full rulebook: STORYTELLING_STYLE.md):
- **The problem** — a false trade: *send your code off your machine, or work almost unprotected.* Plant it on slides 2–3.
- **The solution** — slide 4: local, grounded, in the developer's hands.
- **The surprise** — slide 16: retrieval was expected to help everywhere, and it did not. Slow down there more than anywhere else.
- **The return** — slide 21 and the close: name the false trade again, then say Code Guardian refuses it.

This is a defense, not a keynote — never let presentation outrun the evidence.

---

## Slide 1 — Title  ·  [55 s · ~95 words]

**VOICE**
"Good afternoon. Imagine you have just written code for a bank — or a hospital. You need the answer to one question: is it secure? *(pause)*

Today, getting that answer means making a trade-off. By the end of this talk, I want to convince you it is a trade-off no developer should have to make.

The thesis is titled *Privacy-Preserving Source Code Vulnerability Detection and Repair using Retrieval-Augmented Local LLMs for Visual Studio Code*. The system is called Code Guardian. Three parts: why the tool is needed, what it does, and what the evaluation shows."

*(Pause. Look at the panel. Move on.)*

**TRANSITION** — "I'll start with the problem the tool solves."

---

## Slide 2 — The Developer's Dilemma  ·  [45 s · ~80 words]

**VOICE**
"Three problems arrive at once. First: sensitive code cannot be pasted into a cloud model without breaking compliance. Second: the local scanner keeps missing real bugs — so the vulnerability reaches production. Third: when a scanner does flag something, it only warns. The repair is still entirely your job. *(pause)*

No tool today solves all three. So the real question is the green one in the corner — what is the alternative? That is what this talk answers."

*(Four bubbles on screen: three problems plus the green question. Gesture; don't enumerate.)*

**TRANSITION** — "Let me make the cost concrete."

---

## Slide 3 — Today You Pick: Send Code Away — or Get No Help  ·  [65 s · ~120 words]

**VOICE**
"Today there are two options. On one side, the cloud assistants — Copilot, ChatGPT, Cursor. The reasoning is excellent. But every request leaves your machine — and in finance, healthcare, defence, or any air-gapped setting, that door is simply closed. *(pause)*

On the other side, the local scanners — Semgrep, CodeQL, ESLint. They stay on your machine, so privacy is complete. But they miss most of the bugs. On the JavaScript and TypeScript in this thesis, Semgrep's canonical recall is 12.68 percent. *(pause)* And they only warn. They never fix.

So here is the trade: send your code away, or work almost unprotected. *(slow — this is the through-line; plant it)* That is the whole menu. Neither side is good enough."

**TRANSITION** — "So this thesis asks one question: why should that be the trade at all?"

---

## Slide 4 — No Tool Combines All Three  ·  [65 s · ~110 words]

**VOICE**
"Removing that trade needs three things true at once. The tool must be **local** — code never leaves the machine, and you can prove it. It must be **grounded** — reasoning with real CWE and OWASP knowledge, not fixed patterns. And it must stay **in your hands** — it offers a fix, and you choose to apply it. Nothing is rewritten behind your back. *(pause)*

No existing tool delivers all three together. That is the gap this thesis closes.

And the scope is JavaScript and TypeScript on purpose: the most-used stack on GitHub, and the place where local static analysis is weakest — so it is where a privacy-preserving tool helps most."

**PRE-EMPT — folded in** — the last sentence defuses "why JS/TS?" (QA_PREP A.4).

**LIT-ANCHOR** *(reserve — only if the IDE-integration gap is doubted in Q&A)* — "A 2025 survey of 58 LLM vulnerability studies found not one was wired into a developer's workflow — every one was evaluated offline. That's the gap this slide names." (Zhou et al., TOSEM 2025)  → *backs "in your hands"; QA_PREP J.1*

**TRANSITION** — "Before the system, here are the research questions and the five requirements I commit to."

---

## Slide 5 — Research Questions and Requirements  ·  [75 s · ~130 words]

**VOICE**
"Three research questions frame the work. RQ1 — can a local model, on a normal laptop, detect vulnerabilities well enough under a strict privacy envelope? RQ2 — does grounding it in retrieved CWE and OWASP knowledge actually help? RQ3 — is it fast enough inside the editor for real work? *(pause)*

Before measuring anything, I fixed five requirements. R1 — accuracy: precision, recall, F1. R2 — consistency: valid, stable output. R3 — repair quality. R4 — usability: latency and IDE fit. R5 — privacy: nothing leaves the machine. *(pause)*

Each requirement carries a fixed grading scale, written into the requirements chapter before any model ran. *(slow — look at the panel)* The bar was set before I saw a single result. It is the same bar before and after evaluation."

**PRE-EMPT — folded in** — the last two sentences ARE the pre-empt; they disarm "how did you choose the thresholds?" (QA_PREP G.3). The level counts (R1/R2 four levels, R3/R4 three) are on the slide and appendix A8 — point if asked, don't recite.

**TRANSITION** — "Where do existing systems sit against R1 to R5?"

---

## Slide 6 — Three Existing Approaches  ·  [50 s · ~90 words]

**VOICE**
"The related work falls into three camps. The **cloud assistants** — Copilot, ChatGPT, Cursor, Claude Code — strong on accuracy, repair, and usability, but they fail privacy by design. Every request leaves the machine. **Local static analysis** — Semgrep, CodeQL, ESLint — strong on consistency and privacy, weak on accuracy and repair. It matches patterns instead of reasoning, and it only warns. And the **academic systems** — IRIS, SecRepair, LLMSecGuard, RESCUE — each drops at least one of privacy, repair, or IDE speed. *(pause)* None brings them all together."

**TRANSITION** — "Put them in a matrix against R1 to R5, and the gap is clear."

---

## Slide 7 — No Tool Satisfies R3 + R4 + R5 Together  ·  [55 s · ~95 words]

**VOICE**
"Read across the rows. Copilot meets accuracy, consistency, and repair — partial on usability — and fails privacy. Semgrep and CodeQL meet privacy but fail accuracy and repair. IRIS, even with GPT-4 behind it, fails repair, usability, and privacy — it is a whole-repo batch tool. SecRepair fine-tunes a model, runs in batch, and targets mostly C and C++. *(pause)*

The bottom row is Code Guardian, and it is the claim this talk defends: no existing tool delivers privacy, repair, and IDE-grade speed at the same time."

**LIT-ANCHOR** *(reserve — only if the bottom row is challenged in Q&A)* — "LLMSecGuard's own authors call IDE integration 'essential' — then leave it as future work. Code Guardian ships it." (Kavian et al., EASE 2024)  → *QA_PREP H.1*

**SOURCE NOTE** *(point to the footnote only if asked — don't read it)* — the small line under the matrix says the High / Partial / Not-satisfied levels apply the fixed R1–R5 scales, with accuracy/repair thresholds from IR/SE work, latency from HCI response-time limits, and privacy as a checklist. Full table: **appendix A8** — put it up if the panel pushes on thresholds.  → *QA_PREP G.3*

**TRANSITION** — "Now the system itself."

---

## Slide 8 — Proposed Workflow  ·  [45 s · ~80 words]

**VOICE**
"The extension offers four ways to work: inline diagnostics as you save, a file scan on right-click, a side panel for asking about a finding, and a workspace audit for the whole project. Why four? Because the question 'is this secure?' arises at different moments — and each workflow meets it where it happens. *(pause)*

One pipeline sits behind all four: detect, then repair. And everything inside the dashed line runs on your machine."

**TRANSITION** — "Here are the two stages in detail."

---

## Slide 9 — Two-Stage Local Pipeline  ·  [95 s · ~175 words]

**VOICE**
"Two stages. The first finds the problem. The second repairs it. *(pause)*

Stage one — detection. The code goes to the local model as one JSON-mode call, and the model fills a fixed schema — so what comes back is structured data, not an essay. When RAG is on, the most relevant CWE and OWASP snippets go into the prompt first. And to filter one-off noise, detection runs twice, each pass from a different random seed. A finding survives only when both passes agree. *(pause)*

One honest note. *(slow)* That consensus is real in the shipped extension. In the evaluation, the seed is pinned for reproducibility — repeated runs come out identical — so consistency is reported as a property of deterministic decoding, not a robustness claim. Seed rotation is future work.

Stage two — repair. It runs only when stage one found something. A separate call returns just the fixed code, and that output goes through the Babel parser — prose gets thrown away before you ever see it. What survives appears as a one-click Quick Fix, and you decide whether to apply it. *(pause)*

Notice what never happened: nothing left the machine. Ollama on loopback, local embeddings, no telemetry."

**PRE-EMPT — folded in** — the "one honest note" paragraph defuses "your consensus is just identical runs" (QA_PREP G.2).

**TRANSITION** — "What does this look like when it runs?"

---

## Slide 10 — Live in VS Code  ·  [50 s · ~90 words]

**VOICE** *(pointing at the screenshot)*
"This is the extension on a file full of vulnerable endpoints — SQL injection, reflected XSS, code injection, command injection, path traversal. On the right, the Code Guardian panel is examining the reflected-XSS endpoint. It explains why the input is unsafe, and it proposes a fix. *(pause)*

Notice the panel marks this one 'not auto-applicable.' That is deliberate honesty: it shows the fix but asks you to review it first. No silent rewrites. Nothing leaves the laptop.

The QR code installs the extension from the VS Code Marketplace."

**TRANSITION** — "Behind that UI sits the architecture."

---

## Slide 11 — System Architecture  ·  [100 s · ~185 words]

**VOICE** *(walk the diagram)*
"Everything inside the dashed rectangle runs on your laptop. The extension host drives the four workflows, and it talks to Ollama on loopback only. *(slow)* That line is the privacy boundary.

Ollama runs an 8B-class quantised model — qwen3:8b is the one I evaluate and recommend, though any Ollama model works. And eight billion is a deliberate ceiling, not a compromise: it is the largest that fits a 16-gigabyte laptop alongside VS Code. A 70B model needs over 40 gigabytes — a workstation, not a laptop. *(pause)*

Now follow a request through. It hits the local cache first — on a hit, no model call at all. On a miss, the two-stage analyzer runs, and the result is stored. When RAG is on, the manager pulls the three closest snippets from a local, signed knowledge base — matched by meaning, not keyword — so the right CWE guidance surfaces even when the code never says the word 'injection.'

And the boundary itself: by default, nothing crosses it. The vulnerability data ships pre-bundled, so the tool runs fully offline. There is exactly one outbound call, opt-in and off by default — a refresh of public NVD, OWASP, and CWE metadata on a 24-hour cache. It carries look-ups, never your code. *(pause)*

Privacy here is not a feature you switch on. It is decided by where the boundary sits."

**PRE-EMPT — folded in** — the 16 GB / 70B sentence defuses "why not a bigger model?" (QA_PREP B.4).

**TRANSITION** — "Four ways the privacy claim is enforced."

---

## Slide 12 — Privacy by Construction  ·  [80 s · ~145 words]

**VOICE**
"Privacy here is not one feature. It is four arms — three shut down a specific attack, and the fourth lets you verify the other three. *(pause)*

The network arm: Ollama is bound to loopback — 127.0.0.1 and nothing else — so nothing it sends can leave your laptop.

The provenance arm stops a poisoned knowledge base. The RAG corpus is Ed25519-signed and checked on every load. If it has been tampered with, the extension refuses to load it.

The injection arm stops prompt injection — instructions hidden in the code that try to hijack the model. Twelve crafted attacks were run. All twelve came back clean. *(pause)*

And the reproducibility arm is about trust: the whole pipeline rebuilds from a pinned container at seed 42, so anyone can re-run it and get the same result — rather than taking my word for it.

Because each arm stands alone, no single failure quietly breaks the promise."

**LIT-ANCHOR** *(reserve — network arm, if "why local" is pushed)* — "An industry study on ChatGPT for secure coding lands on the same rule this arm enforces: run local LLMs, kept off the network, so proprietary code never leaves the building." (Espinha Gasiba et al., 2024)  → *QA_PREP F.5*

**LIT-ANCHOR** *(reserve — provenance arm, if corpus-signing is questioned)* — "A 2024 RAG-security survey shows poisoning just 0.04 percent of a corpus can hijack retrieval 98 percent of the time. The signature is the lock on that door." (Zhou et al., RAG-Trust survey 2024)  → *QA_PREP F.4*

**TRANSITION** — "Now the evaluation."

---

## Slide 13 — Evaluation Setup  ·  [105 s · ~195 words]

**VOICE**
"Three things were locked down before any number went on screen. *(pause)*

First, the **corpus**. 101 JavaScript and TypeScript cases — 71 vulnerable, 30 secure, across 20 CWE categories — every label verified by hand. Some are real bugs from npm packages and named CVEs; the rest are written to standard weakness patterns from suites like Juliet, which only ship in C and Java. Why verify by hand? Because CWEval found that fewer than a third of one popular benchmark's flagged samples could even be reproduced. A scanner's labels are not ground truth. And 101 curated cases is a deliberate choice, not a shortcut — the peer benchmark CWEval uses 119, and no existing JavaScript corpus fits. Alongside it sit an external 15-case set and a whole-project NodeGoat scan, run end to end. *(pause)*

Second, the **configurations**. Five local models, each with and without RAG — ten configurations — plus three SAST baselines: Semgrep, CodeQL, ESLint. Each sample runs three times, deterministically — 303 invocations per configuration. There is no cloud-LLM baseline by design: a cloud model would break the very threat model the thesis is built on, so the SAST tools set the local floor.

Third, the **statistics**. The cases are split — tune on one half, freeze the other. McNemar with Bonferroni. Exact-binomial intervals. *(slow)* Rules first, measurements second."

**PRE-EMPT — folded in** — "101 is deliberate / CWEval 119 / no JS corpus" defuses QA_PREP A.1 and A.3; "no cloud baseline by design" defuses QA_PREP B.2.

**TRANSITION** — "Four headline numbers, one per requirement."

---

## Slide 14 — Results  ·  [65 s · ~120 words]

**VOICE** *(land each number, then breathe; detail comes in the next four slides)*
"Four numbers. One per requirement. *(pause)*

Detection: an F1 of **71.43 percent**, from qwen3:8b with RAG. *(pause)* And it travels — 61.11 on code held back during tuning, 63.64 on outside projects.

Repair: **90.32 percent** auto-applicable — the fix parses and applies cleanly — with semantic correctness around 68 percent. *(pause)*

Latency: a median of **2.2 seconds** — well inside the on-demand band. *(pause)*

Privacy: **leak-free** across all 12 injection attempts. *(pause)*

And along the bottom, R2 — consistency. 100 percent valid JSON across all 3,030 invocations. But the runs share a seed, so that reflects determinism, not robustness. I say so plainly. Each of the four gets its own slide next."

**COLOUR NOTE** *(not spoken — only if you want to gesture at the card colours)* — each card is tinted by its requirement band from the A8 scale: repair, latency, and privacy are **green (High / met)**; detection is **amber (Medium)**. The single amber card quietly pre-figures the slide-21 admission. The confidence-gate number (74.07) is not on this card; it lives on appendix A9.

**TRANSITION** — "Start with R1, detection accuracy."

---

## Slide 15 — R1 Detection Accuracy  ·  [100 s · ~190 words]

**VOICE**
"This is the main result. qwen3:8b with retrieval, across all 101 cases. *(pause)*

The headline: an F1 of 71.43. In plain terms, two things at once. When it flags code, it is right about seven times in ten. And of all the real vulnerabilities, it catches about seven in ten. *(pause)* The false-positive rate is ten percent — one safe snippet in ten gets a warning it does not need.

Does that hold on unseen code? I checked two ways. On the held-back cases, it drops to 61. On the external set — projects I had no hand in — about 64. So on unfamiliar code it sits in the low sixties: recall gives ground, precision holds. That dip is not a weakness. It is why you hold cases back — and the gap between curated and real-world code is a well-known pattern.

Now the comparison. On this chart, Code Guardian scores 71. Semgrep, about 20. CodeQL, 11. ESLint, essentially zero. *(pause)* One point on fairness: I ran those tools one function at a time — the same narrow window the model gets — which understates their full-project recall. Details are in appendix A7."

**PRE-EMPT — folded in** — the fairness sentence disarms "your baselines are strawmen / ESLint scores 0" (QA_PREP B.5). Don't skip it.

**RESERVE — confidence gate** *(not spoken — only if pressed on precision; it lives on appendix A9)* — "There's an optional rescore filter at 0.67: precision rises from 72 to 78 and F1 to 74, with recall unchanged. It drops the findings the model couldn't map to a category — six false positives here. It's eval-only, off in the shipped extension, and because the runs are seed-pinned it's a category filter, not run consensus. Full before-and-after: appendix A9."  → *QA_PREP D.3 / G.1*

**LIT-ANCHOR** *(reserve — only if the held-out drop is called a weakness)* — "A review of over 300 works reports the same shape: detection looks strong on curated data and drops on real-world code. So 71 down to the low sixties isn't a crack — it's the field's normal." (Zhang et al., SLR 2024)  → *QA_PREP B.7*

**TRANSITION** — "The second research question — does retrieval actually help — turned out more interesting than I expected."

---

## Slide 16 — RAG Is Not a Uniform Win  ·  [95 s · ~175 words]

**VOICE** *(this is the turn of the talk — slow down here more than anywhere else)*
"The plan was simple: switch RAG on, get better detection, across the board. Five models, two modes each, a paired comparison on F1.

The results did not cooperate. *(pause)* qwen3:8b improved by 3.91. The gemma models were essentially flat. qwen3:4b fell by 5.22. And codellama — *(pause)* — fell by 29.89. The single largest effect in the whole study, and it pointed the wrong way. *(pause)*

Is that real? Only codellama's drop survives Bonferroni at alpha 0.01 — McNemar p equals 0.0013. A genuine effect, not noise.

The error profile explains it. With retrieval on, qwen3 treats the retrieved examples as a reference page — its false alarms fall from one in two to one in ten. The very same text does the opposite to codellama: handed a prompt full of vulnerability descriptions, the weaker model starts seeing vulnerabilities everywhere. A stronger model checks against the context. A weaker one drowns in it. *(pause)*

So retrieval is not a free upgrade. It is a per-model choice. And the field agrees: RESCUE, in 2025, found naive RAG did not significantly help secure generation, and two 2025 systematic reviews report the same pattern."

**PRE-EMPT** — this whole slide is the pre-empt: volunteering that retrieval can hurt, with the Bonferroni discipline, defuses "your RAG hurts / is this significant?" (QA_PREP C.1, G.1). Stating it yourself is far stronger than conceding it under questioning.

**TRANSITION** — "Next, R3, repair quality."

---

## Slide 17 — R3 Repair Quality  ·  [110 s · ~200 words]

**VOICE**
"Repair is measured two ways — one automatic, one by hand. The slide is split to match. *(pause)*

The left half is the automatic measure, and it is the main number. Every fix goes through the Babel parser before you see it, confirming it is valid code the editor can insert as a one-click Quick Fix. Out of 279 fixes, 252 passed — 90.32 percent. *(pause)* In 18 more calls the model returned no fix at all; counted against all 297, the rate is 84.85. This is the main number because the parser decides — objective, and it covers every fix, not a sample.

The right half is the manual review: 25 repairs, read by hand, scored against a rubric. A fix was offered in 76 percent of cases. Of those offered, 89.5 percent correctly address the vulnerability, and 94.7 percent use the right approach. Taken together, about 68 percent of cases got a fix that was both offered and correct. *(pause)*

One score looks low — only 42 percent run exactly as they are. That does not contradict the 90, because they measure different things. 'Applies' means the editor can insert it. 'Runs as is' means a complete program on its own. Most fixes are a two-line patch meant to sit inside your function — it applies cleanly, but lifted out alone it fails, because it references a database handle that only exists in the surrounding code. A correct fix — just not a standalone program. *(pause)*

And to be plain: auto-applicable means the fix parses and applies — not that it is proven secure. That is why both halves are on the slide. The manual review is one reviewer on 25 cases; it supports the result rather than leading it."

**PRE-EMPT — folded in** — the closing paragraph defuses "single reviewer n = 25 / repair rate too high" (QA_PREP D.1, D.3).

**TRANSITION** — "R4, usability — which latency band does this actually fall in?"

---

## Slide 18 — R4 Usability: Latency Bands  ·  [55 s · ~100 words]

**VOICE**
"Three latency bands, fixed before evaluation. Real-time — under 500 milliseconds — is deliberately out of scope for the model. That band belongs to SAST. *(pause)*

Interactive — under 1.5 seconds — is met by gemma3:1b and qwen3:4b, both with RAG, at 1,019 and 1,328 milliseconds. And on-demand — under 5 seconds — is where the headline qwen3:8b lands: a median of 2,216 milliseconds, 95th percentile 4,327. Comfortably inside. *(pause)*

A real product picks the band per workflow: inline diagnostics run a 4B model; on-demand and audit modes run the 8B."

**PRE-EMPT — folded in** — naming real-time as SAST territory up front makes 2.2 s read as on-target, not slow (QA_PREP E.1).

**TRANSITION** — "R5, privacy."

---

## Slide 19 — R5 Privacy: Empirically Verified  ·  [75 s · ~140 words]

**VOICE**
"The same four arms from the architecture — but now each carries a measurement, not just a claim. *(pause)*

The network arm: the policy allows loopback only, so a non-loopback connection cannot even open. A source-leak scan corroborates it — the corpus is broken into more than nine thousand small text fingerprints, and the scan watches for any of them trying to leave the machine. It found none.

The injection arm: twelve crafted attempts to make the model leak. All twelve, leak-free. *(pause)* The slide also carries a stricter number — 83 percent, ten of twelve, returned a clean, well-formed reply. The other two went silent rather than leaking. The worst case was the model saying nothing.

The provenance arm: the Ed25519 signature is verified on every load. Tampering fails closed.

The reproducibility arm: the pinned container gives byte-identical runs — Node 20.19, npm ci, seed 42.

And the cost is modest: the harness stays under a hundred megabytes; Ollama is the heavy part, at 6 to 8 gigabytes."

**TRANSITION** — "What does all of this add up to?"

---

## Slide 20 — What the Evaluation Showed  ·  [75 s · ~140 words]

**VOICE**
"Four things. *(pause)*

First — **a local 8B model is enough**. About 71 percent F1, on a laptop, inside the on-demand band. You do not pay for privacy with quality. *(pause)*

Second — **retrieval depends on the model**. The largest single effect in the whole study is RAG making things worse — codellama, minus 29.89. One result, enough to rewrite the rule.

Third — **repair is the real gap**. Ninety percent auto-applicable means you can act, not just be warned. That is the one thing local scanners cannot do.

Fourth — **privacy is something you can test**. Loopback, a signed corpus, a pinned container — they make 'leak-free' a measurement, not a slogan. *(pause)*

And the three questions from the start are answered. RQ1: yes — 71.43 F1 under the privacy envelope. RQ2: yes, but per-model. RQ3: yes — 2.2 seconds, on-demand."

**TRANSITION** — "So where does that leave Code Guardian against the gap I opened with?"

---

## Slide 21 — Code Guardian Closes the Gap  ·  [55 s · ~100 words]

**VOICE**
"Recall the trade I opened with — send your code away, or work almost unprotected. This is the same matrix from the start, with one row added at the bottom. *(pause)*

Privacy: met. Repair: met — the column every other local tool leaves empty. Usability: inside the band. Consistency: holds. And accuracy I marked partial — deliberately. 71 percent F1 is the Medium band: competitive under these constraints, not class-leading. *(pause)*

So the claim is narrow, and more useful for it: this is the one approach that brings privacy, repair, and IDE-grade speed together. It refuses the trade no developer should have to make."

**TRANSITION** — "Now the limitations."

---

## Slide 22 — Limitations & Future Work  ·  [80 s · ~150 words]

**VOICE**
"Now the honest part — one slide, because every limitation points at its own piece of future work. *(pause)*

Five limitations, in the open. The manual repair review — one reviewer, 25 cases. An informed judgment, not a consensus. The corpus — 101 curated cases, guarded four ways: the held-out split, the external set, the whole-project NodeGoat run, and signed provenance. Only one real project ran end to end — one project cannot prove generalization. The consensus filter does nothing under deterministic decoding — three runs at seed 42 are byte-identical. And no cloud baseline — ruled out by the privacy threat model. *(pause)*

Each one has its next step. Rotate the seeds, and the consensus filter does real work. Add a second rater. Validate across more projects. Stream partial results toward real-time. And gate retrieval per model — straight from the codellama finding. These are not loose ends. They are the roadmap the evaluation wrote for itself."

**TRANSITION** — "Now the contributions."

---

## Slide 23 — Contributions of This Thesis  ·  [50 s · ~85 words]

**VOICE**
"Five contributions. A working VS Code extension — local model, RAG, signed corpus, pinned container — published to the Marketplace, so any developer can install it today. A two-stage detect-and-repair pipeline with a structured JSON contract at every boundary. An empirical study — five models, two modes, three SAST baselines, 303 invocations per configuration, on a CWE-mapped JavaScript and TypeScript corpus. Reproducibility infrastructure — byte-identical runs anyone can repeat. And statistical discipline — corrected significance tests, exact intervals, and a held-out split."

**TRANSITION** — "Those are the contributions; the key references are on the next slide."

---

## Slide 24 — References  ·  [15 s · ~30 words]

**VOICE**
"These are the main sources — the foundation models and RAG, the LLM-for-security comparators, and the standards the corpus maps against. I'll leave this up for a moment."

*(Don't read the list. Advance once the panel has had a moment.)*

**TRANSITION** — "Thank you. I'd be glad to take questions."

---

## Slide 25 — Thank You  ·  [40 s · ~70 words, then Q&A — 20 min]

**VOICE**
"Recall the opening — the bank's code, and today's trade: send your code away, or work almost unprotected. Code Guardian refuses that trade. *(pause)* The code stays on your machine. You get the finding. And you get the fix.

Four numbers hold it together: F1 71.43. Repair 90.32. Latency 2.2 seconds. Leak-free on the harness. *(pause)*

Thank you. I would be glad to take your questions."

*(Stop talking. Look at the panel. Wait.)*

**During Q&A (a full 20 minutes — slow down, answer properly):**
- Briefly restate the question in your reframe. It confirms you understood and buys thinking time.
- Give a full answer, then open the matching appendix slide — put A1–A9 on the projector when it helps.
- Use the QA_PREP structure: Frame → Anchor (one number) → Concede (the smallest honest limit). ~60–90 s per answer.
- It is fine to pause and think. Silence reads as care, not weakness.
- Don't apologise. Don't say "good question." Just answer.

---

## Pacing checkpoints

Budgets above include transitions and pauses and sum to ~28 minutes, leaving a ~2-minute buffer in the 30-minute slot. If you're behind at these slides, trim:

| Checkpoint     | Slide | Time elapsed should be |
|----------------|-------|------------------------|
| End of Act I   | 5     | ~5 min                 |
| End of Act III | 12    | ~14½ min               |
| End of Act IV  | 14    | ~17½ min               |
| End of Act V   | 19    | ~23 min                |
| End of Act VI  | 23    | ~27 min                |

If you're at slide 19 and the clock is past **26 minutes**: keep slide 22 to the limitations column only and cut slide 23 (Contributions) to 30 seconds. Cut connective sentences, never numbers, never the folded pre-empts. Never run over into the 20-minute Q&A.

If you're **ahead** of a checkpoint by more than a minute, you are speaking too fast — stretch the pauses, not the words.

## Voice / tone notes

- **Hold the slow pace.** The script fits 30 minutes at ~115 words per minute. Nerves push everyone toward 150; if a slide feels "too easy" on the clock, that's the buffer working — don't fill it.
- **Pause after every number.** *(pause)* = one slow breath, about two seconds. The audience needs the beat to take in a percentage. At slow pace, the pause is what reads as authority.
- **Finish every sentence.** Slow pace exposes trailing-off. Short, complete, declarative sentences — land each one, then breathe (STORYTELLING_STYLE.md §2).
- **Don't read the slide aloud.** The slide carries the artefact; you carry the argument.
- **Plain English.** "Stage one is detection," not "the first stage performs the detection task."
- **No first person plural.** Say "the thesis" or "Code Guardian," not "we built."
- **Don't apologise.** Anchor a limitation in its future-work item instead.
- **Land each requirement.** When you say "R1" on a results slide, point at the badge in the corner.
- **Plant and call back.** "Send your code away, or work almost unprotected" is the through-line — slide 3, slide 21, and the close.
- **Let the surprise breathe.** Slide 16 is the turn. Pause before the codellama number; don't bury it in the next sentence.
- **Headline, then proof.** One plain sentence, then the number — never the reverse.

## Pre-defense checklist

- [ ] Rehearse the whole talk **with a timer** against the per-slide budgets — you should hit each pacing checkpoint within ±30 s
- [ ] Rehearse slides 14–19 (the results block) on their own — this is where Q&A traction lives
- [ ] Rehearse the folded pre-empt sentences until they sound voluntary, not defensive — they answer the examiner's top questions inside the talk
- [ ] Say the QA_PREP.md anchors out loud — the anchor stats must be muscle memory
- [ ] Re-run make_assets.py and rebuild the deck, then eyeball the architecture diagram, screenshot, and bar charts in the exported PDF
- [ ] Print the QA_PREP.md "quick reference card" and tape it inside your binder
- [ ] Hard-reload the deck on the projector laptop the morning of — fonts can be substituted
- [ ] Have a backup PDF export — projector apps fail
- [ ] Bring water. Sip during the *(pause)* marks, not mid-sentence.
