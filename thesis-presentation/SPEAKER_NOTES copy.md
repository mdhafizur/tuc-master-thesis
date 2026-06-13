# Speaker Notes — Code Guardian Defense

**Total budget:** 30 minutes talk + 20 minutes Q&A
**Per-slide budget:** ~70 s on main slides, longer on results (~95 s) so the numbers land. The slide times below add up to ~28 min, leaving a ~2 min buffer inside the 30 min slot. A few slides carry a short **PRE-EMPT** line; folded into the spoken flow these add roughly a minute total, so plan for ~29 min of content and a ~1 min buffer.
**Voice:** warm but measured spoken prose — plain English, short punchy sentences at the key beats, flowing connective tissue in between. First-person singular is fine where it's natural ("I checked," "I ran"); avoid first-person plural ("we built"). Avoid filler ("um," "so," "basically").
**Posture:** never read the slide aloud. The slide is the *artefact*; your voice is the *story*.

Each entry shows:
- **[Time]** rough budget for that slide
- **VOICE** — the rough spoken text
- **TRANSITION** — the one sentence that lands on the next slide

The transitions matter. They are what make the talk feel like one argument instead of 25 separate ones.

**Pre-empt the examiner — say the "why" before they ask.** Several slides below carry a **PRE-EMPT** line: one short sentence that justifies a design decision out loud, so the panel doesn't have to raise it in Q&A. Each is tagged with the QA_PREP entry it defuses. Fold it into the spoken flow — don't read it as a separate aside. The aim is that by the time Q&A opens, the obvious "why did you…" questions are already answered. A choice you volunteer reads as confidence; the same choice defended under questioning reads as damage control.

**Tell it as one connected argument.** A light narrative thread runs through the talk — a problem, a solution, a surprise, and a return to the problem — but the delivery stays measured and professional throughout.
- **The problem** — a false trade: *send your code off your machine, or work almost unprotected.* Introduce it on slides 2–3.
- **The solution** — slide 4: the tool is local, grounded, and in the developer's hands.
- **The surprise** — slide 16: retrieval was expected to help everywhere, and it did not. Let that finding land; do not rush past it.
- **The return** — slide 21 and the close: name the false trade again, then explain that Code Guardian refuses it.
Let each headline number land with a short pause. The narrative is a thread that connects the evidence, not a set of slogans, so keep the delivery flowing and professional. This is a defense, not a keynote — never let presentation outrun the evidence.

---

## Slide 1 — Title  ·  [60 s]

**VOICE**
"Good afternoon. You have just finished writing code for a bank — or a hospital. You need the answer to one simple question: is it secure? Getting that answer today means making a trade-off. And by the end of this talk, I want to convince you it is a trade-off no developer should have to make.

The thesis is titled *Privacy-Preserving Source Code Vulnerability Detection and Repair using Retrieval-Augmented Local LLMs for Visual Studio Code*. The system is called Code Guardian. Three parts: why the tool is needed, what it does, and what the evaluation shows. About thirty minutes."

*(Pause. Look at the panel. Move to next slide.)*

**TRANSITION** — "I'll start with the problem the tool solves."

---

## Slide 2 — The Developer's Dilemma  ·  [40 s]

**VOICE**
"Three problems arrive at once. First: sensitive code can't be pasted into a cloud model without breaking compliance. Second: the local scanner on your machine keeps missing real bugs — so the vulnerability reaches production. Third: when a scanner does flag something, it warns you, but it never fixes anything. The repair is still entirely your job.

No tool today solves all three. So the real question is the one in the corner — what is the alternative? That is what the rest of this talk answers."

*(Four bubbles on screen: three problems plus one question — the green 'What's the alternative?'. Let the image breathe; gesture, don't enumerate them.)*

**TRANSITION** — "Let me make the cost concrete."

---

## Slide 3 — Today You Pick: Send Code Away — or Get No Help  ·  [80 s]

**VOICE**
"Today, in practice, there are only two options. On one side, the cloud assistants — Copilot, ChatGPT, Cursor. The reasoning is excellent. But every request leaves your machine, and in finance, healthcare, defence, or any air-gapped setting, that door is simply closed.

On the other side, the local scanners — Semgrep, CodeQL, ESLint. They stay on your machine, so privacy is complete. But they miss most of the bugs. On the JavaScript and TypeScript in this thesis, Semgrep's canonical recall is 12.68 percent. And they only warn — they never fix.

So here is the trade you're offered: send your code away, or work almost unprotected. That's the whole menu. And neither side is good enough."

**TRANSITION** — "So this thesis asks one question: why should that be the trade at all?"

---

## Slide 4 — No Tool Combines All Three  ·  [60 s]

**VOICE**
"Removing that trade requires three things to be true at the same time. The tool must be **local**, so your code never leaves the machine and you can prove it. It must be **grounded**, reasoning with real CWE and OWASP knowledge rather than fixed patterns. And it must stay **in your hands**, offering a fix that you choose to apply, with nothing rewritten behind your back.

No existing tool delivers all three together, and that is the gap this thesis sets out to close."

**PRE-EMPT** *(fold into the flow — answers a question before it's asked)* — "And the scope is JavaScript and TypeScript on purpose: it's the most-used stack on GitHub, and it's where local static analysis is weakest — so it's where a privacy-preserving tool helps most."  → *defuses "why JS/TS?" (QA_PREP A.4)*

**LIT-ANCHOR** *(reserve — drop only if the IDE-integration gap is doubted in Q&A)* — "A 2025 survey of 58 LLM vulnerability studies found not one was wired into a developer's workflow — every one was evaluated offline. That's the gap this slide names." (Zhou et al., TOSEM 2025)  → *backs "in your hands"; QA_PREP J.1*

**TRANSITION** — "Before the system, here are the research questions and the five requirements I commit to."

---

## Slide 5 — Research Questions and Requirements  ·  [90 s]

**VOICE**
"Three research questions frame the work. RQ1 asks whether a local model, on a normal laptop, can detect vulnerabilities well enough under a strict privacy envelope. RQ2 asks whether grounding that model in retrieved CWE and OWASP knowledge actually helps. And RQ3 asks whether it is fast enough inside the editor for real work.

Before measuring anything, I fixed five requirements. R1 is accuracy — precision, recall, and F1. R2 is consistency — valid, stable output. R3 is repair quality. R4 is usability — latency and IDE fit. And R5 is privacy — nothing leaves the machine.

Each requirement has a fixed grading scale, written into the requirements chapter before any model ran. R1 and R2 use four levels, and R3 and R4 use three. This matters because the bar was set before I saw a single result, so it is the same bar before and after evaluation."

**PRE-EMPT** *(this line is itself the pre-empt — say it slowly, look at the panel)* — fixing the grading scales before evaluation is exactly what disarms "how did you choose the thresholds?"  → *defuses QA_PREP G.3*

**TRANSITION** — "Where do existing systems sit against R1 to R5?"

---

## Slide 6 — Three Existing Approaches  ·  [60 s]

**VOICE**
"The related work falls into three camps. The **cloud assistants** — Copilot, ChatGPT, Cursor, Claude Code — are strong on accuracy, repair, and usability, but they fail privacy by design, because every request leaves the machine. **Local static analysis** — Semgrep, CodeQL, ESLint — is strong on consistency and privacy, but weak on accuracy and repair, because it matches patterns rather than reasoning and it only warns. And the **academic LLM-for-security work** — IRIS, SecRepair, LLMSecGuard, RESCUE — is promising, but each system drops at least one of privacy, repair, or IDE speed. None brings them all together."

**TRANSITION** — "Put them in a matrix against R1 to R5, and the gap is clear."

---

## Slide 7 — No Tool Satisfies R3 + R4 + R5 Together  ·  [75 s]

**VOICE**
"Read across each row. Copilot meets accuracy, consistency, and repair, is only partial on usability, and fails privacy. Semgrep and CodeQL meet privacy but fail accuracy and repair. IRIS, even with GPT-4 behind it, fails repair, usability, and privacy, because it is a whole-repo batch tool. And SecRepair fine-tunes a model rather than prompting one, runs in batch, and targets mostly C and C++.

The bottom row is Code Guardian, and it is the claim this talk defends: no existing tool delivers privacy, repair, and IDE-grade speed at the same time."

**LIT-ANCHOR** *(reserve — drop only if the bottom row is challenged in Q&A)* — "LLMSecGuard's own authors call IDE integration 'essential' — then leave it as future work. Code Guardian ships it." (Kavian et al., EASE 2024)  → *sharpens the matrix; QA_PREP H.1*

**SOURCE NOTE** *(point to the footnote only if asked where the levels come from — don't read it)* — the small line under the matrix says the High / Partial / Not-satisfied levels apply the fixed R1–R5 scales, with accuracy/repair thresholds from IR/SE work, latency from HCI response-time limits, and privacy as a checklist. The full scale-and-source table is **Appendix slide A8** — put it up if the panel pushes on "how did you choose the thresholds?"  → *backs QA_PREP G.3*

**TRANSITION** — "Now the system itself."

---

## Slide 8 — Proposed Workflow  ·  [60 s]

**VOICE**
"The extension offers four ways to work: inline diagnostics that appear as you save, a file scan on right-click, a side panel for asking about any finding, and a workspace audit that covers the whole project at once.

Why four? Because the question 'is this secure?' arises at different moments — as you save, on a single file, on one finding, or across the whole project — and each workflow meets it where it happens. One pipeline sits behind all four: detect, then repair. And everything inside the dashed line runs on your machine."

**TRANSITION** — "Here are the two stages in detail."

---

## Slide 9 — Two-Stage Local Pipeline  ·  [90 s]

**VOICE**
"Two stages. The first finds the problem. The second repairs it.

Stage one is detection. The code goes to the local model as a single JSON-mode call, and the model fills a fixed schema — so what comes back is structured data, not an essay. When RAG is on, the most relevant CWE and OWASP snippets go into the prompt first. And to filter out one-off noise, detection runs twice — each pass from a different random starting point, what's called a seed. A finding survives only when both passes agree. That's the consensus check.

Stage two is repair. It runs only when stage one has actually found something. It's a separate call that returns just the fixed code and its language. That output goes through the Babel parser — so if the model returns prose instead of code, it's thrown away before you ever see it. What survives appears as an ordinary one-click Quick Fix. And you are the one who applies it. Nothing is rewritten behind your back.

Now notice what didn't happen anywhere in that flow: nothing left the machine. Ollama runs on loopback, the embeddings are local, and there's no telemetry."

**PRE-EMPT** *(fold into the flow — answers a question before it's asked)* — "In the shipping extension those two passes use different seeds — a real consensus step in the product. In the evaluation the seed is pinned for reproducibility, so the repeated runs come out identical — which is why the R2 consistency result is reported as a property of deterministic decoding, not a robustness claim. Measuring the filter's gain under seed rotation is future work."  → *defuses "your consensus is just identical runs" (QA_PREP G.2)*

**TRANSITION** — "What does this look like when it runs?"

---

## Slide 10 — Live in VS Code  ·  [75 s]

**VOICE** *(pointing at the screenshot)*
"This is the extension running on a file full of vulnerable endpoints — SQL injection, reflected XSS, code injection, command injection, and path traversal. On the right is the Code Guardian panel, currently examining the reflected-XSS endpoint. It explains why the user input is unsafe, and it proposes a fix.

Notice that the panel marks this one 'not auto-applicable.' That is the system being deliberately honest: it shows you the fix but asks you to review it first. There are no silent rewrites, and nothing here leaves the laptop.

The QR code installs the extension from the VS Code Marketplace."

**TRANSITION** — "Behind that UI sits the architecture."

---

## Slide 11 — System Architecture  ·  [75 s]

**VOICE** *(walk the diagram)*
"Everything inside the dashed rectangle runs on your laptop. The VS Code extension host drives the four workflows, and it talks to Ollama on loopback only. That line is the privacy boundary. Ollama runs an 8B-class quantised model — qwen3:8b is the one I evaluate and recommend, but any Ollama model works, because the extension isn't tied to one. The RAG store is HNSWlib, on disk, local.

Now follow a request through. It hits the local cache first. On a hit, the answer comes straight back — no model call at all. On a miss, it runs the two-stage analyzer — detect, then repair — and stores the result, so the next identical check is instant.

When RAG is on, the RAG Manager pulls the top three snippets from that local, signed knowledge base — and it picks them by meaning, not by keyword. A small model, also on the laptop, turns the code and the prompt into a string of numbers that captures what they're about. That fingerprint pulls the three closest entries out of the store. So it still finds the right CWE or OWASP guidance even when the code never says the word 'injection' or a CWE number. Those public feeds are what sync into the corpus in the first place.

Now look at the boundary itself. By default, nothing crosses it. The vulnerability data ships pre-bundled, so the tool runs fully offline out of the box. There's exactly one outbound call you can opt into — a refresh of public NVD, OWASP, and CWE metadata, on a 24-hour cache — and it's off by default. Even switched on, it carries look-ups, never your code.

So privacy here isn't a feature you switch on. It's decided by where the boundary sits."

**PRE-EMPT** *(fold into the flow — answers a question before it's asked)* — "The 8B model is a deliberate ceiling, not a compromise: it's the largest that fits a 16 GB laptop alongside VS Code. A 70B model needs 40-plus gigabytes — that turns 'developer laptop' into 'workstation' and shrinks who can run it."  → *defuses "why not a bigger model?" (QA_PREP B.4)*

**TRANSITION** — "Four ways the privacy claim is enforced."

---

## Slide 12 — Privacy by Construction  ·  [75 s]

**VOICE**
"Privacy here is not a single feature; it is four separate arms. Three of them shut down a specific attack, and the fourth lets you verify the other three — and each one can be checked on its own.

The network arm stops your code leaving the machine. Ollama is bound to loopback — 127.0.0.1 and nothing else — so nothing it sends can leave your laptop.

The provenance arm stops a poisoned knowledge base, where someone swaps in malicious guidance that the model would then trust. The RAG corpus is Ed25519-signed and checked on every load, and if it has been tampered with, the extension refuses to load it.

The injection arm stops prompt injection — instructions hidden in the code that try to hijack the model. Twelve crafted attacks were run, and all twelve came back clean.

The reproducibility arm is not about an attacker but about trust. The whole pipeline rebuilds from a pinned container at seed 42, so anyone can re-run it and obtain the exact same result, rather than taking my word for the other three.

Because each arm stands on its own, no single failure can quietly break the whole promise."

**LIT-ANCHOR** *(reserve — network arm, if "why local" is pushed in Q&A)* — "An industry study on ChatGPT for secure coding lands on the same rule this arm enforces: run local LLMs, kept off the network, so proprietary code never leaves the building." (Espinha Gasiba et al., 2024)  → *backs the network arm; QA_PREP F.5*

**LIT-ANCHOR** *(reserve — provenance/injection arms, if corpus-signing is questioned)* — "Why sign the corpus? A 2024 RAG-security survey shows poisoning just 0.04 percent of a corpus can hijack retrieval 98 percent of the time. The signature is the lock on that door." (Zhou et al., RAG-Trust survey 2024)  → *backs the provenance + injection arms; QA_PREP F.4*

**TRANSITION** — "Now the evaluation."

---

## Slide 13 — Evaluation Setup  ·  [85 s]

**VOICE**
"Three things were locked down before any number went on screen.

First, the **corpus**. A curated JavaScript and TypeScript set — 101 cases, 71 vulnerable, 30 secure, across 20 CWE categories, every label verified by hand. And every case is traceable to a source. Some are real bugs from popular npm packages and named CVEs. The rest are written in JavaScript to match standard weakness patterns from suites like Juliet and the OWASP Benchmark — which only ship in C and Java. Alongside it sits an external set of 15 cases — OWASP NodeGoat, Juice Shop, three named CVEs — plus a whole-project NodeGoat scan, run end to end. Why verify the labels by hand, and not with a scanner? Because CWEval found that fewer than a third of one popular benchmark's flagged samples could even be reproduced by its own analyzer. A scanner's labels are not ground truth.

Second, the **configurations**. Five Ollama models, each run two ways — with RAG and without. That's ten. Plus three SAST baselines: Semgrep, CodeQL, and ESLint. Each sample runs three times, deterministically — 303 invocations per configuration.

Third, the **statistical discipline**. The cases are split in two — I tune on one half and freeze the other, so tuning never touches the headline numbers. McNemar with Bonferroni across the paired comparisons. And exact-binomial intervals for the small-sample rates.

Rules set first, measurements taken second. That discipline stands behind every number that follows."

**PRE-EMPT** *(two short ones — fold into the flow, answer before asked)* — First: "101 curated cases is a deliberate choice, not a shortcut — the peer benchmark CWEval uses 119, the big auto-mined sets are mostly broken, and there's no existing JS/TS corpus that fits, since Juliet and OWASP Benchmark are C, C++, and Java." Second: "There's no cloud-LLM baseline by design — a cloud model would break the privacy threat model the thesis is built on, so the three SAST tools set the local floor instead."  → *defuses "101 is too small / why not Juliet?" (QA_PREP A.1, A.3) and "why no GPT-4 baseline?" (QA_PREP B.2)*

**TRANSITION** — "Four headline numbers, one per requirement."

---

## Slide 14 — Results  ·  [70 s]

**VOICE** *(land each number briefly; save the detail for the next four slides)*
"Four numbers. One per requirement.

Detection: an F1 of **71.43 percent** — the balance between precision and recall — from qwen3:8b with RAG. And it travels — 61.11 on code I held back during tuning, 63.64 on outside projects I had no hand in.

Repair: **90.32 percent** auto-applicable — the fix parses and applies cleanly — with combined semantic correctness around 68 percent.

Latency: a median of **2.2 seconds**, well inside the on-demand band.

Privacy: **leak-free** across all 12 injection attempts.

And along the bottom, R2 — consistency. 100 percent valid JSON across all 3,030 invocations. But the runs share a seed, so that agreement reflects determinism, not robustness. I say so plainly rather than dress it up.

Each of these four gets its own slide next. R2 stays in the appendix."

**COLOUR NOTE** *(optional — only if you want to point at the card colours)* — each card is tinted by its requirement band from the A8 scale: repair, latency, and privacy land **green (High / met)**, and detection is **amber (Medium)**. Don't over-explain it — but the single amber card quietly pre-figures the slide-21 admission that accuracy is the one area marked partial, not class-leading. The confidence-gate number (74.07) is no longer on this card; it lives on appendix A9.

**TRANSITION** — "Start with R1, detection accuracy."

---

## Slide 15 — R1 Detection Accuracy  ·  [95 s]

**VOICE**
"This is the main result. qwen3:8b with retrieval — the setup I recommend — run across all 101 cases.

The headline is an F1 of 71.43. In plain terms, that's two things at once. When it flags code, it's right about seven times in ten. And of all the real vulnerabilities in the set, it catches about seven in ten. The false-positive rate is ten percent — so roughly one safe snippet in ten gets a warning it doesn't need. In short: it finds most of the real bugs, and most of what it shows you is real.

Does that hold on code it hasn't seen? I checked two ways. On the cases I held back while tuning, it drops to 61. On a separate external set — real projects I had no hand in — it's about 64. So on unfamiliar code it sits in the low sixties, where recall gives ground but precision holds. That dip isn't a weakness. It's the reason you hold cases back in the first place — and the gap between curated and real-world code is a well-known pattern.

Now set that against what's already on a developer's machine. On the chart it scores 71. Semgrep, about 20. CodeQL, 11. ESLint, essentially zero. Even Semgrep, the strongest of the three, catches only about one in eight of these bugs. One point on fairness: I ran those tools one function at a time — the same narrow window the model gets — which understates their full-project recall. The details are in appendix A7."

**RESERVE — confidence gate** *(eval-only; raise only if pressed on precision — it now lives on appendix A9, not the main slide)* — "There's an optional rescore filter at 0.67: precision rises from 72 to 78 and F1 to 74, with recall unchanged. It drops the findings the model couldn't map to a category — six false positives here. It's eval-only, off in the shipped extension, and because the runs are seed-pinned it's a category filter, not run consensus. The full before-and-after is appendix A9."  → *backs QA_PREP D.3 / G.1*

**PRE-EMPT** *(the fairness note in the VOICE is the pre-empt — don't skip it)* — saying the SAST tools ran at the model's function-level scope, which understates their full-project recall, disarms the "your baselines are strawmen" attack before it's raised.  → *defuses "ESLint scores 0 %, strawman" (QA_PREP B.5)*

**LIT-ANCHOR** *(reserve — drop only if the held-out drop is called a weakness)* — "A review of over 300 works reports the same shape: detection looks strong on curated data and drops on real-world code. So 71 down to the low sixties isn't a crack — it's the field's normal." (Zhang et al., SLR 2024)  → *frames the generalization gap; QA_PREP B.7*

**TRANSITION** — "The second research question — does retrieval actually help — turned out more interesting than I expected."

---

## Slide 16 — RAG Is Not a Uniform Win  ·  [90 s]

**VOICE**
"This is the second research question — whether retrieval actually helps — and the answer was more interesting than I expected.

The plan was simple: switch RAG on and get better detection across the board. Five models, two modes each, in a paired comparison measuring the change in F1 when RAG is enabled.

The results did not cooperate. qwen3:8b improved by **3.91**. The gemma models were essentially flat. qwen3:4b fell by **5.22**. And codellama fell by **29.89** — the single largest effect in the whole study, and it pointed the wrong way.

So the question is whether that is real. Only codellama's drop survives Bonferroni at alpha 0.01, with McNemar p equal to 0.0013. It is a genuine effect, not noise.

The error profile explains why it broke that way. With retrieval on, qwen3 treats the retrieved examples as a reference page, and its false alarms fall from one in two down to one in ten. The very same text does the opposite to codellama: handed a prompt full of vulnerability descriptions, the weaker model starts to see vulnerabilities everywhere — it flags almost everything and catches fewer real bugs than before. The same corpus produces opposite results, and the difference is whether the model can treat that extra context as a reference or simply drowns in it. A stronger model checks against it; a weaker one loses the actual code in the noise.

That changes the lesson. Retrieval is not a free upgrade; it is a per-model choice. And the field agrees. RESCUE, in 2025, found that naive RAG did not significantly help secure generation, blaming noise in the raw retrieved text that drowned the signal, and two 2025 systematic reviews report the same pattern — retrieved context helps some setups and hurts others, depending on the model."

**PRE-EMPT** *(this whole slide is a pre-empt — lean into it)* — volunteering that retrieval can hurt, and that only the codellama drop survives a strict Bonferroni correction, shows the finding is disciplined rather than cherry-picked. Stating it yourself is far stronger than conceding it under questioning.  → *defuses "your RAG hurts / is this significant?" (QA_PREP C.1, G.1)*

**TRANSITION** — "Next, R3, repair quality."

---

## Slide 17 — R3 Repair Quality  ·  [95 s]

**VOICE**
"Repair quality is measured two ways — one automatic, one by hand. The slide is split to match.

The left half is the automatic measure, and it's the main number. Every fix the model writes goes through the Babel parser before you see it. The parser confirms the fix is valid code the editor can insert as a one-click Quick Fix. Out of 279 fixes, 252 passed — 90.32 percent. There were 18 more calls where the model returned no fix at all; count those against the total of 297 and the rate is 84.85 percent.

Why is this the main number? Two reasons. It's objective — the parser decides, not a person. And it covers every fix, not a sample.

The right half is a manual review. I read 25 repairs by hand and scored them against a rubric. A fix was offered in 76 percent of cases. Of the fixes offered, 89.5 percent correctly address the vulnerability, and 94.7 percent use the right approach. Taken together, about 68 percent of cases got a fix that was both offered and correct.

One score on the right looks low — only 42 percent run exactly as they are. That doesn't contradict the 90 percent, because the two measure different things. 'Applies' means the fix is valid code the editor can insert. 'Runs as is' means the fix is a complete program on its own. Most fixes are a small patch meant to sit inside your function, not a whole file — so they apply cleanly even though they wouldn't run by themselves. Take a SQL-injection fix: the model swaps a string-built query for a parameterized one — two lines that slot straight into your function. The editor inserts them cleanly, so they count toward the 90. But lift those same two lines out and run them on their own, and they fail — they reference a database handle and an id that only exist in the surrounding function. A correct fix, just not a standalone program.

So there are two levels, and the thesis reports both. The automatic number shows whether a fix can be applied. The manual review shows whether a developer can rely on it. That review is one reviewer on 25 cases — so it supports the result rather than leading it."

**PRE-EMPT** *(fold into the flow)* — "One thing to state plainly: auto-applicable means the fix parses and applies, not that it is proven secure. That is why both bars are on the slide — the automatic one for whether a fix applies, the manual one for whether it is correct."  → *defuses "single reviewer n = 25 / repair rate too high" (QA_PREP D.1, D.3)*

**TRANSITION** — "R4, usability — which latency band does this actually fall in?"

---

## Slide 18 — R4 Usability: Latency Bands  ·  [80 s]

**VOICE**
"Three latency bands, fixed before evaluation. Real-time — under 500 milliseconds — is the SAST band, not the model's. Interactive — under 1.5 seconds — is met by gemma3:1b with RAG at 1,019 milliseconds, and qwen3:4b with RAG at 1,328. And on-demand — under 5 seconds — is where the headline qwen3:8b with RAG lands: 2,216 milliseconds, with the 95th percentile at 4,327. Comfortably inside.

A real product picks the band per workflow. Inline-diagnostic mode runs a 4B model. On-demand and audit modes run the 8B."

**PRE-EMPT** *(fold into the flow — answers a question before it's asked)* — "Real-time under 500 milliseconds is deliberately out of scope for the LLM — that band belongs to SAST. Framing it that way up front makes 2.2 seconds read as on-target, not slow."  → *defuses "2.2 s is too slow" (QA_PREP E.1)*

**TRANSITION** — "R5, privacy."

---

## Slide 19 — R5 Privacy: Empirically Verified  ·  [70 s]

**VOICE**
"Same four arms from the architecture — but now each one carries a measurement, not just a claim.

The network arm. The policy allows loopback only, so a non-loopback connection can't even open. A source-leak scan corroborates it: it breaks the corpus into more than nine thousand small text fingerprints, then watches for any of those byte-sequences trying to leave the machine. It found none.

The injection arm. Twelve crafted attempts to make the model leak. All twelve, leak-free. The slide also carries a stricter number, answering a different question — did the model return a clean, well-formed reply? There the result is 83 percent, ten of twelve. The other two didn't leak; they just went silent, returning an empty response instead of a proper refusal. So the worst case was the model saying nothing — not the model leaking.

The provenance arm. The corpus's Ed25519 signature is verified on every load. Tampering makes it fail closed.

The reproducibility arm. The pinned container gives byte-identical runs — Node 20.19-alpine, npm ci, seed 42.

And the cost is modest. The harness stays under a hundred megabytes of RAM. Ollama is the heavy part — 6 to 8 gigabytes for an 8B model."

**TRANSITION** — "What does all of this add up to?"

---

## Slide 20 — What the Evaluation Showed  ·  [90 s]

**VOICE**
"So what did all that measurement actually show? Four things.

First — **a local 8B model is enough**. qwen3:8b with RAG reaches about 71 percent F1 on JavaScript and TypeScript, inside the on-demand band, on a laptop. You don't pay for privacy with quality.

Second — **retrieval depends on the model**. It's not a universal win. The largest single effect in the whole study is RAG making things worse — codellama, at minus 29.89. That one result is enough to rewrite the rule.

Third — **repair is the real gap**. Ninety percent auto-applicable means you can act, not just be warned. That's the one thing the local scanners cannot do.

Fourth — **privacy is something you can test**. Loopback, a signed corpus, a pinned container — they make 'leak-free' a measurement, not a slogan.

And the three questions from the start are answered. RQ1: yes — 71.43 F1 under the privacy envelope. RQ2: yes, but per-model. RQ3: yes — 2.2 seconds, on-demand."

**TRANSITION** — "So where does that leave Code Guardian against the gap I opened with?"

---

## Slide 21 — Code Guardian Closes the Gap  ·  [55 s]

**VOICE**
"Recall the trade I opened with — send your code away, or work almost unprotected. This is the same matrix from the start, now with one row added at the bottom.

Privacy is met. Repair is met — and that's the column every other local tool leaves empty. Usability sits inside the band. Consistency holds.

Accuracy I've marked partial, not top — and that's deliberate. 71 percent F1 is the Medium band: competitive under these constraints, but not class-leading. So the claim isn't that the tool is best at everything. It's something narrower, and more useful. This is the one approach that brings privacy, repair, and IDE-grade speed together. And in doing so, it refuses the trade no developer should have to make."

**TRANSITION** — "Now the limitations."

---

## Slide 22 — Limitations & Future Work  ·  [95 s]

**VOICE**
"Now the honest part — and it's on one slide, because every limitation points straight at a piece of future work. Limitations on the left. Where each one leads, on the right.

Five limitations, stated in the open. First — the manual repair review was one reviewer on 25 cases. A single informed judgment, not a consensus. Second — the corpus is 101 curated cases; I guard against that bias four ways: the held-out split, the external 15-case set, the NodeGoat whole-project run, and the signed-manifest provenance. Third — only one real-world project was run end to end, NodeGoat, and one project can't prove the system generalizes. Fourth — the consensus filter does nothing under deterministic decoding, since three runs at seed 42 are byte-identical. And fifth — there's no cloud-LLM baseline, ruled out by the privacy threat model, so the three SAST tools set the floor instead.

And each one has a next step. Rotating the seeds would let the consensus filter do real work. A second rater would strengthen the manual review. Validation across more projects would test generalization. Streaming partial results would reach the real-time band. And gating retrieval per model follows directly from slide 16. None of these are loose ends — they're the roadmap the evaluation wrote for itself."

**TRANSITION** — "Now the contributions."

---

## Slide 23 — Contributions of This Thesis  ·  [70 s]

**VOICE**
"Five contributions. The first is a working VS Code extension — local model, RAG, signed corpus, pinned container — published to the Marketplace, so any developer can install it today. The second is a two-stage pipeline with a structured JSON contract at every boundary, covering detection and repair. The third is an empirical study: five models, two modes, and three SAST baselines, at 303 invocations per configuration, on a CWE-mapped JavaScript and TypeScript corpus. The fourth is reproducibility infrastructure — byte-identical runs, a signed manifest, and a pinned Node container — so anyone can re-run the study and get the same numbers. And the fifth is statistical discipline: Bonferroni-corrected McNemar, exact-binomial intervals, and a held-out test split."

**TRANSITION** — "Those are the contributions; the key references are on the next slide."

---

## Slide 24 — References  ·  [10 s]

**VOICE**
"These are the main sources — the foundation models and RAG, the academic LLM-for-security comparators, and the standards the corpus maps against. I'll leave this up for a moment."

*(Don't read the list. Advance once the panel has had a moment.)*

**TRANSITION** — "Thank you. I'd be glad to take questions."

---

## Slide 25 — Thank You  ·  [Q&A — 20 min]

**VOICE**
"Recall the opening: you, the bank's code, and today's trade — send your code away, or work almost unprotected. Code Guardian refuses that trade. The code stays on your machine, you get the finding, and you get the fix.

Four numbers hold it together: F1 71.43, repair 90.32, latency 2.2 seconds, and leak-free on the harness. Thank you. I would be glad to take your questions."

*(Stop talking. Look at the panel. Wait.)*

**During Q&A (you have a full 20 minutes — slow down, answer properly):**
- Briefly restate the question in your reframe. It confirms you understood and buys thinking time.
- With 20 minutes you can give a full answer and then open the matching appendix slide — put A1–A7 on the projector when it helps.
- Use the QA_PREP structure: Frame → Anchor (one number) → Concede (the smallest honest limit). Aim for ~60–90 s per answer; you're not racing the clock.
- It's fine to pause and think. Silence reads as care, not weakness.
- Don't apologise. Don't say "good question." Just answer.

---

## Pacing checkpoints

If you're behind at these slides, you need to trim:

| Checkpoint     | Slide | Time elapsed should be |
|----------------|-------|------------------------|
| End of Act I   | 5     | ~5 min                 |
| End of Act III | 12    | ~13 min                |
| End of Act IV  | 14    | ~16 min                |
| End of Act V   | 19    | ~23 min                |
| End of Act VI  | 23    | ~28 min                |

The slot is 30 minutes, so finishing the content near 29 min is on target — the PRE-EMPT lines add about a minute — with a small buffer. If you're at slide 19 and the clock is past **26 minutes**, **keep slide 22 to the limitations column only and cut slide 23 (Contributions) to 30 seconds**. Never run over into the 20-minute Q&A.

## Voice / tone notes

- **Pause** after every number. The audience needs a beat to take in a percentage.
- **Don't read the slide aloud.** The slide carries the artefact; you carry the argument.
- **Plain English.** "Stage one is detection," not "the first stage performs the detection task."
- **No first person plural.** Say "the thesis" or "Code Guardian," not "we built."
- **Don't apologise.** Don't say "this might not be perfect, but…" Anchor a limitation in a future-work item instead.
- **Land each requirement.** When you say "R1" on a results slide, point at the badge in the corner.
- **Flow, but punctuate with short beats.** Keep the connective tissue in measured, complete sentences — but at the turns (the problem on 2–3, the surprise on 16, the close), drop in a short, sharp sentence and let it land. Calm and continuous overall, with deliberate punch where it counts. Punch is for emphasis, not for every line — a defense that reads as all slogans loses the panel.
- **Plant and call back.** The line "send your code off your machine, or work almost unprotected" is the through-line — state it on slide 3, then again on 21 and at the close.
- **Let the surprise breathe.** Slide 16 is the turn. Slow down and pause before delivering the codellama number; don't bury it in the next sentence.
- **Headline, then proof.** Open each results slide with one plain sentence, then the number — not the other way round.

## Pre-defense checklist

- [ ] Rehearse slides 14–19 (the results block) on their own — this is where Q&A traction lives
- [ ] Rehearse the **PRE-EMPT** lines until they sound voluntary, not defensive — they answer the examiner's top questions inside the talk
- [ ] Say the QA_PREP.md anchors out loud — the anchor stats must be muscle memory
- [ ] Re-run make_assets.py and rebuild the deck, then eyeball the architecture diagram, screenshot, and bar charts in the exported PDF
- [ ] Print the QA_PREP.md "quick reference card" and tape it inside your binder
- [ ] Hard-reload the deck on the projector laptop the morning of — fonts can be substituted
- [ ] Have a backup PDF export — projector apps fail
- [ ] Bring water. Sip between slides, not during them.
