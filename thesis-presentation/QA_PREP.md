# Q&A Attack-Prep — Code Guardian Defense

**Use:** rehearse 1–2 days before the defense. For each likely question, the answer has four parts:
1. **Frame** — one plain line that turns the question into terms that favour you.
2. **Anchor** — one number or source the examiner cannot argue away.
3. **Concede** — the smallest honest thing you give up.
4. **Route** — the appendix slide you open if they push.

If you remember one thing per question, remember the **anchor**. The rest is just how you say it.

---

## CATEGORY A — DATASET & SELECTION BIAS

### A.1 — "Why only 101 cases? That's too small."

**Frame:** "Small curated test sets are the norm in this field, not a shortcut."

**Anchor:** A recent benchmark, CWEval (Peng et al., 2025), uses **119 hand-built tasks** across 31 CWEs and 5 languages — about the same size as my 101. The same paper shows the big auto-collected benchmarks are mostly broken: **only 562 of 1,916 (29.3 %) of CyberSecEval's vulnerable samples actually reproduce.** So bigger is not better here; bigger is often just noisier.

**Concede:** With a set this size I cannot make strong claims about very rare CWE types. That is exactly why I report exact-binomial confidence intervals instead of pretending the numbers are tighter than they are.

**Route:** Appendix A4 — "Why a Curated Corpus."

---

### A.2 — "You built the test set yourself — isn't that biased?"

**Frame:** "I expected that worry and built in four separate defences against it."

**Anchor:** Four things guard against bias: (1) a **held-out 71/30 split** — the TEST half is frozen, so no tuning ever touches the headline numbers; (2) a **15-case external set** taken from OWASP NodeGoat, Juice Shop, and three named CVEs — code I did not write; (3) a **whole-project run on NodeGoat**, which gives a recall figure for a real project, not just for cases I picked; and (4) the corpus is **signed with an Ed25519 key**, so it cannot be quietly changed after the fact.

**Concede:** The cleanest next step would be a second test set chosen by a different researcher. I name that as future work.

**Route:** Appendix A4.

---

### A.3 — "Why not use Juliet / OWASP Benchmark / SecurityEval?"

**Frame:** "There is no existing JS/TS test set that matches this threat model."

**Anchor:** Juliet covers **C, C++, and Java only**. OWASP Benchmark is **Java only**. SecurityEval (Pearce, 2022) is **small, partly synthetic, and its CWE labels do not line up cleanly with the OWASP Top 10**. The closest fit in size is CWEval (2025) at 119 tasks — and that is for many languages, not just JS/TS.

**Concede:** Porting Juliet to JavaScript would be genuinely useful for the whole field — but that is a big infrastructure project on its own, not part of this thesis.

**Route:** Appendix A4 — left column.

---

### A.4 — "Why JavaScript/TypeScript specifically?"

**Frame:** "JS/TS is where the privacy gap matters most and where existing scanners are weakest."

**Anchor:** JS/TS is the most-used language stack on GitHub (Octoverse 2024). Injection bugs dominate the field's benchmarks — Basic & Giaretta (2025) find that **16 of 20 reviewed studies cover injection** — and injection is exactly where Code Guardian is strongest, at **90–100 % recall** for SQL injection, XSS, command injection, and path traversal. So I evaluate where the field already agrees the signal is clearest.

**Concede:** None of this carries over automatically to compiled, statically-typed languages. Those would need their own validation.

---

### A.5 — "Where did the dataset come from, and are you allowed to use it?"

**Frame:** "Every case comes from a known public source, and the licences are clean from end to end."

**Anchor:** The source of each case is written down in `SOURCES.md` and locked into the **Ed25519-signed manifest**. The sources and their licences: **OWASP NodeGoat and Juice Shop → MIT**; **three named CVEs (CVE-2022-24999, CVE-2021-23337, CVE-2022-24771) → public NIST/NVD disclosures**; **OWASP Top 10 and cheat sheets → CC-BY-SA 4.0**; **CWE (MITRE) and NVD → public domain**; **my own synthetic cases → MIT, written by me.** The mix is: 11 real-project snippets, ~25 OWASP-pattern cases, ~35 CWE-tagged synthetic cases, and 30 hand-picked secure (negative) cases — plus a separate 15-case external set, each with its upstream URL and version.

**Concede:** The public sources are almost certainly already in the models' training data. So I treat those numbers as case studies, not as a fair population estimate — the curated split carries the main claims.

**Route:** Appendix A4 — "Why a Curated Corpus."

---

### A.6 — "You wrote the 26-category taxonomy AND the ground-truth labels — a loose matcher could inflate your own recall."

**Frame:** "The taxonomy is a fixed, published file — not a judgement call I make while scoring."

**Anchor:** The category mapping lives in `src/categoryTaxonomy.json` as **26 ordered regex rules** and is pinned by a **snapshot test** (`category-taxonomy.snapshot.test.js`), so it cannot drift between runs. I did not invent the labels either — each case carries a CWE or OWASP identifier you can trace in `SOURCES.md`. And every run prints **per-category counts**, so anyone can take the raw findings, re-group them under a *different* taxonomy, and re-score without asking me. The mapping was frozen before evaluation, together with the 71/30 split — there is no free knob left at scoring time.

**Concede:** A second person applying the CWE tags would remove the last bit of single-author judgement. That is named as future work.

**Route:** Appendix A1/A2 — per-category counts; Appendix A4 — provenance.

---

## CATEGORY B — DETECTION ACCURACY (R1)

### B.1 — "20 % false-positive rate is too high for production."

**Frame:** "The real number is 10 %, which is competitive, and the confidence gate keeps it there while raising precision."

**Anchor:** My headline is **10.0 % FPR** at F1 = 71.43 % with no gate. Add the confidence filter at ≥ 0.67 and FPR stays at 10 % while **precision climbs to 78.13 %**. Be precise about what that filter is. It is a rescore-time step, not a product toggle, and although it is *built* as an inter-run agreement gate (confidence = agreeing runs ÷ N), the evaluation runs share a fixed seed and are byte-identical — so there is no run variance to gate on, and it reduces to a canonical-category filter: it drops findings the model could not map to a specific category (the low-signal 'other' bucket). For contrast, **IRIS with GPT-4 (Li et al., ICLR 2025) reports an 84.82 % false-discovery rate** on whole-repo Java — that is precision near 15 %. My 78 % precision under a tight constraint set is in a different league.

**Concede:** On the frozen test split one configuration shows 0 % FPR but lower recall. There is a real precision/recall trade-off there, and I show it rather than hide it.

**Route:** Slide 15.

---

### B.2 — "F1 = 71 % isn't impressive — GPT-4 gets over 90 %."

**Frame:** "GPT-4 gets 90 % in the cloud. My system is local-only, sends nothing out, and runs on a laptop."

**Anchor:** CORRECT (Li et al., 2025) shows that even with rich cross-function context, LLM evaluation lands at **F1 above 70 % and precision around 80 %** — and that function-level scoring *under-rates* what the model can do. My **71.43 % F1 and 72.46 % precision** are function-level, with no cloud, on an 8B model quantised to 4-bit. That is a strong result given the handicap. Frontier cloud models will always win raw F1; this thesis competes on the constraints, not on raw score.

**Concede:** A side-by-side with GPT-4's published JS numbers would be a clean one-paragraph addition after the defense.

**Route:** Appendix A5 — "Why No Cloud-LLM Baseline."

---

### B.3 — "Your confidence gate is just a way to inflate precision."

**Frame:** "It is a confidence filter on weakly-categorised findings — and I am precise about its mechanism, because the easy reading of it is wrong."

**Anchor:** With the filter at ≥ 0.67: **F1 goes 71.43 → 74.07 %**, **precision 72.46 → 78.13 %**, and **recall stays at 70.42 %** — unchanged. Here is the honest mechanism, because it is easy to mis-state. First, it is a **rescore-time evaluation step, not a product feature** — the shipped extension's own gate (`minConfidence`) is off by default. Second, it is *built* as an inter-run agreement gate, but the three evaluation runs use a fixed seed and are **byte-identical** — I verified all 101 cases are identical across runs — so there is no run-to-run disagreement to gate on. What the filter drops are findings the model tagged with a type that does not map to a specific canonical category — the catch-all 'other' bucket. In this run that is exactly **six findings, all false positives**, which is why precision rises and recall does not move. Both the filtered and unfiltered numbers are in the thesis, so the reader picks the bar.

**Concede:** Because the runs are identical, this filter cannot show genuine inter-run robustness — that needs rotating seeds, which I list as future work. The 74.07 figure is a real precision gain, but from category confidence, not run consensus.

**Route:** Appendix **A9** (gate before/after table + mechanism — this number was deliberately moved off slide 15 to keep the headline single); A6 for the seed-determinism context.

---

### B.4 — "Why is qwen3:8b your main model and not something bigger?"

**Frame:** "8B at 4-bit is the biggest model that still fits a normal laptop with privacy intact."

**Anchor:** qwen3:8b-q4 needs about **6 GB of VRAM**, so it fits a 16 GB Apple Silicon laptop while VS Code, Ollama, and normal work are all running. A 70B model needs **40+ GB** — that turns "developer laptop" into "developer workstation" and shrinks the group of people who can actually run it. The on-demand latency budget (≤ 5 s) also assumes 8B-class inference.

**Concede:** A 70B model on a local server is a setup I do not test. It would interest air-gapped enterprise users, but it is a different deployment story.

---

### B.5 — "Your SAST baselines look like strawmen — ESLint scores 0 %. How were they set up?"

**Frame:** "Each ran on its own recommended security ruleset, and all three were matched to the model's scope on purpose. If anything, that understates them."

**Anchor:** The configs are written on appendix slide **A7**: Semgrep ran **`p/security-audit`, `p/javascript`, `p/typescript`, and `p/owasp-top-ten`**; CodeQL ran the **`javascript-security-and-quality.qls`** suite; ESLint ran **eslint-plugin-security v4 (recommended)**. The key point: all three were run **one snippet at a time, at the same function-level scope as the model.** That is the only setting that keeps the comparison fair. On a full project, SAST tools see cross-file data flow and catch more — so these numbers are *below* what they would do in production, not above.

**Concede:** A full-project SAST run would show higher baseline recall — but then the scopes would not match the LLM and it would be apples-to-oranges. The function-level framing is the honest one.

**Route:** Appendix A7 — "SAST Baseline Configuration."

---

### B.6 — "Why a general model (qwen3:8b) and not a code-specialized 'coder' model?"

**Frame:** "A coder model *was* in the test — it came last — so the data already answers this."

**Anchor:** The five-model sweep included **codellama**, the code-specialized one. It did worst: **−29.89 F1 with RAG** (the only effect that survived Bonferroni), with **more parse failures** and a tendency to flag every secure case as vulnerable. That fits the task — this is **reasoning plus strict-JSON classification**, not code *completion*, and general instruction-tuned models are better calibrated for that. On hardware, the smallest `qwen3-coder` is a **30B-class model**, which breaks the ~6–8 GB laptop budget that R4 and R5 are built around — the same reason 70B is out (see B.4).

**Concede:** Broader 7B–13B coder ablations are named as future work. And the extension is model-agnostic, so a user *can* run `qwen2.5-coder` locally if they want — it just was not the evaluation headline.

**Route:** Slide 16 (per-model RAG ablation); Future Work.

---

### B.7 — "Your F1 drops from 71 to the low 60s on held-out and external data — doesn't that mean it doesn't generalize?"

**Frame:** "A drop from curated to unseen data is the expected shape in this field — and I report it instead of hiding it."

**Anchor:** The all-101 headline is **F1 71.43**; the frozen held-out split is **61.11**; the external set (code I did not write) is **63.64**. That curated-to-real-world gap is exactly what the literature predicts: **Zhang et al.'s systematic review (2024)** of 300-plus works finds LLM detection gives "desirable results... on synthetic datasets, but performance degrades on more challenging real-world datasets." So the low-60s is the field's normal generalization gap, not a defect — and recall dips while precision holds, which is what a held-out split is for.

**Concede:** A larger external set across more project styles would tighten the estimate; that is named as future work.

**Route:** Slide 15; QA_PREP A.2, G.5.

---

## CATEGORY C — RAG & RQ2

### C.1 — "Your RAG sometimes makes results worse — isn't that a broken design?"

**Frame:** "That RAG helps some models and hurts others is a known field finding, not a Code Guardian bug."

**Anchor:** **RESCUE (Shi & Zhang, 2025)** reports that ordinary RAG "does not significantly improve SecurePass@1 or SecureRate." **He et al. (2024)**, which RESCUE cites, shows that giving the model CWE descriptions alone does **not** improve secure code generation. Two 2025 systematic reviews say the same at field scale — **Basic & Giaretta** and **Sheng et al.** both find retrieved context helps only some configurations and depends on example quality, not a guaranteed gain. My data agrees: qwen3:8b + RAG gains **+3.91 F1**, while codellama + RAG loses **−29.89 F1** — and only that codellama drop survives Bonferroni (**McNemar p = 0.0013**). The mechanism is visible in the error profile: for qwen3:8b the retrieved snippets act as a reference and cut its false-positive rate from **50% to 10%**; for codellama the same context primes a weaker model to flag almost everything — precision collapses and recall falls. Whether RAG helps comes down to whether the model can use the extra context as a reference or is swamped by it. So treating RAG as a per-model choice, not an always-on default, is the disciplined conclusion.

**Concede:** Automatically turning RAG on or off per model, based on this finding, is future work.

**Route:** Slide 16.

---

### C.2 — "Why not fine-tune the model on the RAG corpus instead?"

**Frame:** "Fine-tuning breaks the privacy promise at training time."

**Anchor:** Fine-tuning needs either central training data (which breaks the local-only threat model) or per-user local fine-tuning (which is not realistic for a VS Code extension). Retrieval keeps **both training and inference local** — nothing leaves the machine. The thesis is scoped to **system design and prompt engineering, not model training**, and that scope was set in Chapter 1.

**Concede:** A per-deployment LoRA fine-tune on a developer's own private code is a logical extension — but only if the privacy contract is updated to allow it.

---

### C.3 — "What's actually in your RAG store?"

**Frame:** "CWE patterns, OWASP Top 10 examples, and curated real fix patches — all signed."

**Anchor:** About ~N entries across the corpus's 20 CWE categories, embedded with Ollama and stored in HNSWlib (a vector store), retrieved top-k at inference time. The corpus is **Ed25519-signed**, so the manifest cannot be quietly changed. *(Fill in N from the real store size in src/ragManager.ts before the defense.)*

**Concede:** Letting an organisation add its own private entries is a feature I have not built — and that is probably where most enterprise value would come from.

---

### C.4 — "How does the vector lookup actually work — what does it match against?"

**Frame:** "Retrieval is semantic similarity on the snippet *text* — not keyword search, not a CWE lookup, not a category filter."

**Anchor:** Indexing: each corpus entry's `content` is split into ~1000-character chunks with 200-character overlap (`RecursiveCharacterTextSplitter`), and **each chunk's text** is embedded by a dedicated local model, `nomic-embed-text`, running in Ollama — *not* the analysis LLM. The CWE/OWASP/category/severity labels are carried as **metadata on the side; they are not part of the vector.** Vectors go into an HNSWlib graph on disk (`vector-store/hnswlib.index` + `docstore.json`). Lookup: the query string is the **prompt + the code snippet** (`generateEnhancedPrompt`, `ragManager.ts:508`), embedded with the *same* model so query and corpus share one space; `similaritySearch(query, k=3)` walks the HNSW graph and returns the **top-3 closest chunks** by cosine distance (HNSWlib's default here) — approximate nearest-neighbour, so fast but not an exhaustive scan. Those 3 chunks (with their title/severity/CWE/OWASP shown for context) are pasted into the prompt under "RELEVANT SECURITY KNOWLEDGE." Because one entry can yield several chunks, retrieval is **chunk-level**, and the match is purely on meaning — so it still finds the right guidance when the code never literally says "SQL" or "injection."

**Concede:** Retrieval is single-stage top-k with no re-ranker and no metadata pre-filter (e.g. restricting to a CWE before the vector search) — both are reasonable precision improvements and are future work.

**Route:** Slide 11 (System Architecture); `src/ragManager.ts` (`createDocumentsFromKnowledge`, `searchRelevantKnowledge`).

---

## CATEGORY D — REPAIR (R3)

### D.1 — "One reviewer, n = 25 — that's not a real evaluation."

**Frame:** "The manual review is the qualitative extra. The headline repair number is fully automatic."

**Anchor:** The headline R3 is **90.32 % auto-applicable (252 / 279, n = 279)** — **fully objective and validator-driven, with no human in the loop.** The manual review on 25 cases is the *secondary* check: semantic correctness 89.5 %, combined correctness 68 %. And the field itself admits it has no agreed metric here — **SecRepair (Islam et al., NDSS 2024), §III-C3, says outright that automated repair-quality metrics are "fundamentally inadequate."** My objective auto-applicable rate is a step forward against exactly that gap.

**Concede:** Having a second rater on those 25 cases is the obvious next step, and it is listed in future work.

**Route:** Appendix A3 — "Why the Single-Reviewer Manual Review Is Bounded."

---

### D.2 — "How do you know the repairs are actually secure?"

**Frame:** "A two-stage validator plus the Quick-Fix prompt keeps the developer in the loop."

**Anchor:** Repair is **opt-in**: every patch is confirmed by the developer through VS Code's Quick Fix UI — nothing is rewritten silently. The validator parses the model's output with @babel/parser and rejects prose or broken JS. The 89.5 % semantic-correctness figure comes from manual review by someone who knows the CWE. In the worst case a wrong fix only *appears on screen*, with full context — it never auto-commits.

**Concede:** I do not test whether a "fix" quietly introduces a *different* vulnerability. That adversarial fix-quality testing is out of scope here.

---

### D.3 — "Your repair rate looks too high. What's the catch?"

**Frame:** "Auto-applicable measures whether it parses, not whether it's secure. I report both bars."

**Anchor:** **Auto-applicable 90.32 %** means "the output parses as valid JS/TS" — a syntax bar. **Semantic correctness 89.5 %** (manual, n = 25) means "the fix actually addresses the CWE." **Combined correctness 68 %** (manual) is fix-rate (76 %) × semantic correctness (89.5 %), following the R3 level mapping in Section 5.6.3. The detail breakdown: strategy-aligned 94.7 %, directly runnable as-is 42.1 % — and that low run-as-is rate is exactly why the *headline* is the parse-level number, not the executable one. Two bars on purpose, so the reader picks the one that fits their workflow. (Note: an earlier validator pass scored 0 % auto-applicable before the @babel/parser config was fixed — that history is in evaluation.tex.)

**Concede:** A third metric — "does the fix break existing tests" — is the right next instrument, but it needs test infrastructure the curated corpus does not have.

---

## CATEGORY E — USABILITY & LATENCY (R4)

### E.1 — "2.2 s is too slow to feel interactive."

**Frame:** "2.2 s is the on-demand band — exactly where I said it would land."

**Anchor:** I committed to **three latency bands in Chapter 2, before evaluation**: real-time ≤ 500 ms (SAST only), interactive ≤ 1.5 s, and on-demand ≤ 5 s. qwen3:8b + RAG at **2,216 ms sits comfortably inside on-demand.** If you want interactive speed, **gemma3:1b + RAG (1,019 ms)** and **qwen3:4b (1,328 ms)** both qualify — users have a real choice. Real-time was deliberately left out of scope.

**Concede:** Streaming partial results to reach the real-time band is future work.

**Route:** Slide 18.

---

### E.2 — "How does this work on Windows / Linux / Apple Silicon?"

**Frame:** "Any platform Ollama supports; I tested mainly on Apple Silicon."

**Anchor:** Ollama runs on macOS, Linux, and Windows. My headline numbers were measured on an Apple Silicon M-series with 16 GB of unified memory. The reproducibility harness ships as a **Node 20.19.0-alpine** container, so it runs the same on any Docker host.

**Concede:** I do not calibrate latency per platform (CUDA vs Metal vs CPU). That is not in the thesis.

---

## CATEGORY F — PRIVACY (R5)

### F.1 — "100 % leak-free sounds suspiciously perfect."

**Frame:** "It is measured on a finite test harness, and I am clear about what that harness covers."

**Anchor:** leakFreeRate = 100 % (12/12) on **12 hand-written prompt-injection cases** — 9 pure-injection and 3 injection-plus-real-vuln — that *try* to leak the prompt or hijack the model. It is not luck: the defence is **structural**. Analysis instructions live in the *system* role, while user code is delivered as *data* in the user role; decoding is JSON-mode; the output is **schema-constrained** to `{issues:[…]}`, so there is no free-text channel to echo the system prompt or acknowledge an injected command; and it is single-turn, so a "wait for part 2" directive cannot escalate. On the 3 mixed cases the real vulnerability was **still detected (3/3)**. Be precise about the stricter reading the thesis reports: **schemaValidRate = 83.3 % (10/12)** — this is the schema-validity rate, *not* a leak rate — because two cases returned an *empty* response instead of a clean refusal, a benign bail-out rather than a leak. So 100 % means "no leak observed," not "proven impossible." Separately, the network boundary is enforced in code: the extension's network policy permits loopback only (`src/networkPolicy.ts`), and a source-leak scan over the corpus found **zero non-loopback references across 9,488 code windows**. The signed corpus (Ed25519) is a third, independent privacy check.

**Concede:** A live network capture across the full corpus run, and a full red-team audit instead of my 12 cases, would both strengthen this. That is why I frame the figure as harness-bounded, not absolute.

---

### F.2 — "Couldn't the model still leak through RAG retrieval?"

**Frame:** "RAG is read-only, from a signed local store — there is no inbound channel."

**Anchor:** The RAG entries are built ahead of time, signed with Ed25519, and loaded when the extension starts. Retrieval is **read-only and local** — it never makes a network call at inference time. The separate vulnerability-data refresh is **off by default** (`enableExternalDataFetch = false`, the zero-egress policy) — the extension ships with pre-bundled data and runs fully offline. Even when a user turns it on, it fetches **only public NVD/OWASP/CWE metadata**, on a 24-hour cache, and never includes user code. The Chapter 4 threat model lists every channel and I check each one.

**Concede:** If an attacker is already on the developer's machine and re-signs the manifest, that is out of scope — that is an endpoint-compromise threat, not a network one.

---

### F.3 — "How do you verify privacy actually holds at runtime?"

**Frame:** "Three independent checks: a loopback-only network policy, a source-leak scan, and a signed corpus."

**Anchor:** (1) The extension talks to Ollama on loopback only — its network policy allows 127.0.0.1 and localhost and blocks everything else (`src/networkPolicy.ts`), and the container binds the port to 127.0.0.1. (2) A source-leak scan over the corpus found **zero non-loopback references across 9,488 code windows**. (3) The RAG manifest signature (Ed25519) is verified on load. Three separate checks means one of them failing cannot silently break the privacy promise.

---

### F.4 — "How does the signed RAG corpus actually work — and what stops retrieval poisoning?"

**Frame:** "Two independent checks at load — a content hash and an Ed25519 signature — and it fails closed."

**Anchor:** RAG feeds retrieved knowledge into the prompt as *trusted* context, so a swapped knowledge base is a real attack — and a quantified one: a 2024 RAG-security survey (**Zhou et al.**) reports that poisoning just **0.04 % of a corpus (10 paragraphs) can reach a 98.2 % retrieval-hijack rate.** At load, `verifyCorpus()` (`src/corpusVerifier.ts`) runs two checks against the manifest (`security-knowledge/corpus-manifest.json`): (1) it **recomputes the SHA-256** of each on-disk file and compares it — any mismatch aborts; (2) it verifies the manifest's **base64 Ed25519 detached signature** against the shipped public key — invalid aborts with "possible tampering." The signed payload is a canonical serialisation that **includes `source` and `retrievedAt`**, so provenance is bound to the signature — an attacker cannot even rewrite *where* a fact came from without breaking it. Only the **public** key ships (in the repo and the Docker image); the private key lives outside the repo, so the corpus can be verified but not forged. `requireSignedCorpus` defaults to **true**, so a verification failure is fatal — the RAG refuses to load.

**Concede:** This is integrity, not secrecy. If an attacker already holds the private key or has fully compromised the endpoint, re-signing is possible — that is an endpoint-compromise threat, out of scope. The manifest currently covers one aggregated file (`knowledge-base.json`).

**Route:** Appendix A4 (provenance); `src/corpusVerifier.ts`.

---

### F.5 — "Is 'just run it locally' your own idea, or an accepted best practice?"

**Frame:** "Keeping sensitive code on local LLMs is a documented industry recommendation, not a personal preference."

**Anchor:** An industry study on ChatGPT for secure coding — **Espinha Gasiba et al. (2024)** — recommends outright: "Use local LLMs to prevent internal data leakage," kept "separate from broader networks," to safeguard proprietary code. A 2025 cybersecurity review (**Kaur et al.**) makes the same case: open-source local LLMs keep sensitive data on-premises and help meet rules like GDPR. Code Guardian's loopback-bound design is the implementation of exactly that advice.

**Concede:** Those papers recommend local deployment; they do not measure a specific tool. The measurement that this design actually holds is my own (F.1, F.3).

**Route:** Slide 12; Appendix A4.

---

## CATEGORY G — METHODOLOGY & STATISTICAL DISCIPLINE

### G.1 — "Bonferroni is very strict — are you over-correcting?"

**Frame:** "I report both the raw McNemar p-values and the Bonferroni-corrected ones. The reader decides."

**Anchor:** Across all the paired RAG comparisons, **only codellama's −29.89 F1 effect survives Bonferroni at α = 0.01** (McNemar p = 0.0013, family-adjusted). The other four effects do not — and I say so plainly. I chose the strict correction on purpose, because this field is full of cherry-picked single comparisons.

**Concede:** Holm-Bonferroni or BH-FDR are less strict alternatives, and reporting them as a supplement would be worthwhile.

---

### G.2 — "Three runs is too few for any statistical claim."

**Frame:** "Two things are separate here — the shipping extension's multi-seed consensus, and the evaluation's fixed-seed runs."

**Anchor:** The **extension** runs detection in **two passes with distinct seeds (42, 137)** and keeps a finding only when both passes agree — a consensus step built into the product (`src/analyzer.ts`). The **evaluation** is deliberately different: it pins **seed = 42 across its three runs** for reproducibility, so those runs are byte-identical by construction. That is why R2 inter-run agreement is reported as a property of **deterministic decoding**, not model self-consistency, and why the consensus filter's discriminative value cannot be demonstrated under the evaluated protocol. My statistical claims (McNemar, exact-binomial) are at the **case level (n = 101)**, not the run level. Quantifying the filter under seed rotation in the harness is named as future work.

**Concede:** I would expect run-to-run variance once the evaluation rotates seeds, especially on cases near the decision boundary — that is the measurement the current fixed-seed protocol does not provide.

**Route:** Appendix A6.

---

### G.3 — "How did you pick the threshold scales for R1–R5?"

**Frame:** "They were fixed in Chapter 2 before any evaluation — not chosen afterwards."

**Anchor:** Each requirement maps to a fixed acceptance scale tied to its metric: **R1 and R2 use four levels** (High / Medium / Low / Insufficient), while **R3 and R4 use a coarser three-level scale**, because fine repair and latency distinctions are not reliable on small samples; **R5 is a binary checklist** — privacy is a design constraint, not a spectrum. All were **set in the requirements chapter before any model was run** — the commitment device that stops me moving the goalposts mid-evaluation. And the bands aren't arbitrary: **R1/R2 accuracy bands follow IR/SE convention** (Johnson 2013; Ji 2023), **R3 repair** on automated-patch-quality critique (Monperrus 2014), and **R4 latency** on HCI response-time limits (Card 1983; Nielsen 1994). The full scale-and-source table is on the projector as **Appendix slide A8**.

**Concede:** The thresholds are still author-set. Independent calibration is future work.

**Route:** Put up **slide A8** (Requirement Scales — Metrics, Thresholds & Sources); the same table is in Chapter 2 (R1–R5 requirement sections).

---

### G.4 — "How do you know the evaluation is actually reproducible?"

**Frame:** "It is pinned and deterministic — and I measured the determinism rather than assuming it."

**Anchor:** Two layers. (1) **Pinned environment** — the harness runs in a Docker image fixed to **Node 20.19.0-alpine** with `npm ci` (exact lockfile, no version drift); it ships the source, the signed corpus, and the public key, but **not** the private key (`Dockerfile`). (2) **Deterministic decoding** — temperature 0, fixed seed 42, JSON mode, fixed prompt. Then `evaluation/reproducibility.js` *measures* whether that determinism actually holds: it runs each case three times with the same seed and reports **byteIdentityRate** (raw output identical across runs) and **setIdentityRate** (the canonical (category, line) issue set identical). Both came back **100 %** on the probe — so the runs are byte-identical by construction, not by luck.

**Concede:** This is same-seed determinism on a 10-case probe — it shows the pipeline is reproducible, not that conclusions are robust to *changing* the seed (that is the consensus-filter caveat, future work, see G.2). And the container pins the toolchain, not the Ollama model weights, which are pulled at runtime — so cross-machine identity assumes the same model build.

**Route:** Appendix A6; `evaluation/reproducibility.js`.

---

### G.5 — "You're not training a model — so why a 'train/test' split?"

**Frame:** "Fair point — nothing about the model is trained. The split exists to keep one tuning choice honest: where I set the confidence cutoff."

**Anchor:** The LLM (qwen3:8b) runs **as-is** through Ollama — no fine-tuning, no weight updates. The only knob fit during scoring is the **confidence cutoff** (the ≥ 0.67 gate): findings below it are dropped, trading a little recall for precision. The risk is choosing that cutoff by looking at the same cases I then report on — that inflates the number. So I split the 101 cases (deterministic seed) into a **tuning half of 71** ("train": 50 vulnerable + 21 secure) and a **frozen half of 30** ("test": 21 vulnerable + 9 secure). I pick the cutoff using **only** the 71, lock it, and score the 30 **once**. That frozen-half result is **F1 61.11** — honest, because the 30 cases never influenced the cutoff. A separate **15-case external set** (NodeGoat, Juice Shop, 3 real CVEs — code I did not write) gives **F1 63.64**. Both sit below the all-101 headline of 71.43, which is the expected generalization gap, reported rather than hidden.

**Concede:** "Train/test" is borrowed machine-learning terminology; here "train" is really a **threshold-tuning / development split**, not model training. I use the conventional term, but no weights are learned. (Note too: the "71/30" is the train/test *count* — not the corpus's 71-vulnerable / 30-secure composition, which is a separate, coincidental 71/30.)

**Route:** A.2 (dataset bias); `evaluation/held-out-threshold.js`, `datasets/split-2026-04-28.json`.

**Plain-English version (use if the question comes from confusion, not attack):**
- Each finding comes with a confidence ("85% sure"). One setting — a **cutoff** — decides the minimum confidence worth reporting. Low cutoff = catch more bugs but more false alarms; high cutoff = the reverse.
- **"Tuning"** = trying a few cutoffs and keeping the one that scores best. **"Tuned on the 71"** = the 71 cases are the ones I used to *pick* that cutoff.
- If I picked the cutoff by looking at all 101 and then graded all 101, the score would flatter itself. So I pick the cutoff on the 71, then grade the sealed 30 — which never touched the choice. Their score (61.11) is the trustworthy one.
- The external 15 (real projects I didn't write) is the same idea, one step stronger: brand-new code from outside my collection.

---

## CATEGORY H — RELATED WORK

### H.1 — "Why didn't you compare against LLMSecGuard?"

**Frame:** "LLMSecGuard is a concept paper. My system is what they listed as future work."

**Anchor:** **LLMSecGuard (Kavian et al., EASE 2024)** is a 4-page framework paper with **no measured performance numbers**. Its Section 6 future work says: "integrate LLMSecGuard into at least one popular IDE." Code Guardian has actually *delivered* that — IDE-native, measured, and reproducible.

---

### H.2 — "IRIS uses GPT-4 and gets better numbers."

**Frame:** "Different scale, different language, different threat model."

**Anchor:** **IRIS (Li et al., ICLR 2025)** runs on **whole-repo Java** (~300K lines on average) with **cloud GPT-4**, and reports an **84.82 % false-discovery rate** — precision around 15 %. Code Guardian is function-level JS/TS on a local 8B model, with **precision 72.46 % (78.13 % gated).** Mine is deliberately smaller in scale — it runs on a laptop, not a server farm. The two systems answer different questions.

---

### H.3 — "Where does Code Guardian sit in the SAST + LLM literature?"

**Frame:** "On the complementarity track that the recent survey endorses."

**Anchor:** **Zhou et al., TOSEM 2025** writes: "traditional techniques, such as rule-based detectors or program analysis-based repair tools, encounter challenges due to high false positive rates and their inability to work for diverse types of vulnerabilities." That peer-reviewed survey directly motivates combining LLMs with SAST — which is exactly what Code Guardian does: the SAST baselines act as a deterministic floor, and the LLM extends coverage.

---

### H.4 — "How does each tool in the slide-7 matrix actually work, and why those ratings?"

**Frame:** "Each row is a different detection *paradigm*; the rating falls straight out of how the tool is built — so I can walk each one."

**Anchor:** Five mechanisms, grouped into three paradigms:
- **GitHub Copilot** (cloud LLM assistant; Chen et al., 2021) — a cloud-hosted model wired natively into the editor: you type or ask, it completes, explains, and suggests fixes. The build dictates the row — native IDE integration and strong generative reasoning give it accuracy and repair, but **every request leaves the machine, so it fails privacy (R5) by construction**, and its output is free-form text, not a structured findings schema.
- **Semgrep** (rule-based SAST; Semgrep docs) — matches source against a registry of predefined patterns (`p/security-audit`, `p/owasp-top-ten`, …). Deterministic, fast, fully local → consistency and privacy are high; pattern-matching without deep data-flow → low-ish accuracy; **it only warns — no repair (R3)**.
- **CodeQL** (taint-analysis SAST; CodeQL docs) — compiles code into a queryable database and runs data-flow / taint queries (the `javascript-security-and-quality` suite) over it. Richer than Semgrep's pattern match → medium accuracy; deterministic and local; **detection-only, no repair**.
- **IRIS** (research prototype; Li et al., ICLR 2025) — **couples an LLM with a static analyzer** to push reasoning further than either alone, run as a **whole-repository batch** pipeline assuming a cloud model → no IDE workflow (R4), no repair (R3), no on-device privacy (R5).
- **SecRepair** (research prototype; Islam et al., NDSS 2024) — **fine-tunes a model for secure repair** rather than prompting one, framed as a full data→model→eval pipeline, **batch-evaluated and mostly on C/C++** → produces repairs but no IDE deployment and no privacy story.

The decisive point is the same for everyone, and each paradigm hard-fails a *different* member of the trio: **cloud assistants fail R5 (privacy), local SAST fails R3 (repair), research prototypes fail R4 and R5 (batch — no IDE, no on-device privacy)** — so none of them lands R3 + R4 + R5 (repair + IDE-grade latency + privacy) together, and Code Guardian is the only row that does. R1/accuracy is deliberately *not* in the trio: Code Guardian is only **Medium** on accuracy, so the gap it uniquely closes is repair + usability + privacy. That single sentence is the whole slide.

**Concede:** The slide compresses the thesis's graded scale (`\rfull`/`\rmed`/`\rmedlow`/`\rnone`) into ✅/🟡/❌, so two Copilot cells read more coarsely than the Chapter 2 tables — the thesis rates Copilot **consistency (R2) medium-low** and **usability (R4) high** ("Copilot leads on usability"), whereas the slide shows R2 ✅ and R4 🟡. Neither softens the claim: Copilot is excluded by **privacy (R5)** regardless of its R4, SAST by **repair (R3)**, and the research prototypes by **IDE integration (R4)** — each of those three exclusions is uncontested. If pushed on a specific cell, defend it from the thesis tables, not the slide symbols.

**Route:** Slide 7; Chapter 2 related-work tables (`tab:eval-sast`, `tab:eval-llm`, `tab:eval-privacy-ide`).

---

## CATEGORY I — DEPLOYMENT & REAL-WORLD VALIDITY

### I.1 — "Only one real project (NodeGoat) — that's anecdotal."

**Frame:** "NodeGoat is the deliberate end-to-end check, not the headline."

**Anchor:** The headline numbers come from the 101-case curated corpus plus the 15-case external set across NodeGoat, Juice Shop, and 3 CVEs. The whole-project NodeGoat run is the **integration test** — it proves the system works at project scale, not just file by file. Validating on more projects is named as future work (slide 22).

**Concede:** Covering more project styles (React, Node, Express, NestJS) would strengthen the generalisation claim.

---

### I.2 — "Have developers actually used this?"

**Frame:** "It's published on the VS Code Marketplace; usage analytics are out of scope by the privacy contract."

**Anchor:** The extension is live on the Marketplace with N installs *(check the Marketplace stats before the defense).* By design Code Guardian collects **zero telemetry** — there is no usage data because there is no exfiltration. A proper developer study is future work; it needs a different, IRB-equivalent setup.

**Concede:** Without telemetry the usage signal is anecdotal — I rely on install counts and issue-tracker activity.

---

## CATEGORY J — CONCEPTUAL / NOVELTY

### J.1 — "What's actually new here?"

**Frame:** "The niche is clearly empty — nobody else covers all of it."

**Anchor:** No reviewed system offers **all of**: local inference + IDE-native + real-time/on-demand latency + JS/TS + both detection AND repair. Each close comparator misses something: **IRIS** (batch, whole-repo, cloud GPT-4), **RESCUE** (code-generation task, batch), **SecRepair** (batch fine-tuning, C/C++), **LLMSecGuard** (concept paper, no IDE). Code Guardian sits at the intersection they all miss. Independent backing: **Zhou et al. (TOSEM 2025)** reviewed **58 LLM-vulnerability studies** and found **none were integrated into a developer's workflow — all were evaluated offline.** The niche is not just empty in my reading; a peer-reviewed survey says so.

---

### J.2 — "Isn't this just a wrapper around Ollama?"

**Frame:** "Ollama is one of four subsystems. The thesis is the integration and the evaluation."

**Anchor:** The thesis contributes: (1) a two-stage pipeline with **structured JSON contracts at every boundary**, (2) a **RAG knowledge base with a signed manifest**, (3) **vulnerability-data integration** (NVD/OWASP/CWE), (4) a **deterministic harness** (seed = 42, byte-identical runs), (5) a **canonical-taxonomy matcher** (`src/categoryTaxonomy.json` maps model labels to a 26-class bucket), and (6) an **empirical 303-invocation-per-config study** with real statistical discipline. Ollama just runs the model; everything else is the system.

---

## Quick reference card  ·  print and tape to the inside of your binder

| Anchor stat                  | Use when…                                                        |
|------------------------------|------------------------------------------------------------------|
| **71.43 % F1**               | Asked about detection accuracy                                   |
| **78.13 % precision (gated)**| Asked about FPR / false alarms                                   |
| **90.32 % auto-applicable** (parses & applies; ~68 % combined-correct) | Asked about repair quality            |
| **2,216 ms median**          | Asked about latency / interactivity                              |
| **100 % leakFreeRate**       | Asked about privacy guarantee                                    |
| **−29.89 F1 (codellama RAG)**| Asked "is RAG always good"                                       |
| **84.82 % FDR (IRIS)**       | Asked "20 % FPR too high"                                        |
| **29.3 % CyberSecEval repr.**| Asked "101 is too small"                                         |
| **CWEval = 119 tasks**       | Asked "your dataset is small"                                    |
| **SecRepair §III-C3**        | Asked "single reviewer, n = 25 is weak"                          |
| **RESCUE 2025**              | Asked "your RAG hurts quality"                                   |
| **Zhou et al. TOSEM 2025**   | Asked "isn't SAST enough"                                        |
| **Ed25519 sig + SHA-256, fails closed** | Asked "how is the signed corpus verified / poisoning" (F.4) |
| **byteIdentity & setIdentity = 100 %** | Asked "is the evaluation reproducible" (G.4)            |
| **Schema-constrained output channel** | Asked "how does it resist prompt injection" (F.1)        |
| **McNemar p = 0.0013**       | Asked "statistical significance of codellama RAG drop"           |
| **Train = cutoff-tuning split (no model trained)** | Asked "why train/test if you're not training" (G.5) |
| **Zhou TOSEM: 58 studies, all offline** | Asked "field already does in-IDE LLM detection" (J.1) |
| **Gasiba 2024: "use local LLMs"** | Asked "is local-only your own idea" (F.5) |
| **RAG poisoning 0.04 % → 98.2 %** | Asked "why sign the corpus / poisoning" (F.4) |
| **Zhang SLR: curated → real-world drop** | Asked "F1 drops on held-out, doesn't generalize" (B.7) |
| **A7 = SAST rulesets + scope parity** | Asked "your baselines are strawmen / how configured"    |
| **Per-paradigm mechanism (H.4)** | Asked "how does each tool in the matrix actually work"          |

## Q&A budget — 20 minutes

You have a full **20-minute** Q&A. That is roughly **10–15 questions** — plenty of time, so answer properly instead of racing.
- Briefly restate the question in your reframe — it confirms you understood and buys a few seconds to think.
- Give the full answer (Frame → Anchor → Concede), then **open the matching appendix slide** (A1–A7) when it helps. You have time to navigate.
- Aim for about **60–90 seconds per answer.** It is fine to pause and think; silence reads as care, not as being stuck.
- If a question is outside the thesis scope, say so plainly and point to the relevant future-work item.
- Never apologise. Never say "good question." Just answer.
