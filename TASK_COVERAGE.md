# Task Description Coverage Map

A line-by-line mapping from `code-guardian-thesis-report/src/task_description.tex` to the thesis chapters and the implementation, with file:line citations. Use this as the answer to *"does the delivered work cover what the task asks for?"*

Verdicts: **Covered** = claim is delivered as specified. **Substituted (justified)** = the thesis deviates from the literal text but documents the substitution and its penalty in the body. **Exceeds** = the thesis delivers more than the spec.

---

## 1. Problem framing (task paragraph 1)

| Spec claim | Thesis location | Verdict |
|---|---|---|
| Traditional SAST (Semgrep, CodeQL) effective for predefined patterns but cannot reason about cross-file or context-dependent weaknesses | [introduction.tex:5](code-guardian-thesis-report/src/chapters/introduction.tex#L5), [analysis/related_works/traditional_sast.tex:7](code-guardian-thesis-report/src/chapters/analysis/related_works/traditional_sast.tex#L7) | Covered |
| Cloud LLM assistants give stronger semantic reasoning but compromise data confidentiality and reproducibility | [introduction.tex:5](code-guardian-thesis-report/src/chapters/introduction.tex#L5), [analysis/related_works/privacy_ide.tex:53](code-guardian-thesis-report/src/chapters/analysis/related_works/privacy_ide.tex#L53) | Covered |
| Aim: design and evaluate a fully local, privacy-preserving secure-coding assistant for VS Code | [introduction.tex:76](code-guardian-thesis-report/src/chapters/introduction.tex#L76) (objective statement), entire thesis | Covered |
| Combine LLMs with Retrieval-Augmented Generation | [concept/concept_derivations.tex:11](code-guardian-thesis-report/src/chapters/concept/concept_derivations.tex#L11), [concept/components.tex:13-16](code-guardian-thesis-report/src/chapters/concept/components.tex#L13-L16) | Covered |
| All processing on the developer's machine under a strict zero-egress policy | [implementation/privacy_enforcement.tex:1](code-guardian-thesis-report/src/chapters/implementation/privacy_enforcement.tex), [evaluation/eval_r5_privacy.tex:35](code-guardian-thesis-report/src/chapters/evaluation/eval_r5_privacy.tex#L35), code at [src/networkPolicy.ts](code-guardian-extension/src/networkPolicy.ts) | Covered |
| Source code and intermediate data remain confidential | [implementation/privacy_enforcement.tex](code-guardian-thesis-report/src/chapters/implementation/privacy_enforcement.tex), [implementation/agent.tex:60](code-guardian-thesis-report/src/chapters/implementation/agent.tex#L60) | Covered |

---

## 2. System modes and architecture (task paragraph 2)

### 2.1 Operational modes

| Spec claim | Thesis location | Verdict |
|---|---|---|
| Real-time inline diagnostics with immediate vulnerability alerts | [implementation/system_workflow.tex:8-12](code-guardian-thesis-report/src/chapters/implementation/system_workflow.tex#L8), [implementation/user_interface.tex:6](code-guardian-thesis-report/src/chapters/implementation/user_interface.tex#L6) | Covered |
| Asynchronous **audit** mode | [implementation/system_workflow.tex:24](code-guardian-thesis-report/src/chapters/implementation/system_workflow.tex#L24) ("Audit Mode: AST + LLM Hybrid Pipeline") | Covered |
| **Question-answering** mode | [implementation/user_interface.tex:25](code-guardian-thesis-report/src/chapters/implementation/user_interface.tex#L25) ("Interactive Analysis View and Contextual Q\&A"), [concept/components.tex:21](code-guardian-thesis-report/src/chapters/concept/components.tex#L21) | Covered |
| Offline retrieval of CWE / CVE / OWASP entries | [concept/components.tex:13-16](code-guardian-thesis-report/src/chapters/concept/components.tex#L13-L16), [implementation/agent.tex:42-45](code-guardian-thesis-report/src/chapters/implementation/agent.tex#L42) | Covered |

### 2.2 Modular architecture

| Spec claim | Thesis location | Verdict |
|---|---|---|
| LLM inference layer | [implementation/agent.tex](code-guardian-thesis-report/src/chapters/implementation/agent.tex), [implementation/tech_stack.tex:14](code-guardian-thesis-report/src/chapters/implementation/tech_stack.tex) (Ollama) | Covered |
| Local retrieval pipeline | [concept/components.tex:13-16](code-guardian-thesis-report/src/chapters/concept/components.tex#L13-L16), [implementation/agent.tex:42](code-guardian-thesis-report/src/chapters/implementation/agent.tex#L42) (HNSW + nomic-embed-text) | Covered |
| VS Code extension interface | [implementation/user_interface.tex](code-guardian-thesis-report/src/chapters/implementation/user_interface.tex), [concept/system_architecture_and_design.tex](code-guardian-thesis-report/src/chapters/concept/system_architecture_and_design.tex) (C4 views) | Covered |

### 2.3 Privacy enforcement triad

| Spec claim | Thesis location | Code | Verdict |
|---|---|---|---|
| Local embeddings | [implementation/tech_stack.tex:16](code-guardian-thesis-report/src/chapters/implementation/tech_stack.tex), [implementation/privacy_enforcement.tex:19](code-guardian-thesis-report/src/chapters/implementation/privacy_enforcement.tex) | [ragManager.ts:38-54](code-guardian-extension/src/ragManager.ts#L38-L54) (nomic-embed-text via local Ollama) | Covered |
| Signed corpora | [implementation/privacy_enforcement.tex:32](code-guardian-thesis-report/src/chapters/implementation/privacy_enforcement.tex#L32), [appendices/privacy-verification.tex](code-guardian-thesis-report/src/chapters/appendices/privacy-verification.tex) | [corpusVerifier.ts:52,146](code-guardian-extension/src/corpusVerifier.ts) (Ed25519 + SHA-256 manifest) | Covered |
| Network isolation | [implementation/privacy_enforcement.tex:19](code-guardian-thesis-report/src/chapters/implementation/privacy_enforcement.tex#L19), [evaluation/experimental_setup.tex:30](code-guardian-thesis-report/src/chapters/evaluation/experimental_setup.tex#L30) | [networkPolicy.ts:17-22](code-guardian-extension/src/networkPolicy.ts#L17-L22) (loopback allowlist), Docker-compose loopback bind | Covered |

### 2.4 Reproducibility triad

| Spec claim | Thesis location | Verdict |
|---|---|---|
| Deterministic decoding | [evaluation/experimental_setup.tex:4](code-guardian-thesis-report/src/chapters/evaluation/experimental_setup.tex#L4) (`temperature=0`, seed=42, `format='json'`), [evaluation/eval_reproducibility.tex](code-guardian-thesis-report/src/chapters/evaluation/eval_reproducibility.tex) | Covered |
| Version-pinned dependencies | [evaluation/eval_reproducibility.tex:7](code-guardian-thesis-report/src/chapters/evaluation/eval_reproducibility.tex#L7) (`package-lock.json`), [evaluation/experimental_setup.tex:30](code-guardian-thesis-report/src/chapters/evaluation/experimental_setup.tex#L30) (`npm ci`) | Covered |
| Containerised execution | [evaluation/experimental_setup.tex:30](code-guardian-thesis-report/src/chapters/evaluation/experimental_setup.tex#L30) (Dockerfile pinning Node.js 20.19.0-alpine; `docker-compose.yml` with loopback bind and CPU/RAM caps), [evaluation/eval_reproducibility.tex:7](code-guardian-thesis-report/src/chapters/evaluation/eval_reproducibility.tex#L7) | Covered |

### 2.5 Threat model

| Spec claim (named adversary capability) | Thesis location | Mitigation in thesis | Verdict |
|---|---|---|---|
| Code exfiltration | [introduction.tex:51-58](code-guardian-thesis-report/src/chapters/introduction.tex#L51) (table), [implementation/agent.tex:60](code-guardian-thesis-report/src/chapters/implementation/agent.tex#L60), [analysis/analysis.tex](code-guardian-thesis-report/src/chapters/analysis/analysis.tex) | Loopback-only Ollama + zero-egress gate (`networkPolicy.ts`); local-only embeddings | Covered |
| Retrieval poisoning | [implementation/privacy_enforcement.tex:5](code-guardian-thesis-report/src/chapters/implementation/privacy_enforcement.tex#L5), [evaluation/eval_r5_privacy.tex:63](code-guardian-thesis-report/src/chapters/evaluation/eval_r5_privacy.tex#L63) | Ed25519-signed corpus + SHA-256 manifest verified at load (`corpusVerifier.ts`); `requireSignedCorpus=true` default | Covered |
| Prompt injection | [evaluation/eval_r5_privacy.tex](code-guardian-thesis-report/src/chapters/evaluation/eval_r5_privacy.tex), [implementation/agent.tex:60](code-guardian-thesis-report/src/chapters/implementation/agent.tex#L60), [introduction.tex:57](code-guardian-thesis-report/src/chapters/introduction.tex#L57) (table row) | Strict JSON-only structured-output schema constrains the model to `{message, startLine, endLine}` regardless of content; defensive parser strips fences and rejects non-conformant output; injection corpus exercised by `evaluation/datasets/privacy/injection-corpus.json` | Covered |

The threat-model arms named in the task description appear **verbatim** in [implementation/agent.tex:60](code-guardian-thesis-report/src/chapters/implementation/agent.tex#L60): *"The threat-model arms named in the task description --- code exfiltration, retrieval poisoning, and prompt injection --- are addressed by the network policy, signed corpus, and structured-output schema..."*.

### 2.6 Mitigations enumerated in the spec

| Spec mitigation | Thesis location | Code | Verdict |
|---|---|---|---|
| Corpus signing | [implementation/privacy_enforcement.tex:32](code-guardian-thesis-report/src/chapters/implementation/privacy_enforcement.tex#L32) | [corpusVerifier.ts](code-guardian-extension/src/corpusVerifier.ts) | Covered |
| Network isolation | as 2.3 above | as 2.3 above | Covered |
| Provenance verification | [evaluation/experimental_setup.tex:20](code-guardian-thesis-report/src/chapters/evaluation/experimental_setup.tex#L20) (per-case source URL + upstream commit recorded in `evaluation/datasets/SOURCES.md` and bound into the signed manifest) | `corpusVerifier.ts` + `evaluation/datasets/SOURCES.md` | Covered |

---

## 3. Evaluation plan (task paragraph 3)

### 3.1 Data sources — substitution

| Spec claim | What thesis delivers | Thesis location | Verdict |
|---|---|---|---|
| Benchmark datasets: **Juliet** and **OWASP Benchmark**, ~40-50 CWE-mapped cases | Curated 101-case JS/TS corpus (71 vulnerable + 30 secure) + 15-case external corpus from OWASP NodeGoat, OWASP Juice Shop, and three named CVEs (CVE-2022-24999, CVE-2021-23337, CVE-2022-24771) — total **116 cases** | Substitution justified at [evaluation/experimental_setup.tex:20](code-guardian-thesis-report/src/chapters/evaluation/experimental_setup.tex#L20), restated in [discussion.tex:44-45](code-guardian-thesis-report/src/chapters/discussion.tex#L44), additional context in [evaluation/dataset_details.tex:6,33](code-guardian-thesis-report/src/chapters/evaluation/dataset_details.tex#L6) | **Substituted (justified)** |
| One actively maintained real-world JS/TS project with documented vulnerabilities and verified patches | OWASP **NodeGoat** real-world slice; 7 documented entries; recall reported 3/7 inline → 6/7 audit | [evaluation/experimental_setup.tex:22](code-guardian-thesis-report/src/chapters/evaluation/experimental_setup.tex#L22), [eval_r1_accuracy.tex:162-178](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L162), [discussion.tex:51](code-guardian-thesis-report/src/chapters/discussion.tex#L51), [conclusion.tex:11](code-guardian-thesis-report/src/chapters/conclusion.tex#L11) | Covered |

**Substitution rationale (verbatim from `experimental_setup.tex:20`):** *"Juliet is published by NIST in C/C++ and Java only, and the OWASP Benchmark Project is a Java application. There is no first-party JavaScript port of either, and running this thesis's JS/TS detector against C/C++ or Java would not be meaningful."*

**Substitution penalty quantified (`discussion.tex:45`):** *"The substitution penalty is measured in Section ... under the same headline configuration (`qwen3:8b+RAG`, three runs, confidence gate ≥ 0.67) the external corpus reaches F1 63.64% versus the curated headline's 74.07%, an approximately 10-point gap concentrated in framework-level weakness classes ..."*

### 3.2 Optional SAST baseline

| Spec claim | Thesis delivery | Verdict |
|---|---|---|
| Optional SAST baseline (Semgrep + scoped CodeQL) | Semgrep, CodeQL, and ESLint-security all measured against the same corpus; results compared to the LLM configurations | [eval_r1_accuracy.tex:30-31](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L30), [eval_r1_accuracy.tex:78](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L78) (FPR/recall comparison) | Exceeds (also includes ESLint) |

### 3.3 Metrics — one-for-one

| Spec metric | Thesis location | Verdict |
|---|---|---|
| Precision | Headline 72.46% (gated 78.13%): [eval_r1_accuracy.tex:19,94-95](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L19) | Covered |
| Recall | Headline 70.42%: [eval_r1_accuracy.tex:19](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L19) | Covered |
| F1-score | Headline 71.43% (gated 74.07%): [eval_r1_accuracy.tex:19,95](code-guardian-thesis-report/src/chapters/evaluation/eval_r1_accuracy.tex#L19) | Covered |
| Latency | Stage-1 median 2,216 ms, Stage-2 median 3,320 ms: [eval_r4_usability.tex:24,38](code-guardian-thesis-report/src/chapters/evaluation/eval_r4_usability.tex#L24) | Covered |
| Resource usage | Per-inference `process.cpuUsage()` and sampled `process.memoryUsage()`: [eval_r4_usability.tex](code-guardian-thesis-report/src/chapters/evaluation/eval_r4_usability.tex), called out in [discussion.tex:48](code-guardian-thesis-report/src/chapters/discussion.tex#L48) | Covered |
| Privacy validation | Architectural checklist + automated egress/leak harness: [eval_r5_privacy.tex](code-guardian-thesis-report/src/chapters/evaluation/eval_r5_privacy.tex), [evaluation/privacy/test-egress.js](code-guardian-extension/evaluation/privacy/test-egress.js) | Covered |
| Reproducibility | `byteIdentityRate` and `setIdentityRate` on fixed-seed re-run subset: [eval_reproducibility.tex](code-guardian-thesis-report/src/chapters/evaluation/eval_reproducibility.tex), [evaluation/reproducibility.js](code-guardian-extension/evaluation/reproducibility.js) | Covered |
| (Bonus) JSON-parse success rate | [eval_r2_consistency.tex](code-guardian-thesis-report/src/chapters/evaluation/eval_r2_consistency.tex) | Exceeds |
| (Bonus) Auto-applicable repair rate (90.32% = 252/279) | [eval_r3_repair.tex:121](code-guardian-thesis-report/src/chapters/evaluation/eval_r3_repair.tex#L121) | Exceeds |

The metrics walk-through in [discussion.tex:47-48](code-guardian-thesis-report/src/chapters/discussion.tex#L47) maps each spec metric to its delivery section explicitly.

### 3.4 Deterministic local execution

| Spec claim | Thesis location | Verdict |
|---|---|---|
| All measurements under deterministic local execution | [evaluation/experimental_setup.tex:30](code-guardian-thesis-report/src/chapters/evaluation/experimental_setup.tex#L30) (Docker-compose loopback bind, fixed seed, pinned versions); [eval_reproducibility.tex](code-guardian-thesis-report/src/chapters/evaluation/eval_reproducibility.tex) | Covered |

---

## 4. Summary

**Items covered as specified:** every paragraph-1 claim (problem framing); every paragraph-2 claim (modes, modular architecture, privacy triad, reproducibility triad, threat model, mitigations); every paragraph-3 claim except the literal Juliet/OWASP-Benchmark dataset names.

**Deliberate, defended deviations (1):**
- Datasets — Juliet and OWASP Benchmark are **not first-party JavaScript** (Juliet is C/C++/Java; OWASP Benchmark is Java). Substituted with a 101-case JS-native curated corpus plus a 15-case external corpus (NodeGoat, Juice Shop, three CVEs). The deviation is named in two places, the substitution rationale is given, and the substitution penalty is **measured** (10-point F1 drop on external corpus). Per-case provenance is recorded and bound into the signed manifest.

**Items where the thesis exceeds the spec:**
- Total case count 116 vs. spec's 40-50 (~2.5×).
- SAST baseline includes ESLint-security in addition to the spec's Semgrep + CodeQL.
- Extra evaluation metrics (JSON-parse success rate, auto-applicable repair rate, sample-level FPR with binomial CIs, McNemar tests with Bonferroni correction) beyond the spec's seven.

**Items missing:** none.

The thesis was clearly written with the task description open beside it: [agent.tex:60](code-guardian-thesis-report/src/chapters/implementation/agent.tex#L60) names the threat-model arms verbatim ("code exfiltration, retrieval poisoning, and prompt injection"); [discussion.tex:43-48](code-guardian-thesis-report/src/chapters/discussion.tex#L43) maps each spec metric and dataset clause one-for-one to its delivery location and justifies the only deviation.

---

## Appendix — task description (reproduced for reference)

From [src/task_description.tex](code-guardian-thesis-report/src/task_description.tex):

> Traditional static application security testing (SAST) tools, such as Semgrep and CodeQL, are effective for detecting predefined vulnerability patterns but cannot reason about cross-file or context-dependent weaknesses. Cloud-based language model assistants provide stronger semantic analysis yet compromise data confidentiality and reproducibility because proprietary source code must leave the local environment. This thesis aims to design and evaluate a fully local, privacy-preserving secure coding assistant for Visual Studio Code that integrates large language models (LLMs) with Retrieval-Augmented Generation (RAG). All processing occurs on the developer's machine under a strict zero-egress policy to ensure that source code and intermediate data remain confidential.
>
> The proposed assistant combines two complementary modes: real-time inline diagnostics that deliver immediate vulnerability alerts, and asynchronous audit and question-answering modes that use offline retrieval of vulnerability information such as CWE, CVE, and OWASP entries. A modular architecture separates the LLM inference layer, the local retrieval pipeline, and the Visual Studio Code extension interface. The system enforces privacy through local embeddings, signed corpora, and network isolation, while reproducibility is achieved through deterministic decoding, version-pinned dependencies, and containerized execution. The threat model assumes local adversaries capable of attempting code exfiltration, retrieval poisoning, or prompt injection, mitigated through corpus signing, network isolation, and provenance verification.
>
> Evaluation will be conducted on benchmark and real-world JavaScript/TypeScript code. The comparison will be conducted across benchmark datasets (Juliet and OWASP Benchmark, approximately 40-50 test cases mapped to CWE identifiers) and one actively maintained real-world JavaScript/TypeScript project with documented vulnerabilities and verified patches. If the optional SAST baseline is executed, Semgrep and a scoped CodeQL subset will be included for contextual comparison. Evaluation metrics include precision, recall, F1-score, latency, resource usage, privacy validation, and reproducibility, all measured under deterministic local execution.
