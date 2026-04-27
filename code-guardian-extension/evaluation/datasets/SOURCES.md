# Dataset Provenance and Substitution Notes

This document records the provenance of every test case used in the evaluation
and explicitly documents the substitution made for benchmarks named in the
thesis task description.

## Substitution: Juliet and OWASP Benchmark

The approved task description names "**Juliet** and **OWASP Benchmark**,
approximately 40-50 test cases mapped to CWE identifiers". Both are real
suites — but neither targets JavaScript:

- **Juliet Test Suite** is published by NIST in **C/C++** and **Java** versions
  only (https://samate.nist.gov/SARD/test-suites/). There is no first-party
  JavaScript port.
- **OWASP Benchmark Project** is a **Java** application
  (https://owasp.org/www-project-benchmark/). There is no JavaScript port.

This thesis evaluates a **JavaScript/TypeScript** detector. Running the
detector against C/C++ or Java would not be meaningful: the LLM is prompted
for JS-language vulnerabilities and the canonical taxonomy is JS-specific
(prototype-pollution, deserialisation in JSON, eval-injection, etc.).

We therefore substitute equivalent JS-language corpora that preserve the
intent of Juliet and OWASP Benchmark — CWE-mapped, vulnerability-tagged,
and large enough to span the major weakness categories.

## Curated corpus (101 cases — primary)

`vulnerability-test-cases.json` — 71 vulnerable + 30 secure cases. Each entry
is mapped to a CWE identifier and a canonical category. Case provenance:

| Slice | Count | Source |
|---|---|---|
| Real-project vulnerable code | 11 | Lodash, Express, Mongoose, Node-Forge, react-dom, serialize-javascript, moment, OWASP Juice Shop, NodeGoat — three cases carry real CVE references (CVE-2022-24999, CVE-2021-23337, CVE-2022-24771). |
| OWASP cheat-sheet patterns | ~25 | OWASP JS Security Cheat Sheet, OWASP Top 10 examples (A01-A10:2021). Distilled vulnerability and patched-pair samples. |
| CWE-tagged synthetic cases | ~35 | One or more cases per top-15 CWE relevant to JS/TS (CWE-79, 89, 22, 78, 352, 434, 502, 611, 798, 863, 1321, 94, 95, 117, 327). Synthetic but pattern-faithful. |
| Curated negatives | 30 | Hand-picked secure code paths matching the same surface APIs as the positives, used to measure FPR. |

The CWE mapping per case is in `vulnerability-test-cases.json` under the
`expectedVulnerabilities[*].cwe` field.

## External corpus (additional — `external/`)

`external/` holds an additional CWE-mapped JS slice drawn from the
public corpora most directly comparable to Juliet/OWASP-Benchmark:

- **NodeGoat** — OWASP's reference vulnerable Node.js app
  (https://github.com/OWASP/NodeGoat). Each NodeGoat lesson maps to a single
  OWASP Top 10 weakness; we extract the lesson's vulnerable code path and
  the documented patch, then tag the pair with CWE.
- **OWASP Juice Shop** — OWASP's reference vulnerable Node.js+Angular app
  (https://github.com/juice-shop/juice-shop). Per-challenge code paths are
  similarly tagged.
- **Public CVE references** — additional named-CVE vulnerabilities in
  npm packages with public PoC + fix commits.

Cases are loaded via:

```bash
node evaluation/evaluate-models.js \
  --dataset evaluation/datasets/external/external-test-cases.json \
  --model qwen3:8b
```

### Why this is a defensible substitution

Juliet and OWASP Benchmark are designed to measure SAST tools against
**well-known, CWE-mapped weakness patterns at scale**. The substitute
preserves both properties:

1. **CWE coverage**: every external case carries an `expectedVulnerabilities[*].cwe` field
   identical in shape to the curated corpus. The same canonical category matcher
   ([categoryTaxonomy.ts](../../src/categoryTaxonomy.ts)) is applied on both sides.
2. **Source authority**: NodeGoat and Juice Shop are official OWASP projects;
   the curated CVEs come from npm/Node.js advisories. None of these is a
   weakening of the standard the task description named — only a substitution
   for language coverage.
3. **Reproducibility**: every external case carries a `source` URL and a
   `commit` field pointing to the upstream revision so the corpus can be
   regenerated.

The thesis evaluation chapter discloses this substitution explicitly under
"Experimental Setup" and "Limitations".

## Per-file index

| File | Cases | Purpose |
|---|---|---|
| `vulnerability-test-cases.json` | 71 vulnerable + 30 secure | Primary corpus, headline numbers. |
| `vulnerability-test-cases.generated.json` | 71 + 30 | Generated mirror used by the regression-test loader. |
| `advanced-test-cases.json` | extended | Ablation slice. |
| `advanced-test-cases.generated.json` | extended | Generated mirror. |
| `negatives-only.generated.json` | 30 | Secure code only — used to measure FPR in isolation. |
| `external/external-test-cases.json` | curated subset | NodeGoat + Juice Shop + named CVE substitutes for Juliet/OWASP-Benchmark. |
| `corpus-provenance.json` (in `evaluation/`) | metadata | Source URLs and retrieval timestamps bound into the signed manifest. |
