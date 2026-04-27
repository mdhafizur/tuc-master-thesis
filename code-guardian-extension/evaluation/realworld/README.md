# Real-World Project Evaluation

Phase B2 of the task-description compliance plan: evaluate the detector
end-to-end on **one actively maintained real-world JavaScript/TypeScript
project with documented vulnerabilities and verified patches**, as named in
the approved task description.

## Project: OWASP NodeGoat

NodeGoat is OWASP's reference vulnerable Node.js application. Each lesson
maps to an OWASP Top 10 weakness with a documented vulnerable code path and
a published patch — the exact shape the task description requires.

- Repository: https://github.com/OWASP/NodeGoat
- Active maintenance: yes (OWASP project, ongoing commits)
- Vulnerability documentation: per-lesson README under `tutorial/`
- Patch verification: each tutorial lesson links to a "fix" branch / commit

## Setup

```bash
# Clone outside the extension repo to keep its size out of git
cd evaluation/realworld
git clone https://github.com/OWASP/NodeGoat.git nodegoat
cd nodegoat
git checkout <vulnerable-commit>   # see suggested pin below
```

Suggested pinned commits (used to make results reproducible):

| Label | Commit | Notes |
|---|---|---|
| vulnerable | `master` | Default-vulnerable branch — used for recall measurement. |
| patched | branch `nodegoat-patch-snapshot` | Apply the documented fixes per `tutorial/`. |

## Documented vulnerabilities

`nodegoat-vulnerabilities.json` lists the documented vulnerabilities with
file path, line, CWE, and category. The runner uses this file to compute
recall.

The list is curated from NodeGoat's own `tutorial/` directory and from the
OWASP Top 10 mappings the project advertises. It is small on purpose —
recall on whole-project analysis is the point, not corpus size.

## Run

With Ollama running locally and `qwen3:8b` pulled:

```bash
# Default — full project scan against pinned vulnerable commit
node evaluation/run-realworld.js

# Smoke test — scan the first 5 files only
node evaluation/run-realworld.js --file-limit 5

# Different project (any JS/TS repo with a documented-vulns JSON)
node evaluation/run-realworld.js \
  --project juice-shop \
  --path /abs/path/to/juice-shop
```

Output: `evaluation/logs/realworld-<project>.json` with per-file findings,
overall recall, and per-CWE recall.

## Cost

End-to-end NodeGoat scan on `qwen3:8b+RAG`: roughly 30 minutes of Ollama
time for ~25 source files. The script emits progress every 5 files.

## What this measures

- **Whole-project recall**: how many documented NodeGoat vulnerabilities the
  detector finds when run with no per-case context, just the source.
- **Cross-file blind-spots**: NodeGoat's authorisation bugs span routes and
  models. A function-scoped detector will undercount these — that gap is
  the disclosed limitation.
- **False-positive surface on real code**: NodeGoat's secure code paths
  exercise framework patterns. Findings on those count against precision
  for the real-world slice.

## What it does NOT measure

- Performance against the curated 101-case corpus (that is the headline
  number — see `evaluation/logs/refined-v1/`).
- SAST baseline performance — Semgrep/CodeQL are run on the curated corpus
  only, not on whole projects.
