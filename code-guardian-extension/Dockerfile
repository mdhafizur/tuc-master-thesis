# Phase A4 — Containerized evaluation harness.
#
# The thesis task description names "containerized execution" as a reproducibility
# mechanism. This image runs the evaluation harness inside a pinned Node.js
# environment so any third party can reproduce the numbers without depending on
# the developer's local toolchain.
#
# Build:   docker build -t code-guardian-eval .
# Compose: docker compose up         (orchestrates Ollama + harness)

FROM node:20.19.0-alpine

# Native deps for hnswlib-node (the RAG vector store).
RUN apk add --no-cache python3 make g++ git bash

WORKDIR /app

# Install dependencies first so layer caching survives source edits.
COPY package.json package-lock.json* ./
RUN npm ci --no-audit --no-fund

# Copy harness, source, signed corpus, and public key. Private key is NOT
# included (gitignored); evaluation runs only need verification, not signing.
COPY src ./src
COPY evaluation ./evaluation
COPY security-knowledge ./security-knowledge
COPY keys/corpus-public.pem ./keys/corpus-public.pem
COPY tsconfig.json esbuild.js .eslintrc* ./

# Compile the extension (also lints + type-checks).
RUN npm run compile

# Default to qwen3:8b+RAG full eval. Override at runtime, e.g.:
#   docker run --rm -v $PWD/evaluation/logs:/app/evaluation/logs \
#       -e OLLAMA_HOST=http://host.docker.internal:11434 \
#       code-guardian-eval node evaluation/evaluate-models.js --ablation
ENV OLLAMA_HOST=http://host.docker.internal:11434
CMD ["node", "evaluation/evaluate-models.js"]
