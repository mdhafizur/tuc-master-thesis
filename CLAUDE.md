# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a master's thesis project for **Code Guardian** - a privacy-preserving AI-powered VS Code extension for detecting and repairing security vulnerabilities in JavaScript/TypeScript code using local LLMs (via Ollama) with Retrieval-Augmented Generation (RAG).

The repository contains two main components:

1. **code-guardian-extension/** - VS Code extension (TypeScript)
2. **code-guardian-thesis-report/** - LaTeX thesis document

## Essential Commands

### VS Code Extension (`code-guardian-extension/`)

```bash
cd code-guardian-extension

# Development
make install              # Install dependencies
make compile             # Compile TypeScript (with type-check + lint)
make dev                 # Start watch mode, then press F5 in VS Code

# Testing
make test                # Run all tests
make test-unit           # Run unit tests only
make coverage            # Run tests with coverage report
make evaluate            # Evaluate model accuracy on test cases
make benchmark           # Performance benchmarking

# Packaging & Publishing
make package             # Create VSIX package (runs clean, compile, test first)
make publish-patch       # Bump patch version and publish
make release-patch       # Bump version, tag, push (triggers GitHub Actions)

# Utilities
make lint                # Run ESLint
make lint-fix            # Auto-fix ESLint issues
make clean               # Remove build artifacts
```

### Thesis Report (`code-guardian-thesis-report/`)

```bash
cd code-guardian-thesis-report

# Compilation (run from project root or thesis directory)
pdflatex Template.tex
bibtex Template
pdflatex Template.tex
pdflatex Template.tex    # Run twice for references to resolve
```

Main LaTeX file: `Template.tex`
Bibliography: `bibliography.bib`
Chapters located in: `src/chapters/`

## High-Level Architecture

### Extension Architecture (6-Layer System)

The VS Code extension follows a layered architecture:

**Layer 1: User Interface**
- VS Code editor integration, status bar, quick fixes, diagnostics
- Interactive webviews for AI analysis and security dashboard

**Layer 2: Extension Core**
- Entry point: `src/extension.ts`
- Command handlers, event management, VS Code API integration
- Lifecycle: activation, command registration, diagnostics management

**Layer 3: Intelligence & Analysis**
- `src/analyzer.ts` - Core LLM security analysis engine
- `src/analysisCache.ts` - LRU cache (95-98% hit rate, crypto-based hashing)
- `src/ragManager.ts` - RAG knowledge base with vector search (HNSWlib)
- `src/workspaceScanner.ts` - Concurrent workspace-wide analysis
- `src/dashboardWebview.ts` - Security scoring (0-100, A-F grades)

**Layer 4: External Data Sources**
- `src/vulnerabilityDataManager.ts` - NVD, OWASP, CWE, GitHub APIs
- 165+ vulnerability entries with 24h cache refresh
- Real-time CVE/OWASP/CWE updates

**Layer 5: AI Processing**
- `src/modelManager.ts` - Ollama LLM integration (20+ models)
- Supports CodeLlama, Qwen2.5-Coder, DeepSeek-Coder, etc.
- Retry logic with exponential backoff

**Layer 6: Presentation**
- `src/webview.ts` - Analysis UI with markdown rendering
- `src/dashboardWebview.ts` - Vulnerability heatmaps, security scores
- `media/` - CSS, JavaScript, Marked.js for UI

### Key Design Patterns

**Performance Optimizations:**
- Smart caching: LRU cache reduces LLM calls by 95-98%
- Debounced real-time analysis (800ms delay)
- Lazy loading for heavy components (RAG)
- Concurrent file analysis with progress tracking

**Error Handling:**
- Retry logic with exponential backoff (3 attempts)
- Graceful degradation when RAG or external data unavailable
- Timeout mechanisms for LLM requests

**Analysis Flow:**
```
User Action → Cache Check (95-98% hit) →
[Cache Miss] → RAG Knowledge Search → Vulnerability Data Fetch →
Enhanced Prompt → LLM Analysis (with retry) → Cache Store →
Display Results
```

## Important File Locations

### Extension Source Files
- `code-guardian-extension/src/extension.ts` - Main entry point
- `code-guardian-extension/src/analyzer.ts` - LLM analysis logic
- `code-guardian-extension/src/ragManager.ts` - RAG implementation
- `code-guardian-extension/package.json` - Extension manifest with commands

### Configuration
- `code-guardian-extension/tsconfig.json` - TypeScript compiler settings
- `code-guardian-extension/esbuild.js` - Build configuration
- `code-guardian-extension/.vscode/launch.json` - Debug configurations

### Thesis
- `code-guardian-thesis-report/Template.tex` - Main thesis file
- `code-guardian-thesis-report/src/chapters/` - Thesis chapters
- `code-guardian-thesis-report/bibliography.bib` - References

## Development Workflow

### Working on the Extension

1. Make changes to TypeScript files in `src/`
2. Run `npm run compile` or `make compile` (includes type-check + lint)
3. Press F5 in VS Code to launch Extension Development Host
4. Test changes in the development window
5. Run tests: `npm test` or `make test`

### Extension requires Ollama

The extension requires Ollama to be running locally:
```bash
# Install Ollama from https://ollama.com
# Pull a model
ollama pull qwen2.5-coder:7b

# Verify
ollama list
```

Default Ollama host: `http://localhost:11434` (configurable in VS Code settings)

### Testing Changes

**Unit Tests**: Located in `src/test/*.test.ts`
- Run with `npm run test:unit` or `make test-unit`

**Evaluation**: Run model accuracy tests
- 101 test cases (71 vulnerable + 30 secure) across 14 CWE categories
- `npm run evaluate` or `make evaluate`

### Building for Release

```bash
cd code-guardian-extension
make package              # Creates .vsix file
# Or for GitHub Actions release:
make release-patch        # Bumps version, tags, pushes
```

## Code Style & Conventions

- TypeScript strict mode enabled
- ESLint for code quality (run `make lint-fix` before committing)
- Async/await for asynchronous operations
- Error handling with try-catch and retry logic
- Logging via custom logger (`src/logger.ts`)

## Thesis Writing Rules

- **Citation limit:** Use no more than two citations per statement. Prefer the most frequently cited references in the thesis (`bibliography.bib`) over less-used ones.
- **Simple English:** Use plain, straightforward language. Prefer short sentences and common words. Avoid ornate phrasing, jargon-heavy constructions, and unnecessarily complex sentence structures.
- **Writing style:** Follow a flowing prose pattern. Chapter/section preambles should progressively narrow from broad context to the specific topic. Use numbered lists with bold lead-ins for objectives and contributions. Avoid flat one-sentence-per-chapter outlines — group chapters thematically into paragraphs.
- **Requirements mapping (R1–R5):**
  - R1 = Accuracy (precision, recall, F1)
  - R2 = Consistency (structured output reliability, JSON parse success)
  - R3 = Repair quality (fix suggestions)
  - R4 = Usability (latency, IDE integration)
  - R5 = Privacy (local execution, no code exfiltration)
  - Note: Old references R6/R7 are stale and have been consolidated into R1–R5.

## Security Considerations

**Privacy-First Design:**
- All LLM inference happens locally via Ollama (no cloud APIs)
- Code never leaves the developer's machine
- RAG knowledge base stored locally
- No telemetry or external data transmission

**Vulnerability Detection:**
- Targets JavaScript/TypeScript code
- Detects: SQL injection, XSS, code injection, path traversal, etc.
- Uses combination of LLM analysis + RAG + vulnerability data
- Integrates with VS Code diagnostics for inline warnings

## RAG Knowledge Base

Located in extension's workspace/global storage:
- Uses HNSWlib for vector similarity search
- Embeddings generated via Ollama
- Contains security best practices, CWE patterns, CVE examples
- Managed via `src/ragManager.ts`

Commands to manage:
- "Code Guardian: Manage RAG Knowledge Base"
- "Code Guardian: Toggle RAG On/Off"

## Common Issues

**Extension activation fails:**
- Ensure Ollama is running: `ollama list`
- Check model is available: `ollama pull qwen2.5-coder:7b`
- Check Ollama host setting in VS Code settings

**Build errors:**
- Clean artifacts: `make clean`
- Reinstall dependencies: `rm -rf node_modules && npm install`
- Check TypeScript version: `npm list typescript`

**Test failures:**
- Ensure extension is compiled: `make compile`
- Check Ollama is running for integration tests
- Clear VS Code test cache: `rm -rf .vscode-test/`

## Thesis Structure

Main chapters (in `src/chapters/`):
1. Introduction
2. State of the Art and Requirements (`analysis/`)
3. Concept (`concept/`)
4. Implementation (`implementation/`)
5. Evaluation (`evaluation/`)
6. Conclusion
7. Appendices (`appendices/`)

When editing thesis content, modify `.tex` files in `src/chapters/`, not the compiled PDF.

## Dependencies

**Extension:**
- VS Code API ^1.98.0
- TypeScript 5.8.3
- LangChain for RAG
- Ollama for local LLM inference
- @pinecone-database/pinecone or hnswlib-node for vector store

**Thesis:**
- LaTeX distribution (TeX Live, MiKTeX, etc.)
- BibTeX for bibliography
- scrbook document class (KOMA-Script)
