# 📁 Code Guardian - Repository Structure

Clean, organized repository structure for the Code Guardian VS Code extension.

---

## 🗂️ Directory Layout

```
code-guardian/
├── 📄 Core Files
│   ├── README.md                # Main documentation
│   ├── CHANGELOG.md             # Version history
│   ├── LICENSE                  # MIT License
│   ├── Makefile                 # Build automation
│   ├── package.json             # Project metadata & dependencies
│   ├── package-lock.json        # Locked dependencies
│   ├── tsconfig.json            # TypeScript configuration
│   ├── eslint.config.mjs        # ESLint configuration
│   ├── esbuild.js               # Build configuration
│   └── icon.png                 # Extension icon (128x128)
│
├── 📁 src/                      # Source Code
│   ├── extension.ts             # Extension entry point
│   ├── analyzer.ts              # LLM security analysis engine
│   ├── analysisCache.ts         # LRU cache implementation
│   ├── modelManager.ts          # AI model management
│   ├── ragManager.ts            # RAG knowledge base
│   ├── vulnerabilityDataManager.ts  # Data fetching & caching
│   ├── workspaceScanner.ts      # Workspace-wide scanner
│   ├── dashboardWebview.ts      # Security dashboard
│   ├── diagnostic.ts            # VS Code diagnostics
│   ├── actions.ts               # Quick fixes
│   ├── functionExtractor.ts     # Code parsing
│   ├── webview.ts               # Analysis UI
│   └── test/                    # Test files
│       ├── extension.test.ts
│       ├── analyzer.test.ts
│       ├── ragManager.test.ts
│       └── vulnerabilityDataManager.test.ts
│
├── 📁 docs/                     # Documentation (3 files)
│   ├── README.md                # Documentation index
│   ├── QUICK_START_GUIDE.md     # Getting started guide
│   └── DEPLOYMENT.md            # Complete deployment guide
│
├── 📁 scripts/                  # Utility Scripts
│   ├── README.md                # Scripts documentation
│   ├── test-data-sources.js     # Test all data sources
│   └── test-models.js           # Benchmark Ollama models
│
├── 📁 evaluation/               # Model Evaluation
│   ├── README.md                # Evaluation framework docs
│   ├── evaluate-models.js       # Model accuracy testing
│   └── test-cases/              # 48 vulnerability test cases
│       ├── sql-injection/
│       ├── xss/
│       ├── path-traversal/
│       └── ...
│
├── 📁 media/                    # UI Resources
│   ├── style.css                # Webview styles
│   ├── app.js                   # Webview JavaScript
│   └── marked.min.js            # Markdown parser
│
├── 📁 diagrams/                 # Architecture Diagrams
│   ├── system-architecture.png
│   └── sequence-diagram.png
│
└── 📁 dist/                     # Build Output (gitignored)
    └── extension.js             # Bundled extension
```

---

## 🚫 Ignored Files & Directories

### Git (`.gitignore`)

```
# Build outputs
out/
dist/
*.vsix

# Dependencies
node_modules/

# Test artifacts
.vscode-test/
test-workspace*/
coverage/

# Logs & temp files
*.log
*.tmp
```

### VSIX Package (`.vscodeignore`)

The following are excluded from the published extension:

```
# Source files (compiled to dist/)
src/**

# Documentation (keep only README & CHANGELOG)
docs/**

# Scripts & evaluation
scripts/**
evaluation/**
test-files/**

# Development files
Makefile
tsconfig.json
eslint.config.mjs
esbuild.js
diagrams/**
```

**Package Size Impact:**
- Before: ~15 MB (with all source files)
- After: ~2.2 MB (only dist/ + media/ + README + icon)

---

## 📦 What's Included in VSIX

Only essential files for the extension to run:

```
code-guardian-1.0.6.vsix
├── dist/
│   ├── extension.js        # Bundled extension code
│   └── extension.js.map    # Source maps
├── media/
│   ├── style.css
│   ├── app.js
│   └── marked.min.js
├── README.md               # User-facing docs
├── CHANGELOG.md            # Version history
├── LICENSE                 # License
├── icon.png                # Extension icon
└── package.json            # Metadata
```

---

## 🔍 Quick Navigation

### For Users
- **Getting Started:** [docs/QUICK_START_GUIDE.md](docs/QUICK_START_GUIDE.md)
- **Features:** [README.md](README.md)

### For Developers
- **Build & Deploy:** [Makefile](Makefile) - Run `make help`
- **Deployment:** [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)
- **Testing:** `npm test` or `make test`
- **Scripts:** [scripts/README.md](scripts/README.md)

### For Contributors
- **Source Code:** [src/](src/)
- **Tests:** [src/test/](src/test/)
- **Evaluation:** [evaluation/](evaluation/)

---

## 📊 Repository Statistics

| Category | Count |
|----------|-------|
| **Source Files** | 15 TypeScript files |
| **Test Files** | 4 test suites (79 tests) |
| **Documentation** | 7 markdown files (organized) |
| **Scripts** | 2 utility scripts |
| **Test Cases** | 48 security test cases |
| **Total Lines** | ~8,000 lines of code |

---

## 🎯 Organization Benefits

### Before Reorganization
```
code-guardian/
├── README.md
├── QUICK_START_GUIDE.md
├── DEPLOYMENT.md
├── QUICK_DEPLOY.md
├── DYNAMIC_SOURCES.md
├── PROJECT_STATUS.md          # ❌ Removed (outdated)
├── TESTING_DATA_SOURCES.md    # ❌ Removed (redundant)
├── DATA_ENHANCEMENT_SUMMARY.md
├── INCREMENTAL_KNOWLEDGE_UPDATES.md
├── test-data-sources.js       # ❌ Moved to scripts/
├── test-models.js             # ❌ Moved to scripts/
└── src/
```

**Problems:**
- ❌ 10+ markdown files in root (cluttered)
- ❌ Scripts mixed with docs
- ❌ Hard to find specific documentation
- ❌ No clear organization

### After Reorganization
```
code-guardian/
├── README.md                  # ✅ Main entry point
├── CHANGELOG.md               # ✅ Version history
├── Makefile                   # ✅ Build automation
├── docs/                      # ✅ All docs organized
├── scripts/                   # ✅ Utility scripts
└── src/                       # ✅ Source code
```

**Benefits:**
- ✅ Clean root directory (only 3 markdown files)
- ✅ Logical grouping (docs/, scripts/, src/)
- ✅ Easy navigation
- ✅ Professional appearance
- ✅ Smaller VSIX package
- ✅ Clear separation of concerns

---

## 🔄 Migration Guide

If you have existing documentation references, update them:

| Old Path | New Path |
|----------|----------|
| `QUICK_START_GUIDE.md` | `docs/QUICK_START_GUIDE.md` |
| `DEPLOYMENT.md` | `docs/DEPLOYMENT.md` |
| `QUICK_DEPLOY.md` | `docs/QUICK_DEPLOY.md` |
| `DYNAMIC_SOURCES.md` | `docs/DYNAMIC_SOURCES.md` |
| `test-data-sources.js` | `scripts/test-data-sources.js` |
| `test-models.js` | `scripts/test-models.js` |

**package.json updates:**
```json
{
  "scripts": {
    "test:data-sources": "node scripts/test-data-sources.js",
    "benchmark": "node scripts/test-models.js"
  }
}
```

---

## 🛠️ Maintenance

### Adding New Documentation
```bash
# Create in docs/ folder
touch docs/NEW_FEATURE.md

# Update docs/README.md index
# Update main README.md if user-facing
```

### Adding New Scripts
```bash
# Create in scripts/ folder
touch scripts/new-script.js

# Add to package.json scripts
# Document in scripts/README.md
```

### Before Publishing
```bash
# Verify package contents
vsce ls

# Should NOT include:
# - src/ (raw TypeScript)
# - docs/ (except links in README)
# - scripts/
# - test-workspace*/
# - node_modules/
```

---

## ✅ Verification Checklist

After reorganization:

- [x] All tests passing (`npm test`)
- [x] Scripts work from new location
- [x] Documentation links updated
- [x] `.gitignore` configured
- [x] `.vscodeignore` configured
- [x] VSIX package size reduced
- [x] Build process works (`make package`)
- [x] No broken links in README

---

**Last updated:** December 28, 2025
