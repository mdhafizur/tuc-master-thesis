# 🚀 Quick Start Guide - Code Guardian v1.0.6

## 📋 Table of Contents

1. [Installation](#installation)
2. [First-Time Setup](#first-time-setup)
3. [New Features (v1.0.6)](#new-features-v106)
4. [Common Commands](#common-commands)
5. [Keyboard Shortcuts](#keyboard-shortcuts)
6. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

```bash
# 1. Install Ollama
# Visit: https://ollama.com

# 2. Pull a recommended model
ollama pull qwen2.5-coder:7b

# 3. Verify Ollama is running
ollama list
```

### Extension Setup

```bash
# 1. Install dependencies
npm install

# 2. Compile the extension
npm run compile

# 3. Launch in VS Code
# Press F5 in VS Code to open Extension Development Host
```

---

## First-Time Setup

### 1. Select Your AI Model

```
Cmd/Ctrl + Shift + P → "Code Guardian: 🎯 Select AI Model"
```

**Recommended Models:**
- **Fast:** `qwen2.5-coder:1.5b` (900MB) - Quick prototyping
- **Balanced:** `qwen2.5-coder:7b` (4.7GB) - Best for most use cases
- **Accurate:** `codellama:13b` (7.3GB) - Production environments

### 2. Configure Settings (Optional)

```
Cmd/Ctrl + , → Search "Code Guardian"
```

**Key Settings:**
- `codeGuardian.enableRAG`: Enable RAG enhancement (default: `true`)
- `codeGuardian.ollamaHost`: Ollama server URL (default: `http://localhost:11434`)

---

## New Features (v1.0.6)

### 🔐 Workspace Security Dashboard ⭐ NEW

**What it does:** Scans your entire workspace and provides a comprehensive security overview with scoring, severity breakdown, and interactive visualizations.

**How to use:**
1. Open a JavaScript/TypeScript project
2. `Cmd/Ctrl + Shift + P` → `Code Guardian: 🎯 Workspace Security Dashboard`
3. Wait for scan to complete (2-5 min for medium projects)
4. View results:
   - Security score (0-100) and grade (A-F)
   - Issues by severity (Critical, High, Medium, Low)
   - Vulnerability heatmap
   - Top 20 vulnerable files

**Pro Tips:**
- Click on any file to navigate and fix issues
- Use "Rescan" after making fixes to see improvements
- Target score ≥ 80 before deploying to production

### 📊 Security Score Calculator

**Algorithm:**
```
Weighted Issues = Critical×10 + High×5 + Medium×2 + Low×1
Score = 100 - (Weighted Issues per 1000 LOC × 5)
```

**Grading:**
- A (90-100): Excellent security posture
- B (80-89): Good, minor improvements needed
- C (70-79): Fair, address medium-priority issues
- D (60-69): Poor, fix high-priority issues immediately
- F (<60): Critical, immediate action required

### ⚡ Smart Caching

**What it does:** Automatically caches analysis results to avoid redundant LLM calls.

**Benefits:**
- 95-98% faster on repeated analysis
- Reduces Ollama server load
- 30-minute cache expiration

**View cache stats:**
```
Cmd/Ctrl + Shift + P → "Code Guardian: 📊 View Cache Statistics"
```

---

## Common Commands

### Analysis Commands

#### 1. **Workspace Security Dashboard** (NEW)
```
Cmd/Ctrl + Shift + P → "Code Guardian: 🎯 Workspace Security Dashboard"
```
- **Use when:** You want a comprehensive security overview
- **Time:** 2-5 minutes for 50-200 files

#### 2. **Analyze Full File**
```
Cmd/Ctrl + Shift + P → "Code Guardian: 🔍 Analyze Full File"
```
- **Use when:** You want to scan the current file
- **Time:** 5-15 seconds
- **Results:** Shown in Problems panel

#### 3. **Analyze Selected Code with AI**
```
Cmd/Ctrl + Shift + P → "Code Guardian: 🧠 Analyze Selected Code with AI"
```
- **Use when:** You want detailed analysis with Q&A
- **Time:** 10-30 seconds
- **Results:** Interactive webview with chat

#### 4. **Real-time Analysis** (Automatic)
- **Triggers:** Automatically when you place cursor in a function
- **Debounce:** 800ms delay to avoid excessive calls
- **Results:** Inline diagnostics and squiggles

### Utility Commands

#### 5. **Select AI Model**
```
Cmd/Ctrl + Shift + P → "Code Guardian: 🎯 Select AI Model"
```
- Choose from 20+ available models
- Switch models anytime
- Auto-refreshes available models

#### 6. **View Cache Statistics**
```
Cmd/Ctrl + Shift + P → "Code Guardian: 📊 View Cache Statistics"
```
- See hit rate, cache size, utilization
- Clear or reset cache
- Monitor performance

#### 7. **Manage RAG Knowledge Base**
```
Cmd/Ctrl + Shift + P → "Code Guardian: 🧠 Manage RAG Knowledge Base"
```
- Update vulnerability data
- View knowledge base stats
- Clear vector store

#### 8. **Contextual Q&A**
```
Cmd/Ctrl + Shift + P → "Code Guardian: 💬 Contextual Q&A"
```
- Ask questions about your codebase
- Get security advice
- Explore files and folders

---

## Keyboard Shortcuts

### Suggested Keybindings

Add to your `keybindings.json`:

```json
[
  {
    "key": "ctrl+shift+d",
    "mac": "cmd+shift+d",
    "command": "codeSecurity.workspaceDashboard",
    "when": "editorTextFocus"
  },
  {
    "key": "ctrl+shift+a",
    "mac": "cmd+shift+a",
    "command": "codeSecurity.analyzeFullFile",
    "when": "editorTextFocus"
  },
  {
    "key": "ctrl+shift+q",
    "mac": "cmd+shift+q",
    "command": "codeSecurity.analyzeSelectionWithAI",
    "when": "editorTextFocus"
  },
  {
    "key": "ctrl+shift+m",
    "mac": "cmd+shift+m",
    "command": "codeSecurity.selectModel",
    "when": "editorTextFocus"
  }
]
```

---

## Troubleshooting

### Issue: "Cannot connect to Ollama"

**Solution:**
```bash
# 1. Check if Ollama is running
ps aux | grep ollama

# 2. Start Ollama if not running
ollama serve

# 3. Verify it's accessible
curl http://localhost:11434/api/tags
```

### Issue: "Model not found"

**Solution:**
```bash
# 1. List installed models
ollama list

# 2. Pull the missing model
ollama pull qwen2.5-coder:7b

# 3. Refresh models in Code Guardian
Cmd/Ctrl + Shift + P → "Code Guardian: 🎯 Select AI Model"
```

### Issue: "Workspace scan is slow"

**Optimization:**

1. **Exclude large directories** in `.gitignore`:
   ```
   node_modules/
   dist/
   build/
   coverage/
   ```

2. **Check cache stats:**
   - Enable caching for faster rescans
   - Cache hit rate should be >70% on rescans

3. **Use faster model for large projects:**
   - Switch to `qwen2.5-coder:1.5b` for speed
   - Or `qwen2.5-coder:3b` for balance

### Issue: "Too many false positives"

**Solutions:**

1. **Try a larger model:**
   - `codellama:13b` or `qwen2.5-coder:14b` are more accurate

2. **Enable RAG:**
   ```json
   "codeGuardian.enableRAG": true
   ```

3. **Update vulnerability data:**
   ```
   Cmd/Ctrl + Shift + P → "Code Guardian: 🔄 Update Vulnerability Data"
   ```

### Issue: "Extension is slow to start"

**Normal behavior:**
- First launch: 2-3 seconds (RAG initialization)
- Subsequent launches: <1 second (lazy loading enabled)

**If still slow:**
```json
// Disable RAG if not needed
"codeGuardian.enableRAG": false
```

---

## Performance Tips

### For Best Performance:

1. **Use appropriate model size:**
   - Small projects (<50 files): Any model
   - Medium projects (50-200 files): `qwen2.5-coder:7b`
   - Large projects (200+ files): `qwen2.5-coder:3b` for speed

2. **Leverage caching:**
   - Don't clear cache frequently
   - Rescans are 95-98% faster with cache

3. **Optimize workspace:**
   - Exclude non-code directories
   - Use `.gitignore` patterns
   - Limit to 500-1000 files max

4. **Adjust debouncing:**
   - Default: 800ms
   - Increase for slower machines
   - Located in `src/extension.ts`

---

## Use Case Examples

### 1. Pre-Deployment Security Check

```bash
# Before deploying to production
1. Run workspace dashboard
2. Check security score ≥ 80
3. Fix all critical/high issues
4. Rescan to verify improvements
5. Deploy with confidence
```

### 2. Code Review

```bash
# During pull request review
1. Switch to feature branch
2. Run workspace dashboard
3. Compare score with main branch
4. Ensure no new critical issues
5. Review file-level details
6. Approve when score acceptable
```

### 3. Continuous Security Monitoring

```bash
# Weekly security scans
1. Schedule workspace scan (Monday morning)
2. Track score trends over time
3. Set alerts for score drops >10 points
4. Prioritize critical/high issues
5. Document improvements
```

### 4. Onboarding New Developers

```bash
# Help new team members understand codebase security
1. Run workspace dashboard
2. Review top vulnerable files
3. Use contextual Q&A for explanations
4. Set security score targets
5. Monitor improvements
```

---

## Best Practices

### ✅ Do's

- ✅ Run workspace scan before major releases
- ✅ Target security score ≥ 80 for production
- ✅ Fix critical/high issues immediately
- ✅ Use RAG enhancement for better accuracy
- ✅ Review AI suggestions before applying
- ✅ Keep Ollama models updated

### ❌ Don'ts

- ❌ Don't blindly trust all AI suggestions
- ❌ Don't commit code with critical issues
- ❌ Don't disable real-time analysis (it's debounced)
- ❌ Don't scan extremely large files (>500KB excluded)
- ❌ Don't clear cache too frequently
- ❌ Don't ignore low-severity issues completely

---

## Getting Help

### Documentation

- [README.md](README.md) - General overview
- [PHASE3_IMPROVEMENTS.md](PHASE3_IMPROVEMENTS.md) - Feature specifications
- [PHASE3_COMPLETION_SUMMARY.md](PHASE3_COMPLETION_SUMMARY.md) - Technical details

### Support

- **Issues:** [GitHub Issues](https://github.com/mdhafizur/code-guardian/issues)
- **Discussions:** [GitHub Discussions](https://github.com/mdhafizur/code-guardian/discussions)

### Contributing

Pull requests welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

---

## What's Next?

### Coming in v1.1.0:

- 📄 Export reports (PDF, HTML, JSON, SARIF)
- 📈 Trend analysis over time
- 🧠 Custom knowledge base editor
- 🔄 CI/CD integration

### Roadmap (v1.2.0+):

- 🌍 Multi-language support (Python, Java, Go, Rust)
- 👥 Team collaboration features
- 📊 Advanced visualizations
- 🎯 Custom security rules

---

**Version:** 1.0.6
**Last Updated:** December 28, 2025
**License:** MIT

---

> 🔐 **Security First, Code Better!**
