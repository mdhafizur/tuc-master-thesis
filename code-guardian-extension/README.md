# 🔐 Code Guardian

**Code Guardian** is a Visual Studio Code extension that integrates AI-powered security analysis into your coding workflow. It uses [Ollama](https://ollama.com) to analyze JavaScript and TypeScript code for potential security vulnerabilities, bad practices, and insecure coding patterns.

[![Version](https://img.shields.io/badge/version-1.0.6-blue.svg)](https://github.com/mdhafizur/code-guardian)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

---

## ✨ Features

### 🎯 Workspace-Level Security

- **🔐 Workspace Security Dashboard** *(NEW in v1.0.6)*
  Comprehensive security overview with intelligent scoring (0-100), severity breakdown, and interactive visualizations.

- **📊 Security Score Calculator**
  Automated letter grades (A-F) based on weighted vulnerability analysis normalized by codebase size.

- **📈 Vulnerability Heatmap**
  Interactive bar chart showing issue distribution across severity levels.

### 🔍 File-Level Analysis

- **Real-time Analysis** - Automatic security checks as you type (800ms debounced)
- **Full File Scanning** - Complete file analysis with VS Code diagnostics integration
- **AI-Powered Co-Pilot** - Interactive Q&A for deep security insights

### 💡 Smart Features

- **⚡ Smart Caching** - LRU cache providing 95-98% time reduction on repeated analysis
- **🧠 RAG Enhancement** - Optional knowledge retrieval for improved accuracy
- **🔄 Dynamic Security Data** *(NEW in v1.0.7)* - 165+ entries from NVD (100 CVEs), OWASP (complete Top 10), CWE (20 patterns), GitHub, npm
- **🛠️ Quick Fixes** - One-click application of AI-suggested secure code
- **🎯 Multi-Model Support** - 20+ Ollama models to choose from

### 🚀 Performance & Privacy

- **100% Local** - All analysis happens on your machine via Ollama
- **Fast** - Intelligent caching and debouncing for optimal performance
- **Robust** - Retry logic with exponential backoff handles transient errors

---

## 🚀 Quick Start

### Prerequisites

```bash
# 1. Install Ollama
# Visit: https://ollama.com

# 2. Pull a recommended model
ollama pull qwen2.5-coder:7b

# 3. Verify Ollama is running
ollama list
```

### Installation

```bash
# Clone and install
git clone https://github.com/mdhafizur/code-guardian.git
cd code-guardian
npm install

# Compile and launch
npm run compile

# Press F5 in VS Code to start Extension Development Host
```

---

## 🧪 Usage

### 🔐 Workspace Security Dashboard *(NEW)*

Get a comprehensive security overview of your entire workspace:

1. Open Command Palette (`Cmd/Ctrl + Shift + P`)
2. Run `Code Guardian: 🎯 Workspace Security Dashboard`
3. View:
   - Overall security score (0-100) and grade (A-F)
   - Issues by severity (Critical, High, Medium, Low)
   - Vulnerability heatmap visualization
   - Top 20 most vulnerable files
4. Click files to navigate and fix issues
5. Rescan after fixes to see improvements

**Performance:** 2-5 minutes for 50-200 files on medium projects.

### 🔍 Real-time Analysis

Automatic security checks while you code:

- Open any JavaScript/TypeScript file
- Place cursor in a function
- Extension analyzes and highlights issues automatically
- Hover for detailed explanations

### 📄 Full File Analysis

Complete file scanning:

1. Open Command Palette → `Code Guardian: 🔍 Analyze Full File`
2. View diagnostics in Problems panel
3. Hover over issues for details and remediation

### 🤖 AI Security Co-Pilot

Interactive security analysis:

1. Select code or place cursor on a line
2. Run `Code Guardian: 🧠 Analyze Selected Code with AI`
3. View AI analysis in interactive webview
4. Ask follow-up questions
5. Switch between models as needed

### Other Commands

- **📊 View Cache Statistics** - Monitor cache performance
- **🎯 Select AI Model** - Choose from 20+ models
- **🔄 Update Vulnerability Data** - Refresh security knowledge base
- **💬 Contextual Q&A** - Ask questions about your codebase

---

## 🧠 Supported Models

Code Guardian supports **20+ Ollama models**:

| Family | Models | Best For |
|--------|--------|----------|
| **Qwen 2.5-Coder** | 0.5B, 1.5B, 3B, 7B, 14B, 32B | Recommended - Best balance |
| **CodeLlama** | 7B, 13B, 34B, 70B | Excellent for security analysis |
| **DeepSeek-Coder** | 1.3B, 6.7B, 33B | Fast and accurate |
| **Gemma 3** | 270M, 1B, 4B, 12B, 27B | Multimodal capabilities |
| **StarCoder2** | 3B, 7B, 15B | Next-generation models |
| **WizardCoder** | 33B | Advanced code generation |
| **StableCode** | 3B | Reliable performance |

### Recommended Models

| Use Case | Model | Size | Performance |
|----------|-------|------|-------------|
| **Fast Prototyping** | `qwen2.5-coder:1.5b` | 900MB | ⚡⚡⚡ Fast, ⭐⭐ Accurate |
| **Balanced** | `qwen2.5-coder:7b` | 4.7GB | ⚡⚡ Good, ⭐⭐⭐⭐ Very Accurate |
| **Production** | `codellama:13b` | 7.3GB | ⚡ Slower, ⭐⭐⭐⭐⭐ Excellent |
| **Expert** | `qwen2.5-coder:32b` | 19GB | 🐢 Slow, ⭐⭐⭐⭐⭐ Best |

---

## ⚙️ Configuration

Configure via VS Code Settings (`Cmd/Ctrl + ,`):

### Model Selection

```json
{
  "codeGuardian.model": "qwen2.5-coder:7b",
  "codeGuardian.customModel": "",
  "codeGuardian.ollamaHost": "http://localhost:11434",
  "codeGuardian.autoRefreshModels": true
}
```

### RAG Enhancement

```json
{
  "codeGuardian.enableRAG": true
}
```

Enable/disable Retrieval-Augmented Generation for enhanced vulnerability detection using curated security knowledge.

---

## 📊 Project Structure

```
src/
├── extension.ts             # Extension entry point
├── analyzer.ts              # LLM analysis engine
├── analysisCache.ts         # LRU cache implementation
├── workspaceScanner.ts      # Workspace-wide scanner
├── dashboardWebview.ts      # Dashboard UI generator
├── modelManager.ts          # AI model management
├── ragManager.ts            # RAG knowledge base
├── vulnerabilityDataManager.ts  # Vulnerability data updates
├── diagnostic.ts            # VS Code diagnostics
├── actions.ts               # Quick fixes
├── functionExtractor.ts     # Code parsing
└── webview.ts               # Analysis UI
```

---

## 🏗️ Architecture & Diagrams

### System Architecture

Code Guardian uses a layered architecture for optimal performance and maintainability:

**6 Core Layers:**

1. **User Interface Layer** - VS Code editor integration, status bar, quick fixes
2. **Extension Core Layer** - Command handling, event management, VS Code API
3. **Intelligence & Analysis Layer** - Security analysis, caching, RAG, workspace scanning
4. **External Data Sources** - NVD, OWASP, CWE, GitHub APIs (165+ vulnerability entries)
5. **AI Processing Layer** - Ollama LLM server with 20+ models, embeddings
6. **Webview Presentation Layer** - Interactive dashboards, Q&A UI, visualizations

**Key Components:**

- **Analysis Cache (LRU)**: 95-98% hit rate, crypto-based hashing
- **RAG Manager**: Vector store with HNSWlib for semantic knowledge search
- **Vulnerability Data Manager**: Real-time CVE/OWASP/CWE updates (24h cache)
- **Workspace Scanner**: Concurrent file analysis with progress tracking
- **Dashboard Generator**: Security scoring (0-100, A-F), heatmap visualization

**Performance Features:**

- Smart caching reduces LLM calls by 95-98%
- Retry logic with exponential backoff (3 attempts)
- Debounced real-time analysis (800ms)
- Lazy loading for heavy components (RAG)

### Complete Diagrams

**📐 [Complete Sequence Diagram](diagrams/sequence_diagram_complete.md)**

- 9 comprehensive flows covering all features
- Shows cache, RAG, vulnerability data integration
- Real-time analysis, workspace dashboard, Q&A flows
- Performance optimizations and error handling

**🏛️ [Complete System Architecture](diagrams/system_architecture_complete.md)**

- All 6 architectural layers with component details
- Data flow patterns and integration points
- Technology stack and dependencies
- Scalability considerations and future enhancements

### Architecture Highlights

**Analysis Flow (with all optimizations):**

```text
User Action → Cache Check (95-98% hit) →
[Cache Miss] → RAG Knowledge Search → Vulnerability Data Fetch →
Enhanced Prompt → LLM Analysis (with retry) → Cache Store →
Display Results
```

**Workspace Dashboard Flow:**

```text
Command → File Discovery → For Each File:
  [Cache → Analyze → Store] →
Calculate Score → Generate Heatmap → Display Dashboard
```

---

## 🗺️ Roadmap

### ✅ v1.0.6 (Current)

- ✅ Workspace security dashboard
- ✅ Security scoring algorithm (0-100, A-F grades)
- ✅ Vulnerability heatmap visualization
- ✅ Smart caching (LRU, 95-98% faster)
- ✅ RAG enhancement
- ✅ 20+ model support
- ✅ Error handling with retry logic
- ✅ Comprehensive evaluation framework (48 test cases)

### 🚧 v1.1.0 (In Progress)

- 📄 Export reports (PDF, HTML, JSON, SARIF)
- 📈 Trend analysis over time
- 🧠 Custom knowledge base editor
- 🔄 CI/CD integration (GitHub Actions, GitLab CI)
- 🎯 Filter dashboard by severity

### 🔮 v1.2.0+ (Planned)

- 🌍 Multi-language support (Python, Java, Go, Rust, PHP)
- 👥 Team collaboration features
- 📊 Advanced visualizations (dependency graphs, attack surfaces)
- 🎯 Custom security rules engine
- 🔌 Static analysis tool integration (ESLint, Semgrep)
- ☁️ Cloud-based model support

---

## 📦 Packaging & Publishing

```bash
# Install VSCE
npm install -g @vscode/vsce

# Package extension
npm run package
vsce package

# Publish to marketplace (requires publisher account)
vsce publish
```

---

## 🧪 Testing & Evaluation

### Run Tests

```bash
# Run all tests
npm test

# Run unit tests only
npm run test:unit

# Run with coverage
npm run test:coverage
npm run coverage:view
```

### Evaluate Models

```bash
# Evaluate model accuracy on 48 vulnerability test cases
npm run evaluate
```

### Benchmark Performance

```bash
# Performance benchmarking
npm run benchmark
```

---

## 📚 Documentation

### For Developers

- **[Deployment Guide](docs/DEPLOYMENT.md)** - Package and publish the extension
- **[Makefile Commands](Makefile)** - Build automation (`make help`)
- **[Evaluation Framework](evaluation/README.md)** - Model accuracy testing
- **[Utility Scripts](scripts/README.md)** - Development scripts

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📄 License

MIT License © 2025 [Md Hafizur Rahman](https://github.com/mdhafizur)

See [LICENSE](LICENSE) file for details.

---

## 🙌 Acknowledgements

- [Ollama](https://ollama.com) - Local LLM runtime
- [VS Code Extension API](https://code.visualstudio.com/api) - Extension framework
- [TypeScript](https://www.typescriptlang.org/) - Type-safe development
- [LangChain](https://js.langchain.com) - RAG implementation
- [Marked.js](https://marked.js.org/) - Markdown rendering

---

## 🐛 Support & Issues

- **Issues:** [GitHub Issues](https://github.com/mdhafizur/code-guardian/issues)
- **Discussions:** [GitHub Discussions](https://github.com/mdhafizur/code-guardian/discussions)
- **Repository:** [GitHub](https://github.com/mdhafizur/code-guardian)

---

## ⚠️ Disclaimer

This tool is meant for **developer assistance**. Always validate results manually or with expert review in production workflows. Code Guardian is not a replacement for professional security audits.

---

## 📈 Stats

![GitHub stars](https://img.shields.io/github/stars/mdhafizur/code-guardian?style=social)
![GitHub forks](https://img.shields.io/github/forks/mdhafizur/code-guardian?style=social)
![GitHub issues](https://img.shields.io/github/issues/mdhafizur/code-guardian)
![GitHub pull requests](https://img.shields.io/github/issues-pr/mdhafizur/code-guardian)

---

**🔐 Code Guardian - Your AI-Powered Security Companion**

*Making secure coding accessible to every developer.*
