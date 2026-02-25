# 🔧 Code Guardian Scripts

Utility scripts for testing and development.

---

## 📜 Available Scripts

### test-data-sources.js
**Purpose:** Test all dynamic security data sources to ensure they're working properly.

**Usage:**
```bash
npm run test:data-sources
# or
node scripts/test-data-sources.js
```

**What it tests:**
- ✅ CWE data (curated database)
- ✅ OWASP Top 10 2021 (curated)
- ✅ NVD API (National Vulnerability Database)
- ✅ GitHub Security Advisories API
- ✅ JavaScript vulnerability patterns
- ✅ Cache functionality

**Output:**
- Color-coded test results
- Response times for API calls
- Example data from each source
- Cache status

**Requirements:**
- Internet connection (for NVD and GitHub APIs)
- Node.js 18+

---

### test-models.js
**Purpose:** Performance benchmarking for different Ollama models.

**Usage:**
```bash
npm run benchmark
# or
node scripts/test-models.js
```

**What it tests:**
- Model response times
- Analysis quality
- Resource usage
- Comparison across models

**Requirements:**
- Ollama running locally
- At least one model installed

---

## 🚀 Quick Reference

| Script | Command | Purpose |
|--------|---------|---------|
| **test-data-sources** | `npm run test:data-sources` | Test vulnerability data sources |
| **test-models** | `npm run benchmark` | Benchmark Ollama models |

---

## 🔍 Debugging

If scripts fail:

1. **Check internet connection** (for API-based tests)
2. **Verify Ollama is running** (for model tests)
3. **Check API rate limits:**
   - NVD: 5 requests/30 seconds (without API key)
   - GitHub: 60 requests/hour (without authentication)

---

## 📝 Adding New Scripts

When adding new scripts:

1. Place in `scripts/` directory
2. Add npm script to `package.json`
3. Document in this README
4. Include error handling
5. Add usage examples

---

*For more information, see the main [README](../README.md)*
