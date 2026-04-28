#!/usr/bin/env node

/**
 * Comprehensive Model Evaluation Framework for Code Guardian
 *
 * This script evaluates different Ollama models on their ability to detect
 * security vulnerabilities in code using a curated test dataset.
 */

const fsSync = require('fs');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const { execSync, execFile } = require('child_process');
const { promisify } = require('util');
const { fileURLToPath } = require('url');
const taxonomy = require('./category-taxonomy');
const sastFusion = require('./sast-fusion');
const importResolver = require('./import-resolver');
const repairValidator = require('./repair-validator');

const execFileAsync = promisify(execFile);
let ollamaClient = null;

function getOllamaClient() {
    if (!ollamaClient) {
        const { Ollama } = require('ollama');
        ollamaClient = new Ollama();
    }
    return ollamaClient;
}

const DEFAULT_TIMEOUT_MS = 30000;
const DEFAULT_DELAY_MS = 500;
const DEFAULT_TEMPERATURE = 0;
const DEFAULT_NUM_PREDICT = 1000;
const DEFAULT_RUNS_PER_SAMPLE = 1;
const DEFAULT_RAG_K = 5;
const DEFAULT_BASELINE_TIMEOUT_MS = 180000;
const DEFAULT_BASELINE_TOOLS = ['codeql', 'semgrep', 'eslint-security'];
const BASELINE_TOOL_ALIASES = {
    codeql: 'codeql',
    semgrep: 'semgrep',
    semgrem: 'semgrep',
    eslint: 'eslint-security',
    'eslint-security': 'eslint-security',
    eslintsecurity: 'eslint-security'
};

// Parse CLI flags
const args = process.argv.slice(2);
const ENABLE_RAG_ABLATION = args.includes('--ablation');
const RAG_ONLY = args.includes('--rag-only');
const NO_RAG_ONLY = args.includes('--no-rag-only');
const INCLUDE_BASELINES = args.includes('--include-baselines');
const BASELINES_ONLY = args.includes('--baselines-only');
const KEEP_BASELINE_WORKDIR = args.includes('--keep-baseline-workdir');
const DISABLE_THINKING = !args.includes('--allow-thinking');
const ENABLE_STRUCTURED_OUTPUT = !args.includes('--no-structured-output');
const SAMPLE_LIMIT = parseIntFlag('--limit', 0); // 0 = no limit
const MODEL_FILTER = getFlagValue('--model'); // e.g., --model qwen3:8b
// Hybrid SAST+LLM gating. When enabled, Semgrep is run once over the baseline
// workspace, and each LLM finding overlapping a SAST finding on line range +
// canonical category is promoted to confidence 1.0 / hybrid.
const SAST_FUSION_ENABLED = args.includes('--sast-fusion');
// Apply a runtime confidence gate: drop findings below this threshold after fusion.
// Complements the post-hoc rescoring script at evaluation/rescore-metrics.js.
const CONFIDENCE_THRESHOLD = parseFloatFlag('--confidence-threshold', 0);
// Enrich the user prompt with regex-extracted import / sink context. Off by
// default; opt-in via --import-context to evaluate the lift on semantic categories.
const IMPORT_CONTEXT_ENABLED = args.includes('--import-context');

function getFlagValue(name) {
    const prefixed = `${name}=`;
    const direct = args.find(arg => arg.startsWith(prefixed));
    if (direct) {
        return direct.slice(prefixed.length);
    }

    const idx = args.indexOf(name);
    if (idx !== -1 && idx < args.length - 1) {
        return args[idx + 1];
    }

    return null;
}

function parseIntFlag(name, fallback) {
    const raw = getFlagValue(name);
    if (raw === null) return fallback;
    const value = Number.parseInt(raw, 10);
    return Number.isFinite(value) && value > 0 ? value : fallback;
}

function parseFloatFlag(name, fallback) {
    const raw = getFlagValue(name);
    if (raw === null) return fallback;
    const value = Number.parseFloat(raw);
    return Number.isFinite(value) ? value : fallback;
}

const TIMEOUT_MS = parseIntFlag('--timeout-ms', DEFAULT_TIMEOUT_MS);
const REQUEST_DELAY_MS = parseIntFlag('--delay-ms', DEFAULT_DELAY_MS);
const RUNS_PER_SAMPLE = parseIntFlag('--runs', DEFAULT_RUNS_PER_SAMPLE);
const RAG_K = parseIntFlag('--rag-k', DEFAULT_RAG_K);
const TEMPERATURE = parseFloatFlag('--temperature', DEFAULT_TEMPERATURE);
const NUM_PREDICT = parseIntFlag('--num-predict', DEFAULT_NUM_PREDICT);
const BASELINE_TIMEOUT_MS = parseIntFlag('--baseline-timeout-ms', DEFAULT_BASELINE_TIMEOUT_MS);
const DATASET_FLAG = getFlagValue('--dataset');
const SEMGREP_BIN = getFlagValue('--semgrep-bin') || 'semgrep';
const CODEQL_BIN = getFlagValue('--codeql-bin') || 'codeql';
const ESLINT_BIN_FLAG = getFlagValue('--eslint-bin');
const EXTENSION_ROOT = path.resolve(__dirname, '..');

function normalizeBaselineTool(tool) {
    const key = String(tool || '').trim().toLowerCase();
    return BASELINE_TOOL_ALIASES[key] || null;
}

function parseBaselineTools(rawValue) {
    if (!rawValue) {
        return [...DEFAULT_BASELINE_TOOLS];
    }

    const normalized = rawValue
        .split(',')
        .map(token => normalizeBaselineTool(token))
        .filter(Boolean);

    return normalized.length > 0
        ? [...new Set(normalized)]
        : [...DEFAULT_BASELINE_TOOLS];
}

const REQUESTED_BASELINE_TOOLS = parseBaselineTools(getFlagValue('--baseline-tools'));

// Load test dataset
async function resolveDatasetPath(datasetArg) {
    const candidates = [];
    if (datasetArg) {
        if (path.isAbsolute(datasetArg)) {
            candidates.push(datasetArg);
        } else {
            // Support invocation from both extension root and evaluation directory.
            candidates.push(path.resolve(process.cwd(), datasetArg));
            candidates.push(path.resolve(__dirname, datasetArg));
        }
    } else {
        // Prefer generated dataset if present, otherwise fall back to curated baseline.
        candidates.push(path.join(__dirname, 'datasets', 'vulnerability-test-cases.generated.json'));
        candidates.push(path.join(__dirname, 'datasets', 'vulnerability-test-cases.json'));
    }

    for (const candidate of candidates) {
        try {
            await fs.access(candidate);
            return candidate;
        } catch (_error) {
            // Try next candidate.
        }
    }

    throw new Error(`No dataset file found. Tried: ${candidates.join(', ')}`);
}

function validateTestCases(testCases, datasetPath) {
    if (!Array.isArray(testCases)) {
        throw new Error(`Dataset must be a JSON array: ${datasetPath}`);
    }

    const invalid = testCases.findIndex(testCase =>
        typeof testCase?.id !== 'string' ||
        typeof testCase?.name !== 'string' ||
        typeof testCase?.code !== 'string' ||
        typeof testCase?.language !== 'string' ||
        !Array.isArray(testCase?.expectedVulnerabilities)
    );

    if (invalid !== -1) {
        throw new Error(`Invalid test case schema at index ${invalid} in ${datasetPath}`);
    }
}

async function loadTestDataset(datasetArg = DATASET_FLAG) {
    const datasetPath = await resolveDatasetPath(datasetArg);
    const data = await fs.readFile(datasetPath, 'utf8');
    const testCases = JSON.parse(data);
    validateTestCases(testCases, datasetPath);
    return {
        datasetPath,
        testCases
    };
}

// System prompt for security analysis
// JSON-mode + MODEL_RESPONSE_SCHEMA enforce output shape, so the prompt is a
// tight ~80-token instruction with the four scoring rules; no verbose example
// block is needed.
// Two-stage harness: stage 1 emits detection only ({message, type, startLine,
// endLine, severity}); stage 2 generates a structured {code, language} repair
// per detected finding via a separate Ollama call. This mirrors the production
// extension's split between analyzer.ts detection and analyzer.ts generateRepair,
// so stage-1 latency reflects what users see in inline diagnostics and stage-2
// latency reflects the on-demand quick-fix surface.
const SYSTEM_PROMPT = `Detect exploitable security vulnerabilities in code. Return a JSON array. Each issue needs:
- message: why this is exploitable
- type: specific vulnerability name (e.g. SQL Injection, XSS, Command Injection, Path Traversal, Weak Cryptography)
- startLine, endLine: 1-based line range
- severity: high | medium | low

Rules:
- Report only actually exploitable issues, not theoretical risks or style issues
- Skip hardcoded test values and properly sanitized inputs
- Return [] if the code is secure
- JSON only, no prose`;

const RAG_KNOWLEDGE_SNIPPETS = [
    // Core injection vulnerabilities
    'OWASP A03/CWE-89 SQL Injection: use parameterized queries and prepared statements. FIX: Replace string concatenation like `db.query("SELECT * FROM users WHERE id=" + id)` with `db.query("SELECT * FROM users WHERE id = ?", [id])`.',
    'OWASP A03/CWE-79 XSS: avoid unsafe HTML sinks and sanitize untrusted input. FIX: Replace `element.innerHTML = userInput` with `element.textContent = userInput` or use DOMPurify: `element.innerHTML = DOMPurify.sanitize(userInput)`.',
    'OWASP A03/CWE-78 Command Injection: never concatenate user input into shell commands. FIX: Replace `exec("ls " + userInput)` with `execFile("ls", [userInput])` which does not invoke a shell.',
    'OWASP A01/CWE-22 Path Traversal: canonicalize paths and enforce allowlisted base directories. FIX: Use `path.resolve(baseDir, userInput)` and verify the result starts with `baseDir` before reading.',
    'CWE-327 Weak Crypto: avoid broken algorithms; use modern primitives and secure randomness. FIX: Replace `crypto.createHash("md5")` with `crypto.createHash("sha256")` and `Math.random()` with `crypto.randomBytes()`.',
    'CWE-798 Hardcoded Credentials: keep secrets out of source code and use secret managers. FIX: Replace `const password = "admin123"` with `const password = process.env.DB_PASSWORD`.',
    'CWE-352 CSRF: use anti-CSRF tokens and same-site cookies for state-changing requests. FIX: Add `app.use(csrf())` middleware and include `req.csrfToken()` in forms.',
    'CWE-611 XXE: disable external entities and DTD processing in XML parsers. FIX: Set `parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.',
    // Niche categories (previously missing — improves R3 repair coverage)
    'CWE-1321 Prototype Pollution: prevent modification of Object.prototype via untrusted input. FIX: Replace `obj[key] = value` with a check: `if (key === "__proto__" || key === "constructor" || key === "prototype") return;` or use `Object.create(null)` for lookup objects.',
    'CWE-362 Race Condition (TOCTOU): avoid time-of-check-time-of-use gaps in file operations. FIX: Replace `if (fs.existsSync(f)) fs.readFileSync(f)` with a single `try { fs.readFileSync(f) } catch (e) { /* handle missing */ }` to eliminate the race window.',
    'CWE-918 SSRF: validate and restrict outbound URLs to prevent server-side request forgery. FIX: Parse the URL, verify `hostname` against an allowlist, and reject private/internal IP ranges before making the request.',
    'CWE-502 Insecure Deserialization: never deserialize untrusted data without validation. FIX: Replace `JSON.parse(untrustedInput)` with schema validation using a library like `ajv` or `zod`: `const data = schema.parse(JSON.parse(input))`.',
    'CWE-943 NoSQL Injection: sanitize query operators in MongoDB queries. FIX: Replace `db.find({user: req.body.user})` with `db.find({user: String(req.body.user)})` or use `mongo-sanitize` to strip `$`-prefixed operators.'
];

function buildRAGPrompt(ragK) {
    const selected = RAG_KNOWLEDGE_SNIPPETS.slice(0, Math.max(0, ragK));
    const ragContext = selected.length > 0
        ? selected.map((item, idx) => `${idx + 1}. ${item}`).join('\n')
        : 'No retrieval snippets selected (k=0).';

    return `${SYSTEM_PROMPT}\n\nRELEVANT SECURITY KNOWLEDGE (top-k=${ragK}):\n${ragContext}`;
}

// Stage-1 detection schema: no suggestedFix. Repairs are produced by a separate
// stage-2 call (REPAIR_SCHEMA below) so detection latency reflects inline
// diagnostics and repair latency reflects the quick-fix surface separately.
const MODEL_RESPONSE_SCHEMA = {
    type: 'array',
    items: {
        type: 'object',
        properties: {
            message: { type: 'string' },
            type: { type: 'string' },
            startLine: { type: 'integer' },
            endLine: { type: 'integer' },
            severity: { type: 'string' }
        },
        required: ['message', 'type', 'startLine', 'endLine', 'severity']
    }
};

// Stage-2 repair schema: enforces {code, language} so the model cannot emit
// prose paraphrases of the fix into the suggestedFix field.
const REPAIR_SCHEMA = {
    type: 'object',
    properties: {
        code: { type: 'string' },
        language: { type: 'string', enum: ['javascript', 'typescript'] }
    },
    required: ['code']
};

const REPAIR_SYSTEM_PROMPT = `Secure code repair. Output ONLY a JSON object {"code": "...", "language": "javascript" | "typescript"}.

Rules:
- "code" MUST contain only executable code; do NOT include prose, explanation, comments, or markdown fences
- Address the reported vulnerability type directly
- Preserve the original functionality
- Use established secure patterns (parameterized queries, input validation, safe APIs)
- "language" reflects the source language of the snippet`;

function toPositiveInteger(value, fallback) {
    const parsed = Number.parseInt(String(value), 10);
    return Number.isInteger(parsed) && parsed > 0 ? parsed : fallback;
}

function normalizeModelSeverity(value) {
    const severity = String(value || '').toLowerCase().trim();
    if (severity === 'critical' || severity === 'high' || severity === 'error') return 'high';
    if (severity === 'medium' || severity === 'warning') return 'medium';
    if (severity === 'low' || severity === 'info') return 'low';
    return 'medium';
}

function normalizeIssueObject(issue) {
    if (!issue || typeof issue !== 'object') {
        return null;
    }

    const message = String(
        issue.message ||
        issue.description ||
        issue.issue ||
        issue.title ||
        'Potential security issue'
    ).trim();

    const type = String(
        issue.type ||
        issue.vulnerability ||
        issue.vulnerabilityType ||
        issue.issueType ||
        issue.category ||
        'Security Issue'
    ).trim();

    const startLine = toPositiveInteger(
        issue.startLine ?? issue.start_line ?? issue.line ?? issue.start ?? 1,
        1
    );
    let endLine = toPositiveInteger(
        issue.endLine ?? issue.end_line ?? issue.line ?? issue.end ?? startLine,
        startLine
    );

    if (endLine < startLine) {
        endLine = startLine;
    }

    // Phase 1 contract: suggestedFix may arrive as either
    //   - {code: string, language?: string}  (new tightened schema)
    //   - string                              (legacy shape, kept for back-compat
    //                                          when re-normalising stored run JSONs)
    // Aliases (issue.fix / .recommendation / .remediation) follow the legacy
    // string convention.
    let suggestedFixRaw =
        issue.suggestedFix ??
        issue.fix ??
        issue.recommendation ??
        issue.remediation;

    if (suggestedFixRaw && typeof suggestedFixRaw === 'object' && !Array.isArray(suggestedFixRaw)) {
        suggestedFixRaw = typeof suggestedFixRaw.code === 'string' ? suggestedFixRaw.code : undefined;
    }

    const normalized = {
        message: message || 'Potential security issue',
        type: type || 'Security Issue',
        startLine,
        endLine,
        severity: normalizeModelSeverity(issue.severity)
    };

    if (typeof suggestedFixRaw === 'string' && suggestedFixRaw.trim().length > 0) {
        normalized.suggestedFix = suggestedFixRaw.trim();
    }

    // Phase 1: preserve confidence and detectionSource if the producer emitted them.
    // Phase 2 will populate these from the analyzer; for now we just propagate.
    if (typeof issue.confidence === 'number' && Number.isFinite(issue.confidence)) {
        normalized.confidence = Math.max(0, Math.min(1, issue.confidence));
    }
    if (typeof issue.detectionSource === 'string') {
        const src = issue.detectionSource.toLowerCase();
        if (src === 'llm' || src === 'sast' || src === 'hybrid') {
            normalized.detectionSource = src;
        }
    }

    return normalized;
}

function normalizeIssuePayload(payload) {
    if (Array.isArray(payload)) {
        return payload
            .map(normalizeIssueObject)
            .filter(Boolean);
    }

    if (!payload || typeof payload !== 'object') {
        return null;
    }

    const arrayKeys = ['issues', 'vulnerabilities', 'results', 'findings'];
    for (const key of arrayKeys) {
        if (Array.isArray(payload[key])) {
            return payload[key]
                .map(normalizeIssueObject)
                .filter(Boolean);
        }
    }

    if (
        payload.message ||
        payload.description ||
        payload.issue ||
        payload.type ||
        payload.vulnerability
    ) {
        const normalized = normalizeIssueObject(payload);
        return normalized ? [normalized] : null;
    }

    return null;
}

function stripMarkdownFences(text) {
    return String(text || '')
        .replace(/```json\s*/gi, '')
        .replace(/```\s*/g, '')
        .trim();
}

function extractFirstBalancedSegment(text, openChar, closeChar) {
    const input = String(text || '');
    let start = -1;
    let depth = 0;
    let inString = false;
    let escaping = false;

    for (let i = 0; i < input.length; i++) {
        const ch = input[i];

        if (inString) {
            if (escaping) {
                escaping = false;
                continue;
            }
            if (ch === '\\') {
                escaping = true;
                continue;
            }
            if (ch === '"') {
                inString = false;
            }
            continue;
        }

        if (ch === '"') {
            inString = true;
            continue;
        }

        if (ch === openChar) {
            if (depth === 0) {
                start = i;
            }
            depth += 1;
            continue;
        }

        if (ch === closeChar && depth > 0) {
            depth -= 1;
            if (depth === 0 && start !== -1) {
                return input.slice(start, i + 1);
            }
        }
    }

    return null;
}

function tryParseModelPayload(rawText, source) {
    const cleaned = stripMarkdownFences(rawText);
    if (!cleaned) {
        return {
            success: false,
            parseReason: `empty_${source}`
        };
    }

    try {
        const parsed = JSON.parse(cleaned);
        const normalized = normalizeIssuePayload(parsed);
        if (normalized) {
            return {
                success: true,
                issues: normalized,
                parseReason: Array.isArray(parsed)
                    ? `${source}_direct_array`
                    : `${source}_direct_object`
            };
        }
        return {
            success: false,
            parseReason: `unusable_json_${source}`
        };
    } catch (_error) {
        // Try substring extraction below.
    }

    const arraySegment = extractFirstBalancedSegment(cleaned, '[', ']');
    if (arraySegment) {
        try {
            const parsedArray = JSON.parse(arraySegment);
            const normalized = normalizeIssuePayload(parsedArray);
            if (normalized) {
                return {
                    success: true,
                    issues: normalized,
                    parseReason: `${source}_extracted_array`
                };
            }
            return {
                success: false,
                parseReason: `unusable_extracted_array_${source}`
            };
        } catch (_error) {
            // Try object extraction below.
        }
    }

    const objectSegment = extractFirstBalancedSegment(cleaned, '{', '}');
    if (objectSegment) {
        try {
            const parsedObject = JSON.parse(objectSegment);
            const normalized = normalizeIssuePayload(parsedObject);
            if (normalized) {
                return {
                    success: true,
                    issues: normalized,
                    parseReason: `${source}_extracted_object`
                };
            }
            return {
                success: false,
                parseReason: `unusable_extracted_object_${source}`
            };
        } catch (_error) {
            return {
                success: false,
                parseReason: `invalid_json_${source}`
            };
        }
    }

    return {
        success: false,
        parseReason: `non_json_${source}`
    };
}

function parseModelIssues(message) {
    const content = String(message?.content || '');
    const thinking = String(message?.thinking || '');
    const hasContent = content.trim().length > 0;
    const hasThinking = thinking.trim().length > 0;

    if (!hasContent && !hasThinking) {
        return {
            issues: [],
            parseSuccess: false,
            parseReason: 'no_output',
            parsedFrom: null
        };
    }

    const primary = tryParseModelPayload(content, 'content');
    if (primary.success) {
        return {
            issues: primary.issues,
            parseSuccess: true,
            parseReason: primary.parseReason,
            parsedFrom: 'content'
        };
    }

    if (!hasContent && hasThinking) {
        const fallback = tryParseModelPayload(thinking, 'thinking');
        if (fallback.success) {
            return {
                issues: fallback.issues,
                parseSuccess: true,
                parseReason: fallback.parseReason,
                parsedFrom: 'thinking'
            };
        }

        return {
            issues: [],
            parseSuccess: false,
            parseReason: fallback.parseReason || 'empty_content_with_thinking',
            parsedFrom: null
        };
    }

    return {
        issues: [],
        parseSuccess: false,
        parseReason: primary.parseReason || 'parse_failed',
        parsedFrom: null
    };
}

function incrementCount(counts, key) {
    const normalized = String(key || 'unknown');
    counts[normalized] = (counts[normalized] || 0) + 1;
}

function formatTopReasonCounts(counts, limit = 3) {
    if (!counts || typeof counts !== 'object') {
        return '';
    }

    const ranked = Object.entries(counts)
        .sort((a, b) => b[1] - a[1])
        .slice(0, limit);

    if (ranked.length === 0) {
        return '';
    }

    return ranked.map(([reason, count]) => `${reason}: ${count}`).join(', ');
}

function mean(values) {
    if (values.length === 0) return 0;
    return values.reduce((sum, v) => sum + v, 0) / values.length;
}

function median(values) {
    if (values.length === 0) return 0;
    const sorted = [...values].sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    if (sorted.length % 2 === 0) {
        return (sorted[mid - 1] + sorted[mid]) / 2;
    }
    return sorted[mid];
}

async function collectExecutionEnvironment() {
    let ollamaVersion = 'unknown';
    try {
        ollamaVersion = execSync('ollama --version', {
            encoding: 'utf8',
            stdio: ['ignore', 'pipe', 'ignore']
        }).trim();
    } catch (error) {
        ollamaVersion = 'unavailable';
    }

    const cpus = os.cpus() || [];
    const totalMemGB = (os.totalmem() / (1024 ** 3)).toFixed(2);
    const freeMemGB = (os.freemem() / (1024 ** 3)).toFixed(2);

    return {
        os: {
            platform: os.platform(),
            release: os.release(),
            arch: os.arch()
        },
        nodeVersion: process.version,
        ollamaVersion,
        hardware: {
            cpuModel: cpus[0] ? cpus[0].model : 'unknown',
            cpuCores: cpus.length,
            totalMemoryGB: Number(totalMemGB),
            freeMemoryGB: Number(freeMemGB),
            gpu: 'not captured by this script (Ollama backend dependent)'
        }
    };
}

function resolveModelsToTest(modelsToEvaluate, availableModelObjects) {
    const resolved = [];
    const usedResolvedNames = new Set();

    for (const requestedModel of modelsToEvaluate) {
        const exact = availableModelObjects.find(m => m.name === requestedModel);
        const prefix = availableModelObjects.find(m => m.name.startsWith(requestedModel));
        const match = exact || prefix;

        if (!match) {
            console.log(`⚠️  Skipping ${requestedModel} (not installed)`);
            continue;
        }

        if (usedResolvedNames.has(match.name)) {
            console.log(`⚠️  Skipping ${requestedModel} (duplicates resolved model ${match.name})`);
            continue;
        }

        usedResolvedNames.add(match.name);
        resolved.push({
            requestedModel,
            resolvedModel: match.name,
            modelDigest: match.digest || null,
            modelSizeBytes: match.size || null,
            modifiedAt: match.modified_at || null,
            details: match.details || null
        });
    }

    return resolved;
}

function normalizeFilePath(filePath) {
    return path.resolve(filePath).replace(/\\/g, '/');
}

function normalizeDatasetLanguage(language) {
    const normalized = String(language || '').toLowerCase();
    return normalized === 'typescript' ? 'typescript' : 'javascript';
}

function sanitizeSampleFileName(value) {
    const safe = String(value || 'sample')
        .toLowerCase()
        .replace(/[^a-z0-9_.-]/g, '_')
        .replace(/_+/g, '_')
        .replace(/^_+|_+$/g, '');
    return safe || 'sample';
}

function resolveEslintBinary() {
    if (ESLINT_BIN_FLAG) {
        return ESLINT_BIN_FLAG;
    }

    const ext = process.platform === 'win32' ? '.cmd' : '';
    const local = path.join(EXTENSION_ROOT, 'node_modules', '.bin', `eslint${ext}`);
    if (fsSync.existsSync(local)) {
        return local;
    }

    return 'eslint';
}

function hasEslintSecurityPlugin() {
    try {
        require.resolve('eslint-plugin-security', { paths: [EXTENSION_ROOT] });
        return true;
    } catch (_error) {
        return false;
    }
}

async function runExecFileCommand(command, args, options = {}) {
    const start = Date.now();
    try {
        const { stdout, stderr } = await execFileAsync(command, args, {
            cwd: options.cwd,
            env: options.env,
            timeout: options.timeoutMs,
            maxBuffer: options.maxBuffer || 50 * 1024 * 1024
        });

        return {
            exitCode: 0,
            stdout: stdout || '',
            stderr: stderr || '',
            durationMs: Date.now() - start,
            executionError: null
        };
    } catch (error) {
        const durationMs = Date.now() - start;
        const hasNumericCode = Number.isInteger(error.code);

        if (hasNumericCode) {
            return {
                exitCode: error.code,
                stdout: error.stdout || '',
                stderr: error.stderr || '',
                durationMs,
                executionError: null
            };
        }

        return {
            exitCode: null,
            stdout: error.stdout || '',
            stderr: error.stderr || '',
            durationMs,
            executionError: error
        };
    }
}

async function readToolVersion(command, args = ['--version']) {
    const outcome = await runExecFileCommand(command, args, {
        timeoutMs: 20000,
        maxBuffer: 2 * 1024 * 1024
    });

    if (outcome.executionError || outcome.exitCode !== 0) {
        return null;
    }

    const output = `${outcome.stdout}\n${outcome.stderr}`.trim();
    if (!output) {
        return null;
    }

    return output.split('\n')[0].trim();
}

function normalizeToolSeverity(rawSeverity) {
    const severity = String(rawSeverity || '').toLowerCase();
    if (severity === 'error' || severity === 'critical' || severity === 'high' || severity === '2') {
        return 'high';
    }
    if (severity === 'warning' || severity === 'medium' || severity === '1') {
        return 'medium';
    }
    return 'low';
}

const TOOL_TYPE_PATTERNS = [
    { regex: /(nosql|mongodb|mongo\s*injection|cwe-943)/i, type: 'NoSQL Injection' },
    { regex: /(sql\s*injection|sqli|cwe-89)/i, type: 'SQL Injection' },
    { regex: /(xss|cross[\s-]*site[\s-]*scripting|cwe-79)/i, type: 'Cross-Site Scripting (XSS)' },
    { regex: /(command[\s-]*injection|shell[\s-]*injection|child_process|exec\(|cwe-78)/i, type: 'Command Injection' },
    { regex: /(path[\s-]*traversal|directory[\s-]*traversal|zip[\s-]*slip|non-literal-fs-filename|cwe-22)/i, type: 'Path Traversal' },
    { regex: /(prototype[\s-]*pollution|object[\s-]*injection|__proto__|cwe-1321)/i, type: 'Prototype Pollution' },
    { regex: /(ldap[\s-]*injection|cwe-90)/i, type: 'LDAP Injection' },
    { regex: /(header[\s-]*injection|response[\s-]*splitting|cwe-113)/i, type: 'Header Injection' },
    { regex: /(xml external entity|xxe|entity expansion|cwe-611|cwe-776)/i, type: 'XML External Entity (XXE)' },
    { regex: /(ssrf|server[\s-]*side request forgery|request forgery|cwe-918)/i, type: 'Server-Side Request Forgery (SSRF)' },
    { regex: /(regex|re?dos|catastrophic backtracking|cwe-1333)/i, type: 'Regular Expression DoS' },
    { regex: /(deserializ|unsafe deserialization|cwe-502)/i, type: 'Insecure Deserialization' },
    { regex: /(weak\s*(crypto|cryptography)|broken crypto|insecure random|md5|sha1|\\bdes\\b|cwe-327|cwe-338)/i, type: 'Weak Cryptography' },
    { regex: /(hardcoded credential|hardcoded secret|embedded secret|api key|cwe-798)/i, type: 'Hardcoded Credentials' },
    { regex: /(authentication bypass|auth[\s-]*bypass|jwt.+(none|verify)|cwe-287)/i, type: 'Authentication Bypass' },
    { regex: /(improper authentication|weak authentication)/i, type: 'Improper Authentication' },
    { regex: /(race condition|toctou|cwe-362)/i, type: 'Race Condition' },
    { regex: /(information exposure|sensitive data|data leak|cwe-200|cwe-532)/i, type: 'Information Exposure' },
    { regex: /(input validation|validation bypass|unsanitized input|cwe-20)/i, type: 'Input Validation' },
    { regex: /(weak encryption|insufficient key|cwe-326)/i, type: 'Weak Encryption' },
    { regex: /(crypto verification|signature verification|timing safe)/i, type: 'Crypto Verification' },
    { regex: /(code injection|eval-with-expression|eval injection|template injection|cwe-94)/i, type: 'Code Injection' }
];

function inferVulnerabilityType(hintText, fallback = 'Security Issue') {
    const normalized = String(hintText || '').trim();
    for (const entry of TOOL_TYPE_PATTERNS) {
        if (entry.regex.test(normalized)) {
            return entry.type;
        }
    }
    return fallback;
}

async function createBaselineWorkspace(testCases) {
    const workspaceDir = await fs.mkdtemp(path.join(os.tmpdir(), 'code-guardian-baseline-'));
    const usedNames = new Set();
    const byNormalizedPath = new Map();
    const byBasename = new Map();

    for (let index = 0; index < testCases.length; index++) {
        const testCase = testCases[index];
        const extension = normalizeDatasetLanguage(testCase.language) === 'typescript' ? '.ts' : '.js';
        const seedName = sanitizeSampleFileName(testCase.id || `sample_${index + 1}`);
        let fileName = `${seedName}${extension}`;
        let suffix = 1;
        while (usedNames.has(fileName)) {
            fileName = `${seedName}_${suffix}${extension}`;
            suffix += 1;
        }
        usedNames.add(fileName);

        const filePath = path.join(workspaceDir, fileName);
        await fs.writeFile(filePath, `${testCase.code}\n`, 'utf8');

        byNormalizedPath.set(normalizeFilePath(filePath), testCase);
        byBasename.set(fileName, testCase);
    }

    return {
        workspaceDir,
        byNormalizedPath,
        byBasename
    };
}

function resolveTestCaseFromResultPath(filePath, workspace) {
    if (!filePath) {
        return null;
    }

    let rawPath = String(filePath);
    if (rawPath.startsWith('file://')) {
        try {
            rawPath = fileURLToPath(rawPath);
        } catch (_error) {
            // Keep rawPath as-is if URL parsing fails.
        }
    }

    const candidates = [];
    if (path.isAbsolute(rawPath)) {
        candidates.push(rawPath);
    } else {
        candidates.push(path.resolve(workspace.workspaceDir, rawPath));
        candidates.push(path.resolve(rawPath));
    }

    for (const candidate of candidates) {
        const resolved = workspace.byNormalizedPath.get(normalizeFilePath(candidate));
        if (resolved) {
            return resolved;
        }
    }

    return workspace.byBasename.get(path.basename(rawPath)) || null;
}

function createFindingsMap(testCases) {
    const map = new Map();
    for (const testCase of testCases) {
        map.set(testCase.id, []);
    }
    return map;
}

function appendFinding(findingsByCase, testCase, finding) {
    if (!testCase || !findingsByCase.has(testCase.id)) {
        return;
    }

    findingsByCase.get(testCase.id).push(finding);
}

function buildBaselineEvaluationResult({
    toolName,
    toolVersion,
    findingsByCase,
    testCases,
    totalDurationMs
}) {
    const details = [];
    const metrics = [];
    const latencySamples = [];
    const perSampleLatency = testCases.length > 0
        ? Math.max(1, Math.round(totalDurationMs / testCases.length))
        : 0;

    for (const testCase of testCases) {
        const detectedIssues = findingsByCase.get(testCase.id) || [];
        const caseMetrics = calculateMetrics(
            detectedIssues,
            testCase.expectedVulnerabilities,
            testCase.code
        );

        metrics.push(caseMetrics);
        latencySamples.push(perSampleLatency);

        details.push({
            testCaseId: testCase.id,
            testCaseName: testCase.name,
            run: 1,
            success: true,
            responseTime: perSampleLatency,
            detected: detectedIssues.length,
            expected: testCase.expectedVulnerabilities.length,
            parseSuccess: true,
            parseReason: 'baseline_tool_output',
            parsedFrom: 'tool',
            detectedIssues,
            expectedVulnerabilities: testCase.expectedVulnerabilities,
            expectedFix: testCase.expectedFix || null,
            metrics: caseMetrics,
            ragEnabled: false
        });
    }

    const aggregateMetrics = calculateAggregateMetrics(metrics);
    const perCategoryMetrics = calculatePerCategoryMetrics(details);
    const meanLatencyMs = latencySamples.length > 0 ? Math.round(mean(latencySamples)) : 0;
    const medianLatencyMs = latencySamples.length > 0 ? Math.round(median(latencySamples)) : 0;

    return {
        requestedModel: toolName,
        model: toolName,
        modelVersion: {
            digest: null,
            sizeBytes: null,
            modifiedAt: null,
            details: {
                toolVersion: toolVersion || 'unknown'
            }
        },
        promptMode: 'SAST baseline',
        evaluationFamily: 'baseline',
        ragEnabled: false,
        ragConfig: {
            retrievalMode: 'none',
            k: 0
        },
        runsPerSample: 1,
        testCases: testCases.length,
        totalRequests: testCases.length,
        successfulRequests: testCases.length,
        meanLatencyMs,
        medianLatencyMs,
        parseSuccessRate: '100.00',
        parseDiagnostics: {
            reasons: {
                baseline_tool_output: testCases.length
            },
            failures: {}
        },
        metrics: aggregateMetrics,
        perCategoryMetrics,
        detailedResults: details
    };
}

async function runSemgrepBaseline(testCases, workspace, options) {
    console.log(`\n${'='.repeat(80)}`);
    console.log('🔧 Baseline: Semgrep');
    console.log(`${'='.repeat(80)}\n`);

    const version = await readToolVersion(options.semgrepBin);
    if (!version) {
        return { skipped: true, reason: `binary not available: ${options.semgrepBin}` };
    }

    const args = [
        '--config=p/security-audit',
        '--config=p/javascript',
        '--config=p/typescript',
        '--config=p/owasp-top-ten',
        '--json',
        '--metrics=off',
        '--quiet',
        workspace.workspaceDir
    ];

    const outcome = await runExecFileCommand(options.semgrepBin, args, {
        timeoutMs: options.timeoutMs
    });

    if (outcome.executionError || ![0, 1].includes(outcome.exitCode)) {
        return {
            skipped: true,
            reason: `failed to execute (exit=${outcome.exitCode ?? 'n/a'}): ${String(outcome.executionError?.message || outcome.stderr || 'unknown error').trim()}`
        };
    }

    let parsed;
    try {
        parsed = JSON.parse(outcome.stdout || '{"results": []}');
    } catch (_error) {
        return { skipped: true, reason: 'output parse failure' };
    }

    const findingsByCase = createFindingsMap(testCases);
    for (const finding of parsed.results || []) {
        const testCase = resolveTestCaseFromResultPath(finding.path, workspace);
        if (!testCase) {
            continue;
        }

        const message = String(finding.extra?.message || '').trim();
        const ruleId = String(finding.check_id || '');
        const cwe = Array.isArray(finding.extra?.metadata?.cwe)
            ? finding.extra.metadata.cwe.join(' ')
            : String(finding.extra?.metadata?.cwe || '');

        appendFinding(findingsByCase, testCase, {
            message: message || 'Semgrep finding',
            type: inferVulnerabilityType(`${ruleId} ${message} ${cwe}`),
            startLine: finding.start?.line || 1,
            endLine: finding.end?.line || finding.start?.line || 1,
            severity: normalizeToolSeverity(finding.extra?.severity || 'warning'),
            ruleId,
            tool: 'semgrep'
        });
    }

    return {
        skipped: false,
        result: buildBaselineEvaluationResult({
            toolName: 'semgrep',
            toolVersion: version,
            findingsByCase,
            testCases,
            totalDurationMs: outcome.durationMs
        })
    };
}

/**
 * Phase 2 refinement helper. Runs Semgrep ONCE over a temporary baseline
 * workspace and returns a Map<testCaseId, SastFinding[]> suitable for SAST×LLM
 * fusion. This deliberately duplicates the rule set of runSemgrepBaseline so
 * LLM fusion sees exactly the same signal the SAST baseline would score.
 *
 * Returns `{ findingsByCase, workspace }`. Caller is responsible for calling
 * `await fs.rm(workspace.workspaceDir, { recursive: true, force: true })` when
 * done (or for leaving it behind when --keep-baseline-workdir is set).
 */
async function collectSastFindingsForFusion(testCases, { semgrepBin, timeoutMs }) {
    const findingsByCase = createFindingsMap(testCases);
    const workspace = await createBaselineWorkspace(testCases);

    const version = await readToolVersion(semgrepBin);
    if (!version) {
        console.log(`⚠️  SAST fusion requested but Semgrep binary unavailable (${semgrepBin}); proceeding without fusion.`);
        return { findingsByCase, workspace, skipped: true };
    }

    const semgrepArgs = [
        '--config=p/security-audit',
        '--config=p/javascript',
        '--config=p/typescript',
        '--config=p/owasp-top-ten',
        '--json',
        '--metrics=off',
        '--quiet',
        workspace.workspaceDir
    ];

    const outcome = await runExecFileCommand(semgrepBin, semgrepArgs, { timeoutMs });
    if (outcome.executionError || ![0, 1].includes(outcome.exitCode)) {
        console.log(`⚠️  SAST fusion Semgrep failed (exit=${outcome.exitCode}); proceeding without fusion.`);
        return { findingsByCase, workspace, skipped: true };
    }

    let parsed;
    try {
        parsed = JSON.parse(outcome.stdout || '{"results": []}');
    } catch (_error) {
        console.log('⚠️  SAST fusion Semgrep output parse failure; proceeding without fusion.');
        return { findingsByCase, workspace, skipped: true };
    }

    for (const finding of parsed.results || []) {
        const testCase = resolveTestCaseFromResultPath(finding.path, workspace);
        if (!testCase) continue;

        const message = String(finding.extra?.message || '').trim();
        const ruleId = String(finding.check_id || '');
        const cwe = Array.isArray(finding.extra?.metadata?.cwe)
            ? finding.extra.metadata.cwe.join(' ')
            : String(finding.extra?.metadata?.cwe || '');

        appendFinding(findingsByCase, testCase, {
            message: message || 'Semgrep finding',
            type: inferVulnerabilityType(`${ruleId} ${message} ${cwe}`),
            startLine: finding.start?.line || 1,
            endLine: finding.end?.line || finding.start?.line || 1,
            severity: normalizeToolSeverity(finding.extra?.severity || 'warning'),
            ruleId,
            tool: 'semgrep'
        });
    }

    const totalFindings = [...findingsByCase.values()].reduce((sum, v) => sum + v.length, 0);
    console.log(`🔗 SAST fusion corpus: ${totalFindings} Semgrep findings across ${findingsByCase.size} test cases (Semgrep ${version})`);
    return { findingsByCase, workspace, skipped: false };
}

async function runCodeqlBaseline(testCases, workspace, options) {
    console.log(`\n${'='.repeat(80)}`);
    console.log('🔧 Baseline: CodeQL');
    console.log(`${'='.repeat(80)}\n`);

    const version = await readToolVersion(options.codeqlBin);
    if (!version) {
        return { skipped: true, reason: `binary not available: ${options.codeqlBin}` };
    }

    const dbPath = path.join(workspace.workspaceDir, '.codeql-db');
    const outputPath = path.join(workspace.workspaceDir, 'codeql-results.sarif');

    const createArgs = [
        'database',
        'create',
        dbPath,
        '--language=javascript',
        '--source-root',
        workspace.workspaceDir,
        '--overwrite'
    ];

    const createOutcome = await runExecFileCommand(options.codeqlBin, createArgs, {
        timeoutMs: options.timeoutMs
    });

    if (createOutcome.executionError || createOutcome.exitCode !== 0) {
        return {
            skipped: true,
            reason: `database creation failed (exit=${createOutcome.exitCode ?? 'n/a'})`
        };
    }

    const analyzeArgs = [
        'database',
        'analyze',
        dbPath,
        'codeql/javascript-queries:codeql-suites/javascript-security-and-quality.qls',
        '--format=sarif-latest',
        '--output',
        outputPath
    ];

    const analyzeOutcome = await runExecFileCommand(options.codeqlBin, analyzeArgs, {
        timeoutMs: options.timeoutMs
    });

    if (analyzeOutcome.executionError || analyzeOutcome.exitCode !== 0) {
        return {
            skipped: true,
            reason: `analysis failed (exit=${analyzeOutcome.exitCode ?? 'n/a'})`
        };
    }

    let sarif;
    try {
        const raw = await fs.readFile(outputPath, 'utf8');
        sarif = JSON.parse(raw);
    } catch (_error) {
        return { skipped: true, reason: 'output parse failure' };
    }

    const findingsByCase = createFindingsMap(testCases);

    for (const run of sarif.runs || []) {
        const ruleInfo = new Map();
        for (const rule of run.tool?.driver?.rules || []) {
            const id = String(rule.id || '');
            const shortDescription = String(rule.shortDescription?.text || '');
            const name = String(rule.name || '');
            ruleInfo.set(id, `${name} ${shortDescription}`.trim());
        }

        for (const result of run.results || []) {
            const ruleId = String(result.ruleId || '');
            const message = String(result.message?.text || '').trim();
            const ruleDetails = ruleInfo.get(ruleId) || '';
            const location = result.locations?.[0]?.physicalLocation || {};
            const uri = location.artifactLocation?.uri;
            const testCase = resolveTestCaseFromResultPath(uri, workspace);
            if (!testCase) {
                continue;
            }

            appendFinding(findingsByCase, testCase, {
                message: message || 'CodeQL finding',
                type: inferVulnerabilityType(`${ruleId} ${ruleDetails} ${message}`),
                startLine: location.region?.startLine || 1,
                endLine: location.region?.endLine || location.region?.startLine || 1,
                severity: normalizeToolSeverity(result.level || 'warning'),
                ruleId,
                tool: 'codeql'
            });
        }
    }

    return {
        skipped: false,
        result: buildBaselineEvaluationResult({
            toolName: 'codeql',
            toolVersion: version,
            findingsByCase,
            testCases,
            totalDurationMs: createOutcome.durationMs + analyzeOutcome.durationMs
        })
    };
}

async function runEslintSecurityBaseline(testCases, workspace, options) {
    console.log(`\n${'='.repeat(80)}`);
    console.log('🔧 Baseline: ESLint Security');
    console.log(`${'='.repeat(80)}\n`);

    if (!hasEslintSecurityPlugin()) {
        return {
            skipped: true,
            reason: 'eslint-plugin-security not installed in extension workspace'
        };
    }

    const eslintBin = options.eslintBin;
    const version = await readToolVersion(eslintBin, ['--version']);
    if (!version) {
        return { skipped: true, reason: `binary not available: ${eslintBin}` };
    }

    const configPath = path.join(workspace.workspaceDir, 'eslint.config.cjs');
    const configContents = `'use strict';
const path = require('path');

const candidates = [
  path.join(${JSON.stringify(EXTENSION_ROOT)}, 'node_modules', 'eslint-plugin-security'),
  'eslint-plugin-security'
];

let security;
for (const candidate of candidates) {
  try {
    security = require(candidate);
    break;
  } catch (_error) {
    // Try next candidate.
  }
}

if (!security) {
  throw new Error('eslint-plugin-security is required for baseline evaluation.');
}

module.exports = [
  {
    files: ['**/*.js', '**/*.ts'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module'
    },
    plugins: {
      security
    },
    rules: {
      ...(security.configs.recommended?.rules || {})
    }
  }
];
`;
    await fs.writeFile(configPath, configContents, 'utf8');

    const nodePath = path.join(EXTENSION_ROOT, 'node_modules');
    const env = {
        ...process.env,
        NODE_PATH: process.env.NODE_PATH
            ? `${nodePath}${path.delimiter}${process.env.NODE_PATH}`
            : nodePath
    };

    const args = [
        workspace.workspaceDir,
        '--ext',
        '.js,.ts',
        '--format',
        'json',
        '--no-error-on-unmatched-pattern'
    ];

    const outcome = await runExecFileCommand(eslintBin, args, {
        cwd: workspace.workspaceDir,
        env,
        timeoutMs: options.timeoutMs
    });

    if (outcome.executionError || ![0, 1].includes(outcome.exitCode)) {
        return {
            skipped: true,
            reason: `analysis failed (exit=${outcome.exitCode ?? 'n/a'})`
        };
    }

    let parsed;
    try {
        parsed = JSON.parse(outcome.stdout || '[]');
    } catch (_error) {
        return { skipped: true, reason: 'output parse failure' };
    }

    const findingsByCase = createFindingsMap(testCases);
    for (const fileEntry of parsed) {
        const testCase = resolveTestCaseFromResultPath(fileEntry.filePath, workspace);
        if (!testCase) {
            continue;
        }

        for (const message of fileEntry.messages || []) {
            const ruleId = String(message.ruleId || '');
            const text = String(message.message || '').trim();
            appendFinding(findingsByCase, testCase, {
                message: text || 'ESLint finding',
                type: inferVulnerabilityType(`${ruleId} ${text}`),
                startLine: message.line || 1,
                endLine: message.endLine || message.line || 1,
                severity: normalizeToolSeverity(String(message.severity || '1')),
                ruleId,
                tool: 'eslint-security'
            });
        }
    }

    return {
        skipped: false,
        result: buildBaselineEvaluationResult({
            toolName: 'eslint-security',
            toolVersion: version,
            findingsByCase,
            testCases,
            totalDurationMs: outcome.durationMs
        })
    };
}

async function evaluateBaselines(testCases, options) {
    const status = {
        requestedTools: options.requestedTools,
        completedTools: [],
        skippedTools: []
    };
    const results = [];

    if (!Array.isArray(options.requestedTools) || options.requestedTools.length === 0) {
        return { results, status };
    }

    const workspace = await createBaselineWorkspace(testCases);

    try {
        for (const tool of options.requestedTools) {
            let outcome;
            if (tool === 'semgrep') {
                outcome = await runSemgrepBaseline(testCases, workspace, options);
            } else if (tool === 'codeql') {
                outcome = await runCodeqlBaseline(testCases, workspace, options);
            } else if (tool === 'eslint-security') {
                outcome = await runEslintSecurityBaseline(testCases, workspace, options);
            } else {
                status.skippedTools.push({ tool, reason: 'unsupported baseline identifier' });
                continue;
            }

            if (outcome.skipped) {
                console.log(`⚠️  Skipping baseline ${tool}: ${outcome.reason}`);
                status.skippedTools.push({ tool, reason: outcome.reason });
                continue;
            }

            results.push(outcome.result);
            status.completedTools.push(tool);
            console.log(`✅ Baseline ${tool} completed`);
        }
    } finally {
        if (!options.keepWorkspace) {
            await fs.rm(workspace.workspaceDir, { recursive: true, force: true });
        } else {
            console.log(`ℹ️  Baseline workspace retained at: ${workspace.workspaceDir}`);
        }
    }

    return { results, status };
}

// Stage-2 per-issue repair generation. Mirrors src/analyzer.ts generateRepair:
// windowed context (±5 lines) when the issue spans ≤10 lines, full code
// otherwise; structured-output schema enforces {code, language} so the model
// cannot reply with prose. Returns {fix, latencyMs} regardless of outcome so
// the caller can attribute time and reason for failures.
async function generateRepairStage2(modelName, code, issue, options) {
    const { temperature, timeoutMs } = options;
    const ollama = getOllamaClient();

    const allLines = code.split('\n');
    const startIdx = Math.max(0, (issue.startLine || 1) - 1);
    const endIdx = Math.max(startIdx, (issue.endLine || issue.startLine || 1));
    const vulnerableLines = allLines.slice(startIdx, endIdx).join('\n');

    const issueSpan = endIdx - startIdx;
    const useWindow = issueSpan <= 10;
    const windowStart = Math.max(0, startIdx - 5);
    const windowEnd = Math.min(allLines.length, endIdx + 5);
    const windowedContext = useWindow
        ? allLines.slice(windowStart, windowEnd).join('\n')
        : code;
    const contextLabel = useWindow
        ? `Surrounding context (lines ${windowStart + 1}-${windowEnd})`
        : 'Full code context';

    const userPrompt = `Vulnerability: ${issue.message || issue.type || 'security issue'}
Vulnerable lines (${issue.startLine}-${issue.endLine}):
${vulnerableLines}

${contextLabel}:
${windowedContext}

Return ONLY the JSON object {code, language}.`;

    const start = Date.now();
    try {
        const requestPayload = {
            model: modelName,
            messages: [
                { role: 'system', content: REPAIR_SYSTEM_PROMPT },
                { role: 'user', content: userPrompt }
            ],
            format: ENABLE_STRUCTURED_OUTPUT ? REPAIR_SCHEMA : 'json',
            options: { temperature, seed: 42 }
        };
        if (DISABLE_THINKING) {
            requestPayload.think = false;
        }

        const response = await Promise.race([
            ollama.chat(requestPayload),
            new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Stage-2 repair timeout')), timeoutMs)
            )
        ]);

        const raw = (response.message?.content || '').trim();
        let parsed;
        try {
            parsed = JSON.parse(raw);
        } catch {
            return { fix: undefined, latencyMs: Date.now() - start, error: 'parse_error' };
        }

        if (parsed && typeof parsed.code === 'string' && parsed.code.trim().length > 0) {
            return { fix: parsed.code.trim(), latencyMs: Date.now() - start };
        }
        // Fallback: any non-empty string property.
        const firstString = parsed && typeof parsed === 'object'
            ? Object.values(parsed).find(v => typeof v === 'string' && v.trim().length > 0)
            : undefined;
        if (firstString) {
            return { fix: firstString.trim(), latencyMs: Date.now() - start };
        }
        return { fix: undefined, latencyMs: Date.now() - start, error: 'empty_response' };
    } catch (error) {
        return { fix: undefined, latencyMs: Date.now() - start, error: error.message };
    }
}

// Analyze code with a specific model
async function analyzeWithModel(modelName, code, options) {
    const {
        useRAG,
        timeoutMs,
        ragK,
        temperature,
        numPredict
    } = options;
    const ollama = getOllamaClient();

    try {
        const startTime = Date.now();
        // Phase B3 — resource instrumentation. cpuUsage() returns microseconds
        // since process start; memoryUsage() is a per-call snapshot. We capture
        // baselines here and diff after the inference call so the metrics appear
        // alongside responseTime in every run JSON.
        const cpuStart = process.cpuUsage();
        const memBefore = process.memoryUsage();
        let memPeakRss = memBefore.rss;
        let memPeakHeap = memBefore.heapUsed;
        const memSampler = setInterval(() => {
            const m = process.memoryUsage();
            if (m.rss > memPeakRss) memPeakRss = m.rss;
            if (m.heapUsed > memPeakHeap) memPeakHeap = m.heapUsed;
        }, 100);
        const systemPrompt = useRAG
            ? `${SYSTEM_PROMPT}\n\nRELEVANT SECURITY KNOWLEDGE (top-k=${ragK}):\n${RAG_KNOWLEDGE_SNIPPETS.slice(0, Math.max(0, ragK)).map((s, i) => `${i + 1}. ${s}`).join('\n') || 'No retrieval snippets selected (k=0).'}`
            : SYSTEM_PROMPT;

        // Phase 3: optionally inject deterministic import / sink context.
        // The context is appended AFTER the code so it cannot be confused for
        // code by the model, and so the leading code position stays identical
        // to the baseline prompt for cache-friendly comparisons.
        let userContent = `Analyze the following code for security vulnerabilities:\n\n${code}`;
        if (IMPORT_CONTEXT_ENABLED) {
            const ctx = importResolver.resolveImportContext(code);
            const formatted = importResolver.formatImportContext(ctx);
            if (formatted) {
                userContent += `\n\n[Static context — use to inform analysis, do not echo back]\n${formatted}`;
            }
        }

        const requestPayload = {
            model: modelName,
            messages: [
                { role: 'system', content: systemPrompt },
                { role: 'user', content: userContent }
            ],
            format: 'json',
            options: {
                temperature,
                num_predict: numPredict,
                seed: 42
            }
        };

        if (ENABLE_STRUCTURED_OUTPUT) {
            requestPayload.format = MODEL_RESPONSE_SCHEMA;
        }
        if (DISABLE_THINKING) {
            requestPayload.think = false;
        }

        const response = await Promise.race([
            ollama.chat(requestPayload),
            new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Timeout')), timeoutMs)
            )
        ]);

        const inferenceEndTime = Date.now();
        const inferenceTimeMs = inferenceEndTime - startTime;
        const parsed = parseModelIssues(response.message);
        const parseEndTime = Date.now();
        const parseTimeMs = parseEndTime - inferenceEndTime;
        const responseTime = parseEndTime - startTime;
        clearInterval(memSampler);
        const cpuDelta = process.cpuUsage(cpuStart);
        const resourceUsage = {
            cpuUserMs: Math.round(cpuDelta.user / 1000),
            cpuSystemMs: Math.round(cpuDelta.system / 1000),
            cpuTotalMs: Math.round((cpuDelta.user + cpuDelta.system) / 1000),
            memPeakRssBytes: memPeakRss,
            memPeakHeapBytes: memPeakHeap,
            memDeltaRssBytes: memPeakRss - memBefore.rss
        };

        if (!parsed.parseSuccess) {
            console.log(`   ⚠️  JSON parsing failed for ${modelName} (${parsed.parseReason})`);
        }

        // Stage-2: per-detected-issue structured repair generation. Runs only when
        // detection emitted at least one issue; mirrors the extension's two-call
        // pipeline so stage-1 latency reflects inline diagnostics.
        const stage2Start = Date.now();
        let stage2RepairCount = 0;
        let stage2RepairOk = 0;
        const issuesWithRepairs = [];
        for (const issue of parsed.issues || []) {
            const result = await generateRepairStage2(modelName, code, issue, {
                temperature,
                timeoutMs
            });
            stage2RepairCount += 1;
            const augmented = { ...issue };
            if (result.fix) {
                augmented.suggestedFix = result.fix;
                stage2RepairOk += 1;
            }
            issuesWithRepairs.push(augmented);
        }
        const stage2TotalMs = Date.now() - stage2Start;

        return {
            success: true,
            responseTime,                  // stage-1 detection only
            inferenceTimeMs,               // stage-1 detection inference time
            parseTimeMs,
            stage2TotalMs,                 // total wall-clock spent on stage-2 repairs
            stage2RepairCount,             // how many stage-2 calls were made
            stage2RepairOk,                // how many returned a usable fix string
            resourceUsage,
            issues: issuesWithRepairs,
            parseSuccess: parsed.parseSuccess,
            parseReason: parsed.parseReason,
            parsedFrom: parsed.parsedFrom,
            rawResponse: response.message?.content || '',
            rawThinking: response.message?.thinking || '',
            ragEnabled: useRAG
        };
    } catch (error) {
        clearInterval(memSampler);
        return {
            success: false,
            error: error.message,
            responseTime: null,
            issues: [],
            parseSuccess: false,
            parseReason: 'request_failure',
            parsedFrom: null,
            ragEnabled: useRAG
        };
    }
}

/**
 * Compute per-test-case metrics using the canonical taxonomy matcher
 * (src/categoryTaxonomy.json). Both sides are first normalized to a canonical
 * category, then matched as sets.
 */
function calculateMetrics(detected, expected, code) {
    const isSecureSample = expected.length === 0;

    const detectedCats = taxonomy.normalizeCategories(detected.map(d => d.type));
    const expectedCats = taxonomy.normalizeCategories(expected.map(e => e.type));
    const intersect = new Set();
    for (const c of detectedCats) {
        if (expectedCats.has(c)) intersect.add(c);
    }
    const truePositives = intersect.size;
    const falsePositives = detectedCats.size - truePositives;
    const falseNegatives = expectedCats.size - truePositives;

    const secureFalsePositiveCases = isSecureSample && detected.length > 0 ? 1 : 0;
    const secureTrueNegativeCases = isSecureSample && detected.length === 0 ? 1 : 0;
    const trueNegatives = secureTrueNegativeCases;

    const codeLines = code.split('\n').length;
    let lineAccuracyCount = 0;
    let lineAccuracyTotal = 0;

    for (const issue of detected) {
        if (typeof issue.startLine === 'number' && typeof issue.endLine === 'number') {
            lineAccuracyTotal++;
            if (issue.startLine >= 1 && issue.startLine <= codeLines &&
                issue.endLine >= 1 && issue.endLine <= codeLines &&
                issue.startLine <= issue.endLine) {
                lineAccuracyCount++;
            }
        }
    }

    return {
        truePositives,
        falsePositives,
        falseNegatives,
        trueNegatives,
        secureFalsePositiveCases,
        secureTrueNegativeCases,
        lineAccuracy: lineAccuracyTotal > 0 ? lineAccuracyCount / lineAccuracyTotal : null
    };
}

function calculateAggregateMetrics(allMetrics) {
    const tp = allMetrics.reduce((sum, m) => sum + m.truePositives, 0);
    const fp = allMetrics.reduce((sum, m) => sum + m.falsePositives, 0);
    const fn = allMetrics.reduce((sum, m) => sum + m.falseNegatives, 0);
    const tn = allMetrics.reduce((sum, m) => sum + m.trueNegatives, 0);
    const secureFpCases = allMetrics.reduce((sum, m) => sum + (m.secureFalsePositiveCases || 0), 0);
    const secureTnCases = allMetrics.reduce((sum, m) => sum + (m.secureTrueNegativeCases || 0), 0);

    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1Score = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
    const accuracy = (tp + tn) / (tp + fp + fn + tn || 1);
    const fpr = secureFpCases + secureTnCases > 0 ? secureFpCases / (secureFpCases + secureTnCases) : 0;

    const lineAccuracies = allMetrics
        .filter(m => m.lineAccuracy !== null)
        .map(m => m.lineAccuracy);
    const avgLineAccuracy = lineAccuracies.length > 0
        ? lineAccuracies.reduce((sum, a) => sum + a, 0) / lineAccuracies.length
        : null;

    const result = {
        precision: (precision * 100).toFixed(2),
        recall: (recall * 100).toFixed(2),
        f1Score: (f1Score * 100).toFixed(2),
        accuracy: (accuracy * 100).toFixed(2),
        falsePositiveRate: (fpr * 100).toFixed(2),
        lineAccuracy: avgLineAccuracy !== null ? (avgLineAccuracy * 100).toFixed(2) : 'N/A',
        truePositives: tp,
        falsePositives: fp,
        falseNegatives: fn,
        trueNegatives: tn,
        secureFalsePositiveCases: secureFpCases,
        secureTrueNegativeCases: secureTnCases
    };

    return result;
}

/**
 * Phase 3 refinement: per-canonical-category metrics aggregator.
 *
 * Walks the run's detailedResults, normalizes detected and expected types via
 * the canonical taxonomy, and reports per-category TP/FP/FN/precision/recall/F1.
 * The "FN" count for a category is incremented for every case whose expected
 * set contains the category but whose detected set does not. The "FP" count is
 * incremented for every case whose detected set contains the category but
 * whose expected set does not (or whose expected set is empty — i.e. secure
 * samples). This aligns with how the thesis reports per-category recall.
 */
function calculatePerCategoryMetrics(detailedResults) {
    if (!Array.isArray(detailedResults) || detailedResults.length === 0) {
        return null;
    }

    const buckets = new Map(); // category → { tp, fp, fn, casesWithCategoryExpected, casesWithCategoryDetected }

    function bumpBucket(cat, key) {
        if (!buckets.has(cat)) {
            buckets.set(cat, { tp: 0, fp: 0, fn: 0, casesWithCategoryExpected: 0, casesWithCategoryDetected: 0 });
        }
        buckets.get(cat)[key]++;
    }

    for (const dr of detailedResults) {
        const detectedCats = taxonomy.normalizeCategories(
            (dr.detectedIssues || []).map(d => d.type)
        );
        const expectedCats = taxonomy.normalizeCategories(
            (dr.expectedVulnerabilities || []).map(e => e.type)
        );

        for (const cat of expectedCats) {
            bumpBucket(cat, 'casesWithCategoryExpected');
            if (detectedCats.has(cat)) bumpBucket(cat, 'tp');
            else bumpBucket(cat, 'fn');
        }
        for (const cat of detectedCats) {
            bumpBucket(cat, 'casesWithCategoryDetected');
            if (!expectedCats.has(cat)) bumpBucket(cat, 'fp');
        }
    }

    const out = {};
    for (const [cat, b] of buckets) {
        const precision = b.tp + b.fp > 0 ? b.tp / (b.tp + b.fp) : 0;
        const recall = b.tp + b.fn > 0 ? b.tp / (b.tp + b.fn) : 0;
        const f1 = precision + recall > 0 ? 2 * precision * recall / (precision + recall) : 0;
        out[cat] = {
            truePositives: b.tp,
            falsePositives: b.fp,
            falseNegatives: b.fn,
            casesExpected: b.casesWithCategoryExpected,
            casesDetected: b.casesWithCategoryDetected,
            precision: (precision * 100).toFixed(2),
            recall: (recall * 100).toFixed(2),
            f1Score: (f1 * 100).toFixed(2)
        };
    }
    return out;
}

function getRankingStrategy(testCases) {
    const secureCount = testCases.filter(tc => tc.expectedVulnerabilities.length === 0).length;
    const vulnerableCount = testCases.length - secureCount;

    if (vulnerableCount === 0) {
        return {
            key: 'fpr',
            label: 'by Lowest FPR (secure-only dataset)'
        };
    }

    return {
        key: 'f1',
        label: 'by F1 Score'
    };
}

function sortEvaluationResults(results, rankingKey) {
    if (rankingKey === 'fpr') {
        return [...results].sort((a, b) => {
            const fprDiff = Number.parseFloat(a.metrics.falsePositiveRate) - Number.parseFloat(b.metrics.falsePositiveRate);
            if (fprDiff !== 0) return fprDiff;

            const parseDiff = Number.parseFloat(b.parseSuccessRate) - Number.parseFloat(a.parseSuccessRate);
            if (parseDiff !== 0) return parseDiff;

            return a.meanLatencyMs - b.meanLatencyMs;
        });
    }

    return [...results].sort((a, b) => {
        const f1Diff = Number.parseFloat(b.metrics.f1Score) - Number.parseFloat(a.metrics.f1Score);
        if (f1Diff !== 0) return f1Diff;

        const precisionDiff = Number.parseFloat(b.metrics.precision) - Number.parseFloat(a.metrics.precision);
        if (precisionDiff !== 0) return precisionDiff;

        return a.meanLatencyMs - b.meanLatencyMs;
    });
}

async function evaluateModel(modelInfo, testCases, options) {
    const {
        useRAG,
        runsPerSample,
        timeoutMs,
        delayMs,
        ragK,
        temperature,
        numPredict,
        sastFindingsByCase, // optional Map<testCaseId, SastFinding[]> for --sast-fusion
        confidenceThreshold // optional [0,1] runtime confidence gate
    } = options;

    const modeLabel = useRAG ? '(RAG)' : '(Base)';
    console.log(`\n${'='.repeat(80)}`);
    console.log(`🧪 Evaluating Model: ${modelInfo.resolvedModel} ${modeLabel}`);
    console.log(`${'='.repeat(80)}\n`);

    const results = [];
    const metrics = [];
    const latencies = [];
    let successfulParses = 0;
    let successfulRequests = 0;
    const parseReasonCounts = {};
    const parseFailureReasonCounts = {};

    const totalRequests = testCases.length * runsPerSample;
    let requestCounter = 0;

    for (let i = 0; i < testCases.length; i++) {
        const testCase = testCases[i];

        for (let run = 1; run <= runsPerSample; run++) {
            requestCounter++;
            console.log(`[${requestCounter}/${totalRequests}] ${testCase.name} (run ${run}/${runsPerSample})`);

            const result = await analyzeWithModel(modelInfo.resolvedModel, testCase.code, {
                useRAG,
                timeoutMs,
                ragK,
                temperature,
                numPredict
            });

            if (result.success) {
                successfulRequests++;
                latencies.push(result.responseTime);
                incrementCount(parseReasonCounts, result.parseReason);

                if (result.parseSuccess) {
                    successfulParses++;
                } else {
                    incrementCount(parseFailureReasonCounts, result.parseReason);
                }

                // Phase 2: optional SAST×LLM fusion (promotes LLM findings that Semgrep also flags).
                let fusedIssues = result.issues;
                let fusionStats = null;
                if (sastFindingsByCase) {
                    const sastForCase = sastFindingsByCase.get(testCase.id) || [];
                    fusedIssues = sastFusion.fuseSastWithLlm(result.issues, sastForCase);
                    fusionStats = sastFusion.fusionSummary(fusedIssues);
                }

                // Phase 2: optional runtime confidence gate.
                let gatedIssues = fusedIssues;
                if (confidenceThreshold && confidenceThreshold > 0) {
                    gatedIssues = fusedIssues.filter(issue => {
                        const c = typeof issue.confidence === 'number' ? issue.confidence : 0.5;
                        return c >= confidenceThreshold;
                    });
                }

                // Phase 5: tag each issue with autoApplicable based on syntax validation.
                gatedIssues = gatedIssues.map(issue => {
                    if (issue && typeof issue.suggestedFix === 'string' && issue.suggestedFix.length > 0) {
                        const v = repairValidator.validateRepair(issue.suggestedFix);
                        return {
                            ...issue,
                            autoApplicable: v.valid,
                            autoApplicableReason: v.valid ? undefined : v.reason
                        };
                    }
                    return issue;
                });

                const caseMetrics = calculateMetrics(
                    gatedIssues,
                    testCase.expectedVulnerabilities,
                    testCase.code
                );

                metrics.push(caseMetrics);

                const fusionLog = fusionStats ? ` | hybrid:${fusionStats.hybrid}, llm-only:${fusionStats.llmOnly}` : '';
                const gateLog = (confidenceThreshold && confidenceThreshold > 0)
                    ? ` | gated:${fusedIssues.length - gatedIssues.length}@≥${confidenceThreshold}`
                    : '';
                console.log(`   ✅ Completed in ${result.responseTime}ms${fusionLog}${gateLog}`);
                console.log(`   📊 TP: ${caseMetrics.truePositives}, FP: ${caseMetrics.falsePositives}, FN: ${caseMetrics.falseNegatives}${caseMetrics.lineAccuracy !== null ? `, Line Acc: ${(caseMetrics.lineAccuracy * 100).toFixed(0)}%` : ''}`);

                results.push({
                    testCaseId: testCase.id,
                    testCaseName: testCase.name,
                    run,
                    success: true,
                    responseTime: result.responseTime,
                    inferenceTimeMs: result.inferenceTimeMs,
                    parseTimeMs: result.parseTimeMs,
                    stage2TotalMs: result.stage2TotalMs ?? 0,
                    stage2RepairCount: result.stage2RepairCount ?? 0,
                    stage2RepairOk: result.stage2RepairOk ?? 0,
                    resourceUsage: result.resourceUsage || null,
                    detected: gatedIssues.length,
                    detectedRaw: result.issues.length,
                    expected: testCase.expectedVulnerabilities.length,
                    parseSuccess: result.parseSuccess,
                    parseReason: result.parseReason,
                    parsedFrom: result.parsedFrom,
                    detectedIssues: gatedIssues,
                    detectedIssuesRaw: result.issues,
                    fusionStats,
                    expectedVulnerabilities: testCase.expectedVulnerabilities,
                    expectedFix: testCase.expectedFix || null,
                    metrics: caseMetrics,
                    ragEnabled: useRAG
                });
            } else {
                console.log(`   ❌ Failed: ${result.error}`);
                results.push({
                    testCaseId: testCase.id,
                    testCaseName: testCase.name,
                    run,
                    success: false,
                    error: result.error,
                    parseSuccess: false,
                    parseReason: result.parseReason || 'request_failure',
                    parsedFrom: null,
                    detectedIssues: [],
                    expectedVulnerabilities: testCase.expectedVulnerabilities,
                    expectedFix: testCase.expectedFix || null,
                    ragEnabled: useRAG
                });
                incrementCount(parseReasonCounts, result.parseReason || 'request_failure');
                incrementCount(parseFailureReasonCounts, result.parseReason || 'request_failure');
            }

            await new Promise(resolve => setTimeout(resolve, delayMs));
        }
    }

    const aggregateMetrics = calculateAggregateMetrics(metrics);
    const perCategoryMetrics = calculatePerCategoryMetrics(results);
    // Phase 5: auto-applicable repair rate across all detected (non-empty) fixes
    // produced in the run. Walks results' detected (non-raw) issues so the rate
    // reflects what the user would actually see post-fusion + post-gate.
    const repairAggregate = repairValidator.aggregateAutoApplicable(
        results.filter(r => r.success).map(r => r.detectedIssues || [])
    );
    const meanLatencyMs = latencies.length > 0 ? Math.round(mean(latencies)) : 0;
    const medianLatencyMs = latencies.length > 0 ? Math.round(median(latencies)) : 0;
    const inferenceLatencies = results.filter(r => r.success && Number.isFinite(r.inferenceTimeMs)).map(r => r.inferenceTimeMs);
    const parseLatencies = results.filter(r => r.success && Number.isFinite(r.parseTimeMs)).map(r => r.parseTimeMs);
    const meanInferenceMs = inferenceLatencies.length > 0 ? Math.round(mean(inferenceLatencies)) : null;
    const medianInferenceMs = inferenceLatencies.length > 0 ? Math.round(median(inferenceLatencies)) : null;
    const meanParseMs = parseLatencies.length > 0 ? Math.round(mean(parseLatencies)) : null;
    const medianParseMs = parseLatencies.length > 0 ? Math.round(median(parseLatencies)) : null;
    const parseSuccessRate = (successfulParses / totalRequests * 100).toFixed(2);

    // Stage-2 repair latency. Aggregated per-call (averaged over the total number
    // of stage-2 calls actually made) so the value reflects per-fix cost rather
    // than per-case cost — most cases produce 0 or 1 fixes, a few produce 2+.
    const stage2Latencies = [];
    let stage2CallsTotal = 0;
    let stage2OkTotal = 0;
    for (const r of results) {
        if (!r.success) continue;
        const calls = r.stage2RepairCount || 0;
        stage2CallsTotal += calls;
        stage2OkTotal += (r.stage2RepairOk || 0);
        // Per-fix latency is the per-case stage2TotalMs divided by the call count.
        if (calls > 0 && Number.isFinite(r.stage2TotalMs)) {
            const perCall = r.stage2TotalMs / calls;
            for (let i = 0; i < calls; i++) stage2Latencies.push(perCall);
        }
    }
    const meanStage2Ms = stage2Latencies.length > 0 ? Math.round(mean(stage2Latencies)) : null;
    const medianStage2Ms = stage2Latencies.length > 0 ? Math.round(median(stage2Latencies)) : null;

    return {
        requestedModel: modelInfo.requestedModel,
        model: modelInfo.resolvedModel,
        modelVersion: {
            digest: modelInfo.modelDigest,
            sizeBytes: modelInfo.modelSizeBytes,
            modifiedAt: modelInfo.modifiedAt,
            details: modelInfo.details
        },
        promptMode: useRAG ? 'LLM+RAG' : 'LLM-only',
        evaluationFamily: 'llm',
        ragEnabled: useRAG,
        ragConfig: {
            retrievalMode: useRAG ? 'static_security_snippets' : 'none',
            k: useRAG ? ragK : 0
        },
        runsPerSample,
        testCases: testCases.length,
        totalRequests,
        successfulRequests,
        meanLatencyMs,
        medianLatencyMs,
        meanInferenceMs,
        medianInferenceMs,
        meanParseMs,
        medianParseMs,
        meanStage2Ms,
        medianStage2Ms,
        stage2CallsTotal,
        stage2OkTotal,
        parseSuccessRate,
        parseDiagnostics: {
            reasons: parseReasonCounts,
            failures: parseFailureReasonCounts
        },
        metrics: aggregateMetrics,
        perCategoryMetrics,
        repairQuality: {
            totalRepairs: repairAggregate.totalRepairs,
            autoApplicable: repairAggregate.autoApplicable,
            autoApplicableRate: Number((repairAggregate.autoApplicableRate * 100).toFixed(2)),
            byReason: repairAggregate.byReason
        },
        importContextEnabled: IMPORT_CONTEXT_ENABLED,
        detailedResults: results
    };
}

function printExecutionConfig(config) {
    console.log('\n⚙️  Execution Config');
    console.log(`   Prompt mode: ${config.modeLabel}`);
    console.log(`   LLM evaluation: ${config.runLlm ? 'enabled' : 'disabled'}`);
    console.log(`   Baseline comparison: ${config.runBaselines ? 'enabled' : 'disabled'}`);
    if (config.runBaselines) {
        console.log(`   Baseline tools: ${config.baselineTools.join(', ')}`);
        console.log(`   Baseline timeout: ${config.baselineTimeoutMs}ms`);
    }
    console.log(`   Structured output: ${config.structuredOutput ? 'enabled' : 'disabled'}`);
    console.log(`   Thinking mode: ${config.disableThinking ? 'disabled' : 'enabled'}`);
    console.log(`   Runs per sample: ${config.runsPerSample}`);
    console.log(`   RAG k: ${config.ragK}`);
    console.log(`   Temperature: ${config.temperature}`);
    console.log(`   Num predict: ${config.numPredict}`);
    console.log(`   Timeout: ${config.timeoutMs}ms`);
    console.log(`   Delay: ${config.delayMs}ms`);
}

async function runEvaluation() {
    const startTimestamp = new Date();
    let shouldRunLlm = !BASELINES_ONLY;
    const shouldRunBaselines = INCLUDE_BASELINES || BASELINES_ONLY;

    console.log('🚀 Code Guardian Model Evaluation Framework');
    if (ENABLE_RAG_ABLATION && shouldRunLlm) {
        console.log('📋 Mode: RAG Ablation Study (comparing Base vs RAG)');
    }
    if (shouldRunBaselines) {
        console.log(`📋 Baseline comparison enabled: ${REQUESTED_BASELINE_TOOLS.join(', ')}`);
    }
    if (BASELINES_ONLY) {
        console.log('📋 Mode: Baselines only (LLM disabled)');
    }
    console.log('='.repeat(80));

    const executionEnvironment = await collectExecutionEnvironment();

    console.log('\n📂 Loading test dataset...');
    let { datasetPath, testCases } = await loadTestDataset();

    // Apply sample limit if specified (--limit N)
    if (SAMPLE_LIMIT > 0 && SAMPLE_LIMIT < testCases.length) {
        // Take a balanced subset: some vulnerable + some secure
        const vulnerable = testCases.filter(tc => tc.expectedVulnerabilities.length > 0);
        const secure = testCases.filter(tc => tc.expectedVulnerabilities.length === 0);
        const vulnLimit = Math.max(1, Math.ceil(SAMPLE_LIMIT * 0.8));
        const secLimit = Math.max(1, SAMPLE_LIMIT - vulnLimit);
        testCases = [...vulnerable.slice(0, vulnLimit), ...secure.slice(0, secLimit)];
        console.log(`🔬 Limited to ${testCases.length} samples (--limit ${SAMPLE_LIMIT})`);
    }

    const secureCount = testCases.filter(tc => tc.expectedVulnerabilities.length === 0).length;
    const vulnCount = testCases.length - secureCount;
    console.log(`✅ Loaded ${testCases.length} test cases (${vulnCount} vulnerable, ${secureCount} secure/negative)`);
    console.log(`📄 Dataset file: ${datasetPath}`);

    let modelsToEvaluate = [
        'gemma3:1b',
        'gemma3:4b',
        'qwen3:4b',
        'qwen3:8b',
        'CodeLlama:latest',
    ];

    // Apply model filter if specified (--model name)
    if (MODEL_FILTER) {
        modelsToEvaluate = [MODEL_FILTER];
        console.log(`🎯 Filtered to single model: ${MODEL_FILTER}`);
    }

    const ragModes = [];
    if (ENABLE_RAG_ABLATION && shouldRunLlm) {
        ragModes.push(false, true);
    } else if (RAG_ONLY && shouldRunLlm) {
        ragModes.push(true);
    } else if (NO_RAG_ONLY && shouldRunLlm) {
        ragModes.push(false);
    } else if (shouldRunLlm) {
        ragModes.push(false);
    }

    let llmUnavailableReason = null;
    let modelsToTest = [];
    if (shouldRunLlm) {
        console.log('\n🔍 Checking available models...');
        let availableModelObjects;
        try {
            const ollama = getOllamaClient();
            const modelList = await ollama.list();
            availableModelObjects = modelList.models || [];
            console.log(`✅ Found ${availableModelObjects.length} installed models`);
        } catch (error) {
            llmUnavailableReason = `failed to connect to Ollama (${error.message})`;
            if (!shouldRunBaselines) {
                console.error(`❌ ${llmUnavailableReason}`);
                process.exit(1);
            }
            console.log(`⚠️  Skipping LLM evaluation: ${llmUnavailableReason}`);
            shouldRunLlm = false;
        }

        if (shouldRunLlm) {
            modelsToTest = resolveModelsToTest(modelsToEvaluate, availableModelObjects);
            if (modelsToTest.length === 0) {
                llmUnavailableReason = 'no configured models are installed';
                if (!shouldRunBaselines) {
                    console.error('❌ No models available for testing. Please install at least one model.');
                    process.exit(1);
                }
                console.log(`⚠️  Skipping LLM evaluation: ${llmUnavailableReason}`);
                shouldRunLlm = false;
            } else {
                console.log(`\n📋 Testing ${modelsToTest.length} resolved model(s): ${modelsToTest.map(m => m.resolvedModel).join(', ')}`);
            }
        }
    }

    const modeLabel = shouldRunLlm
        ? (ENABLE_RAG_ABLATION ? 'Base + RAG' : (RAG_ONLY ? 'RAG only' : 'Base only'))
        : (shouldRunBaselines ? 'Baselines only' : 'Disabled');

    printExecutionConfig({
        modeLabel,
        runLlm: shouldRunLlm,
        runBaselines: shouldRunBaselines,
        baselineTools: REQUESTED_BASELINE_TOOLS,
        baselineTimeoutMs: BASELINE_TIMEOUT_MS,
        structuredOutput: ENABLE_STRUCTURED_OUTPUT,
        disableThinking: DISABLE_THINKING,
        runsPerSample: RUNS_PER_SAMPLE,
        ragK: RAG_K,
        temperature: TEMPERATURE,
        numPredict: NUM_PREDICT,
        timeoutMs: TIMEOUT_MS,
        delayMs: REQUEST_DELAY_MS
    });

    // Phase 2: SAST×LLM fusion prep. Run Semgrep once if --sast-fusion is set.
    let sastFusionCorpus = null;
    if (SAST_FUSION_ENABLED && shouldRunLlm) {
        console.log(`\n🔗 Preparing SAST fusion corpus (--sast-fusion)...`);
        sastFusionCorpus = await collectSastFindingsForFusion(testCases, {
            semgrepBin: SEMGREP_BIN,
            timeoutMs: BASELINE_TIMEOUT_MS
        });
        if (sastFusionCorpus.skipped) {
            sastFusionCorpus = null;
        }
    }
    if (CONFIDENCE_THRESHOLD > 0) {
        console.log(`🎚️  Runtime confidence gate active: issues below ${CONFIDENCE_THRESHOLD} will be dropped.`);
    }

    const evaluationResults = [];
    if (shouldRunLlm) {
        for (const modelInfo of modelsToTest) {
            for (const useRAG of ragModes) {
                const result = await evaluateModel(modelInfo, testCases, {
                    useRAG,
                    runsPerSample: RUNS_PER_SAMPLE,
                    timeoutMs: TIMEOUT_MS,
                    delayMs: REQUEST_DELAY_MS,
                    ragK: RAG_K,
                    temperature: TEMPERATURE,
                    numPredict: NUM_PREDICT,
                    sastFindingsByCase: sastFusionCorpus ? sastFusionCorpus.findingsByCase : null,
                    confidenceThreshold: CONFIDENCE_THRESHOLD
                });
                if (sastFusionCorpus) {
                    result.sastFusionEnabled = true;
                }
                if (CONFIDENCE_THRESHOLD > 0) {
                    result.confidenceThreshold = CONFIDENCE_THRESHOLD;
                }
                evaluationResults.push(result);
            }
        }
    }

    // Cleanup fusion workspace unless baselines are also running (in which case it
    // would create/clean its own workspace) or user passed --keep-baseline-workdir.
    if (sastFusionCorpus && !KEEP_BASELINE_WORKDIR) {
        try {
            await fs.rm(sastFusionCorpus.workspace.workspaceDir, { recursive: true, force: true });
        } catch (_err) { /* best effort */ }
    }

    let baselineStatus = {
        requestedTools: REQUESTED_BASELINE_TOOLS,
        completedTools: [],
        skippedTools: []
    };
    if (shouldRunBaselines) {
        const baselineEvaluation = await evaluateBaselines(testCases, {
            requestedTools: REQUESTED_BASELINE_TOOLS,
            semgrepBin: SEMGREP_BIN,
            codeqlBin: CODEQL_BIN,
            eslintBin: resolveEslintBinary(),
            timeoutMs: BASELINE_TIMEOUT_MS,
            keepWorkspace: KEEP_BASELINE_WORKDIR
        });
        evaluationResults.push(...baselineEvaluation.results);
        baselineStatus = baselineEvaluation.status;
    }

    if (evaluationResults.length === 0) {
        console.error('❌ No evaluation results were produced. Ensure Ollama models and/or baseline tools are available.');
        process.exit(1);
    }

    console.log('\n\n' + '='.repeat(80));
    console.log('📊 EVALUATION SUMMARY');
    console.log('='.repeat(80));

    const rankingStrategy = getRankingStrategy(testCases);
    const sortedResults = sortEvaluationResults(evaluationResults, rankingStrategy.key);

    console.log(`\n🏆 Model Rankings (${rankingStrategy.label}):\n`);

    sortedResults.forEach((result, index) => {
        const medal = index === 0 ? '🥇' : index === 1 ? '🥈' : index === 2 ? '🥉' : '  ';
        console.log(`${medal} ${index + 1}. ${result.model} [${result.promptMode}]`);
        console.log(`   Digest:       ${result.modelVersion.digest || 'N/A'}`);
        console.log(`   F1 Score:     ${result.metrics.f1Score}%`);
        console.log(`   Precision:    ${result.metrics.precision}%`);
        console.log(`   Recall:       ${result.metrics.recall}%`);
        console.log(`   FPR:          ${result.metrics.falsePositiveRate}%`);
        console.log(`   Parse Rate:   ${result.parseSuccessRate}%`);
        const topFailureReasons = formatTopReasonCounts(result.parseDiagnostics?.failures, 2);
        if (topFailureReasons) {
            console.log(`   Parse Fail:   ${topFailureReasons}`);
        }
        console.log(`   Mean Latency: ${result.meanLatencyMs}ms`);
        console.log(`   Median Lat.:  ${result.medianLatencyMs}ms`);
        console.log('');
    });

    if (shouldRunLlm && ENABLE_RAG_ABLATION) {
        console.log('\n📊 RAG ABLATION COMPARISON:\n');
        console.log('| Model | Mode | F1 Score | Precision | Recall | FPR | Parse Rate | Mean Lat. | Median Lat. |');
        console.log('|-------|------|----------|-----------|--------|-----|------------|-----------|-------------|');

        const llmResults = evaluationResults.filter(r => r.evaluationFamily === 'llm');
        const uniqueModels = [...new Set(llmResults.map(r => r.model))];
        for (const model of uniqueModels) {
            const base = llmResults.find(r => r.model === model && !r.ragEnabled);
            const rag = llmResults.find(r => r.model === model && r.ragEnabled);

            if (base) {
                console.log(`| ${model} | Base | ${base.metrics.f1Score}% | ${base.metrics.precision}% | ${base.metrics.recall}% | ${base.metrics.falsePositiveRate}% | ${base.parseSuccessRate}% | ${base.meanLatencyMs}ms | ${base.medianLatencyMs}ms |`);
            }
            if (rag) {
                console.log(`| ${model} | RAG | ${rag.metrics.f1Score}% | ${rag.metrics.precision}% | ${rag.metrics.recall}% | ${rag.metrics.falsePositiveRate}% | ${rag.parseSuccessRate}% | ${rag.meanLatencyMs}ms | ${rag.medianLatencyMs}ms |`);
            }
        }
        console.log('');
    }

    if (shouldRunBaselines) {
        console.log('\n🧰 BASELINE TOOL STATUS:\n');
        if (baselineStatus.completedTools.length > 0) {
            console.log(`✅ Completed: ${baselineStatus.completedTools.join(', ')}`);
        }
        if (baselineStatus.skippedTools.length > 0) {
            baselineStatus.skippedTools.forEach(item => {
                console.log(`⚠️  ${item.tool}: ${item.reason}`);
            });
        }
        if (baselineStatus.completedTools.length === 0 && baselineStatus.skippedTools.length === 0) {
            console.log('⚠️  No baseline tools were executed.');
        }
    }

    const bestModel = sortedResults[0];
    console.log(`💡 Recommended Model: ${bestModel.model} (${bestModel.promptMode})`);
    if (rankingStrategy.key === 'fpr') {
        console.log(`   Best FPR: ${bestModel.metrics.falsePositiveRate}% | Mean latency: ${bestModel.meanLatencyMs}ms`);
    } else {
        console.log(`   Best F1: ${bestModel.metrics.f1Score}% | Mean latency: ${bestModel.meanLatencyMs}ms`);
    }

    const endTimestamp = new Date();
    const timestamp = endTimestamp.toISOString().replace(/[:.]/g, '-');
    const suffixParts = [];
    if (shouldRunLlm && ENABLE_RAG_ABLATION) {
        suffixParts.push('ablation');
    }
    if (shouldRunBaselines) {
        suffixParts.push('baselines');
    }
    if (!shouldRunLlm && shouldRunBaselines) {
        suffixParts.push('only');
    }
    const suffix = suffixParts.length > 0 ? `-${suffixParts.join('-')}` : '';
    const reportPath = path.join(__dirname, 'logs', `evaluation-${timestamp}${suffix}.json`);

    const executionConfig = {
        mode: !shouldRunLlm && shouldRunBaselines
            ? 'baselines-only'
            : (ENABLE_RAG_ABLATION ? 'ablation' : (RAG_ONLY ? 'rag-only' : 'base-only')),
        ragAblation: shouldRunLlm && ENABLE_RAG_ABLATION,
        runLlm: shouldRunLlm,
        runBaselines: shouldRunBaselines,
        llmUnavailableReason,
        testCases: testCases.length,
        secureCases: secureCount,
        vulnerableCases: vulnCount,
        datasetPath,
        runsPerSample: RUNS_PER_SAMPLE,
        promptModes: ragModes.map(r => r ? 'LLM+RAG' : 'LLM-only'),
        rag: {
            strategy: shouldRunLlm ? 'static_security_snippets' : 'none',
            k: shouldRunLlm ? RAG_K : 0
        },
        baselines: {
            requestedTools: REQUESTED_BASELINE_TOOLS,
            completedTools: baselineStatus.completedTools,
            skippedTools: baselineStatus.skippedTools,
            timeoutMs: BASELINE_TIMEOUT_MS
        },
        modelGeneration: {
            temperature: TEMPERATURE,
            numPredict: NUM_PREDICT,
            timeoutMs: TIMEOUT_MS,
            requestDelayMs: REQUEST_DELAY_MS
        },
        outputContract: {
            structuredOutput: ENABLE_STRUCTURED_OUTPUT,
            disableThinking: DISABLE_THINKING,
            schema: ENABLE_STRUCTURED_OUTPUT ? 'MODEL_RESPONSE_SCHEMA' : 'none'
        },
        startedAt: startTimestamp.toISOString(),
        finishedAt: endTimestamp.toISOString(),
        totalDurationMs: endTimestamp.getTime() - startTimestamp.getTime(),
        runtimeConditions: {
            executionOrder: 'sequential',
            retries: 0,
            warmup: 'none'
        }
    };

    await fs.mkdir(path.join(__dirname, 'logs'), { recursive: true });
    await fs.writeFile(
        reportPath,
        JSON.stringify({
            timestamp: endTimestamp.toISOString(),
            config: executionConfig,
            executionEnvironment,
            modelsResolved: modelsToTest,
            results: evaluationResults
        }, null, 2)
    );

    console.log(`\n📄 Detailed report saved to: ${reportPath}`);

    const markdownReport = generateMarkdownReport({
        results: evaluationResults,
        testCases,
        executionConfig,
        executionEnvironment
    });

    const mdReportPath = path.join(__dirname, 'logs', `evaluation-${timestamp}${suffix}.md`);
    await fs.writeFile(mdReportPath, markdownReport);
    console.log(`📄 Markdown report saved to: ${mdReportPath}`);
}

function generateMarkdownReport({ results, testCases, executionConfig, executionEnvironment }) {
    const secureCount = testCases.filter(tc => tc.expectedVulnerabilities.length === 0).length;
    const vulnCount = testCases.length - secureCount;
    const rankingStrategy = getRankingStrategy(testCases);

    let report = '# Code Guardian Model Evaluation Report\n\n';
    report += `**Date:** ${new Date().toISOString()}\n\n`;
    report += `**Test Cases:** ${testCases.length} (${vulnCount} vulnerable, ${secureCount} secure/negative)\n\n`;

    report += '## Model Summary\n\n';
    report += '| Model | Digest | Prompt Mode | Precision | Recall | F1 | FPR | Parse Rate | Mean Latency | Median Latency | Runs/Sample |\n';
    report += '|-------|--------|-------------|-----------|--------|----|-----|------------|--------------|----------------|-------------|\n';

    const sorted = sortEvaluationResults(results, rankingStrategy.key);
    sorted.forEach(result => {
        report += `| ${result.model} | ${result.modelVersion.digest || 'N/A'} | ${result.promptMode} | ${result.metrics.precision}% | ${result.metrics.recall}% | ${result.metrics.f1Score}% | ${result.metrics.falsePositiveRate}% | ${result.parseSuccessRate}% | ${result.meanLatencyMs}ms | ${result.medianLatencyMs}ms | ${result.runsPerSample} |\n`;
    });

    report += '\n## Configuration\n\n';
    report += `- **Evaluation Mode:** ${executionConfig.mode}\n`;
    report += `- **LLM Evaluation:** ${executionConfig.runLlm ? 'enabled' : 'disabled'}\n`;
    report += `- **Prompt Modes:** ${executionConfig.promptModes.length > 0 ? executionConfig.promptModes.join(', ') : 'none'}\n`;
    report += `- **Baseline Comparison:** ${executionConfig.runBaselines ? 'enabled' : 'disabled'}\n`;
    if (executionConfig.runBaselines) {
        report += `- **Baseline Tools (requested):** ${executionConfig.baselines.requestedTools.join(', ')}\n`;
        report += `- **Baseline Tools (completed):** ${executionConfig.baselines.completedTools.length > 0 ? executionConfig.baselines.completedTools.join(', ') : 'none'}\n`;
        report += `- **Baseline Timeout:** ${executionConfig.baselines.timeoutMs}ms\n`;
        if (executionConfig.baselines.skippedTools.length > 0) {
            const skipped = executionConfig.baselines.skippedTools
                .map(item => `${item.tool} (${item.reason})`)
                .join('; ');
            report += `- **Baseline Tools (skipped):** ${skipped}\n`;
        }
    }
    report += `- **RAG Strategy:** ${executionConfig.rag.strategy}\n`;
    report += `- **RAG k:** ${executionConfig.rag.k}\n`;
    report += `- **Structured Output:** ${executionConfig.outputContract?.structuredOutput ? 'enabled' : 'disabled'}\n`;
    report += `- **Thinking Mode:** ${executionConfig.outputContract?.disableThinking ? 'disabled' : 'enabled'}\n`;
    report += `- **Temperature:** ${executionConfig.modelGeneration.temperature}\n`;
    report += `- **Num Predict:** ${executionConfig.modelGeneration.numPredict}\n`;
    report += `- **Runs per Sample:** ${executionConfig.runsPerSample}\n`;
    report += `- **Timeout:** ${executionConfig.modelGeneration.timeoutMs}ms\n`;
    report += `- **Inter-request Delay:** ${executionConfig.modelGeneration.requestDelayMs}ms\n`;
    report += `- **Dataset Path:** ${executionConfig.datasetPath}\n\n`;

    report += '## Execution Environment\n\n';
    report += `- **OS:** ${executionEnvironment.os.platform} ${executionEnvironment.os.release} (${executionEnvironment.os.arch})\n`;
    report += `- **Node.js:** ${executionEnvironment.nodeVersion}\n`;
    report += `- **Ollama:** ${executionEnvironment.ollamaVersion}\n`;
    report += `- **CPU:** ${executionEnvironment.hardware.cpuModel} (${executionEnvironment.hardware.cpuCores} cores)\n`;
    report += `- **RAM (Total):** ${executionEnvironment.hardware.totalMemoryGB} GB\n`;
    report += `- **RAM (Free at Start):** ${executionEnvironment.hardware.freeMemoryGB} GB\n`;
    report += `- **GPU:** ${executionEnvironment.hardware.gpu}\n`;
    report += `- **Started At:** ${executionConfig.startedAt}\n`;
    report += `- **Finished At:** ${executionConfig.finishedAt}\n`;
    report += `- **Duration:** ${executionConfig.totalDurationMs} ms\n\n`;

    report += '## Detailed Metrics\n\n';
    sorted.forEach(result => {
        report += `### ${result.model} (${result.promptMode})\n\n`;
        report += `- **Requested Model:** ${result.requestedModel}\n`;
        report += `- **Resolved Model:** ${result.model}\n`;
        report += `- **Model Digest:** ${result.modelVersion.digest || 'N/A'}\n`;
        report += `- **Model Modified At:** ${result.modelVersion.modifiedAt || 'N/A'}\n`;
        report += `- **True Positives:** ${result.metrics.truePositives}\n`;
        report += `- **False Positives:** ${result.metrics.falsePositives}\n`;
        report += `- **False Negatives:** ${result.metrics.falseNegatives}\n`;
        report += `- **True Negatives:** ${result.metrics.trueNegatives}\n`;
        report += `- **Precision:** ${result.metrics.precision}%\n`;
        report += `- **Recall:** ${result.metrics.recall}%\n`;
        report += `- **F1 Score:** ${result.metrics.f1Score}%\n`;
        report += `- **FPR:** ${result.metrics.falsePositiveRate}%\n`;
        report += `- **Parse Rate:** ${result.parseSuccessRate}%\n`;
        report += `- **Parse Failure Reasons:** ${formatTopReasonCounts(result.parseDiagnostics?.failures, 5) || 'none'}\n`;
        report += `- **Mean Latency:** ${result.meanLatencyMs} ms\n`;
        report += `- **Median Latency:** ${result.medianLatencyMs} ms\n`;
        report += `- **Line Accuracy:** ${result.metrics.lineAccuracy}%\n`;
        report += `- **Runs per Sample:** ${result.runsPerSample}\n`;
        report += `- **RAG k:** ${result.ragConfig.k}\n\n`;
    });

    report += buildQualitativeCaseStudySection(sorted[0]);

    return report;
}

function buildQualitativeCaseStudySection(bestResult) {
    if (!bestResult || !Array.isArray(bestResult.detailedResults)) {
        return '\n## Qualitative Case Studies (S4 Evidence)\n\nNo case-study data available.\n';
    }

    const successful = bestResult.detailedResults.filter(r => r.success);
    const byUniqueCase = new Map();
    for (const item of successful) {
        if (!byUniqueCase.has(item.testCaseId)) {
            byUniqueCase.set(item.testCaseId, item);
        }
    }
    const uniqueCases = [...byUniqueCase.values()];

    const tp = uniqueCases.find(c => c.expected > 0 && c.metrics && c.metrics.truePositives > 0);
    const fp = uniqueCases.find(c => c.expected === 0 && c.detected > 0);
    const fn = uniqueCases.find(c => c.expected > 0 && c.metrics && c.metrics.falseNegatives > 0);

    const selected = [tp, fp, fn].filter(Boolean);
    const usedIds = new Set(selected.map(c => c.testCaseId));
    for (const c of uniqueCases) {
        if (selected.length >= 4) break;
        if (usedIds.has(c.testCaseId)) continue;
        selected.push(c);
        usedIds.add(c.testCaseId);
    }

    if (selected.length === 0) {
        return '\n## Qualitative Case Studies (S4 Evidence)\n\nNo successful evaluation cases available for qualitative analysis.\n';
    }

    let section = '\n## Qualitative Case Studies (S4 Evidence)\n\n';
    section += `Model under study: **${bestResult.model} (${bestResult.promptMode})**\n\n`;

    selected.slice(0, 4).forEach((example, idx) => {
        const label = getCaseLabel(example);
        const note = buildRepairQualityNote(example);
        const generatedFix = extractGeneratedFix(example);
        const expectedFix = summarizeText(example.expectedFix);

        section += `### Case ${idx + 1}: ${label} - ${example.testCaseName}\n\n`;
        section += `- **Type:** ${label}\n`;
        section += `- **Run:** ${example.run}\n`;
        section += `- **Outcome:** TP=${example.metrics?.truePositives ?? 0}, FP=${example.metrics?.falsePositives ?? 0}, FN=${example.metrics?.falseNegatives ?? 0}\n`;
        section += `- **Repair quality note:** ${note}\n`;
        section += `- **Expected repair:** ${expectedFix}\n`;
        section += `- **Model repair suggestion:** ${generatedFix}\n\n`;
    });

    return section;
}

function getCaseLabel(example) {
    const tp = example.metrics?.truePositives ?? 0;
    const fp = example.metrics?.falsePositives ?? 0;
    const fn = example.metrics?.falseNegatives ?? 0;

    if (example.expected === 0 && fp > 0) return 'FP';
    if (example.expected > 0 && tp > 0) return 'TP';
    if (example.expected > 0 && fn > 0) return 'FN';
    return 'Mixed';
}

function extractGeneratedFix(example) {
    if (!Array.isArray(example.detectedIssues) || example.detectedIssues.length === 0) {
        return 'No fix suggestion produced.';
    }
    const withFix = example.detectedIssues.find(i => typeof i.suggestedFix === 'string' && i.suggestedFix.trim().length > 0);
    if (!withFix) return 'No fix suggestion produced.';
    return summarizeText(withFix.suggestedFix);
}

function summarizeText(text, maxLen = 180) {
    if (!text || typeof text !== 'string') return 'N/A';
    const compact = text.replace(/\s+/g, ' ').trim();
    if (compact.length <= maxLen) return compact;
    return `${compact.slice(0, maxLen)}...`;
}

function buildRepairQualityNote(example) {
    const label = getCaseLabel(example);
    const hasGeneratedFix = Array.isArray(example.detectedIssues) &&
        example.detectedIssues.some(i => typeof i.suggestedFix === 'string' && i.suggestedFix.trim().length > 0);
    const hasExpectedFix = typeof example.expectedFix === 'string' && example.expectedFix.trim().length > 0;

    if (label === 'TP') {
        if (hasGeneratedFix && hasExpectedFix) {
            return 'Correctly detected vulnerability with actionable repair guidance.';
        }
        if (hasGeneratedFix) {
            return 'Correct detection with some repair guidance, but no dataset fix baseline for strict comparison.';
        }
        return 'Correct detection, but repair guidance is missing or too generic.';
    }

    if (label === 'FP') {
        if (hasGeneratedFix) {
            return 'False alarm: model suggested repairs for a secure sample, indicating over-flagging behavior.';
        }
        return 'False alarm without concrete fix guidance; likely low-confidence misclassification.';
    }

    if (label === 'FN') {
        if (example.detected === 0) {
            return 'Missed known vulnerability entirely; no remediation guidance produced.';
        }
        return 'Partially detected issues but still missed expected vulnerability classes.';
    }

    return 'Mixed outcome: includes both correct and incorrect detections.';
}

runEvaluation().catch(console.error);
