#!/usr/bin/env node

/**
 * Generate extension-compatible evaluation datasets from code-guardian-evaluation manifests.
 *
 * By default this script keeps externally sourced samples and filters out known
 * pattern/fallback-style entries so the generated dataset is less synthetic.
 */

const fs = require('fs').promises;
const path = require('path');

const SOURCE_DATASET_FILES = [
    { name: 'benchmark', relPath: 'benchmark/benchmark_dataset.json' },
    { name: 'extended', relPath: 'extended/extended_dataset.json' },
    { name: 'real-world', relPath: 'real-world/real-world_dataset.json' },
    { name: 'adversarial', relPath: 'adversarial/adversarial_dataset.json' }
];

const SOURCE_URLS = {
    'nvd-cve': 'https://nvd.nist.gov/vuln/detail/',
    'owasp-benchmark': 'https://github.com/OWASP-Benchmark/Benchmark',
    'nist-juliet': 'https://samate.nist.gov/SARD/',
    'owasp-juice-shop': 'https://github.com/juice-shop/juice-shop',
    'owasp-nodegoat': 'https://github.com/OWASP/NodeGoat',
    'github-advisory': 'https://github.com/advisories/',
    'osv': 'https://osv.dev/vulnerability/',
    'snyk': 'https://security.snyk.io/vuln/',
    'devign-dataset': 'https://github.com/epicosy/devign',
    'big-vul-dataset': 'https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset',
    'code-guardian-evaluation': 'https://github.com/mdhafizur/code-guardian'
};

const PROJECT_SOURCE_URLS = {
    express: 'https://github.com/expressjs/express',
    lodash: 'https://github.com/lodash/lodash',
    moment: 'https://github.com/moment/moment',
    mongoose: 'https://github.com/Automattic/mongoose',
    'node-forge': 'https://github.com/digitalbazaar/forge',
    'react-dom': 'https://github.com/facebook/react',
    'serialize-javascript': 'https://github.com/yahoo/serialize-javascript'
};

const CATEGORY_TO_TYPE = {
    'auth-bypass': 'Authentication Bypass',
    'code-injection': 'Code Injection',
    'command-injection': 'Command Injection',
    'crypto-verification': 'Crypto Verification',
    'crypto-weakness': 'Weak Cryptography',
    'deserialization': 'Insecure Deserialization',
    'hardcoded-credentials': 'Hardcoded Credentials',
    'header-injection': 'Header Injection',
    'improper-authentication': 'Improper Authentication',
    'information-exposure': 'Information Exposure',
    'input-validation': 'Input Validation',
    'insecure-deserialization': 'Insecure Deserialization',
    'ldap-injection': 'LDAP Injection',
    'memory-leak': 'Memory Leak',
    'nosql-injection': 'NoSQL Injection',
    'path-traversal': 'Path Traversal',
    'prototype-pollution': 'Prototype Pollution',
    'race-condition': 'Race Condition',
    'regex-dos': 'Regular Expression DoS',
    'sql-injection': 'SQL Injection',
    'session-fixation': 'Authentication Bypass',
    'ssrf': 'Server-Side Request Forgery (SSRF)',
    'weak-cryptography': 'Weak Cryptography',
    'weak-encryption': 'Weak Encryption',
    'xss': 'Cross-Site Scripting (XSS)',
    'xxe': 'XML External Entity (XXE)'
};

const CATEGORY_TO_FIX = {
    'auth-bypass': 'Harden authentication checks and validate token/session integrity.',
    'code-injection': 'Avoid dynamic code execution and validate or whitelist inputs.',
    'command-injection': 'Use safe process APIs and never concatenate untrusted input into commands.',
    'crypto-verification': 'Use constant-time comparison and verified cryptographic APIs.',
    'crypto-weakness': 'Replace weak cryptographic primitives with modern approved algorithms.',
    'deserialization': 'Avoid unsafe deserialization and enforce strict schema validation.',
    'hardcoded-credentials': 'Remove hardcoded secrets and load credentials from secure storage.',
    'header-injection': 'Sanitize header values and enforce strict header construction.',
    'improper-authentication': 'Enforce robust authentication and fail securely on invalid auth state.',
    'information-exposure': 'Avoid leaking sensitive data and apply redaction/minimization controls.',
    'input-validation': 'Validate and sanitize all untrusted input before use.',
    'insecure-deserialization': 'Use safe serializers or strict type/schema validation.',
    'ldap-injection': 'Use parameterized LDAP queries and sanitize user-controlled input.',
    'memory-leak': 'Release resources deterministically and avoid unbounded allocations.',
    'nosql-injection': 'Use parameterized query objects and validate query operators/fields.',
    'path-traversal': 'Canonicalize paths and restrict access to approved directories.',
    'prototype-pollution': 'Block dangerous keys and clone/validate objects before merge operations.',
    'race-condition': 'Use synchronization/atomic operations to protect shared state.',
    'regex-dos': 'Avoid catastrophic regex patterns and enforce input/time limits.',
    'sql-injection': 'Use parameterized SQL queries or prepared statements.',
    'session-fixation': 'Regenerate session IDs after authentication and set secure session flags.',
    'ssrf': 'Validate outbound targets and restrict requests with allowlists/network controls.',
    'weak-cryptography': 'Use strong algorithms and secure key generation/management.',
    'weak-encryption': 'Use modern encryption modes with secure keys and nonces.',
    'xss': 'Escape/sanitize untrusted content and avoid unsafe DOM sinks.',
    'xxe': 'Disable external entities and DTD processing in XML parsers.'
};

function parseArgs() {
    const args = process.argv.slice(2);

    const defaults = {
        sourceDatasetsDir: path.resolve(__dirname, '..', '..', 'code-guardian-evaluation', 'datasets'),
        outputDir: path.resolve(__dirname, 'datasets'),
        sourcePolicy: 'external-only',
        includeAdversarial: false,
        includeFileSources: false,
        includeCuratedNegatives: false,
        requireProvenance: true,
        writeDefault: false
    };

    for (const arg of args) {
        if (arg.startsWith('--source-datasets-dir=')) {
            defaults.sourceDatasetsDir = path.resolve(arg.split('=')[1]);
        } else if (arg.startsWith('--output-dir=')) {
            defaults.outputDir = path.resolve(arg.split('=')[1]);
        } else if (arg.startsWith('--source-policy=')) {
            defaults.sourcePolicy = arg.split('=')[1];
        } else if (arg === '--include-adversarial') {
            defaults.includeAdversarial = true;
        } else if (arg === '--include-file-sources') {
            defaults.includeFileSources = true;
        } else if (arg === '--include-curated-negatives') {
            defaults.includeCuratedNegatives = true;
        } else if (arg === '--allow-missing-provenance') {
            defaults.requireProvenance = false;
        } else if (arg === '--write-default') {
            defaults.writeDefault = true;
        } else if (arg === '--help' || arg === '-h') {
            printHelp();
            process.exit(0);
        }
    }

    if (!['external-only', 'all'].includes(defaults.sourcePolicy)) {
        throw new Error(`Invalid --source-policy="${defaults.sourcePolicy}". Use "external-only" or "all".`);
    }

    return defaults;
}

function printHelp() {
    console.log('Generate extension datasets from code-guardian-evaluation manifests.\n');
    console.log('Usage: node evaluation/generate-datasets.js [options]\n');
    console.log('Options:');
    console.log('  --source-datasets-dir=<path>   Source datasets directory');
    console.log('  --output-dir=<path>            Output directory (default: evaluation/datasets)');
    console.log('  --source-policy=external-only|all');
    console.log('                                 external-only filters out fallback/pattern entries');
    console.log('  --include-adversarial          Include adversarial dataset in generated outputs');
    console.log('  --include-file-sources         Ingest source JS files not present in manifest JSON');
    console.log('  --include-curated-negatives    Add secure/negative cases from evaluation/datasets/vulnerability-test-cases.json');
    console.log('  --allow-missing-provenance     Keep samples even when reference id/URL cannot be inferred');
    console.log('  --write-default                Overwrite vulnerability-test-cases.json and advanced-test-cases.json');
    console.log('  -h, --help                     Show this help');
}

function normalizeLanguage(language) {
    const value = String(language || '').toLowerCase();
    if (value === 'typescript') return 'typescript';
    return 'javascript';
}

function normalizeSeverity(severity) {
    const value = String(severity || '').toLowerCase();
    if (value === 'critical') return 'high';
    if (value === 'high' || value === 'medium' || value === 'low') return value;
    return 'medium';
}

function titleFromCategory(category) {
    const normalized = String(category || '').trim().toLowerCase();
    if (CATEGORY_TO_TYPE[normalized]) return CATEGORY_TO_TYPE[normalized];
    return normalized
        .split('-')
        .filter(Boolean)
        .map(token => token.charAt(0).toUpperCase() + token.slice(1))
        .join(' ');
}

function defaultFix(category) {
    const normalized = String(category || '').trim().toLowerCase();
    return CATEGORY_TO_FIX[normalized] || 'Validate untrusted input and use secure APIs for this operation.';
}

function isPatternBasedSample(sample) {
    const id = String(sample.id || '').toLowerCase();
    const source = String(sample.source || '').toLowerCase();
    const combined = `${id} ${source}`;
    const disallowedTokens = [
        'fallback',
        'additional benchmark pattern',
        'pattern analysis',
        'extended research pattern',
        'adversarial -'
    ];
    return disallowedTokens.some(token => combined.includes(token));
}

function isExternalSourceSample(sample) {
    const id = String(sample.id || '');
    const source = String(sample.source || '');
    const combined = `${id} ${source}`.toLowerCase();

    const hasCve = /cve-\d{4}-\d+/i.test(combined);
    const hasOwaspBenchmark = combined.includes('owasp benchmark');
    const hasJuliet = combined.includes('juliet');
    const hasOwaspJuiceShop = combined.includes('owasp juice shop');
    const hasOwaspNodeGoat = combined.includes('owasp nodegoat');

    return hasCve || hasOwaspBenchmark || hasJuliet || hasOwaspJuiceShop || hasOwaspNodeGoat;
}

function extractCveId(sample) {
    const explicit = String(sample.cve_id || '').toUpperCase();
    if (/^CVE-\d{4}-\d+$/i.test(explicit)) {
        return explicit;
    }

    const combined = `${sample.id || ''} ${sample.source || ''} ${sample.description || ''}`;
    const match = combined.match(/CVE-\d{4}-\d+/i);
    return match ? match[0].toUpperCase() : null;
}

function extractGhsaId(sample) {
    const combined = `${sample.id || ''} ${sample.source || ''} ${sample.description || ''}`;
    const match = combined.match(/GHSA-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}-[23456789cfghjmpqrvwx]{4}/i);
    return match ? match[0].toUpperCase() : null;
}

function extractOsvId(sample) {
    const combined = `${sample.id || ''} ${sample.source || ''} ${sample.description || ''}`;
    const match = combined.match(/\b(OSV-\d{4}-\d+|RUSTSEC-\d{4}-\d+|PYSEC-\d{4}-\d+|GO-\d{4}-\d+)\b/i);
    return match ? match[0].toUpperCase() : null;
}

function extractSnykId(sample) {
    const combined = `${sample.id || ''} ${sample.source || ''} ${sample.description || ''}`;
    const match = combined.match(/\bSNYK-[A-Z0-9-]+\b/i);
    return match ? match[0].toUpperCase() : null;
}

function extractProjectFromSource(sample) {
    const source = String(sample.source || '').trim();
    if (!source || !source.includes(' - ')) return null;
    const project = source.split(' - ')[0].trim().toLowerCase();
    return project || null;
}

function inferSourceType(sample) {
    const combined = `${sample.id || ''} ${sample.source || ''}`.toLowerCase();
    if (extractCveId(sample)) return 'cve';
    if (extractGhsaId(sample)) return 'github-advisory';
    if (extractOsvId(sample)) return 'osv';
    if (extractSnykId(sample)) return 'snyk';
    if (combined.includes('owasp benchmark')) return 'owasp-benchmark';
    if (combined.includes('juliet')) return 'nist-juliet';
    if (combined.includes('owasp juice shop')) return 'owasp-juice-shop';
    if (combined.includes('owasp nodegoat')) return 'owasp-nodegoat';
    if (combined.includes('devign pattern')) return 'devign-dataset';
    if (combined.includes('big-vul pattern')) return 'big-vul-dataset';
    if (combined.includes('pattern analysis')) return 'project-pattern-analysis';
    if (combined.includes('additional benchmark pattern')) return 'code-guardian-evaluation';
    if (combined.includes('extended research pattern')) return 'code-guardian-evaluation';
    if (combined.includes('adversarial -')) return 'code-guardian-evaluation';
    return 'unknown';
}

function inferSourceUrl(sample, sourceType) {
    const explicit = String(sample.source_url || '').trim();
    if (explicit) {
        return explicit;
    }

    if (sourceType === 'cve') {
        const cveId = extractCveId(sample);
        if (cveId) {
            return `${SOURCE_URLS['nvd-cve']}${cveId}`;
        }
    }

    if (sourceType === 'github-advisory') {
        const ghsaId = extractGhsaId(sample);
        if (ghsaId) {
            return `${SOURCE_URLS['github-advisory']}${ghsaId}`;
        }
    }

    if (sourceType === 'osv') {
        const osvId = extractOsvId(sample);
        if (osvId) {
            return `${SOURCE_URLS.osv}${osvId}`;
        }
    }

    if (sourceType === 'snyk') {
        const snykId = extractSnykId(sample);
        if (snykId) {
            return `${SOURCE_URLS.snyk}${snykId}`;
        }
    }

    if (sourceType === 'project-pattern-analysis') {
        const project = extractProjectFromSource(sample);
        if (project && PROJECT_SOURCE_URLS[project]) {
            return PROJECT_SOURCE_URLS[project];
        }
    }

    return SOURCE_URLS[sourceType] || null;
}

function buildProvenance(sample) {
    const sourceType = inferSourceType(sample);
    const cveId = extractCveId(sample);
    const ghsaId = extractGhsaId(sample);
    const osvId = extractOsvId(sample);
    const snykId = extractSnykId(sample);
    const project = extractProjectFromSource(sample);
    const referenceId = cveId || ghsaId || osvId || snykId || String(sample.source || '').trim() || null;
    const sourceUrl = inferSourceUrl(sample, sourceType);

    return {
        sourceType,
        referenceId,
        sourceUrl,
        sourceLabel: String(sample.source || '').trim() || null,
        sourceProject: project,
        collectedFrom: sample.__ingestion || 'manifest',
        sourcePath: sample.__sourceFileRelPath || null
    };
}

function hasRequiredProvenance(provenance) {
    return Boolean(provenance && provenance.referenceId && provenance.sourceUrl);
}

function shouldIncludeSample(sample, datasetName, options) {
    if (!sample || typeof sample.code !== 'string' || sample.code.trim() === '') {
        return false;
    }

    // Adversarial cases are controlled solely by the includeAdversarial flag so
    // they can be adopted without broadening non-adversarial source policy.
    if (datasetName === 'adversarial') {
        return options.includeAdversarial;
    }

    if (options.sourcePolicy === 'all') {
        return true;
    }

    if (isPatternBasedSample(sample)) {
        return false;
    }

    return isExternalSourceSample(sample);
}

function buildExpectedVulnerability(sample) {
    const category = String(sample.category || '');
    const type = titleFromCategory(category);

    return {
        type,
        cwe: sample.cwe_id || 'CWE-UNKNOWN',
        severity: normalizeSeverity(sample.severity),
        description: sample.description || `${type} pattern`
    };
}

function buildCaseName(sample, type) {
    const description = String(sample.description || '').trim();
    if (!description) return type;
    return `${type} - ${description}`;
}

function toExtensionCase(sample, datasetName, options, provenance) {
    const type = titleFromCategory(sample.category);
    return {
        id: String(sample.id),
        name: buildCaseName(sample, type),
        code: sample.code,
        language: normalizeLanguage(sample.language),
        expectedVulnerabilities: [buildExpectedVulnerability(sample)],
        expectedFix: defaultFix(sample.category),
        metadata: {
            sourceDataset: datasetName,
            sourcePolicy: options.sourcePolicy,
            source: sample.source || null,
            originalId: sample.id || null,
            vulnerableLines: Array.isArray(sample.vulnerable_lines) ? sample.vulnerable_lines : [],
            provenance
        }
    };
}

function ensureUniqueId(testCase, usedIds, datasetName) {
    let candidate = testCase.id;
    if (!usedIds.has(candidate)) {
        usedIds.add(candidate);
        return testCase;
    }

    let counter = 1;
    while (usedIds.has(`${candidate}-${datasetName}-${counter}`)) {
        counter += 1;
    }
    const nextId = `${candidate}-${datasetName}-${counter}`;
    usedIds.add(nextId);

    return {
        ...testCase,
        id: nextId
    };
}

async function readDatasetManifest(sourceDatasetsDir, spec) {
    const filePath = path.join(sourceDatasetsDir, spec.relPath);
    const raw = await fs.readFile(filePath, 'utf8');
    const parsed = JSON.parse(raw);
    const samples = Array.isArray(parsed.samples) ? parsed.samples : [];
    return { filePath, samples };
}

async function walkJsFiles(dir) {
    const entries = await fs.readdir(dir, { withFileTypes: true });
    const files = [];

    for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);
        if (entry.isDirectory()) {
            const nested = await walkJsFiles(fullPath);
            files.push(...nested);
            continue;
        }

        if (entry.isFile() && entry.name.endsWith('.js')) {
            files.push(fullPath);
        }
    }

    return files;
}

function parseHeaderLineValue(text, label) {
    const escaped = label.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`^\\s*//\\s*${escaped}:\\s*(.+?)\\s*$`, 'im');
    const match = text.match(regex);
    return match ? match[1].trim() : null;
}

function parseFirstDescription(text) {
    const lines = text.split('\n').slice(0, 20);
    for (const rawLine of lines) {
        const line = rawLine.trim();
        if (!line.startsWith('//')) continue;
        const value = line.replace(/^\/\/\s*/, '');
        if (!value || value.includes(':')) continue;
        return value.trim();
    }
    return null;
}

function parseVulnerableLines(text) {
    const value = parseHeaderLineValue(text, 'Vulnerable lines');
    if (!value) return [];

    try {
        const parsed = JSON.parse(value);
        if (Array.isArray(parsed)) {
            return parsed.filter(n => Number.isInteger(n) && n > 0);
        }
    } catch (_) {
        // Ignore malformed metadata comments and keep parsing resilient.
    }

    return [];
}

async function readSourceFileSamples(sourceDatasetsDir, datasetName) {
    const datasetDir = path.join(sourceDatasetsDir, datasetName);
    let files = [];

    try {
        files = await walkJsFiles(datasetDir);
    } catch (_) {
        return [];
    }

    const samples = [];

    for (const filePath of files) {
        const code = await fs.readFile(filePath, 'utf8');
        const source = parseHeaderLineValue(code, 'Source');
        const sourceUrl = parseHeaderLineValue(code, 'Source URL');
        const cweId = parseHeaderLineValue(code, 'CWE') || 'CWE-UNKNOWN';
        const severity = parseHeaderLineValue(code, 'Severity') || 'medium';
        const description = parseFirstDescription(code) || `${path.basename(filePath, '.js')} sample`;
        const vulnerableLines = parseVulnerableLines(code);
        const id = path.basename(filePath, '.js');
        const category = path.basename(path.dirname(filePath));
        const sourceFileRelPath = path.relative(sourceDatasetsDir, filePath);

        samples.push({
            id,
            cwe_id: cweId,
            category,
            language: 'javascript',
            description,
            code,
            severity,
            source: source || `${datasetName} source file`,
            source_url: sourceUrl || null,
            vulnerable_lines: vulnerableLines,
            created_at: null,
            __ingestion: 'file-source',
            __sourceFileRelPath: sourceFileRelPath
        });
    }

    return samples;
}

async function readCuratedNegativeSamples() {
    const candidates = [
        path.resolve(__dirname, 'datasets', 'vulnerability-test-cases.json'),
        path.resolve(__dirname, 'datasets', 'vulnerability-test-cases.generated.json')
    ];

    for (const filePath of candidates) {
        try {
            const raw = await fs.readFile(filePath, 'utf8');
            const parsed = JSON.parse(raw);
            if (!Array.isArray(parsed)) {
                continue;
            }

            const negatives = parsed
                .filter(sample =>
                    sample &&
                    typeof sample.code === 'string' &&
                    sample.code.trim() !== '' &&
                    Array.isArray(sample.expectedVulnerabilities) &&
                    sample.expectedVulnerabilities.length === 0
                )
                .map(sample => ({
                    id: String(sample.id || ''),
                    name: String(sample.name || '').trim() || 'Secure Code Sample',
                    code: sample.code,
                    language: normalizeLanguage(sample.language),
                    expectedVulnerabilities: [],
                    expectedFix: sample.expectedFix || 'No fix required; code is secure as written.',
                    metadata: {
                        ...(sample.metadata && typeof sample.metadata === 'object' ? sample.metadata : {}),
                        sourceDataset: 'curated-negatives',
                        sourcePolicy: 'curated',
                        source: 'Code Guardian curated secure examples',
                        originalId: sample.id || null,
                        vulnerableLines: [],
                        provenance: {
                            sourceType: 'code-guardian-evaluation',
                            referenceId: sample.id || sample.name || 'curated-secure-sample',
                            sourceUrl: SOURCE_URLS['code-guardian-evaluation'],
                            sourceLabel: 'Code Guardian curated secure examples',
                            sourceProject: null,
                            collectedFrom: 'curated',
                            sourcePath: path.relative(path.resolve(__dirname, '..'), filePath)
                        }
                    }
                }))
                .filter(sample => sample.id);

            return {
                filePath,
                samples: negatives
            };
        } catch (_error) {
            // Try next candidate path.
        }
    }

    return {
        filePath: null,
        samples: []
    };
}

async function writeJson(filePath, value) {
    const serialized = `${JSON.stringify(value, null, 2)}\n`;
    await fs.writeFile(filePath, serialized, 'utf8');
}

async function generate() {
    const options = parseArgs();

    await fs.mkdir(options.outputDir, { recursive: true });

    const perDatasetSummary = {};
    const usedIds = new Set();
    const coreCases = [];
    const advancedCases = [];
    let skippedMissingProvenanceTotal = 0;
    let curatedNegativesIncluded = 0;
    let curatedNegativesSkippedDuplicates = 0;
    let curatedNegativesSourcePath = null;

    for (const spec of SOURCE_DATASET_FILES) {
        const { samples: manifestSamples, filePath } = await readDatasetManifest(options.sourceDatasetsDir, spec);
        const samples = [...manifestSamples];
        let fileSamplesAdded = 0;

        if (options.includeFileSources) {
            const sourceFileSamples = await readSourceFileSamples(options.sourceDatasetsDir, spec.name);
            const knownIds = new Set(samples.map(sample => String(sample.id || '')));
            for (const sample of sourceFileSamples) {
                const sampleId = String(sample.id || '');
                if (!sampleId || knownIds.has(sampleId)) {
                    continue;
                }
                knownIds.add(sampleId);
                samples.push(sample);
                fileSamplesAdded += 1;
            }
        }

        let included = 0;
        let skipped = 0;
        let skippedMissingProvenance = 0;

        for (const sample of samples) {
            if (!shouldIncludeSample(sample, spec.name, options)) {
                skipped += 1;
                continue;
            }

            const provenance = buildProvenance(sample);
            if (options.requireProvenance && !hasRequiredProvenance(provenance)) {
                skipped += 1;
                skippedMissingProvenance += 1;
                skippedMissingProvenanceTotal += 1;
                continue;
            }

            const extensionCase = toExtensionCase(sample, spec.name, options, provenance);
            const uniqueCase = ensureUniqueId(extensionCase, usedIds, spec.name);

            if (spec.name === 'adversarial') {
                advancedCases.push(uniqueCase);
            } else {
                coreCases.push(uniqueCase);
            }
            included += 1;
        }

        perDatasetSummary[spec.name] = {
            filePath,
            manifestTotal: manifestSamples.length,
            fileSamplesAdded,
            total: samples.length,
            included,
            skipped,
            skippedMissingProvenance
        };
    }

    const allCases = [...coreCases, ...advancedCases];

    if (options.includeCuratedNegatives) {
        const curated = await readCuratedNegativeSamples();
        curatedNegativesSourcePath = curated.filePath;

        for (const sample of curated.samples) {
            if (usedIds.has(sample.id)) {
                curatedNegativesSkippedDuplicates += 1;
                continue;
            }
            const uniqueCase = ensureUniqueId(sample, usedIds, 'curated-negatives');
            coreCases.push(uniqueCase);
            allCases.push(uniqueCase);
            curatedNegativesIncluded += 1;
        }
    }

    const corePath = path.join(options.outputDir, 'vulnerability-test-cases.generated.json');
    const advancedPath = path.join(options.outputDir, 'advanced-test-cases.generated.json');
    const allPath = path.join(options.outputDir, 'all-test-cases.generated.json');

    await writeJson(corePath, coreCases);
    await writeJson(advancedPath, advancedCases);
    await writeJson(allPath, allCases);

    if (options.writeDefault) {
        await writeJson(path.join(options.outputDir, 'vulnerability-test-cases.json'), coreCases);
        await writeJson(path.join(options.outputDir, 'advanced-test-cases.json'), advancedCases);
    }

    const secureCases = allCases.filter(c => c.expectedVulnerabilities.length === 0).length;
    const vulnerableCases = allCases.length - secureCases;

    console.log('✅ Dataset generation complete');
    console.log(`   Source policy: ${options.sourcePolicy}`);
    console.log(`   Include adversarial: ${options.includeAdversarial ? 'yes' : 'no'}`);
    console.log(`   Include file sources: ${options.includeFileSources ? 'yes' : 'no'}`);
    console.log(`   Include curated negatives: ${options.includeCuratedNegatives ? 'yes' : 'no'}`);
    console.log(`   Require provenance: ${options.requireProvenance ? 'yes' : 'no'}`);
    console.log(`   Core output: ${corePath} (${coreCases.length} cases)`);
    console.log(`   Advanced output: ${advancedPath} (${advancedCases.length} cases)`);
    console.log(`   Combined output: ${allPath} (${allCases.length} cases)`);
    console.log(`   Vulnerable cases: ${vulnerableCases}`);
    console.log(`   Secure cases: ${secureCases}`);
    console.log(`   Skipped (missing provenance): ${skippedMissingProvenanceTotal}`);
    if (options.includeCuratedNegatives) {
        console.log(`   Curated negatives included: ${curatedNegativesIncluded}`);
        console.log(`   Curated negatives skipped (duplicate ids): ${curatedNegativesSkippedDuplicates}`);
        console.log(`   Curated negatives source: ${curatedNegativesSourcePath || 'not found'}`);
    }

    if (secureCases === 0) {
        console.log('⚠️  Generated dataset has 0 secure/negative samples; FPR/TN metrics will be less informative.');
    }

    console.log('\nDataset breakdown:');
    for (const [datasetName, stats] of Object.entries(perDatasetSummary)) {
        console.log(
            `   ${datasetName}: ${stats.included}/${stats.total} included (${stats.skipped} skipped, ` +
            `${stats.skippedMissingProvenance} missing provenance, ` +
            `${stats.fileSamplesAdded} file-backed added, manifest=${stats.manifestTotal})`
        );
    }
}

generate().catch(error => {
    console.error('❌ Failed to generate datasets:', error.message);
    process.exit(1);
});
