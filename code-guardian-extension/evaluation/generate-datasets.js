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

    return hasCve || hasOwaspBenchmark || hasJuliet;
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

function toExtensionCase(sample, datasetName, options) {
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
            vulnerableLines: Array.isArray(sample.vulnerable_lines) ? sample.vulnerable_lines : []
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

    for (const spec of SOURCE_DATASET_FILES) {
        const { samples, filePath } = await readDatasetManifest(options.sourceDatasetsDir, spec);
        let included = 0;
        let skipped = 0;

        for (const sample of samples) {
            if (!shouldIncludeSample(sample, spec.name, options)) {
                skipped += 1;
                continue;
            }

            const extensionCase = toExtensionCase(sample, spec.name, options);
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
            total: samples.length,
            included,
            skipped
        };
    }

    const allCases = [...coreCases, ...advancedCases];

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
    console.log(`   Core output: ${corePath} (${coreCases.length} cases)`);
    console.log(`   Advanced output: ${advancedPath} (${advancedCases.length} cases)`);
    console.log(`   Combined output: ${allPath} (${allCases.length} cases)`);
    console.log(`   Vulnerable cases: ${vulnerableCases}`);
    console.log(`   Secure cases: ${secureCases}`);

    if (secureCases === 0) {
        console.log('⚠️  Generated dataset has 0 secure/negative samples; FPR/TN metrics will be less informative.');
    }

    console.log('\nDataset breakdown:');
    for (const [datasetName, stats] of Object.entries(perDatasetSummary)) {
        console.log(`   ${datasetName}: ${stats.included}/${stats.total} included (${stats.skipped} skipped)`);
    }
}

generate().catch(error => {
    console.error('❌ Failed to generate datasets:', error.message);
    process.exit(1);
});
