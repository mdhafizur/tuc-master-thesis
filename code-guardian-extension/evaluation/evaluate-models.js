#!/usr/bin/env node

/**
 * Comprehensive Model Evaluation Framework for Code Guardian
 *
 * This script evaluates different Ollama models on their ability to detect
 * security vulnerabilities in code using a curated test dataset.
 */

const { Ollama } = require('ollama');
const fs = require('fs').promises;
const path = require('path');
const os = require('os');
const { execSync } = require('child_process');

const ollama = new Ollama();

const DEFAULT_TIMEOUT_MS = 30000;
const DEFAULT_DELAY_MS = 500;
const DEFAULT_TEMPERATURE = 0.1;
const DEFAULT_NUM_PREDICT = 1000;
const DEFAULT_RUNS_PER_SAMPLE = 1;
const DEFAULT_RAG_K = 5;

// Parse CLI flags
const args = process.argv.slice(2);
const ENABLE_RAG_ABLATION = args.includes('--ablation');
const RAG_ONLY = args.includes('--rag-only');
const NO_RAG_ONLY = args.includes('--no-rag-only');

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
const DATASET_FLAG = getFlagValue('--dataset');

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
const SYSTEM_PROMPT = `You are a secure code analyzer. Detect security issues in code and return them in JSON format like this:
[
  {
    "message": "Issue description",
    "type": "Vulnerability type (e.g., SQL Injection, XSS)",
    "startLine": 1,
    "endLine": 3,
    "severity": "high|medium|low",
    "suggestedFix": "Optional suggested secure version"
  }
]

Return an empty array [] if no vulnerabilities are found. Only return valid JSON, no explanations.`;

const RAG_KNOWLEDGE_SNIPPETS = [
    'OWASP A03/CWE-89 SQL Injection: use parameterized queries and prepared statements.',
    'OWASP A03/CWE-79 XSS: avoid unsafe HTML sinks and sanitize untrusted input.',
    'OWASP A03/CWE-78 Command Injection: never concatenate user input into shell commands.',
    'OWASP A01/CWE-22 Path Traversal: canonicalize paths and enforce allowlisted base directories.',
    'CWE-327 Weak Crypto: avoid broken algorithms; use modern primitives and secure randomness.',
    'CWE-798 Hardcoded Credentials: keep secrets out of source code and use secret managers.',
    'CWE-352 CSRF: use anti-CSRF tokens and same-site cookies for state-changing requests.',
    'CWE-611 XXE: disable external entities and DTD processing in XML parsers.'
];

function buildRAGPrompt(ragK) {
    const selected = RAG_KNOWLEDGE_SNIPPETS.slice(0, Math.max(0, ragK));
    const ragContext = selected.length > 0
        ? selected.map((item, idx) => `${idx + 1}. ${item}`).join('\n')
        : 'No retrieval snippets selected (k=0).';

    return `${SYSTEM_PROMPT}\n\nRELEVANT SECURITY KNOWLEDGE (top-k=${ragK}):\n${ragContext}`;
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

// Analyze code with a specific model
async function analyzeWithModel(modelName, code, options) {
    const {
        useRAG,
        timeoutMs,
        ragK,
        temperature,
        numPredict
    } = options;

    try {
        const startTime = Date.now();
        const systemPrompt = useRAG ? buildRAGPrompt(ragK) : SYSTEM_PROMPT;

        const response = await Promise.race([
            ollama.chat({
                model: modelName,
                messages: [
                    { role: 'system', content: systemPrompt },
                    { role: 'user', content: `Analyze the following code for security vulnerabilities:\n\n${code}` }
                ],
                options: {
                    temperature,
                    num_predict: numPredict
                }
            }),
            new Promise((_, reject) =>
                setTimeout(() => reject(new Error('Timeout')), timeoutMs)
            )
        ]);

        const endTime = Date.now();
        const responseTime = endTime - startTime;

        let issues = [];
        let parseSuccess = false;

        try {
            const content = response.message.content.trim();
            const cleanContent = content
                .replace(/```json\n?/g, '')
                .replace(/```\n?/g, '')
                .trim();

            issues = JSON.parse(cleanContent);
            parseSuccess = Array.isArray(issues);
        } catch (parseError) {
            console.log(`   ⚠️  JSON parsing failed for ${modelName}`);
        }

        return {
            success: true,
            responseTime,
            issues,
            parseSuccess,
            rawResponse: response.message.content,
            ragEnabled: useRAG
        };
    } catch (error) {
        return {
            success: false,
            error: error.message,
            responseTime: null,
            issues: [],
            parseSuccess: false,
            ragEnabled: useRAG
        };
    }
}

// Calculate metrics for a test case (with line-number accuracy)
function calculateMetrics(detected, expected, code) {
    const detectedTypes = new Set(detected.map(d => d.type?.toLowerCase() || ''));
    const expectedTypes = new Set(expected.map(e => e.type.toLowerCase()));

    const truePositives = [...detectedTypes].filter(d =>
        [...expectedTypes].some(e => e.includes(d) || d.includes(e))
    ).length;

    const falsePositives = detectedTypes.size - truePositives;
    const falseNegatives = expectedTypes.size - truePositives;
    const trueNegatives = expected.length === 0 && detected.length === 0 ? 1 : 0;

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
        lineAccuracy: lineAccuracyTotal > 0 ? lineAccuracyCount / lineAccuracyTotal : null
    };
}

function calculateAggregateMetrics(allMetrics) {
    const tp = allMetrics.reduce((sum, m) => sum + m.truePositives, 0);
    const fp = allMetrics.reduce((sum, m) => sum + m.falsePositives, 0);
    const fn = allMetrics.reduce((sum, m) => sum + m.falseNegatives, 0);
    const tn = allMetrics.reduce((sum, m) => sum + m.trueNegatives, 0);

    const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
    const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
    const f1Score = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
    const accuracy = (tp + tn) / (tp + fp + fn + tn || 1);
    const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;

    const lineAccuracies = allMetrics
        .filter(m => m.lineAccuracy !== null)
        .map(m => m.lineAccuracy);
    const avgLineAccuracy = lineAccuracies.length > 0
        ? lineAccuracies.reduce((sum, a) => sum + a, 0) / lineAccuracies.length
        : null;

    return {
        precision: (precision * 100).toFixed(2),
        recall: (recall * 100).toFixed(2),
        f1Score: (f1Score * 100).toFixed(2),
        accuracy: (accuracy * 100).toFixed(2),
        falsePositiveRate: (fpr * 100).toFixed(2),
        lineAccuracy: avgLineAccuracy !== null ? (avgLineAccuracy * 100).toFixed(2) : 'N/A',
        truePositives: tp,
        falsePositives: fp,
        falseNegatives: fn,
        trueNegatives: tn
    };
}

async function evaluateModel(modelInfo, testCases, options) {
    const {
        useRAG,
        runsPerSample,
        timeoutMs,
        delayMs,
        ragK,
        temperature,
        numPredict
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

                if (result.parseSuccess) {
                    successfulParses++;
                }

                const caseMetrics = calculateMetrics(
                    result.issues,
                    testCase.expectedVulnerabilities,
                    testCase.code
                );

                metrics.push(caseMetrics);

                console.log(`   ✅ Completed in ${result.responseTime}ms`);
                console.log(`   📊 TP: ${caseMetrics.truePositives}, FP: ${caseMetrics.falsePositives}, FN: ${caseMetrics.falseNegatives}${caseMetrics.lineAccuracy !== null ? `, Line Acc: ${(caseMetrics.lineAccuracy * 100).toFixed(0)}%` : ''}`);

                results.push({
                    testCaseId: testCase.id,
                    testCaseName: testCase.name,
                    run,
                    success: true,
                    responseTime: result.responseTime,
                    detected: result.issues.length,
                    expected: testCase.expectedVulnerabilities.length,
                    parseSuccess: result.parseSuccess,
                    detectedIssues: result.issues,
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
                    detectedIssues: [],
                    expectedVulnerabilities: testCase.expectedVulnerabilities,
                    expectedFix: testCase.expectedFix || null,
                    ragEnabled: useRAG
                });
            }

            await new Promise(resolve => setTimeout(resolve, delayMs));
        }
    }

    const aggregateMetrics = calculateAggregateMetrics(metrics);
    const meanLatencyMs = latencies.length > 0 ? Math.round(mean(latencies)) : 0;
    const medianLatencyMs = latencies.length > 0 ? Math.round(median(latencies)) : 0;
    const parseSuccessRate = (successfulParses / totalRequests * 100).toFixed(2);

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
        parseSuccessRate,
        metrics: aggregateMetrics,
        detailedResults: results
    };
}

function printExecutionConfig(config) {
    console.log('\n⚙️  Execution Config');
    console.log(`   Prompt mode: ${config.modeLabel}`);
    console.log(`   Runs per sample: ${config.runsPerSample}`);
    console.log(`   RAG k: ${config.ragK}`);
    console.log(`   Temperature: ${config.temperature}`);
    console.log(`   Num predict: ${config.numPredict}`);
    console.log(`   Timeout: ${config.timeoutMs}ms`);
    console.log(`   Delay: ${config.delayMs}ms`);
}

async function runEvaluation() {
    const startTimestamp = new Date();
    console.log('🚀 Code Guardian Model Evaluation Framework');
    if (ENABLE_RAG_ABLATION) {
        console.log('📋 Mode: RAG Ablation Study (comparing Base vs RAG)');
    }
    console.log('='.repeat(80));

    const executionEnvironment = await collectExecutionEnvironment();

    console.log('\n📂 Loading test dataset...');
    const { datasetPath, testCases } = await loadTestDataset();
    const secureCount = testCases.filter(tc => tc.expectedVulnerabilities.length === 0).length;
    const vulnCount = testCases.length - secureCount;
    console.log(`✅ Loaded ${testCases.length} test cases (${vulnCount} vulnerable, ${secureCount} secure/negative)`);
    console.log(`📄 Dataset file: ${datasetPath}`);

    const modelsToEvaluate = [
        'gemma3:1b',
        'gemma3:4b',
        'qwen3:4b',
        'qwen3:8b',
        'CodeLlama:latest',
    ];

    console.log('\n🔍 Checking available models...');
    let availableModelObjects;
    try {
        const modelList = await ollama.list();
        availableModelObjects = modelList.models || [];
        console.log(`✅ Found ${availableModelObjects.length} installed models`);
    } catch (error) {
        console.error('❌ Failed to connect to Ollama:', error.message);
        process.exit(1);
    }

    const modelsToTest = resolveModelsToTest(modelsToEvaluate, availableModelObjects);

    if (modelsToTest.length === 0) {
        console.error('❌ No models available for testing. Please install at least one model.');
        process.exit(1);
    }

    console.log(`\n📋 Testing ${modelsToTest.length} resolved model(s): ${modelsToTest.map(m => m.resolvedModel).join(', ')}`);

    const ragModes = [];
    if (ENABLE_RAG_ABLATION) {
        ragModes.push(false, true);
    } else if (RAG_ONLY) {
        ragModes.push(true);
    } else if (NO_RAG_ONLY) {
        ragModes.push(false);
    } else {
        ragModes.push(false);
    }

    printExecutionConfig({
        modeLabel: ENABLE_RAG_ABLATION ? 'Base + RAG' : (RAG_ONLY ? 'RAG only' : 'Base only'),
        runsPerSample: RUNS_PER_SAMPLE,
        ragK: RAG_K,
        temperature: TEMPERATURE,
        numPredict: NUM_PREDICT,
        timeoutMs: TIMEOUT_MS,
        delayMs: REQUEST_DELAY_MS
    });

    const evaluationResults = [];
    for (const modelInfo of modelsToTest) {
        for (const useRAG of ragModes) {
            const result = await evaluateModel(modelInfo, testCases, {
                useRAG,
                runsPerSample: RUNS_PER_SAMPLE,
                timeoutMs: TIMEOUT_MS,
                delayMs: REQUEST_DELAY_MS,
                ragK: RAG_K,
                temperature: TEMPERATURE,
                numPredict: NUM_PREDICT
            });
            evaluationResults.push(result);
        }
    }

    console.log('\n\n' + '='.repeat(80));
    console.log('📊 EVALUATION SUMMARY');
    console.log('='.repeat(80));

    const sortedResults = [...evaluationResults].sort((a, b) =>
        Number.parseFloat(b.metrics.f1Score) - Number.parseFloat(a.metrics.f1Score)
    );

    console.log('\n🏆 Model Rankings (by F1 Score):\n');

    sortedResults.forEach((result, index) => {
        const medal = index === 0 ? '🥇' : index === 1 ? '🥈' : index === 2 ? '🥉' : '  ';
        console.log(`${medal} ${index + 1}. ${result.model} [${result.promptMode}]`);
        console.log(`   Digest:       ${result.modelVersion.digest || 'N/A'}`);
        console.log(`   F1 Score:     ${result.metrics.f1Score}%`);
        console.log(`   Precision:    ${result.metrics.precision}%`);
        console.log(`   Recall:       ${result.metrics.recall}%`);
        console.log(`   FPR:          ${result.metrics.falsePositiveRate}%`);
        console.log(`   Parse Rate:   ${result.parseSuccessRate}%`);
        console.log(`   Mean Latency: ${result.meanLatencyMs}ms`);
        console.log(`   Median Lat.:  ${result.medianLatencyMs}ms`);
        console.log('');
    });

    if (ENABLE_RAG_ABLATION) {
        console.log('\n📊 RAG ABLATION COMPARISON:\n');
        console.log('| Model | Mode | F1 Score | Precision | Recall | FPR | Parse Rate | Mean Lat. | Median Lat. |');
        console.log('|-------|------|----------|-----------|--------|-----|------------|-----------|-------------|');

        const uniqueModels = [...new Set(evaluationResults.map(r => r.model))];
        for (const model of uniqueModels) {
            const base = evaluationResults.find(r => r.model === model && !r.ragEnabled);
            const rag = evaluationResults.find(r => r.model === model && r.ragEnabled);

            if (base) {
                console.log(`| ${model} | Base | ${base.metrics.f1Score}% | ${base.metrics.precision}% | ${base.metrics.recall}% | ${base.metrics.falsePositiveRate}% | ${base.parseSuccessRate}% | ${base.meanLatencyMs}ms | ${base.medianLatencyMs}ms |`);
            }
            if (rag) {
                console.log(`| ${model} | RAG | ${rag.metrics.f1Score}% | ${rag.metrics.precision}% | ${rag.metrics.recall}% | ${rag.metrics.falsePositiveRate}% | ${rag.parseSuccessRate}% | ${rag.meanLatencyMs}ms | ${rag.medianLatencyMs}ms |`);
            }
        }
        console.log('');
    }

    const bestModel = sortedResults[0];
    console.log(`💡 Recommended Model: ${bestModel.model} (${bestModel.promptMode})`);
    console.log(`   Best F1: ${bestModel.metrics.f1Score}% | Mean latency: ${bestModel.meanLatencyMs}ms`);

    const endTimestamp = new Date();
    const timestamp = endTimestamp.toISOString().replace(/[:.]/g, '-');
    const suffix = ENABLE_RAG_ABLATION ? '-ablation' : '';
    const reportPath = path.join(__dirname, 'logs', `evaluation-${timestamp}${suffix}.json`);

    const executionConfig = {
        mode: ENABLE_RAG_ABLATION ? 'ablation' : (RAG_ONLY ? 'rag-only' : 'base-only'),
        ragAblation: ENABLE_RAG_ABLATION,
        testCases: testCases.length,
        secureCases: secureCount,
        vulnerableCases: vulnCount,
        datasetPath,
        runsPerSample: RUNS_PER_SAMPLE,
        promptModes: ragModes.map(r => r ? 'LLM+RAG' : 'LLM-only'),
        rag: {
            strategy: 'static_security_snippets',
            k: RAG_K
        },
        modelGeneration: {
            temperature: TEMPERATURE,
            numPredict: NUM_PREDICT,
            timeoutMs: TIMEOUT_MS,
            requestDelayMs: REQUEST_DELAY_MS
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

    let report = '# Code Guardian Model Evaluation Report\n\n';
    report += `**Date:** ${new Date().toISOString()}\n\n`;
    report += `**Test Cases:** ${testCases.length} (${vulnCount} vulnerable, ${secureCount} secure/negative)\n\n`;

    report += '## Model Summary\n\n';
    report += '| Model | Digest | Prompt Mode | Precision | Recall | F1 | FPR | Parse Rate | Mean Latency | Median Latency | Runs/Sample |\n';
    report += '|-------|--------|-------------|-----------|--------|----|-----|------------|--------------|----------------|-------------|\n';

    const sorted = [...results].sort((a, b) => Number.parseFloat(b.metrics.f1Score) - Number.parseFloat(a.metrics.f1Score));
    sorted.forEach(result => {
        report += `| ${result.model} | ${result.modelVersion.digest || 'N/A'} | ${result.promptMode} | ${result.metrics.precision}% | ${result.metrics.recall}% | ${result.metrics.f1Score}% | ${result.metrics.falsePositiveRate}% | ${result.parseSuccessRate}% | ${result.meanLatencyMs}ms | ${result.medianLatencyMs}ms | ${result.runsPerSample} |\n`;
    });

    report += '\n## Configuration\n\n';
    report += `- **Evaluation Mode:** ${executionConfig.mode}\n`;
    report += `- **Prompt Modes:** ${executionConfig.promptModes.join(', ')}\n`;
    report += `- **RAG Strategy:** ${executionConfig.rag.strategy}\n`;
    report += `- **RAG k:** ${executionConfig.rag.k}\n`;
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
