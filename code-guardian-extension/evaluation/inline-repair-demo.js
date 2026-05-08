#!/usr/bin/env node
/**
 * End-to-end demo of the inline-mode workflow: Stage 1 detection on a function
 * snippet, then a lazy Stage 2 repair per finding (mirrors what the IDE
 * code-action provider invokes when the developer opens the lightbulb on an
 * inline diagnostic). Mirrors the prompts and JSON schemas from
 * src/analyzer.ts exactly so the demo reflects production behavior.
 *
 * Usage:
 *   node evaluation/inline-repair-demo.js [--model qwen3:8b] [--snippet sql|xss|cmd]
 */

'use strict';

const ollama = require('ollama').default || require('ollama');

const args = process.argv.slice(2);
function getArg(name, dflt) {
    const i = args.indexOf(name);
    return i >= 0 ? args[i + 1] : dflt;
}
const MODEL = getArg('--model', 'qwen3:8b');
const SNIPPET_KIND = getArg('--snippet', 'sql');

const SNIPPETS = {
    sql: `function loginUser(username, password) {
    const query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
    return db.execute(query);
}`,
    xss: `function renderComment(comment) {
    document.getElementById('output').innerHTML = '<div>' + comment + '</div>';
}`,
    cmd: `const { exec } = require('child_process');
function runUserCommand(filename) {
    exec('cat ' + filename, (err, stdout) => {
        console.log(stdout);
    });
}`
};

const code = SNIPPETS[SNIPPET_KIND];
if (!code) {
    console.error(`Unknown --snippet '${SNIPPET_KIND}'. Choose one of: ${Object.keys(SNIPPETS).join(', ')}`);
    process.exit(1);
}

// ---- Stage 1 prompt + schema (mirrors src/analyzer.ts:864-870, 244-253) ----
const DETECTION_SYSTEM = `Detect exploitable security vulnerabilities in code. Return ONLY a JSON array. Each issue: {message, startLine, endLine}.

Rules:
- Only actually exploitable issues, not theoretical risks or style issues
- Use specific names ("SQL Injection", "XSS", "Command Injection", etc.)
- Return [] if the code is secure
- JSON only, no prose`;

const DETECTION_SCHEMA = {
    type: 'array',
    items: {
        type: 'object',
        properties: {
            message: { type: 'string' },
            startLine: { type: 'number' },
            endLine: { type: 'number' }
        },
        required: ['message', 'startLine', 'endLine']
    }
};

// ---- Stage 2 prompt + schema (mirrors src/analyzer.ts:630-639, 666-672) ----
const REPAIR_SYSTEM = `Secure code repair. Output ONLY a JSON object {"code": "...", "language": "javascript" | "typescript"}.

Rules:
- "code" MUST be a DROP-IN REPLACEMENT for ONLY the vulnerable lines provided. It will be substituted in-place via VS Code WorkspaceEdit.replace(range).
- DO NOT include any surrounding context, imports, function/class declarations, or other lines that already exist outside the vulnerable range. Those lines are shown only for context.
- Preserve the original indentation level of the vulnerable lines.
- The replacement should typically have a similar number of lines as the original; do not wrap it in a new function or block unless the original was a function/block.
- "code" MUST contain only executable code; do NOT include prose, explanation, comments, or markdown fences.
- Address the reported vulnerability type directly using established secure patterns (parameterized queries, input validation, safe APIs) while preserving original functionality.
- "language" reflects the source language of the snippet.`;

const REPAIR_SCHEMA = {
    type: 'object',
    properties: {
        code: { type: 'string' },
        language: { type: 'string', enum: ['javascript', 'typescript'] }
    },
    required: ['code']
};

function rule(label) {
    console.log(`\n${'='.repeat(72)}\n  ${label}\n${'='.repeat(72)}`);
}

(async () => {
    rule(`SNIPPET (${SNIPPET_KIND})`);
    code.split('\n').forEach((l, i) => console.log(`${String(i + 1).padStart(2)}  ${l}`));

    // ---- Stage 1: inline-mode detection ----
    rule('STAGE 1 — inline-scope detection');
    const t1 = Date.now();
    const detRes = await ollama.chat({
        model: MODEL,
        messages: [
            { role: 'system', content: DETECTION_SYSTEM },
            { role: 'user', content: `Analyze the following code for security vulnerabilities and return ONLY a JSON array:\n\n${code}` }
        ],
        format: DETECTION_SCHEMA,
        options: { temperature: 0, seed: 42, num_ctx: 4096 }
    });
    const stage1Ms = Date.now() - t1;
    let issues;
    try { issues = JSON.parse(detRes.message.content.trim()); }
    catch { console.error('Failed to parse Stage 1 JSON:', detRes.message.content); process.exit(1); }

    console.log(`Latency: ${stage1Ms} ms`);
    console.log(`Findings: ${issues.length}`);
    issues.forEach((iss, i) => {
        console.log(`  [${i + 1}] lines ${iss.startLine}-${iss.endLine}: ${iss.message}`);
    });

    if (issues.length === 0) {
        console.log('\nNo issues — nothing to repair. Exiting.');
        return;
    }

    // ---- Stage 2: lazy repair per finding (one Ollama call per issue, like the lightbulb) ----
    rule('STAGE 2 — lazy repair (one call per finding)');
    const allLines = code.split('\n');
    for (let i = 0; i < issues.length; i++) {
        const issue = issues[i];
        const vulnerableLines = allLines.slice(Math.max(0, issue.startLine - 1), issue.endLine).join('\n');
        const windowStart = Math.max(0, issue.startLine - 1 - 5);
        const windowEnd = Math.min(allLines.length, issue.endLine + 5);
        const windowedContext = allLines.slice(windowStart, windowEnd).join('\n');

        const userPrompt = `Vulnerability: ${issue.message}

VULNERABLE LINES TO REPLACE (lines ${issue.startLine}-${issue.endLine}) — your "code" field must replace exactly these:
${vulnerableLines}

Surrounding context (lines ${windowStart + 1}-${windowEnd}) (FOR UNDERSTANDING ONLY — DO NOT INCLUDE IN OUTPUT):
${windowedContext}

Output the JSON object {code, language} where "code" is the replacement for the vulnerable lines above and nothing else.`;

        const t2 = Date.now();
        const repRes = await ollama.chat({
            model: MODEL,
            messages: [
                { role: 'system', content: REPAIR_SYSTEM },
                { role: 'user', content: userPrompt }
            ],
            format: REPAIR_SCHEMA,
            options: { temperature: 0, seed: 42 }
        });
        const stage2Ms = Date.now() - t2;
        let parsed;
        try { parsed = JSON.parse(repRes.message.content.trim()); }
        catch { console.error('Failed to parse Stage 2 JSON:', repRes.message.content); continue; }

        console.log(`\n[${i + 1}] ${issue.message} — repair latency ${stage2Ms} ms (lang=${parsed.language || 'unknown'})`);
        console.log(`  Original lines ${issue.startLine}-${issue.endLine}:`);
        vulnerableLines.split('\n').forEach(l => console.log(`    - ${l}`));
        console.log(`  Suggested replacement:`);
        (parsed.code || '').split('\n').forEach(l => console.log(`    + ${l}`));
    }

    rule('SUMMARY');
    console.log(`Stage 1 detection: ${stage1Ms} ms, ${issues.length} finding(s)`);
    console.log(`Stage 2 repair:    one Ollama call per finding (lazy in production — fired by the IDE code-action provider when the developer opens the lightbulb)`);
})();
