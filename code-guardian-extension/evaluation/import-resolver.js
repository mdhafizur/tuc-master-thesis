'use strict';

/**
 * JS twin of src/importResolver.ts. Loads the same shared JSON catalog at
 * src/importResolver.json. Used by the evaluation harness to enrich prompts
 * with import / sink / validator context behind a CLI flag.
 *
 * A snapshot test in evaluation/import-resolver.snapshot.test.js asserts both
 * twins agree on a fixed fixture set.
 */

const path = require('path');
const resolverData = require(path.join(__dirname, '..', 'src', 'importResolver.json'));

const COMPILED_SINKS = resolverData.sinkPatterns.map(p => ({
    regex: new RegExp(p.regex, 'i'),
    category: p.category,
    description: p.description
}));

const VALIDATOR_MODULES = new Set(resolverData.validatorModules);

const REQUIRE_RE = /\brequire\s*\(\s*['"]([^'"]+)['"]\s*\)/g;
const ESM_FROM_RE = /\bimport\s+(?:[\w*\s,{}]+\s+from\s+)?['"]([^'"]+)['"]/g;
const ESM_BARE_RE = /\bimport\s+['"]([^'"]+)['"]/g;

function uniq(arr) {
    return Array.from(new Set(arr));
}

function extractModules(code) {
    const out = [];
    for (const re of [REQUIRE_RE, ESM_FROM_RE, ESM_BARE_RE]) {
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(code)) !== null) {
            if (m[1]) out.push(m[1]);
        }
    }
    return uniq(out);
}

function lineNumberOf(code, charIndex) {
    let line = 1;
    for (let i = 0; i < charIndex && i < code.length; i++) {
        if (code.charCodeAt(i) === 10) line++;
    }
    return line;
}

function resolveImportContext(code) {
    if (typeof code !== 'string' || code.length === 0) {
        return { modules: [], validators: [], sinks: [], categoryHints: [] };
    }

    const modules = extractModules(code);
    const validators = modules.filter(m => VALIDATOR_MODULES.has(m));

    const sinks = [];
    for (const sink of COMPILED_SINKS) {
        const re = new RegExp(sink.regex.source, sink.regex.flags.includes('g') ? sink.regex.flags : sink.regex.flags + 'g');
        let m;
        while ((m = re.exec(code)) !== null) {
            sinks.push({
                description: sink.description,
                category: sink.category,
                line: lineNumberOf(code, m.index)
            });
            if (m.index === re.lastIndex) re.lastIndex++;
        }
    }

    const categoryHints = uniq(sinks.map(s => s.category));
    return { modules, validators, sinks, categoryHints };
}

function formatImportContext(ctx, maxLen = 400) {
    if (ctx.modules.length === 0 && ctx.sinks.length === 0) {
        return '';
    }
    const parts = [];
    if (ctx.modules.length > 0) {
        parts.push(`imports: ${ctx.modules.slice(0, 12).join(', ')}`);
    }
    if (ctx.validators.length > 0) {
        parts.push(`validators-available: ${ctx.validators.join(', ')}`);
    }
    if (ctx.sinks.length > 0) {
        const sinkSummary = ctx.sinks.slice(0, 8).map(s => `${s.description}@L${s.line}`).join(', ');
        parts.push(`sinks: ${sinkSummary}`);
    }
    if (ctx.categoryHints.length > 0) {
        parts.push(`likely-categories: ${ctx.categoryHints.join(', ')}`);
    }
    let s = parts.join(' | ');
    if (s.length > maxLen) {
        s = s.slice(0, maxLen - 3) + '...';
    }
    return s;
}

module.exports = { resolveImportContext, formatImportContext };
