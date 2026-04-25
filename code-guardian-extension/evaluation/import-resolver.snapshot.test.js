'use strict';

/**
 * Snapshot test for evaluation/import-resolver.js (and by extension the TS twin
 * which loads the same JSON catalog).
 *
 * Run via: node evaluation/import-resolver.snapshot.test.js
 */

const assert = require('assert');
const { resolveImportContext, formatImportContext } = require('./import-resolver');

// --- empty input -------------------------------------------------------
{
    const ctx = resolveImportContext('');
    assert.deepStrictEqual(ctx, { modules: [], validators: [], sinks: [], categoryHints: [] });
    assert.strictEqual(formatImportContext(ctx), '');
}

// --- CommonJS imports + eval sink --------------------------------------
{
    const code = [
        "const express = require('express');",
        "const http = require('http');",
        "function run(req, res) {",
        "  const code = req.body.code;",
        "  eval(code);",
        "}"
    ].join('\n');
    const ctx = resolveImportContext(code);
    assert.deepStrictEqual(ctx.modules, ['express', 'http']);
    assert.strictEqual(ctx.validators.length, 0);
    const evalSink = ctx.sinks.find(s => s.description === 'eval()');
    assert.ok(evalSink, 'detects eval()');
    assert.strictEqual(evalSink.category, 'code-injection');
    assert.strictEqual(evalSink.line, 5, 'eval is on line 5');
    assert.ok(ctx.categoryHints.includes('code-injection'));
}

// --- ESM imports + sanitizer recognition -------------------------------
{
    const code = [
        "import express from 'express';",
        "import sanitizeHtml from 'sanitize-html';",
        "import { exec } from 'child_process';",
        "exec('ls -la');"
    ].join('\n');
    const ctx = resolveImportContext(code);
    assert.ok(ctx.modules.includes('express'));
    assert.ok(ctx.modules.includes('sanitize-html'));
    assert.ok(ctx.modules.includes('child_process'));
    assert.deepStrictEqual(ctx.validators, ['sanitize-html'], 'sanitize-html recognized');
    // exec is matched as a regex on `child_process.exec(` — but here it's a destructured import
    // so the SQL injection regex won't trigger. That's fine.
}

// --- weak crypto -------------------------------------------------------
{
    const code = [
        "const crypto = require('crypto');",
        "const hash = crypto.createHash('md5').update(password).digest('hex');"
    ].join('\n');
    const ctx = resolveImportContext(code);
    assert.ok(ctx.sinks.some(s => s.category === 'weak-crypto'));
    assert.ok(ctx.categoryHints.includes('weak-crypto'));
}

// --- xss / innerHTML ---------------------------------------------------
{
    const code = "element.innerHTML = userInput;";
    const ctx = resolveImportContext(code);
    assert.ok(ctx.sinks.some(s => s.category === 'xss'), 'innerHTML should map to xss');
}

// --- path traversal ----------------------------------------------------
{
    const code = [
        "const fs = require('fs');",
        "app.get('/file', (req, res) => {",
        "  fs.readFile(req.query.name, (err, data) => res.send(data));",
        "});"
    ].join('\n');
    const ctx = resolveImportContext(code);
    assert.ok(ctx.sinks.some(s => s.category === 'path-traversal'),
        'fs.readFile with req.query is a path-traversal sink');
}

// --- jwt verify (auth-bypass hint) -------------------------------------
{
    const code = [
        "const jwt = require('jsonwebtoken');",
        "const decoded = jwt.verify(token, 'secret');"
    ].join('\n');
    const ctx = resolveImportContext(code);
    assert.ok(ctx.sinks.some(s => s.category === 'auth-bypass'),
        'jwt.verify is an auth-bypass hint');
}

// --- formatImportContext bound length ----------------------------------
{
    const code = "const a=require('m1');".repeat(50);
    const ctx = resolveImportContext(code);
    const formatted = formatImportContext(ctx, 100);
    assert.ok(formatted.length <= 100, 'formatted output respects maxLen');
}

// --- secure code with no sinks/imports stays empty --------------------
{
    const code = "function add(a, b) { return a + b; }";
    const ctx = resolveImportContext(code);
    assert.deepStrictEqual(ctx.sinks, []);
    assert.deepStrictEqual(ctx.modules, []);
    assert.strictEqual(formatImportContext(ctx), '');
}

console.log('import-resolver snapshot OK');
