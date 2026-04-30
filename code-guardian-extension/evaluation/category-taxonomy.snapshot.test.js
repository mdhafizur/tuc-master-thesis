'use strict';

/**
 * Snapshot test for the category taxonomy.
 *
 * Run via:  node evaluation/category-taxonomy.snapshot.test.js
 *
 * This test does NOT require Mocha or vscode-test. It exercises the JS twin of
 * the taxonomy on a fixed set of representative inputs and asserts the canonical
 * category. If the test fails, either the taxonomy JSON drifted or one of the
 * fixture inputs no longer maps as intended — both warrant a manual review
 * before re-running the full evaluation harness.
 *
 * The TS module (src/categoryTaxonomy.ts) loads the same JSON, so passing this
 * test is sufficient evidence that both surfaces agree.
 */

const assert = require('assert');
const taxonomy = require('./category-taxonomy');

const FIXTURES = [
    // [input, expectedCategory]
    ['SQL Injection', 'sql-injection'],
    ['SQLi via concat', 'sql-injection'],
    ['CWE-89 detected', 'sql-injection'],
    ['NoSQL Injection in mongo query', 'nosql-injection'],
    ['Cross-Site Scripting (XSS)', 'xss'],
    ['innerHTML assignment without escaping', 'xss'],
    ['Command Injection through child_process', 'command-injection'],
    ['Code Injection via eval()', 'code-injection'],
    ['Path Traversal in file path', 'path-traversal'],
    ['Server-Side Request Forgery (SSRF)', 'ssrf'],
    ['XML External Entity (XXE)', 'xxe'],
    ['LDAP Injection', 'ldap-injection'],
    ['Header Injection / response splitting', 'header-injection'],
    ['Insecure Deserialization with eval', 'deserialization'],
    ['Weak Cryptography (MD5)', 'weak-crypto'],
    ['Weak Hashing Algorithm', 'weak-crypto'],
    ['Weak Cipher Algorithm DES', 'weak-crypto'],
    ['Weak Random Number Generation', 'weak-crypto'],
    ['Hardcoded Credentials API key', 'hardcoded-credential'],
    ['Authentication Bypass via JWT none', 'auth-bypass'],
    ['Timing Attack on auth check', 'auth-bypass'],
    ['Improper Authentication', 'improper-auth'],
    ['Prototype Pollution via __proto__', 'prototype-pollution'],
    ['Race Condition (TOCTOU)', 'race-condition'],
    ['ReDoS catastrophic backtracking', 'redos'],
    ['Input Validation missing', 'input-validation'],
    ['Role Escalation through unchecked input', 'input-validation'],
    ['Information Exposure of secrets', 'information-exposure'],
    ['Crypto Verification missing', 'crypto-verification'],
    ['Weak Encryption insufficient key length', 'weak-encryption'],
    // Taxonomy v1.1 additions
    ['Session Fixation in login flow', 'session-fixation'],
    ['CWE-384 detected', 'session-fixation'],
    ['Vulnerable Dependency: lodash 4.17.20', 'vulnerable-dependency'],
    ['Outdated package with known CVE', 'vulnerable-dependency'],
    ['CVE-2021-23337 referenced', 'vulnerable-dependency'],
    ['Weak Validation of JWT algorithm', 'weak-validation'],
    ['Mass Assignment via req.body destructure', 'weak-validation'],
    ['JWT algorithm confusion', 'weak-validation'],
    // Canonical IDs must round-trip back to themselves
    ['sql-injection', 'sql-injection'],
    ['weak-crypto', 'weak-crypto'],
    ['information-exposure', 'information-exposure'],
    ['session-fixation', 'session-fixation'],
    ['vulnerable-dependency', 'vulnerable-dependency'],
    ['weak-validation', 'weak-validation'],
    ['Some completely unrelated string', 'other'],
    ['', 'other'],
    [null, 'other'],
    [undefined, 'other']
];

let failures = 0;
for (const [input, expected] of FIXTURES) {
    const actual = taxonomy.normalizeCategory(input);
    if (actual !== expected) {
        console.error(`FAIL: normalizeCategory(${JSON.stringify(input)}) => ${actual} (expected ${expected})`);
        failures++;
    }
}

assert.strictEqual(typeof taxonomy.TAXONOMY_VERSION, 'string', 'TAXONOMY_VERSION must be a string');
assert.ok(taxonomy.ALL_CATEGORIES.includes('other'), 'ALL_CATEGORIES must include the "other" sentinel');
assert.ok(taxonomy.ALL_CATEGORIES.length >= 10, 'expected at least 10 canonical categories');

if (failures > 0) {
    console.error(`\n${failures} taxonomy fixture(s) failed.`);
    process.exit(1);
}

console.log(`taxonomy snapshot OK (${FIXTURES.length} fixtures, version ${taxonomy.TAXONOMY_VERSION})`);
