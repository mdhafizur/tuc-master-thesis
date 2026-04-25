'use strict';

/**
 * Snapshot test for evaluation/repair-validator.js.
 * Run via: node evaluation/repair-validator.snapshot.test.js
 */

const assert = require('assert');
const { validateRepair, aggregateAutoApplicable, stripFencesAndQuotes } = require('./repair-validator');

// --- empty / non-string input -----------------------------------------
assert.strictEqual(validateRepair(undefined).valid, false);
assert.strictEqual(validateRepair(null).valid, false);
assert.strictEqual(validateRepair('').valid, false);
assert.strictEqual(validateRepair(123).valid, false);
assert.strictEqual(validateRepair('   ').valid, false);

// --- valid JS expressions and statements ------------------------------
{
    const r = validateRepair('db.query("SELECT * FROM users WHERE id = ?", [userId])');
    assert.strictEqual(r.valid, true, 'parameterized SQL query is valid');
}
{
    const r = validateRepair('const sanitized = sanitizeHtml(userInput);');
    assert.strictEqual(r.valid, true, 'variable declaration is valid');
}
{
    const r = validateRepair(`
        const hash = crypto.createHash('sha256').update(password).digest('hex');
        return hash;
    `);
    assert.strictEqual(r.valid, true, 'multi-statement block is valid');
}
{
    const r = validateRepair('element.textContent = userInput;');
    assert.strictEqual(r.valid, true, 'simple assignment is valid');
}

// --- TypeScript syntax accepted ---------------------------------------
{
    const r = validateRepair(`
        interface User { id: number; }
        function safeQuery(id: number): Promise<User> {
            return db.query("SELECT * FROM users WHERE id = ?", [id]);
        }
    `);
    assert.strictEqual(r.valid, true, 'TS interface + typed fn is valid');
}

// --- async / await --------------------------------------------------
{
    const r = validateRepair('await fetch(url, { method: "GET" })');
    assert.strictEqual(r.valid, true, 'top-level await accepted');
}

// --- code with markdown fences ---------------------------------------
{
    const fenced = "```js\nconst x = sanitize(input);\n```";
    const r = validateRepair(fenced);
    assert.strictEqual(r.valid, true, 'markdown-fenced code unwraps cleanly');
}
{
    const fenced = "```\nconst y = 5;\n```";
    const r = validateRepair(fenced);
    assert.strictEqual(r.valid, true, 'unlanguaged fence unwraps');
}

// --- code in single backticks -----------------------------------------
{
    const r = validateRepair('`const x = 1;`');
    assert.strictEqual(r.valid, true, 'inline backtick code unwraps');
}

// --- prose rejections -------------------------------------------------
{
    const r = validateRepair('You should use a parameterized query like db.query(?)');
    assert.strictEqual(r.valid, false);
    assert.strictEqual(r.reason, 'prose_not_code');
}
{
    const r = validateRepair('To fix this vulnerability, replace the line with sanitize(x)');
    assert.strictEqual(r.valid, false);
    assert.strictEqual(r.reason, 'prose_not_code');
}
{
    const r = validateRepair('The vulnerability is in line 5');
    assert.strictEqual(r.valid, false);
    assert.strictEqual(r.reason, 'prose_not_code');
}

// --- syntactically broken code rejected -------------------------------
{
    const r = validateRepair('const x = ;;');
    assert.strictEqual(r.valid, false);
    assert.ok(r.reason.startsWith('parse_error'), 'broken syntax has parse_error reason');
}
{
    const r = validateRepair('function foo(');
    assert.strictEqual(r.valid, false);
    assert.ok(r.reason.startsWith('parse_error'));
}

// --- aggregateAutoApplicable -----------------------------------------
{
    const detectedLists = [
        [
            { suggestedFix: 'db.query("SELECT * FROM users WHERE id = ?", [id])' }, // valid
            { suggestedFix: 'You should use a prepared statement here.' }            // prose
        ],
        [
            { suggestedFix: 'element.textContent = input;' },                        // valid
            { suggestedFix: '' },                                                     // skipped (empty)
            { suggestedFix: 'function foo(' }                                         // invalid syntax
        ],
        []
    ];
    const agg = aggregateAutoApplicable(detectedLists);
    assert.strictEqual(agg.totalRepairs, 4, 'empty fix is skipped');
    assert.strictEqual(agg.autoApplicable, 2, '2 of 4 fixes parse');
    assert.strictEqual(Math.round(agg.autoApplicableRate * 100), 50, 'rate 50%');
    assert.ok(agg.byReason.prose_not_code === 1);
    assert.ok(agg.byReason['parse_error: ' + Object.keys(agg.byReason).find(k => k.startsWith('parse_error'))?.slice('parse_error: '.length)] !== undefined ||
              Object.keys(agg.byReason).some(k => k.startsWith('parse_error')),
              'parse_error reason recorded');
}

// --- stripFencesAndQuotes is idempotent on plain code ----------------
assert.strictEqual(stripFencesAndQuotes('const x = 1;'), 'const x = 1;');

console.log('repair-validator snapshot OK');
