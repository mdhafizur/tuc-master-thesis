'use strict';

/**
 * JS twin of src/categoryTaxonomy.ts for the evaluation harness.
 * Loads the same shared JSON and exposes the same API.
 *
 * Both modules MUST stay in sync — a snapshot test in
 * evaluation/category-taxonomy.snapshot.test.js asserts they produce
 * identical normalization results on a fixed input set.
 */

const path = require('path');
const taxonomyData = require(path.join(__dirname, '..', 'src', 'categoryTaxonomy.json'));

const COMPILED_PATTERNS = taxonomyData.patterns.map(p => ({
    regex: new RegExp(p.regex, 'i'),
    category: p.category
}));

const TAXONOMY_VERSION = taxonomyData.version;
const ALL_CATEGORIES = Object.freeze([...taxonomyData.categories]);

function normalizeCategory(raw) {
    if (raw === undefined || raw === null || raw === '') {
        return 'other';
    }
    const haystack = String(raw);
    for (const p of COMPILED_PATTERNS) {
        if (p.regex.test(haystack)) {
            return p.category;
        }
    }
    return 'other';
}

function normalizeCategories(rawList) {
    const out = new Set();
    for (const r of rawList) {
        out.add(normalizeCategory(r));
    }
    return out;
}

module.exports = {
    TAXONOMY_VERSION,
    ALL_CATEGORIES,
    normalizeCategory,
    normalizeCategories
};
