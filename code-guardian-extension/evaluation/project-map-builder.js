#!/usr/bin/env node
/**
 * Stage 1 of the audit-mode pipeline.
 *
 * Walks a project's source tree, parses each .js/.ts file with the TypeScript
 * compiler API, and emits a compact structural map describing:
 *   - imports per file
 *   - exported function / class / method names
 *   - direct sink calls (eval, Function ctor, child_process.exec/execSync,
 *     weak-hash crypto.createHash arguments, MongoDB $where with template
 *     literal interpolation, regex literals with nested quantifiers /
 *     ReDoS shapes)
 *   - first-use locations of req.body / req.query / req.params
 *
 * The map is deterministic, AST-derived, and zero LLM cost. It is prepended to
 * the system prompt in audit mode (Stage 2) so the LLM has explicit awareness
 * of cross-file flows and direct sinks before it reads any individual file.
 *
 * Usage:
 *   node evaluation/project-map-builder.js --root <project-dir>
 *   node evaluation/project-map-builder.js --root <project-dir> --json     # raw JSON
 */

const fs = require('fs');
const path = require('path');
const ts = require('typescript');

const SKIP_DIRS = new Set([
  'node_modules', '.git', 'dist', 'build', 'coverage', 'out', '.next', '.cache',
  'public', 'cypress', 'test', 'tests', '__tests__', 'spec', 'docs', 'tutorial',
  'artifacts', '.github', 'vendor'
]);

function* walkSource(target) {
  if (!fs.existsSync(target)) return;
  const st = fs.statSync(target);
  if (st.isFile()) {
    if (/\.(jsx?|tsx?)$/.test(target)) yield target;
    return;
  }
  for (const name of fs.readdirSync(target)) {
    if (SKIP_DIRS.has(name)) continue;
    const abs = path.join(target, name);
    const sub = fs.statSync(abs);
    if (sub.isDirectory()) yield* walkSource(abs);
    else if (/\.(jsx?|tsx?)$/.test(name)) yield abs;
  }
}

const DANGEROUS_CALLEES = {
  'eval': 'eval — CWE-95 code injection',
  'Function': 'Function constructor — CWE-95 code injection',
  'exec': 'child_process.exec — CWE-78 command injection',
  'execSync': 'child_process.execSync — CWE-78 command injection',
  'spawn': 'child_process.spawn (when called with a shell) — CWE-78',
  'spawnSync': 'child_process.spawnSync (when called with a shell) — CWE-78',
};

const WEAK_HASH_ARGS = new Set(['md5', 'sha1', 'rmd160']);

function getCalleeName(node) {
  // Identifier callee (e.g. eval(...))
  if (node.expression && node.expression.kind === ts.SyntaxKind.Identifier) {
    return node.expression.escapedText || node.expression.text;
  }
  // PropertyAccessExpression callee (e.g. crypto.createHash, child_process.exec)
  if (node.expression && node.expression.kind === ts.SyntaxKind.PropertyAccessExpression) {
    const pa = node.expression;
    return pa.name && (pa.name.escapedText || pa.name.text);
  }
  return null;
}

function getRequestArgChain(node) {
  // Returns 'req.body' / 'req.query' / 'req.params' if the call's first arg is
  // a property access starting at `req`.
  if (!node.arguments || node.arguments.length === 0) return null;
  const arg = node.arguments[0];
  if (arg.kind !== ts.SyntaxKind.PropertyAccessExpression) return null;
  let head = arg;
  while (head.expression && head.expression.kind === ts.SyntaxKind.PropertyAccessExpression) {
    head = head.expression;
  }
  if (head.expression && head.expression.kind === ts.SyntaxKind.Identifier) {
    const root = head.expression.escapedText || head.expression.text;
    const next = head.name && (head.name.escapedText || head.name.text);
    if (root === 'req' && (next === 'body' || next === 'query' || next === 'params')) {
      return `req.${next}`;
    }
  }
  return null;
}

function regexHasNestedQuantifier(pattern) {
  // ReDoS canonical shapes: (X+)+, (X+)*, (X*)+, (X*)*, (X|Y)+ around quantifiers,
  // also (a+)*. Conservative match — flags `quantifier inside group then quantifier outside`.
  // Common patterns: /(.+)+/ /([0-9]+)+#/ /(\w*)*$/ /(a|b)+(c|d)+/
  if (typeof pattern !== 'string') return false;
  // Strip escape sequences so they don't trick the matcher
  const stripped = pattern.replace(/\\./g, 'X');
  return /\([^()]*[+*?][^()]*\)[+*]/.test(stripped);
}

function lineOf(sourceFile, node) {
  return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
}

function isMongoWhereLiteral(node) {
  // ObjectLiteralExpression with a property whose key is `$where` (StringLiteral
  // or Identifier '$where') and whose value contains a TemplateExpression.
  if (node.kind !== ts.SyntaxKind.ObjectLiteralExpression) return null;
  for (const prop of node.properties) {
    if (prop.kind !== ts.SyntaxKind.PropertyAssignment) continue;
    const keyNode = prop.name;
    let keyName = '';
    if (keyNode.kind === ts.SyntaxKind.StringLiteral) keyName = keyNode.text;
    else if (keyNode.kind === ts.SyntaxKind.Identifier) keyName = keyNode.escapedText || keyNode.text;
    if (keyName === '$where') {
      // Check value for template-literal interpolation
      const v = prop.initializer;
      if (v.kind === ts.SyntaxKind.TemplateExpression || v.kind === ts.SyntaxKind.NoSubstitutionTemplateLiteral) {
        return true;
      }
      // Also flag if the value is a string with `+` concatenation (BinaryExpression with +)
      if (v.kind === ts.SyntaxKind.BinaryExpression) return true;
    }
  }
  return null;
}

function analyseFile(absPath, repoRoot) {
  const content = fs.readFileSync(absPath, 'utf8');
  const sf = ts.createSourceFile(absPath, content, ts.ScriptTarget.Latest, true);
  const rel = path.relative(repoRoot, absPath);
  const result = {
    file: rel,
    imports: [],
    exports: [],
    sinks: [],
    requestUsage: 0,
    requestSamples: []
  };

  function recordSink(line, label, detail) {
    result.sinks.push({ line, label, detail });
  }

  function visit(node) {
    // Imports
    if (node.kind === ts.SyntaxKind.CallExpression) {
      const callee = getCalleeName(node);

      // require('x') / require(`x`)
      if (callee === 'require' && node.arguments && node.arguments[0]) {
        const arg = node.arguments[0];
        if (arg.kind === ts.SyntaxKind.StringLiteral) result.imports.push(arg.text);
        else result.sinks.push({ line: lineOf(sf, node), label: 'require(<dynamic>)', detail: 'CWE-22 / dynamic require' });
      }

      // Direct dangerous callees
      if (callee && DANGEROUS_CALLEES[callee]) {
        const reqChain = getRequestArgChain(node);
        const detail = reqChain ? `${DANGEROUS_CALLEES[callee]}; argument: ${reqChain}` : DANGEROUS_CALLEES[callee];
        recordSink(lineOf(sf, node), `${callee}()`, detail);
      }

      // crypto.createHash('md5'|'sha1')
      if (callee === 'createHash' && node.arguments && node.arguments[0]) {
        const arg = node.arguments[0];
        if (arg.kind === ts.SyntaxKind.StringLiteral && WEAK_HASH_ARGS.has(arg.text.toLowerCase())) {
          recordSink(lineOf(sf, node), `createHash('${arg.text}')`, 'CWE-327 weak crypto');
        }
      }
    }

    // import ... from 'x'
    if (node.kind === ts.SyntaxKind.ImportDeclaration && node.moduleSpecifier && node.moduleSpecifier.kind === ts.SyntaxKind.StringLiteral) {
      result.imports.push(node.moduleSpecifier.text);
    }

    // Exported declarations (top-level only — we don't recurse into class members for the map)
    const isExport = node.modifiers && node.modifiers.some(m => m.kind === ts.SyntaxKind.ExportKeyword);
    if (isExport) {
      if (node.kind === ts.SyntaxKind.FunctionDeclaration && node.name) {
        result.exports.push(`function ${node.name.text}`);
      } else if (node.kind === ts.SyntaxKind.ClassDeclaration && node.name) {
        result.exports.push(`class ${node.name.text}`);
      }
    }

    // module.exports = ... and exports.X = ...
    if (node.kind === ts.SyntaxKind.BinaryExpression && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
      const lhs = node.left;
      if (lhs.kind === ts.SyntaxKind.PropertyAccessExpression) {
        const head = lhs.expression && (lhs.expression.escapedText || lhs.expression.text);
        const member = lhs.name && (lhs.name.escapedText || lhs.name.text);
        if (head === 'module' && member === 'exports') result.exports.push('module.exports');
        if (head === 'exports' && member) result.exports.push(`exports.${member}`);
      }
    }

    // Mongo $where
    if (node.kind === ts.SyntaxKind.ObjectLiteralExpression && isMongoWhereLiteral(node)) {
      recordSink(lineOf(sf, node), '$where', 'CWE-943 NoSQL injection via $where with template literal / concatenation');
    }

    // CWE-915 Mass Assignment: ObjectBindingPattern destructuring of req.body /
    // req.query / req.params with >= 3 fields (textbook mass-assignment shape).
    // Aliasing form (`const x = req.body; ... dao.update(x)`) is also covered
    // by the request-usage counter; the destructure form is the high-precision
    // signal we surface as a sink.
    if (node.kind === ts.SyntaxKind.VariableDeclaration) {
      const init = node.initializer;
      const name = node.name;
      if (
        init && init.kind === ts.SyntaxKind.PropertyAccessExpression &&
        name && name.kind === ts.SyntaxKind.ObjectBindingPattern
      ) {
        const head = init.expression;
        const member = init.name && (init.name.escapedText || init.name.text);
        if (head && head.kind === ts.SyntaxKind.Identifier) {
          const root = head.escapedText || head.text;
          if (root === 'req' && (member === 'body' || member === 'query' || member === 'params')) {
            const fieldCount = name.elements ? name.elements.length : 0;
            if (fieldCount >= 3) {
              recordSink(
                lineOf(sf, node),
                `mass-assign req.${member}`,
                `CWE-915 mass assignment via destructure of req.${member} (${fieldCount} fields without allowlist)`
              );
            }
          }
        }
      }
    }

    // Regex literals
    if (node.kind === ts.SyntaxKind.RegularExpressionLiteral) {
      const text = node.text;
      const body = text.replace(/^\//, '').replace(/\/[a-z]*$/, '');
      if (regexHasNestedQuantifier(body)) {
        recordSink(lineOf(sf, node), `regex ${text}`, 'CWE-1333 ReDoS — nested quantifier shape');
      }
    }

    // req.body / req.query / req.params usage (PropertyAccess from `req`)
    if (node.kind === ts.SyntaxKind.PropertyAccessExpression) {
      const obj = node.expression;
      const member = node.name && (node.name.escapedText || node.name.text);
      if (obj && obj.kind === ts.SyntaxKind.Identifier) {
        const root = obj.escapedText || obj.text;
        if (root === 'req' && (member === 'body' || member === 'query' || member === 'params')) {
          result.requestUsage++;
          if (result.requestSamples.length < 3) {
            result.requestSamples.push({ line: lineOf(sf, node), chain: `req.${member}` });
          }
        }
      }
    }

    ts.forEachChild(node, visit);
  }

  ts.forEachChild(sf, visit);
  // Deduplicate
  result.imports = [...new Set(result.imports)].sort();
  result.exports = [...new Set(result.exports)].sort();
  return result;
}

function buildProjectMap(rootDir) {
  if (!fs.existsSync(rootDir)) {
    throw new Error(`Project root not found: ${rootDir}`);
  }
  const perFile = [];
  for (const f of walkSource(rootDir)) {
    try {
      perFile.push(analyseFile(f, rootDir));
    } catch (e) {
      // Skip unparseable files but record them so the map is honest
      perFile.push({ file: path.relative(rootDir, f), imports: [], exports: [], sinks: [], requestUsage: 0, requestSamples: [], parseError: e.message });
    }
  }
  perFile.sort((a, b) => a.file.localeCompare(b.file));
  return { rootDir, fileCount: perFile.length, perFile };
}

// Map AST sink labels to canonical category bins so the AST detections
// participate in the same recall/recompute pipeline as the LLM findings.
function categoryForSink(label, detail) {
  const text = `${label} ${detail}`.toLowerCase();
  if (text.includes('cwe-915') || text.includes('mass assign')) return 'auth-bypass';
  if (text.includes('cwe-89') || text.includes('sql injection')) return 'sql-injection';
  if (text.includes('cwe-943') || text.includes('nosql') || text.includes('$where')) return 'nosql-injection';
  if (text.includes('cwe-78') || text.includes('command injection')) return 'command-injection';
  if (text.includes('cwe-95') || text.includes('eval') || text.includes('function constructor') || text.includes('code injection')) return 'code-injection';
  if (text.includes('cwe-22') || text.includes('path traversal') || text.includes('dynamic require')) return 'path-traversal';
  if (text.includes('cwe-327') || text.includes('weak crypto')) return 'weak-crypto';
  if (text.includes('cwe-1333') || text.includes('redos')) return 'redos';
  if (text.includes('cwe-1104') || text.includes('deprecated')) return 'weak-crypto';
  return 'other';
}

function astFindingsFromMap(map) {
  // Project-wide AST detections produced as a flat list of finding objects in
  // the same shape as LLM findings (so the rest of the pipeline doesn't need
  // to know the source). Tagged with `source: 'ast'` for provenance.
  const out = [];
  for (const f of map.perFile) {
    for (const s of f.sinks) {
      out.push({
        file: f.file,
        line: s.line,
        category: categoryForSink(s.label, s.detail),
        severity: 'high',
        message: `[AST] ${s.label}: ${s.detail}`,
        source: 'ast'
      });
    }
  }
  return out;
}

function formatProjectMap(map, opts = {}) {
  const lines = [];
  lines.push('=== PROJECT MAP ===');
  lines.push(`files: ${map.fileCount}`);

  // KNOWN-RISKY SINKS section is suppressible. In audit mode the AST detections
  // are added directly to the findings list (Stage 0) and we do NOT want to
  // also tell the LLM about them — that causes the model to defer ("already
  // flagged, skipping") and lowers LLM recall.
  if (!opts.skipSinks) {
    const sinkLines = [];
    for (const f of map.perFile) {
      for (const s of f.sinks) {
        sinkLines.push(`  ${f.file}:${s.line}  ${s.label} — ${s.detail}`);
      }
    }
    if (sinkLines.length) {
      lines.push('');
      lines.push('=== KNOWN-RISKY SINKS (AST-derived) ===');
      lines.push(...sinkLines);
    }
  }

  // req.body / req.query / req.params usage summary
  const reqUsage = map.perFile.filter(f => f.requestUsage > 0);
  if (reqUsage.length) {
    lines.push('');
    lines.push('=== USER-INPUT (req.body / req.query / req.params) USAGE ===');
    for (const f of reqUsage) {
      const samples = f.requestSamples.map(s => `${s.chain}@${s.line}`).join(', ');
      lines.push(`  ${f.file}  ${f.requestUsage}× — ${samples}`);
    }
  }

  // Imports of security-relevant modules per file
  const flaggedImports = new Set([
    'bcrypt-nodejs', 'md5', 'sha1', 'jsonwebtoken', 'node-forge', 'lodash',
    'serialize-javascript', 'moment', 'mongo-sanitize', 'csurf', 'helmet'
  ]);
  const importLines = [];
  for (const f of map.perFile) {
    const flagged = f.imports.filter(i => flaggedImports.has(i) || /bcrypt|crypto|jwt|forge|mongo|sequelize/.test(i));
    if (flagged.length) importLines.push(`  ${f.file}  imports: ${flagged.join(', ')}`);
  }
  if (importLines.length) {
    lines.push('');
    lines.push('=== SECURITY-RELEVANT IMPORTS ===');
    lines.push(...importLines);
  }

  // File inventory (compact, one line per file with N exports if non-trivial)
  if (!opts.skipInventory) {
    lines.push('');
    lines.push('=== FILE INVENTORY ===');
    for (const f of map.perFile) {
      const ex = f.exports.length ? `(exports: ${f.exports.slice(0, 4).join(', ')}${f.exports.length > 4 ? `, +${f.exports.length - 4}` : ''})` : '';
      lines.push(`  ${f.file}  ${ex}`);
    }
  }

  return lines.join('\n');
}

function main() {
  const args = process.argv.slice(2);
  const idx = args.indexOf('--root');
  if (idx < 0) {
    console.error('Usage: project-map-builder.js --root <project-dir> [--json]');
    process.exit(1);
  }
  const root = path.resolve(args[idx + 1]);
  const map = buildProjectMap(root);
  if (args.includes('--json')) {
    console.log(JSON.stringify(map, null, 2));
  } else {
    console.log(formatProjectMap(map));
  }
}

if (require.main === module) main();

module.exports = { buildProjectMap, formatProjectMap, analyseFile, astFindingsFromMap, categoryForSink };
