import * as ts from 'typescript';
import * as fs from 'fs';
import * as path from 'path';
import { SecurityIssue } from './analyzer';
import { getLogger } from './logger';

/**
 * Stage 0 of audit mode: deterministic AST extraction over a project tree.
 *
 * Produces:
 *   - per-file structural index (imports, exports, request-input usage)
 *   - direct sink detections (eval, $where, ReDoS regex, weak-hash crypto,
 *     mass-assignment via req.body destructure, deprecated bcrypt-nodejs,
 *     dynamic require)
 *
 * This module is the TypeScript counterpart of `evaluation/project-map-builder.js`.
 * The two share the same detection logic so audit-mode results in the
 * harness transfer one-to-one to the extension's `Workspace Security
 * Dashboard` flow.
 *
 * The AST findings are emitted as `SecurityIssue` objects tagged with
 * `detectionSource: 'ast'` so downstream rendering can distinguish
 * deterministic syntactic detections from semantic LLM detections.
 */

export interface AstSink {
    line: number;
    label: string;
    detail: string;
}

export interface ProjectMapEntry {
    file: string;          // relative to map root
    absPath: string;
    imports: string[];
    exports: string[];
    sinks: AstSink[];
    requestUsage: number;
    requestSamples: { line: number; chain: string }[];
    parseError?: string;
}

export interface ProjectMap {
    rootDir: string;
    fileCount: number;
    perFile: ProjectMapEntry[];
}

const SKIP_DIRS: ReadonlySet<string> = new Set([
    'node_modules', '.git', 'dist', 'build', 'coverage', 'out', '.next', '.cache',
    'public', 'cypress', 'test', 'tests', '__tests__', 'spec', 'docs', 'tutorial',
    'artifacts', '.github', 'vendor'
]);

const DANGEROUS_CALLEES: Record<string, string> = {
    'eval': 'eval — CWE-95 code injection',
    'Function': 'Function constructor — CWE-95 code injection',
    'exec': 'child_process.exec — CWE-78 command injection',
    'execSync': 'child_process.execSync — CWE-78 command injection',
    'spawn': 'child_process.spawn (when called with a shell) — CWE-78',
    'spawnSync': 'child_process.spawnSync (when called with a shell) — CWE-78'
};

const WEAK_HASH_ARGS: ReadonlySet<string> = new Set(['md5', 'sha1', 'rmd160']);

function* walkSource(target: string): Generator<string> {
    if (!fs.existsSync(target)) {return;}
    const st = fs.statSync(target);
    if (st.isFile()) {
        if (/\.(jsx?|tsx?)$/.test(target)) {yield target;}
        return;
    }
    for (const name of fs.readdirSync(target)) {
        if (SKIP_DIRS.has(name)) {continue;}
        const abs = path.join(target, name);
        const sub = fs.statSync(abs);
        if (sub.isDirectory()) {yield* walkSource(abs);}
        else if (/\.(jsx?|tsx?)$/.test(name)) {yield abs;}
    }
}

function getCalleeName(node: ts.CallExpression): string | null {
    if (ts.isIdentifier(node.expression)) {
        return node.expression.escapedText.toString();
    }
    if (ts.isPropertyAccessExpression(node.expression)) {
        return node.expression.name.escapedText.toString();
    }
    return null;
}

function getRequestArgChain(node: ts.CallExpression): string | null {
    if (!node.arguments || node.arguments.length === 0) {return null;}
    const arg = node.arguments[0];
    if (!ts.isPropertyAccessExpression(arg)) {return null;}
    let head: ts.PropertyAccessExpression = arg;
    while (ts.isPropertyAccessExpression(head.expression)) {
        head = head.expression;
    }
    if (ts.isIdentifier(head.expression)) {
        const root = head.expression.escapedText.toString();
        const next = head.name.escapedText.toString();
        if (root === 'req' && (next === 'body' || next === 'query' || next === 'params')) {
            return `req.${next}`;
        }
    }
    return null;
}

function regexHasNestedQuantifier(pattern: string): boolean {
    if (typeof pattern !== 'string') {return false;}
    // Strip escape sequences so they don't trick the matcher.
    const stripped = pattern.replace(/\\./g, 'X');
    return /\([^()]*[+*?][^()]*\)[+*]/.test(stripped);
}

function lineOf(sourceFile: ts.SourceFile, node: ts.Node): number {
    return sourceFile.getLineAndCharacterOfPosition(node.getStart()).line + 1;
}

function isMongoWhereLiteral(node: ts.ObjectLiteralExpression): boolean {
    for (const prop of node.properties) {
        if (!ts.isPropertyAssignment(prop)) {continue;}
        let keyName = '';
        if (ts.isStringLiteral(prop.name)) {keyName = prop.name.text;}
        else if (ts.isIdentifier(prop.name)) {keyName = prop.name.escapedText.toString();}
        if (keyName !== '$where') {continue;}
        const v = prop.initializer;
        if (ts.isTemplateExpression(v) || ts.isNoSubstitutionTemplateLiteral(v)) {return true;}
        if (ts.isBinaryExpression(v)) {return true;}
    }
    return false;
}

/**
 * Map a sink label/detail string to a canonical taxonomy bin.
 *
 * Note: keep in sync with `evaluation/project-map-builder.js` so harness and
 * extension agree on category assignment.
 */
export function categoryForSink(label: string, detail: string): string {
    const text = `${label} ${detail}`.toLowerCase();
    if (text.includes('cwe-915') || text.includes('mass assign')) {return 'auth-bypass';}
    if (text.includes('cwe-89') || text.includes('sql injection')) {return 'sql-injection';}
    if (text.includes('cwe-943') || text.includes('nosql') || text.includes('$where')) {return 'nosql-injection';}
    if (text.includes('cwe-78') || text.includes('command injection')) {return 'command-injection';}
    if (text.includes('cwe-95') || text.includes('eval') || text.includes('function constructor') || text.includes('code injection')) {return 'code-injection';}
    if (text.includes('cwe-22') || text.includes('path traversal') || text.includes('dynamic require')) {return 'path-traversal';}
    if (text.includes('cwe-327') || text.includes('weak crypto')) {return 'weak-crypto';}
    if (text.includes('cwe-1333') || text.includes('redos')) {return 'redos';}
    if (text.includes('cwe-1104') || text.includes('deprecated')) {return 'weak-crypto';}
    return 'other';
}

export function analyseFile(absPath: string, repoRoot: string): ProjectMapEntry {
    const rel = path.relative(repoRoot, absPath);
    const result: ProjectMapEntry = {
        file: rel,
        absPath,
        imports: [],
        exports: [],
        sinks: [],
        requestUsage: 0,
        requestSamples: []
    };

    let content: string;
    try {
        content = fs.readFileSync(absPath, 'utf8');
    } catch (e) {
        result.parseError = (e as Error).message;
        return result;
    }

    let sf: ts.SourceFile;
    try {
        sf = ts.createSourceFile(absPath, content, ts.ScriptTarget.Latest, true);
    } catch (e) {
        result.parseError = (e as Error).message;
        return result;
    }

    function recordSink(line: number, label: string, detail: string): void {
        result.sinks.push({ line, label, detail });
    }

    function visit(node: ts.Node): void {
        // CallExpression: imports (require), dangerous callees, weak hash
        if (ts.isCallExpression(node)) {
            const callee = getCalleeName(node);

            if (callee === 'require' && node.arguments[0]) {
                const arg = node.arguments[0];
                if (ts.isStringLiteral(arg)) {
                    result.imports.push(arg.text);
                } else {
                    recordSink(lineOf(sf, node), 'require(<dynamic>)', 'CWE-22 / dynamic require');
                }
            }

            if (callee && DANGEROUS_CALLEES[callee]) {
                const reqChain = getRequestArgChain(node);
                const detail = reqChain ? `${DANGEROUS_CALLEES[callee]}; argument: ${reqChain}` : DANGEROUS_CALLEES[callee];
                recordSink(lineOf(sf, node), `${callee}()`, detail);
            }

            if (callee === 'createHash' && node.arguments[0]) {
                const arg = node.arguments[0];
                if (ts.isStringLiteral(arg) && WEAK_HASH_ARGS.has(arg.text.toLowerCase())) {
                    recordSink(lineOf(sf, node), `createHash('${arg.text}')`, 'CWE-327 weak crypto');
                }
            }
        }

        // import ... from 'x'
        if (ts.isImportDeclaration(node) && ts.isStringLiteral(node.moduleSpecifier)) {
            result.imports.push(node.moduleSpecifier.text);
        }

        // export function / class
        if (ts.canHaveModifiers(node)) {
            const mods = ts.getModifiers(node);
            const isExport = mods?.some(m => m.kind === ts.SyntaxKind.ExportKeyword);
            if (isExport) {
                if (ts.isFunctionDeclaration(node) && node.name) {
                    result.exports.push(`function ${node.name.text}`);
                } else if (ts.isClassDeclaration(node) && node.name) {
                    result.exports.push(`class ${node.name.text}`);
                }
            }
        }

        // module.exports = ... and exports.X = ...
        if (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.EqualsToken) {
            if (ts.isPropertyAccessExpression(node.left)) {
                const head = ts.isIdentifier(node.left.expression) ? node.left.expression.escapedText.toString() : '';
                const member = node.left.name.escapedText.toString();
                if (head === 'module' && member === 'exports') {result.exports.push('module.exports');}
                if (head === 'exports' && member) {result.exports.push(`exports.${member}`);}
            }
        }

        // Mongo $where
        if (ts.isObjectLiteralExpression(node) && isMongoWhereLiteral(node)) {
            recordSink(lineOf(sf, node), '$where', 'CWE-943 NoSQL injection via $where with template literal / concatenation');
        }

        // CWE-915 mass assignment via req.body destructure with >= 3 fields
        if (ts.isVariableDeclaration(node)
            && node.initializer
            && ts.isPropertyAccessExpression(node.initializer)
            && ts.isObjectBindingPattern(node.name)
        ) {
            const init = node.initializer;
            if (ts.isIdentifier(init.expression)) {
                const root = init.expression.escapedText.toString();
                const member = init.name.escapedText.toString();
                if (root === 'req' && (member === 'body' || member === 'query' || member === 'params')) {
                    const fieldCount = node.name.elements.length;
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

        // Regex literals
        if (node.kind === ts.SyntaxKind.RegularExpressionLiteral) {
            const text = (node as ts.RegularExpressionLiteral).text;
            const body = text.replace(/^\//, '').replace(/\/[a-z]*$/, '');
            if (regexHasNestedQuantifier(body)) {
                recordSink(lineOf(sf, node), `regex ${text}`, 'CWE-1333 ReDoS — nested quantifier shape');
            }
        }

        // req.body / req.query / req.params usage tally
        if (ts.isPropertyAccessExpression(node) && ts.isIdentifier(node.expression)) {
            const root = node.expression.escapedText.toString();
            const member = node.name.escapedText.toString();
            if (root === 'req' && (member === 'body' || member === 'query' || member === 'params')) {
                result.requestUsage++;
                if (result.requestSamples.length < 3) {
                    result.requestSamples.push({ line: lineOf(sf, node), chain: `req.${member}` });
                }
            }
        }

        ts.forEachChild(node, visit);
    }

    ts.forEachChild(sf, visit);
    result.imports = [...new Set(result.imports)].sort();
    result.exports = [...new Set(result.exports)].sort();
    return result;
}

/**
 * Walk the project tree and produce the project map. Synchronous I/O — fast
 * enough for typical projects (Node fs is microseconds per file). For
 * very large workspaces consider chunking the walk and yielding to the event
 * loop between batches.
 */
export function buildProjectMap(rootDir: string): ProjectMap {
    if (!fs.existsSync(rootDir)) {
        throw new Error(`Project root not found: ${rootDir}`);
    }
    const perFile: ProjectMapEntry[] = [];
    const logger = getLogger();
    for (const f of walkSource(rootDir)) {
        try {
            perFile.push(analyseFile(f, rootDir));
        } catch (e) {
            logger.warn(`projectMapBuilder: failed to analyse ${f}: ${(e as Error).message}`);
            perFile.push({
                file: path.relative(rootDir, f),
                absPath: f,
                imports: [], exports: [], sinks: [],
                requestUsage: 0, requestSamples: [],
                parseError: (e as Error).message
            });
        }
    }
    perFile.sort((a, b) => a.file.localeCompare(b.file));
    return { rootDir, fileCount: perFile.length, perFile };
}

/**
 * Convert all AST sink detections in the project map into SecurityIssue
 * objects, tagged with `detectionSource: 'ast'`. The result is a flat list
 * keyed by absolute path so workspaceScanner can merge them with LLM
 * findings on a per-file basis.
 */
export interface AstFindingForFile {
    absPath: string;
    relativePath: string;
    issue: SecurityIssue;
    canonicalCategory: string;
}

export function astFindingsFromMap(map: ProjectMap): AstFindingForFile[] {
    const out: AstFindingForFile[] = [];
    for (const f of map.perFile) {
        for (const s of f.sinks) {
            const cat = categoryForSink(s.label, s.detail);
            out.push({
                absPath: f.absPath,
                relativePath: f.file,
                canonicalCategory: cat,
                issue: {
                    message: `[AST/${cat}] ${s.label}: ${s.detail}`,
                    startLine: s.line,
                    endLine: s.line,
                    confidence: 1.0, // AST detections are deterministic
                    detectionSource: 'ast'
                }
            });
        }
    }
    return out;
}

/**
 * Group AST findings by file path for fast lookup during workspace scan.
 */
export function astFindingsByFile(map: ProjectMap): Map<string, SecurityIssue[]> {
    const byFile = new Map<string, SecurityIssue[]>();
    for (const f of astFindingsFromMap(map)) {
        const list = byFile.get(f.absPath) ?? [];
        list.push(f.issue);
        byFile.set(f.absPath, list);
    }
    return byFile;
}

export interface FormatProjectMapOptions {
    skipSinks?: boolean;
    skipInventory?: boolean;
}

export function formatProjectMap(map: ProjectMap, opts: FormatProjectMapOptions = {}): string {
    const lines: string[] = [];
    lines.push('=== PROJECT MAP ===');
    lines.push(`files: ${map.fileCount}`);

    if (!opts.skipSinks) {
        const sinkLines: string[] = [];
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

    const reqUsage = map.perFile.filter(f => f.requestUsage > 0);
    if (reqUsage.length) {
        lines.push('');
        lines.push('=== USER-INPUT (req.body / req.query / req.params) USAGE ===');
        for (const f of reqUsage) {
            const samples = f.requestSamples.map(s => `${s.chain}@${s.line}`).join(', ');
            lines.push(`  ${f.file}  ${f.requestUsage}× — ${samples}`);
        }
    }

    if (!opts.skipInventory) {
        lines.push('');
        lines.push('=== FILE INVENTORY ===');
        for (const f of map.perFile) {
            const ex = f.exports.length
                ? `(exports: ${f.exports.slice(0, 4).join(', ')}${f.exports.length > 4 ? `, +${f.exports.length - 4}` : ''})`
                : '';
            lines.push(`  ${f.file}  ${ex}`);
        }
    }

    return lines.join('\n');
}
