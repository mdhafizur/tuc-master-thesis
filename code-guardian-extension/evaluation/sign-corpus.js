#!/usr/bin/env node
/**
 * Phase A2 — Corpus signing tool.
 *
 * Produces a SHA-256 manifest over every file in the security-knowledge directory
 * and signs the canonical file list with the corpus Ed25519 private key. The
 * extension verifies this manifest at RAG load time (corpusVerifier.ts).
 *
 * Usage:
 *   node evaluation/sign-corpus.js                     # default paths
 *   node evaluation/sign-corpus.js --keys keys/        # custom key dir
 *   node evaluation/sign-corpus.js --gen-keys          # generate keypair if missing
 *
 * Outputs:
 *   keys/corpus-public.pem   (committed)
 *   keys/corpus-private.pem  (NOT committed; .gitignored)
 *   security-knowledge/corpus-manifest.json
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ROOT = path.resolve(__dirname, '..');
const DEFAULT_KEYS_DIR = path.join(ROOT, 'keys');
const DEFAULT_CORPUS_DIR = path.join(ROOT, 'security-knowledge');
const DEFAULT_PROVENANCE_FILE = path.join(__dirname, 'corpus-provenance.json');

function parseArgs(argv) {
  const args = { keys: DEFAULT_KEYS_DIR, corpus: DEFAULT_CORPUS_DIR, genKeys: false };
  for (let i = 2; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--keys') args.keys = path.resolve(argv[++i]);
    else if (a === '--corpus') args.corpus = path.resolve(argv[++i]);
    else if (a === '--gen-keys') args.genKeys = true;
    else if (a === '--help' || a === '-h') {
      console.log(`Usage: node sign-corpus.js [--keys DIR] [--corpus DIR] [--gen-keys]`);
      process.exit(0);
    }
  }
  return args;
}

function ensureKeypair(keysDir, allowGenerate) {
  const priv = path.join(keysDir, 'corpus-private.pem');
  const pub = path.join(keysDir, 'corpus-public.pem');
  if (fs.existsSync(priv) && fs.existsSync(pub)) return { priv, pub };
  if (!allowGenerate) {
    throw new Error(
      `Keypair missing in ${keysDir}. Re-run with --gen-keys to create it (one-time).`
    );
  }
  fs.mkdirSync(keysDir, { recursive: true });
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  fs.writeFileSync(priv, privateKey.export({ type: 'pkcs8', format: 'pem' }));
  fs.writeFileSync(pub, publicKey.export({ type: 'spki', format: 'pem' }));
  fs.chmodSync(priv, 0o600);
  console.log(`Generated Ed25519 keypair in ${keysDir}`);
  return { priv, pub };
}

function sha256OfFile(p) {
  return crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
}

function listCorpusFiles(corpusDir) {
  const entries = [];
  // Top-level files only — vector-store/ subdirectory is regenerated locally
  // and is not signed (it is a derived artifact, not source data).
  for (const name of fs.readdirSync(corpusDir)) {
    const abs = path.join(corpusDir, name);
    const stat = fs.statSync(abs);
    if (stat.isFile() && name !== 'corpus-manifest.json') {
      entries.push({ rel: name, abs, size: stat.size });
    }
  }
  return entries.sort((a, b) => a.rel.localeCompare(b.rel));
}

function loadProvenance() {
  if (!fs.existsSync(DEFAULT_PROVENANCE_FILE)) return {};
  try {
    return JSON.parse(fs.readFileSync(DEFAULT_PROVENANCE_FILE, 'utf8'));
  } catch (e) {
    console.warn(`Provenance file ${DEFAULT_PROVENANCE_FILE} unparseable: ${e.message}`);
    return {};
  }
}

function canonicalPayload(files) {
  const sorted = [...files].sort((a, b) => a.path.localeCompare(b.path));
  return Buffer.from(
    sorted
      .map(f => [f.path, f.sha256, String(f.size), f.source || '', f.retrievedAt || ''].join('\t'))
      .join('\n'),
    'utf8'
  );
}

function main() {
  const args = parseArgs(process.argv);

  if (!fs.existsSync(args.corpus)) {
    console.error(`Corpus dir not found: ${args.corpus}`);
    process.exit(1);
  }

  const { priv, pub } = ensureKeypair(args.keys, args.genKeys);
  const provenance = loadProvenance();

  const fileEntries = listCorpusFiles(args.corpus).map(e => ({
    path: e.rel,
    sha256: sha256OfFile(e.abs),
    size: e.size,
    source: provenance[e.rel]?.source,
    retrievedAt: provenance[e.rel]?.retrievedAt
  }));

  const payload = canonicalPayload(fileEntries);
  const privKeyPem = fs.readFileSync(priv);
  const signature = crypto.sign(null, payload, privKeyPem).toString('base64');

  const manifest = {
    version: '1',
    createdAt: new Date().toISOString(),
    files: fileEntries,
    signature
  };

  const manifestPath = path.join(args.corpus, 'corpus-manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');

  console.log(`Signed ${fileEntries.length} files`);
  console.log(`Manifest: ${manifestPath}`);
  console.log(`Public key: ${pub}`);
}

if (require.main === module) main();
