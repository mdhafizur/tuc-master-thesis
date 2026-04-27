import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';
import { getLogger } from './logger';

/**
 * Phase A2 + A5 — Signed corpora and provenance verification.
 *
 * Defends against the "retrieval poisoning" arm of the threat model: a local
 * adversary swaps the on-disk RAG knowledge base for one carrying malicious
 * "guidance" that the LLM then trusts as authoritative context. Verification
 * runs at load time and refuses to proceed on hash or signature mismatch.
 *
 * Manifest format (`corpus-manifest.json`):
 * {
 *   "version": "1",
 *   "createdAt": "2026-04-27T...",
 *   "files": [
 *     { "path": "knowledge-base.json", "sha256": "...", "size": 12345,
 *       "source": "owasp.org/top10", "retrievedAt": "2026-04-20T..." }
 *   ],
 *   "signature": "<base64 ed25519 over canonical(files)>"
 * }
 *
 * Public key ships with the extension; private key is held outside the repo.
 */

export interface ManifestEntry {
    path: string;
    sha256: string;
    size: number;
    source?: string;
    retrievedAt?: string;
}

export interface CorpusManifest {
    version: string;
    createdAt: string;
    files: ManifestEntry[];
    signature?: string; // base64-encoded ed25519 detached signature
}

export interface VerificationResult {
    valid: boolean;
    reason?: string;
    verifiedFiles: number;
    expectedFiles: number;
    signatureChecked: boolean;
    provenance: ManifestEntry[];
}

const HASH_ALGO = 'sha256';

export function sha256OfFile(filePath: string): string {
    const buf = fs.readFileSync(filePath);
    return crypto.createHash(HASH_ALGO).update(buf).digest('hex');
}

/**
 * Canonical byte serialisation of the file list used as the signing payload.
 * Sorted by path; `source`/`retrievedAt` included so provenance is bound to the
 * signature (an attacker cannot rewrite provenance without invalidating it).
 */
export function canonicalSigningPayload(files: ManifestEntry[]): Buffer {
    const sorted = [...files].sort((a, b) => a.path.localeCompare(b.path));
    const lines = sorted.map(f =>
        [f.path, f.sha256, String(f.size), f.source ?? '', f.retrievedAt ?? ''].join('\t')
    );
    return Buffer.from(lines.join('\n'), 'utf8');
}

export function loadManifest(manifestPath: string): CorpusManifest {
    const raw = fs.readFileSync(manifestPath, 'utf8');
    return JSON.parse(raw) as CorpusManifest;
}

/**
 * Verify every file in the manifest against the on-disk content under `rootDir`,
 * and (if a public key is given) verify the manifest's signature. Failure is
 * fatal to the caller — RAG load must abort.
 */
export function verifyCorpus(
    rootDir: string,
    manifestPath: string,
    publicKeyPath?: string
): VerificationResult {
    const logger = getLogger();

    if (!fs.existsSync(manifestPath)) {
        return {
            valid: false,
            reason: `manifest not found at ${manifestPath}`,
            verifiedFiles: 0,
            expectedFiles: 0,
            signatureChecked: false,
            provenance: []
        };
    }

    let manifest: CorpusManifest;
    try {
        manifest = loadManifest(manifestPath);
    } catch (e) {
        return {
            valid: false,
            reason: `manifest parse failed: ${(e as Error).message}`,
            verifiedFiles: 0,
            expectedFiles: 0,
            signatureChecked: false,
            provenance: []
        };
    }

    let verified = 0;
    for (const entry of manifest.files) {
        const fullPath = path.join(rootDir, entry.path);
        if (!fs.existsSync(fullPath)) {
            return {
                valid: false,
                reason: `corpus file missing: ${entry.path}`,
                verifiedFiles: verified,
                expectedFiles: manifest.files.length,
                signatureChecked: false,
                provenance: manifest.files
            };
        }
        const actual = sha256OfFile(fullPath);
        if (actual !== entry.sha256) {
            return {
                valid: false,
                reason: `hash mismatch on ${entry.path}: expected ${entry.sha256}, got ${actual}`,
                verifiedFiles: verified,
                expectedFiles: manifest.files.length,
                signatureChecked: false,
                provenance: manifest.files
            };
        }
        verified++;
    }

    let signatureChecked = false;
    if (publicKeyPath && fs.existsSync(publicKeyPath) && manifest.signature) {
        try {
            const pubKeyPem = fs.readFileSync(publicKeyPath);
            const sigBytes = Buffer.from(manifest.signature, 'base64');
            const ok = crypto.verify(
                null, // ed25519 ignores the digest arg
                canonicalSigningPayload(manifest.files),
                pubKeyPem,
                sigBytes
            );
            if (!ok) {
                return {
                    valid: false,
                    reason: 'manifest signature invalid (possible tampering)',
                    verifiedFiles: verified,
                    expectedFiles: manifest.files.length,
                    signatureChecked: true,
                    provenance: manifest.files
                };
            }
            signatureChecked = true;
        } catch (e) {
            return {
                valid: false,
                reason: `signature verification failed: ${(e as Error).message}`,
                verifiedFiles: verified,
                expectedFiles: manifest.files.length,
                signatureChecked: false,
                provenance: manifest.files
            };
        }
    } else if (publicKeyPath) {
        logger.warn('Public key present but manifest carries no signature; only hashes verified.');
    }

    return {
        valid: true,
        verifiedFiles: verified,
        expectedFiles: manifest.files.length,
        signatureChecked,
        provenance: manifest.files
    };
}
