import * as vscode from 'vscode';
import { URL } from 'url';

/**
 * Phase A1 — Zero-egress policy enforcement.
 *
 * The thesis task description mandates a "strict zero-egress policy to ensure that
 * source code and intermediate data remain confidential" and threat-model mitigations
 * including "network isolation". This module is the single chokepoint every outbound
 * caller must consult before opening a socket.
 *
 * Allowlist: loopback only (Ollama default host).
 * External fetches (NVD/OWASP/CWE refresh) are gated behind the
 * `codeGuardian.enableExternalDataFetch` setting; default false.
 */

const LOOPBACK_HOSTS: ReadonlySet<string> = new Set([
    'localhost',
    '127.0.0.1',
    '::1',
    '0.0.0.0'
]);

export class EgressBlockedError extends Error {
    public readonly host: string;
    public readonly url: string;
    constructor(host: string, url: string) {
        super(`EGRESS_BLOCKED: outbound network call to '${host}' violates the zero-egress policy. URL: ${url}`);
        this.name = 'EgressBlockedError';
        this.host = host;
        this.url = url;
    }
}

export function isLoopback(hostname: string): boolean {
    return LOOPBACK_HOSTS.has(hostname.toLowerCase());
}

/**
 * Returns true if the user has explicitly opted into external CWE/CVE/OWASP refresh.
 * Defaults to false to preserve the zero-egress posture out of the box.
 */
export function isExternalFetchEnabled(): boolean {
    try {
        const config = vscode.workspace.getConfiguration('codeGuardian');
        return config.get<boolean>('enableExternalDataFetch', false);
    } catch {
        // Outside a VS Code host (e.g., harness, unit tests): default to disallowed.
        return false;
    }
}

/**
 * Throws EgressBlockedError if the URL is not on the allowlist.
 * Loopback is always allowed (Ollama). External hosts are allowed only when the
 * user opts in via `codeGuardian.enableExternalDataFetch`.
 */
export function assertEgressAllowed(rawUrl: string): void {
    let parsed: URL;
    try {
        parsed = new URL(rawUrl);
    } catch {
        throw new EgressBlockedError('<invalid-url>', rawUrl);
    }
    if (isLoopback(parsed.hostname)) {
        return;
    }
    if (isExternalFetchEnabled()) {
        return;
    }
    throw new EgressBlockedError(parsed.hostname, rawUrl);
}
