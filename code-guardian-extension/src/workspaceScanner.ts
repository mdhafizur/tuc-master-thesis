import * as vscode from 'vscode';
import * as path from 'path';
import { analyzeCodeWithLLM, SecurityIssue } from './analyzer';
import { RAGManager } from './ragManager';
import { buildProjectMap, astFindingsByFile, ProjectMap } from './projectMapBuilder';

import { getLogger } from './logger';
/**
 * File scan result with security issues
 */
export interface FileScanResult {
	filePath: string;
	relativePath: string;
	issues: SecurityIssue[];
	linesOfCode: number;
	scanTime: number;
	timestamp: Date;
}

/**
 * Workspace security summary
 */
export interface WorkspaceSummary {
	totalFiles: number;
	scannedFiles: number;
	totalIssues: number;
	criticalIssues: number;
	highIssues: number;
	mediumIssues: number;
	lowIssues: number;
	totalLinesOfCode: number;
	scanDuration: number;
	timestamp: Date;
	fileResults: FileScanResult[];
}

/**
 * Severity classification
 */
export enum IssueSeverity {
	CRITICAL = 'critical',
	HIGH = 'high',
	MEDIUM = 'medium',
	LOW = 'low',
	INFO = 'info'
}

/**
 * Workspace Security Scanner
 *
 * Scans all JavaScript/TypeScript files in workspace for security vulnerabilities
 */
export class WorkspaceScanner {
    private readonly logger = getLogger();
	private abortController: AbortController | null = null;
	private scanInProgress = false;

	constructor(
		private context: vscode.ExtensionContext,
		private ragManager?: RAGManager
	) {}

	/**
	 * Classify issue severity based on keywords
	 */
	private classifySeverity(issue: SecurityIssue): IssueSeverity {
		const message = issue.message.toLowerCase();

		// Critical severity keywords
		if (
			message.includes('remote code execution') ||
			message.includes('sql injection') ||
			message.includes('command injection') ||
			message.includes('arbitrary code') ||
			message.includes('authentication bypass') ||
			message.includes('hardcoded credential') ||
			message.includes('hardcoded secret') ||
			message.includes('critical')
		) {
			return IssueSeverity.CRITICAL;
		}

		// High severity keywords
		if (
			message.includes('xss') ||
			message.includes('cross-site scripting') ||
			message.includes('csrf') ||
			message.includes('path traversal') ||
			message.includes('xxe') ||
			message.includes('insecure deserialization') ||
			message.includes('high')
		) {
			return IssueSeverity.HIGH;
		}

		// Medium severity keywords
		if (
			message.includes('weak') ||
			message.includes('insecure') ||
			message.includes('vulnerable') ||
			message.includes('exposure') ||
			message.includes('medium')
		) {
			return IssueSeverity.MEDIUM;
		}

		// Default to low
		return IssueSeverity.LOW;
	}

	/**
	 * Count lines of code in a file
	 */
	private countLines(content: string): number {
		return content.split('\n').filter(line => {
			const trimmed = line.trim();
			// Exclude empty lines and comments
			return trimmed.length > 0 &&
				   !trimmed.startsWith('//') &&
				   !trimmed.startsWith('/*') &&
				   !trimmed.startsWith('*');
		}).length;
	}

	/**
	 * Get all JavaScript/TypeScript files in workspace
	 */
	private async getWorkspaceFiles(): Promise<vscode.Uri[]> {
		const files: vscode.Uri[] = [];

		// Find all JS/TS files
		const jsFiles = await vscode.workspace.findFiles(
			'**/*.{js,jsx,ts,tsx}',
			'**/node_modules/**'
		);

		files.push(...jsFiles);

		return files;
	}

	/**
	 * Scan a single file for vulnerabilities.
	 *
	 * `astIssuesForFile` (audit mode) is a precomputed list of AST detections
	 * for this file. They are unioned with the LLM findings without re-running
	 * the AST traversal per file.
	 */
	private async scanFile(
		fileUri: vscode.Uri,
		workspaceRoot: string,
		onProgress?: (message: string) => void,
		astIssuesForFile?: SecurityIssue[]
	): Promise<FileScanResult> {
		const startTime = Date.now();

		try {
			// Read file content
			const document = await vscode.workspace.openTextDocument(fileUri);
			const content = document.getText();

			// Skip very large files (>500KB)
			if (content.length > 500000) {
				this.logger.info(`⚠️  Skipping large file: ${fileUri.fsPath}`);
				return {
					filePath: fileUri.fsPath,
					relativePath: path.relative(workspaceRoot, fileUri.fsPath),
					issues: astIssuesForFile ?? [],
					linesOfCode: 0,
					scanTime: Date.now() - startTime,
					timestamp: new Date()
				};
			}

			onProgress?.(`Scanning ${path.basename(fileUri.fsPath)}...`);

			// Analyze with LLM (Stage 1 of audit mode, single stage of inline mode).
			const llmIssues = await analyzeCodeWithLLM(content, undefined, this.ragManager);

			// Audit mode: union AST detections (Stage 0) and LLM findings (Stage 1),
			// deduplicated by (canonical-shape, line). AST findings carry
			// detectionSource='ast' and confidence=1.0.
			const issues = this.mergeIssues(astIssuesForFile ?? [], llmIssues);

			const linesOfCode = this.countLines(content);

			return {
				filePath: fileUri.fsPath,
				relativePath: path.relative(workspaceRoot, fileUri.fsPath),
				issues,
				linesOfCode,
				scanTime: Date.now() - startTime,
				timestamp: new Date()
			};

		} catch (error) {
			this.logger.error(`Error scanning ${fileUri.fsPath}:`, error);
			return {
				filePath: fileUri.fsPath,
				relativePath: path.relative(workspaceRoot, fileUri.fsPath),
				issues: astIssuesForFile ?? [],
				linesOfCode: 0,
				scanTime: Date.now() - startTime,
				timestamp: new Date()
			};
		}
	}

	/**
	 * Deduplicate audit-mode issues by (line, message-shape). When an AST and
	 * an LLM finding overlap on the same line for the same canonical category,
	 * the AST finding wins because it is deterministic; we annotate it as
	 * 'hybrid' to flag that the LLM corroborated.
	 */
	private mergeIssues(astIssues: SecurityIssue[], llmIssues: SecurityIssue[]): SecurityIssue[] {
		if (astIssues.length === 0) {
			return llmIssues;
		}
		const merged: SecurityIssue[] = [...astIssues];
		const astByLine = new Map<number, SecurityIssue>();
		for (const a of astIssues) {
			astByLine.set(a.startLine, a);
		}
		for (const l of llmIssues) {
			// If the LLM flagged the same line, mark the AST entry as 'hybrid'
			// (corroborated). Otherwise add the LLM finding unchanged.
			const overlap = astByLine.get(l.startLine);
			if (overlap) {
				overlap.detectionSource = 'hybrid';
				continue;
			}
			merged.push(l);
		}
		return merged;
	}

	/**
	 * Scan entire workspace for security issues
	 */
	async scanWorkspace(
		onProgress?: (current: number, total: number, message: string) => void
	): Promise<WorkspaceSummary | null> {
		if (this.scanInProgress) {
			vscode.window.showWarningMessage('Workspace scan already in progress');
			return null;
		}

		const workspaceFolders = vscode.workspace.workspaceFolders;
		if (!workspaceFolders || workspaceFolders.length === 0) {
			vscode.window.showErrorMessage('No workspace folder open');
			return null;
		}

		this.scanInProgress = true;
		this.abortController = new AbortController();
		const workspaceRoot = workspaceFolders[0].uri.fsPath;
		const startTime = Date.now();

		try {
			// Get all files to scan
			const files = await this.getWorkspaceFiles();

			if (files.length === 0) {
				vscode.window.showInformationMessage('No JavaScript/TypeScript files found');
				return null;
			}

			// Audit mode (Stage 0): build the deterministic AST project map once
			// per scan. This is fast (microseconds per file) and produces sink
			// detections that ground the LLM analysis (Stage 1) per file. The
			// audit mode is on by default; users can disable it via the
			// `codeGuardian.enableAuditMode` setting if they want LLM-only.
			const auditEnabled = vscode.workspace
				.getConfiguration('codeGuardian')
				.get<boolean>('enableAuditMode', true);
			let astByFile: Map<string, SecurityIssue[]> = new Map();
			let auditMap: ProjectMap | null = null;
			if (auditEnabled) {
				try {
					const mapStart = Date.now();
					auditMap = buildProjectMap(workspaceRoot);
					astByFile = astFindingsByFile(auditMap);
					const total = [...astByFile.values()].reduce((s, l) => s + l.length, 0);
					this.logger.info(
						`Audit mode: project map built in ${Date.now() - mapStart}ms; ` +
						`${auditMap.fileCount} files, ${total} AST detections.`
					);
					onProgress?.(0, files.length, `Audit map built (${total} AST detections); starting LLM analysis…`);
				} catch (e) {
					this.logger.warn(`Audit-mode project map failed; falling back to LLM-only: ${(e as Error).message}`);
				}
			}

			onProgress?.(0, files.length, 'Starting workspace scan...');

			// Scan files concurrently in batches
			const CONCURRENCY = 3;
			const fileResults: FileScanResult[] = [];
			let scannedCount = 0;

			for (let i = 0; i < files.length; i += CONCURRENCY) {
				// Check if scan was aborted
				if (this.abortController.signal.aborted) {
					this.logger.info('Workspace scan aborted');
					break;
				}

				const batch = files.slice(i, i + CONCURRENCY);
				const batchResults = await Promise.all(
					batch.map(file =>
						this.scanFile(
							file,
							workspaceRoot,
							(msg) => onProgress?.(scannedCount, files.length, msg),
							astByFile.get(file.fsPath)
						)
					)
				);

				fileResults.push(...batchResults);
				scannedCount += batchResults.length;

				onProgress?.(
					scannedCount,
					files.length,
					`Scanned ${scannedCount}/${files.length} files`
				);
			}

			// Calculate summary statistics
			const totalIssues = fileResults.reduce((sum, r) => sum + r.issues.length, 0);
			const totalLinesOfCode = fileResults.reduce((sum, r) => sum + r.linesOfCode, 0);

			// Classify issues by severity
			let criticalIssues = 0;
			let highIssues = 0;
			let mediumIssues = 0;
			let lowIssues = 0;

			fileResults.forEach(result => {
				result.issues.forEach(issue => {
					const severity = this.classifySeverity(issue);
					switch (severity) {
						case IssueSeverity.CRITICAL:
							criticalIssues++;
							break;
						case IssueSeverity.HIGH:
							highIssues++;
							break;
						case IssueSeverity.MEDIUM:
							mediumIssues++;
							break;
						case IssueSeverity.LOW:
							lowIssues++;
							break;
					}
				});
			});

			const summary: WorkspaceSummary = {
				totalFiles: files.length,
				scannedFiles: scannedCount,
				totalIssues,
				criticalIssues,
				highIssues,
				mediumIssues,
				lowIssues,
				totalLinesOfCode,
				scanDuration: Date.now() - startTime,
				timestamp: new Date(),
				fileResults
			};

			return summary;

		} finally {
			this.scanInProgress = false;
			this.abortController = null;
		}
	}

	/**
	 * Abort ongoing scan
	 */
	abortScan(): void {
		if (this.abortController) {
			this.abortController.abort();
		}
	}

	/**
	 * Check if scan is in progress
	 */
	isScanning(): boolean {
		return this.scanInProgress;
	}

	/**
	 * Calculate security score (0-100)
	 * Higher is better
	 */
	calculateSecurityScore(summary: WorkspaceSummary): number {
		if (summary.totalLinesOfCode === 0) {
			return 100;
		}

		// Calculate issues per 1000 lines of code
		const issuesPerKLOC = (summary.totalIssues / summary.totalLinesOfCode) * 1000;

		// Weight by severity
		const weightedIssues =
			summary.criticalIssues * 10 +
			summary.highIssues * 5 +
			summary.mediumIssues * 2 +
			summary.lowIssues * 1;

		const weightedPerKLOC = (weightedIssues / summary.totalLinesOfCode) * 1000;

		// Score calculation (inverse of weighted issues)
		// 0 issues = 100 score
		// More issues = lower score
		const baseScore = Math.max(0, 100 - (weightedPerKLOC * 5));

		// Round to 1 decimal place
		return Math.round(baseScore * 10) / 10;
	}

	/**
	 * Get security grade based on score
	 */
	getSecurityGrade(score: number): string {
		if (score >= 90) {return 'A';}
		if (score >= 80) {return 'B';}
		if (score >= 70) {return 'C';}
		if (score >= 60) {return 'D';}
		return 'F';
	}
}
