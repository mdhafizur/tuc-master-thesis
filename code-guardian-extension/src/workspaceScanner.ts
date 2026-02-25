import * as vscode from 'vscode';
import * as path from 'path';
import { analyzeCodeWithLLM, SecurityIssue } from './analyzer';
import { RAGManager } from './ragManager';

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
	 * Scan a single file for vulnerabilities
	 */
	private async scanFile(
		fileUri: vscode.Uri,
		workspaceRoot: string,
		onProgress?: (message: string) => void
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
					issues: [],
					linesOfCode: 0,
					scanTime: Date.now() - startTime,
					timestamp: new Date()
				};
			}

			onProgress?.(`Scanning ${path.basename(fileUri.fsPath)}...`);

			// Analyze with LLM
			const issues = await analyzeCodeWithLLM(content, undefined, this.ragManager);

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
				issues: [],
				linesOfCode: 0,
				scanTime: Date.now() - startTime,
				timestamp: new Date()
			};
		}
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
							(msg) => onProgress?.(scannedCount, files.length, msg)
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
