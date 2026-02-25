import * as vscode from 'vscode';
import { WorkspaceSummary, FileScanResult } from './workspaceScanner';

/**
 * Generate HTML content for workspace security dashboard
 */
export function getDashboardHTML(
	panel: vscode.WebviewPanel,
	context: vscode.ExtensionContext,
	summary: WorkspaceSummary,
	securityScore: number,
	securityGrade: string
): string {
	const nonce = getNonce();

	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
	<title>Workspace Security Dashboard</title>
	<style>
		* {
			box-sizing: border-box;
			margin: 0;
			padding: 0;
		}

		body {
			font-family: var(--vscode-font-family);
			color: var(--vscode-foreground);
			background-color: var(--vscode-editor-background);
			padding: 20px;
			line-height: 1.6;
		}

		.header {
			display: flex;
			justify-content: space-between;
			align-items: center;
			margin-bottom: 30px;
			padding-bottom: 20px;
			border-bottom: 2px solid var(--vscode-panel-border);
		}

		.header h1 {
			font-size: 28px;
			font-weight: 600;
		}

		.score-card {
			text-align: center;
			padding: 20px;
			background: var(--vscode-editor-selectionBackground);
			border-radius: 8px;
			min-width: 150px;
		}

		.score-value {
			font-size: 48px;
			font-weight: bold;
			margin: 10px 0;
		}

		.grade-a { color: #4caf50; }
		.grade-b { color: #8bc34a; }
		.grade-c { color: #ffc107; }
		.grade-d { color: #ff9800; }
		.grade-f { color: #f44336; }

		.score-label {
			font-size: 14px;
			opacity: 0.8;
		}

		.metrics-grid {
			display: grid;
			grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
			gap: 20px;
			margin-bottom: 30px;
		}

		.metric-card {
			background: var(--vscode-editor-selectionBackground);
			padding: 20px;
			border-radius: 8px;
			border-left: 4px solid var(--vscode-textLink-foreground);
		}

		.metric-value {
			font-size: 32px;
			font-weight: bold;
			margin: 10px 0;
		}

		.metric-label {
			font-size: 14px;
			opacity: 0.8;
			text-transform: uppercase;
			letter-spacing: 0.5px;
		}

		.severity-critical { border-left-color: #f44336; }
		.severity-high { border-left-color: #ff9800; }
		.severity-medium { border-left-color: #ffc107; }
		.severity-low { border-left-color: #2196f3; }

		.section {
			margin-bottom: 30px;
		}

		.section-title {
			font-size: 20px;
			font-weight: 600;
			margin-bottom: 15px;
			padding-bottom: 10px;
			border-bottom: 1px solid var(--vscode-panel-border);
		}

		.chart-container {
			background: var(--vscode-editor-selectionBackground);
			padding: 20px;
			border-radius: 8px;
			margin-bottom: 20px;
		}

		.bar-chart {
			display: flex;
			align-items: flex-end;
			height: 200px;
			gap: 10px;
			padding: 10px 0;
		}

		.bar {
			flex: 1;
			background: linear-gradient(to top, var(--vscode-textLink-foreground), transparent);
			border-radius: 4px 4px 0 0;
			position: relative;
			min-height: 10px;
			transition: transform 0.3s ease;
		}

		.bar:hover {
			transform: translateY(-5px);
		}

		.bar-label {
			position: absolute;
			bottom: -25px;
			left: 50%;
			transform: translateX(-50%);
			font-size: 11px;
			white-space: nowrap;
		}

		.bar-value {
			position: absolute;
			top: -25px;
			left: 50%;
			transform: translateX(-50%);
			font-weight: bold;
			font-size: 12px;
		}

		.file-list {
			max-height: 400px;
			overflow-y: auto;
		}

		.file-item {
			background: var(--vscode-editor-selectionBackground);
			padding: 15px;
			border-radius: 6px;
			margin-bottom: 10px;
			cursor: pointer;
			transition: background 0.2s;
		}

		.file-item:hover {
			background: var(--vscode-list-hoverBackground);
		}

		.file-header {
			display: flex;
			justify-content: space-between;
			align-items: center;
			margin-bottom: 8px;
		}

		.file-path {
			font-family: var(--vscode-editor-font-family);
			font-size: 13px;
		}

		.issue-badge {
			padding: 4px 8px;
			border-radius: 12px;
			font-size: 11px;
			font-weight: 600;
		}

		.badge-critical { background: #f44336; color: white; }
		.badge-high { background: #ff9800; color: white; }
		.badge-medium { background: #ffc107; color: black; }
		.badge-low { background: #2196f3; color: white; }
		.badge-none { background: #4caf50; color: white; }

		.file-stats {
			font-size: 12px;
			opacity: 0.7;
		}

		.actions {
			margin-top: 30px;
			display: flex;
			gap: 10px;
		}

		button {
			background: var(--vscode-button-background);
			color: var(--vscode-button-foreground);
			border: none;
			padding: 10px 20px;
			border-radius: 4px;
			cursor: pointer;
			font-size: 14px;
			font-weight: 500;
		}

		button:hover {
			background: var(--vscode-button-hoverBackground);
		}

		.timestamp {
			font-size: 12px;
			opacity: 0.6;
			margin-top: 10px;
		}

		.empty-state {
			text-align: center;
			padding: 60px 20px;
			opacity: 0.7;
		}

		.empty-state h3 {
			margin-bottom: 10px;
		}
	</style>
</head>
<body>
	<div class="header">
		<h1>🔐 Workspace Security Dashboard</h1>
		<div class="score-card">
			<div class="score-label">Security Score</div>
			<div class="score-value grade-${securityGrade.toLowerCase()}">${securityScore}</div>
			<div class="score-label">Grade: ${securityGrade}</div>
		</div>
	</div>

	<div class="metrics-grid">
		<div class="metric-card">
			<div class="metric-label">Total Files</div>
			<div class="metric-value">${summary.scannedFiles}</div>
			<div class="file-stats">${summary.totalLinesOfCode.toLocaleString()} lines of code</div>
		</div>
		<div class="metric-card severity-critical">
			<div class="metric-label">Critical Issues</div>
			<div class="metric-value">${summary.criticalIssues}</div>
		</div>
		<div class="metric-card severity-high">
			<div class="metric-label">High Severity</div>
			<div class="metric-value">${summary.highIssues}</div>
		</div>
		<div class="metric-card severity-medium">
			<div class="metric-label">Medium Severity</div>
			<div class="metric-value">${summary.mediumIssues}</div>
		</div>
		<div class="metric-card severity-low">
			<div class="metric-label">Low Severity</div>
			<div class="metric-value">${summary.lowIssues}</div>
		</div>
		<div class="metric-card">
			<div class="metric-label">Total Issues</div>
			<div class="metric-value">${summary.totalIssues}</div>
			<div class="file-stats">Scan took ${(summary.scanDuration / 1000).toFixed(1)}s</div>
		</div>
	</div>

	<div class="section">
		<div class="section-title">Issues by Severity</div>
		<div class="chart-container">
			<div class="bar-chart">
				<div class="bar" style="height: ${getBarHeight(summary.criticalIssues, summary.totalIssues)}%">
					<div class="bar-value">${summary.criticalIssues}</div>
					<div class="bar-label">Critical</div>
				</div>
				<div class="bar" style="height: ${getBarHeight(summary.highIssues, summary.totalIssues)}%">
					<div class="bar-value">${summary.highIssues}</div>
					<div class="bar-label">High</div>
				</div>
				<div class="bar" style="height: ${getBarHeight(summary.mediumIssues, summary.totalIssues)}%">
					<div class="bar-value">${summary.mediumIssues}</div>
					<div class="bar-label">Medium</div>
				</div>
				<div class="bar" style="height: ${getBarHeight(summary.lowIssues, summary.totalIssues)}%">
					<div class="bar-value">${summary.lowIssues}</div>
					<div class="bar-label">Low</div>
				</div>
			</div>
		</div>
	</div>

	<div class="section">
		<div class="section-title">Files with Issues (${getFilesWithIssues(summary.fileResults)})</div>
		<div class="file-list">
			${generateFileList(summary.fileResults)}
		</div>
	</div>

	<div class="actions">
		<button onclick="rescanWorkspace()">🔄 Rescan Workspace</button>
		<button onclick="exportReport()">📄 Export Report</button>
		<button onclick="viewSettings()">⚙️ Settings</button>
	</div>

	<div class="timestamp">
		Last scanned: ${summary.timestamp.toLocaleString()}
	</div>

	<script nonce="${nonce}">
		const vscode = acquireVsCodeApi();

		function rescanWorkspace() {
			vscode.postMessage({ type: 'rescan' });
		}

		function exportReport() {
			vscode.postMessage({ type: 'export' });
		}

		function viewSettings() {
			vscode.postMessage({ type: 'settings' });
		}

		function openFile(filePath) {
			vscode.postMessage({ type: 'openFile', filePath });
		}
	</script>
</body>
</html>`;
}

function getBarHeight(value: number, total: number): number {
	if (total === 0) {return 0;}
	return Math.max(10, (value / total) * 100);
}

function getFilesWithIssues(files: FileScanResult[]): string {
	const filesWithIssues = files.filter(f => f.issues.length > 0).length;
	return `${filesWithIssues} of ${files.length} files`;
}

function generateFileList(files: FileScanResult[]): string {
	// Sort by number of issues (descending)
	const sortedFiles = [...files].sort((a, b) => b.issues.length - a.issues.length);

	// Only show files with issues or top 20 files
	const filesToShow = sortedFiles.filter(f => f.issues.length > 0).slice(0, 20);

	if (filesToShow.length === 0) {
		return `<div class="empty-state">
			<h3>✅ No security issues found!</h3>
			<p>Your workspace looks secure.</p>
		</div>`;
	}

	return filesToShow.map(file => {
		const badgeClass = file.issues.length === 0 ? 'badge-none' :
						   file.issues.length >= 10 ? 'badge-critical' :
						   file.issues.length >= 5 ? 'badge-high' :
						   file.issues.length >= 2 ? 'badge-medium' : 'badge-low';

		return `
		<div class="file-item" onclick="openFile('${file.filePath}')">
			<div class="file-header">
				<div class="file-path">${file.relativePath}</div>
				<div class="issue-badge ${badgeClass}">
					${file.issues.length} issue${file.issues.length !== 1 ? 's' : ''}
				</div>
			</div>
			<div class="file-stats">
				${file.linesOfCode} lines • Scanned in ${file.scanTime}ms
			</div>
		</div>`;
	}).join('');
}

function getNonce(): string {
	let text = '';
	const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	for (let i = 0; i < 32; i++) {
		text += possible.charAt(Math.floor(Math.random() * possible.length));
	}
	return text;
}
