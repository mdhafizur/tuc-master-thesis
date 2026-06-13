import * as vscode from 'vscode';
import { WorkspaceSummary, FileScanResult } from './workspaceScanner';

/**
 * Generate HTML content for the workspace security dashboard.
 *
 * Theme-aware (uses VS Code CSS variables), with a score-ring gauge, metric
 * cards, a proportional severity-distribution bar, and a clickable file list.
 * Interactivity is wired via addEventListener (inline handlers are blocked by
 * the nonce-based CSP).
 */
export function getDashboardHTML(
	panel: vscode.WebviewPanel,
	context: vscode.ExtensionContext,
	summary: WorkspaceSummary,
	securityScore: number,
	securityGrade: string
): string {
	const nonce = getNonce();
	const grade = securityGrade.toLowerCase();
	const scoreDeg = Math.round(Math.max(0, Math.min(100, securityScore)) * 3.6);
	const filesWithIssues = summary.fileResults.filter(f => f.issues.length > 0).length;

	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
	<title>Workspace Security Dashboard</title>
	<style>
		:root {
			--cg-border: var(--vscode-panel-border, rgba(128,128,128,0.25));
			--cg-surface: var(--vscode-editorWidget-background, rgba(128,128,128,0.08));
			--cg-radius: 12px;
			--sev-critical: var(--vscode-charts-red, #f14c4c);
			--sev-high: var(--vscode-charts-orange, #e8a33d);
			--sev-medium: var(--vscode-charts-yellow, #d7ba7d);
			--sev-low: var(--vscode-charts-blue, #3794ff);
		}
		* { box-sizing: border-box; margin: 0; padding: 0; }
		body {
			font-family: var(--vscode-font-family);
			font-size: var(--vscode-font-size, 13px);
			color: var(--vscode-foreground);
			background: var(--vscode-editor-background);
			line-height: 1.5;
		}
		.wrap { max-width: 1040px; margin: 0 auto; padding: 28px 28px 40px; }

		/* Header */
		.header { display: flex; align-items: center; gap: 14px; margin-bottom: 26px; }
		.header-logo {
			width: 40px; height: 40px; flex: 0 0 40px; border-radius: 10px;
			display: flex; align-items: center; justify-content: center; font-size: 22px;
			background: linear-gradient(135deg, var(--vscode-textLink-foreground, #3794ff), var(--vscode-charts-purple, #b180d7));
		}
		.header-text h1 { font-size: 20px; font-weight: 600; line-height: 1.2; }
		.header-text p { font-size: 0.86em; opacity: 0.65; }

		/* Overview: score ring + summary stats */
		.overview {
			display: grid; grid-template-columns: auto 1fr; gap: 22px; align-items: center;
			background: var(--cg-surface); border: 1px solid var(--cg-border);
			border-radius: var(--cg-radius); padding: 22px 24px; margin-bottom: 22px;
		}
		.ring {
			--deg: ${scoreDeg}deg;
			width: 132px; height: 132px; border-radius: 50%; position: relative;
			background: conic-gradient(var(--grade-color) var(--deg), var(--cg-border) var(--deg) 360deg);
			display: flex; align-items: center; justify-content: center; flex: 0 0 132px;
		}
		.ring::before { content: ''; position: absolute; inset: 11px; border-radius: 50%; background: var(--vscode-editor-background); }
		.ring-inner { position: relative; text-align: center; }
		.ring-score { font-size: 36px; font-weight: 700; line-height: 1; color: var(--grade-color); }
		.ring-max { font-size: 0.7em; opacity: 0.55; }
		.ring-grade { margin-top: 4px; font-size: 0.8em; letter-spacing: 0.5px; opacity: 0.8; }

		.grade-a { --grade-color: var(--vscode-charts-green, #3fb950); }
		.grade-b { --grade-color: #8bc34a; }
		.grade-c { --grade-color: var(--vscode-charts-yellow, #d7ba7d); }
		.grade-d { --grade-color: var(--vscode-charts-orange, #e8a33d); }
		.grade-f { --grade-color: var(--vscode-charts-red, #f14c4c); }

		.summary-stats { display: grid; grid-template-columns: repeat(3, 1fr); gap: 18px 24px; }
		.stat-label { font-size: 0.74em; text-transform: uppercase; letter-spacing: 0.6px; opacity: 0.6; }
		.stat-value { font-size: 1.7em; font-weight: 600; margin-top: 2px; }
		.stat-sub { font-size: 0.78em; opacity: 0.6; }

		/* Severity cards */
		.sev-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 14px; margin-bottom: 22px; }
		.sev-card {
			background: var(--cg-surface); border: 1px solid var(--cg-border);
			border-radius: var(--cg-radius); padding: 16px 18px; border-top: 3px solid var(--sev-color);
		}
		.sev-card .dot { display: inline-block; width: 9px; height: 9px; border-radius: 50%; background: var(--sev-color); margin-right: 7px; }
		.sev-card .label { font-size: 0.82em; opacity: 0.8; }
		.sev-card .count { font-size: 1.9em; font-weight: 700; margin-top: 4px; }
		.sev-card.critical { --sev-color: var(--sev-critical); }
		.sev-card.high { --sev-color: var(--sev-high); }
		.sev-card.medium { --sev-color: var(--sev-medium); }
		.sev-card.low { --sev-color: var(--sev-low); }

		/* Sections */
		.section { margin-bottom: 24px; }
		.section-title { font-size: 0.78em; text-transform: uppercase; letter-spacing: 0.8px; opacity: 0.6; margin-bottom: 12px; }

		/* Distribution bar */
		.dist {
			background: var(--cg-surface); border: 1px solid var(--cg-border);
			border-radius: var(--cg-radius); padding: 18px 20px;
		}
		.dist-bar { display: flex; height: 14px; border-radius: 7px; overflow: hidden; background: var(--cg-border); }
		.dist-seg { height: 100%; }
		.dist-seg.critical { background: var(--sev-critical); }
		.dist-seg.high { background: var(--sev-high); }
		.dist-seg.medium { background: var(--sev-medium); }
		.dist-seg.low { background: var(--sev-low); }
		.legend { display: flex; flex-wrap: wrap; gap: 18px; margin-top: 14px; font-size: 0.84em; }
		.legend-item { display: flex; align-items: center; gap: 7px; }
		.legend-dot { width: 10px; height: 10px; border-radius: 3px; }
		.legend-dot.critical { background: var(--sev-critical); }
		.legend-dot.high { background: var(--sev-high); }
		.legend-dot.medium { background: var(--sev-medium); }
		.legend-dot.low { background: var(--sev-low); }
		.legend-val { font-weight: 600; }
		.legend-name { opacity: 0.7; }

		/* File list */
		.file-list { display: flex; flex-direction: column; gap: 8px; max-height: 460px; overflow-y: auto; }
		.file-item {
			display: flex; align-items: center; justify-content: space-between; gap: 12px;
			background: var(--cg-surface); border: 1px solid var(--cg-border);
			border-left: 3px solid var(--row-color, var(--cg-border));
			border-radius: 8px; padding: 11px 14px; cursor: pointer; transition: background 0.15s, border-color 0.15s;
		}
		.file-item:hover { background: var(--vscode-list-hoverBackground, rgba(128,128,128,0.12)); }
		.file-main { min-width: 0; }
		.file-path { font-family: var(--vscode-editor-font-family, monospace); font-size: 0.9em; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
		.file-stats { font-size: 0.76em; opacity: 0.6; margin-top: 3px; }
		.badge {
			flex: 0 0 auto; padding: 3px 10px; border-radius: 11px; font-size: 0.76em; font-weight: 600;
			background: var(--row-color); color: #fff;
		}
		.file-item.tier-critical { --row-color: var(--sev-critical); }
		.file-item.tier-high { --row-color: var(--sev-high); }
		.file-item.tier-medium { --row-color: var(--sev-medium); }
		.file-item.tier-medium .badge { color: #000; }
		.file-item.tier-low { --row-color: var(--sev-low); }

		.empty-state { text-align: center; padding: 56px 20px; }
		.empty-icon { font-size: 36px; margin-bottom: 8px; }
		.empty-state h3 { margin-bottom: 6px; }
		.empty-state p { opacity: 0.65; }

		/* Actions + footer */
		.actions { display: flex; gap: 10px; margin-top: 26px; }
		button {
			background: var(--vscode-button-background); color: var(--vscode-button-foreground);
			border: none; padding: 9px 16px; border-radius: 7px; cursor: pointer; font: inherit; font-weight: 500;
		}
		button:hover { background: var(--vscode-button-hoverBackground); }
		button.secondary {
			background: var(--vscode-button-secondaryBackground, transparent);
			color: var(--vscode-button-secondaryForeground, var(--vscode-foreground));
			border: 1px solid var(--cg-border);
		}
		button.secondary:hover { background: var(--vscode-button-secondaryHoverBackground, rgba(128,128,128,0.15)); }
		.footer { margin-top: 16px; font-size: 0.78em; opacity: 0.5; }
	</style>
</head>
<body>
	<div class="wrap">
		<div class="header">
			<div class="header-logo">🛡️</div>
			<div class="header-text">
				<h1>Workspace Security Dashboard</h1>
				<p>Static + AI analysis across ${summary.scannedFiles} file${summary.scannedFiles === 1 ? '' : 's'}</p>
			</div>
		</div>

		<div class="overview">
			<div class="ring grade-${grade}">
				<div class="ring-inner">
					<div class="ring-score">${securityScore}<span class="ring-max">/100</span></div>
					<div class="ring-grade">GRADE ${securityGrade}</div>
				</div>
			</div>
			<div class="summary-stats">
				<div>
					<div class="stat-label">Files Scanned</div>
					<div class="stat-value">${summary.scannedFiles}</div>
					<div class="stat-sub">${summary.totalLinesOfCode.toLocaleString()} lines of code</div>
				</div>
				<div>
					<div class="stat-label">Total Issues</div>
					<div class="stat-value">${summary.totalIssues}</div>
					<div class="stat-sub">${filesWithIssues} file${filesWithIssues === 1 ? '' : 's'} affected</div>
				</div>
				<div>
					<div class="stat-label">Scan Time</div>
					<div class="stat-value">${(summary.scanDuration / 1000).toFixed(1)}s</div>
					<div class="stat-sub">last run ${escapeHtml(summary.timestamp.toLocaleTimeString())}</div>
				</div>
			</div>
		</div>

		<div class="sev-grid">
			<div class="sev-card critical"><div class="label"><span class="dot"></span>Critical</div><div class="count">${summary.criticalIssues}</div></div>
			<div class="sev-card high"><div class="label"><span class="dot"></span>High</div><div class="count">${summary.highIssues}</div></div>
			<div class="sev-card medium"><div class="label"><span class="dot"></span>Medium</div><div class="count">${summary.mediumIssues}</div></div>
			<div class="sev-card low"><div class="label"><span class="dot"></span>Low</div><div class="count">${summary.lowIssues}</div></div>
		</div>

		<div class="section">
			<div class="section-title">Severity Distribution</div>
			<div class="dist">
				${generateDistribution(summary)}
			</div>
		</div>

		<div class="section">
			<div class="section-title">Files with Issues — ${filesWithIssues} of ${summary.fileResults.length}</div>
			<div class="file-list">
				${generateFileList(summary.fileResults)}
			</div>
		</div>

		<div class="actions">
			<button id="btn-rescan">🔄 Rescan Workspace</button>
			<button id="btn-export" class="secondary">📄 Export Report</button>
		</div>
		<div class="footer">Last scanned ${escapeHtml(summary.timestamp.toLocaleString())}</div>
	</div>

	<script nonce="${nonce}">
		const vscode = acquireVsCodeApi();
		document.getElementById('btn-rescan').addEventListener('click', () => vscode.postMessage({ type: 'rescan' }));
		document.getElementById('btn-export').addEventListener('click', () => vscode.postMessage({ type: 'export' }));
		document.querySelectorAll('.file-item').forEach((item) => {
			item.addEventListener('click', () => {
				const filePath = item.getAttribute('data-filepath');
				if (filePath) { vscode.postMessage({ type: 'openFile', filePath }); }
			});
		});
	</script>
</body>
</html>`;
}

/** Builds the proportional stacked severity bar plus a value legend. */
function generateDistribution(summary: WorkspaceSummary): string {
	const total = summary.totalIssues;
	if (total === 0) {
		return '<p style="opacity:0.65">No issues detected — nothing to distribute. 🎉</p>';
	}
	const pct = (n: number) => (n / total) * 100;
	const seg = (cls: string, n: number) =>
		n > 0 ? `<div class="dist-seg ${cls}" style="width:${pct(n).toFixed(2)}%" title="${cls}: ${n}"></div>` : '';
	const legendItem = (cls: string, name: string, n: number) =>
		`<div class="legend-item"><span class="legend-dot ${cls}"></span><span class="legend-val">${n}</span> <span class="legend-name">${name}</span></div>`;
	return `
		<div class="dist-bar">
			${seg('critical', summary.criticalIssues)}
			${seg('high', summary.highIssues)}
			${seg('medium', summary.mediumIssues)}
			${seg('low', summary.lowIssues)}
		</div>
		<div class="legend">
			${legendItem('critical', 'Critical', summary.criticalIssues)}
			${legendItem('high', 'High', summary.highIssues)}
			${legendItem('medium', 'Medium', summary.mediumIssues)}
			${legendItem('low', 'Low', summary.lowIssues)}
		</div>`;
}

function generateFileList(files: FileScanResult[]): string {
	// Sort by number of issues (descending), keep the top 20 with issues.
	const filesToShow = [...files]
		.filter(f => f.issues.length > 0)
		.sort((a, b) => b.issues.length - a.issues.length)
		.slice(0, 20);

	if (filesToShow.length === 0) {
		return `<div class="empty-state">
			<div class="empty-icon">✅</div>
			<h3>No security issues found</h3>
			<p>Your workspace looks secure.</p>
		</div>`;
	}

	return filesToShow.map(file => {
		const n = file.issues.length;
		const tier = n >= 10 ? 'critical' : n >= 5 ? 'high' : n >= 2 ? 'medium' : 'low';
		return `
		<div class="file-item tier-${tier}" data-filepath="${escapeAttr(file.filePath)}">
			<div class="file-main">
				<div class="file-path">${escapeHtml(file.relativePath)}</div>
				<div class="file-stats">${file.linesOfCode} lines · scanned in ${file.scanTime}ms</div>
			</div>
			<div class="badge">${n} issue${n !== 1 ? 's' : ''}</div>
		</div>`;
	}).join('');
}

/**
 * Escapes text for safe embedding in HTML element content.
 */
function escapeHtml(value: string): string {
	return value
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;');
}

/**
 * Escapes a value for safe embedding inside a double-quoted HTML attribute.
 */
function escapeAttr(value: string): string {
	return escapeHtml(value).replace(/"/g, '&quot;');
}

function getNonce(): string {
	let text = '';
	const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
	for (let i = 0; i < 32; i++) {
		text += possible.charAt(Math.floor(Math.random() * possible.length));
	}
	return text;
}
