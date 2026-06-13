import { SecurityKnowledge } from './ragManager';

export interface KnowledgeViewOptions {
	heading?: string;
	icon?: string;
	noun?: string;   // "entries" | "results"
	note?: string;   // e.g. for "xss"
}

/**
 * Renders a list of security-knowledge entries as a scrollable, searchable
 * webview — replacing the old modal dumps that could not scroll and truncated.
 * Used for both the full knowledge base and search results. Theme-aware;
 * client-side search filters entries live. CSP uses a nonce.
 */
export function getKnowledgeBaseHTML(knowledge: SecurityKnowledge[], opts: KnowledgeViewOptions = {}): string {
	const nonce = getNonce();
	const heading = opts.heading ?? 'RAG Knowledge Base';
	const icon = opts.icon ?? '🧠';
	const noun = opts.noun ?? 'entries';
	const note = opts.note ? ` ${escapeHtml(opts.note)}` : '';

	const counts = { high: 0, medium: 0, low: 0 };
	for (const k of knowledge) {
		if (k.severity === 'high') { counts.high++; }
		else if (k.severity === 'medium') { counts.medium++; }
		else { counts.low++; }
	}

	const cards = knowledge.map(buildCard).join('\n');

	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
	<title>RAG Knowledge Base</title>
	<style>
		:root {
			--cg-border: var(--vscode-panel-border, rgba(128,128,128,0.25));
			--cg-surface: var(--vscode-editorWidget-background, rgba(128,128,128,0.08));
			--sev-high: var(--vscode-charts-red, #f14c4c);
			--sev-medium: var(--vscode-charts-yellow, #d7ba7d);
			--sev-low: var(--vscode-charts-blue, #3794ff);
		}
		* { box-sizing: border-box; margin: 0; padding: 0; }
		html, body { height: 100%; }
		body {
			font-family: var(--vscode-font-family);
			font-size: var(--vscode-font-size, 13px);
			color: var(--vscode-foreground);
			background: var(--vscode-editor-background);
			display: flex; flex-direction: column; height: 100vh;
		}

		/* Sticky header with search + stats */
		.kb-header {
			flex: 0 0 auto; padding: 16px 20px 12px;
			border-bottom: 1px solid var(--cg-border);
			background: var(--vscode-editor-background);
		}
		.kb-title { display: flex; align-items: center; gap: 10px; margin-bottom: 12px; }
		.kb-logo {
			width: 34px; height: 34px; border-radius: 8px; flex: 0 0 34px;
			display: flex; align-items: center; justify-content: center; font-size: 18px;
			background: linear-gradient(135deg, var(--vscode-textLink-foreground, #3794ff), var(--vscode-charts-purple, #b180d7));
		}
		.kb-title h1 { font-size: 17px; font-weight: 600; line-height: 1.1; }
		.kb-title .sub { font-size: 0.82em; opacity: 0.65; }
		.kb-controls { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
		.kb-search {
			flex: 1; min-width: 180px;
			background: var(--vscode-input-background); color: var(--vscode-input-foreground);
			border: 1px solid var(--vscode-input-border, var(--cg-border));
			border-radius: 7px; padding: 8px 12px; font: inherit;
		}
		.kb-search:focus { outline: none; border-color: var(--vscode-focusBorder); }
		.kb-stats { display: flex; gap: 8px; font-size: 0.8em; }
		.pill {
			display: inline-flex; align-items: center; gap: 6px;
			padding: 3px 10px; border-radius: 12px; background: var(--cg-surface); border: 1px solid var(--cg-border);
		}
		.pill .dot { width: 8px; height: 8px; border-radius: 50%; }
		.dot.high { background: var(--sev-high); }
		.dot.medium { background: var(--sev-medium); }
		.dot.low { background: var(--sev-low); }

		/* Scrollable list */
		.kb-list { flex: 1 1 auto; overflow-y: auto; padding: 16px 20px; }
		.kb-card {
			background: var(--cg-surface); border: 1px solid var(--cg-border);
			border-left: 3px solid var(--sev-color, var(--cg-border));
			border-radius: 10px; padding: 14px 16px; margin-bottom: 12px;
		}
		.kb-card.sev-high { --sev-color: var(--sev-high); }
		.kb-card.sev-medium { --sev-color: var(--sev-medium); }
		.kb-card.sev-low { --sev-color: var(--sev-low); }
		.kb-card-head { display: flex; align-items: flex-start; justify-content: space-between; gap: 12px; }
		.kb-card-title { font-weight: 600; font-size: 1.02em; }
		.kb-sev {
			flex: 0 0 auto; font-size: 0.72em; text-transform: uppercase; letter-spacing: 0.5px;
			padding: 2px 9px; border-radius: 10px; color: #fff; background: var(--sev-color);
		}
		.kb-card.sev-medium .kb-sev { color: #000; }
		.kb-meta { display: flex; flex-wrap: wrap; gap: 6px; margin: 8px 0; }
		.tag {
			font-size: 0.74em; padding: 2px 8px; border-radius: 10px;
			background: var(--vscode-badge-background, rgba(128,128,128,0.2));
			color: var(--vscode-badge-foreground, inherit);
		}
		.tag.id { font-family: var(--vscode-editor-font-family, monospace); border: 1px solid var(--cg-border); background: transparent; }
		.kb-content {
			font-size: 0.9em; line-height: 1.5; opacity: 0.9; white-space: pre-wrap;
			max-height: 150px; overflow: hidden; position: relative; margin-top: 6px;
		}
		.kb-content.expanded { max-height: none; }
		.kb-toggle {
			margin-top: 6px; background: transparent; border: none; cursor: pointer;
			color: var(--vscode-textLink-foreground); font: inherit; font-size: 0.84em; padding: 0;
		}
		.kb-empty { text-align: center; padding: 60px 20px; opacity: 0.65; }
		#noResults { display: none; }
	</style>
</head>
<body>
	<div class="kb-header">
		<div class="kb-title">
			<div class="kb-logo">${icon}</div>
			<div>
				<h1>${escapeHtml(heading)}</h1>
				<div class="sub"><span id="visibleCount">${knowledge.length}</span> of ${knowledge.length} ${escapeHtml(noun)}${note}</div>
			</div>
		</div>
		<div class="kb-controls">
			<input id="search" class="kb-search" type="text" placeholder="🔎 Filter by title, category, CWE, tag…" />
			<div class="kb-stats">
				<span class="pill"><span class="dot high"></span>${counts.high} High</span>
				<span class="pill"><span class="dot medium"></span>${counts.medium} Medium</span>
				<span class="pill"><span class="dot low"></span>${counts.low} Low</span>
			</div>
		</div>
	</div>

	<div class="kb-list" id="list">
		${cards || '<div class="kb-empty"><h3>No knowledge entries</h3><p>The knowledge base is empty.</p></div>'}
		<div class="kb-empty" id="noResults"><h3>No matching entries</h3><p>Try a different search term.</p></div>
	</div>

	<script nonce="${nonce}">
		const search = document.getElementById('search');
		const cards = Array.prototype.slice.call(document.querySelectorAll('.kb-card'));
		const visibleCount = document.getElementById('visibleCount');
		const noResults = document.getElementById('noResults');

		search.addEventListener('input', () => {
			const q = search.value.trim().toLowerCase();
			let shown = 0;
			cards.forEach((card) => {
				const hit = !q || (card.getAttribute('data-search') || '').indexOf(q) !== -1;
				card.style.display = hit ? '' : 'none';
				if (hit) { shown++; }
			});
			visibleCount.textContent = shown;
			noResults.style.display = (shown === 0 && cards.length > 0) ? 'block' : 'none';
		});

		// Expand/collapse long content.
		document.querySelectorAll('.kb-toggle').forEach((btn) => {
			btn.addEventListener('click', () => {
				const content = btn.previousElementSibling;
				const expanded = content.classList.toggle('expanded');
				btn.textContent = expanded ? 'Show less' : 'Show more';
			});
		});
	</script>
</body>
</html>`;
}

function buildCard(k: SecurityKnowledge): string {
	const sev = k.severity === 'high' || k.severity === 'medium' || k.severity === 'low' ? k.severity : 'low';
	const tags = (k.tags || []).map(t => `<span class="tag">${escapeHtml(t)}</span>`).join('');
	const cwe = k.cwe ? `<span class="tag">${escapeHtml(k.cwe)}</span>` : '';
	const owasp = k.owasp ? `<span class="tag">${escapeHtml(k.owasp)}</span>` : '';
	const source = k.source ? `<span class="tag">src: ${escapeHtml(k.source)}</span>` : '';
	const content = (k.content || '').trim();
	const needsToggle = content.length > 320;

	// Lowercased haystack for client-side filtering.
	const haystack = [k.title, k.category, k.cwe, k.owasp, k.source, ...(k.tags || []), content]
		.filter(Boolean).join(' ').toLowerCase();

	return `
	<div class="kb-card sev-${sev}" data-search="${escapeAttr(haystack)}">
		<div class="kb-card-head">
			<div class="kb-card-title">${escapeHtml(k.title)}</div>
			<span class="kb-sev">${sev}</span>
		</div>
		<div class="kb-meta">
			<span class="tag">${escapeHtml(k.category || 'general')}</span>
			${cwe}${owasp}${source}
			<span class="tag id">${escapeHtml(k.id)}</span>
		</div>
		<div class="kb-content">${escapeHtml(content)}</div>
		${needsToggle ? '<button class="kb-toggle">Show more</button>' : ''}
		${tags ? `<div class="kb-meta">${tags}</div>` : ''}
	</div>`;
}

interface CacheEntryInfo { file: string; exists: boolean; age: number; size: number; }
export interface VulnerabilityStats {
	totalKnowledge: number;
	vulnerabilityData: number;
	lastUpdate?: string | Date | null;
	cacheInfo: CacheEntryInfo[];
}

/**
 * Renders vulnerability-data statistics as a professional, scrollable panel
 * (replacing the old modal text dump). Theme-aware; CSP uses a nonce.
 */
export function getVulnerabilityStatsHTML(stats: VulnerabilityStats): string {
	const nonce = getNonce();
	const lastUpdate = stats.lastUpdate ? escapeHtml(String(stats.lastUpdate)) : 'Never';

	const rows = (stats.cacheInfo || []).map(info => {
		const ageHours = info.exists ? Math.round(info.age / (1000 * 60 * 60)) : null;
		const sizeKB = info.exists ? Math.round(info.size / 1024) : 0;
		const status = info.exists
			? `<span class="ok">● cached</span>`
			: `<span class="muted">○ not cached</span>`;
		return `<tr>
			<td class="mono">${escapeHtml(info.file)}</td>
			<td>${status}</td>
			<td>${info.exists ? ageHours + 'h ago' : '—'}</td>
			<td>${info.exists ? sizeKB.toLocaleString() + ' KB' : '—'}</td>
		</tr>`;
	}).join('');

	return `<!DOCTYPE html>
<html lang="en">
<head>
	<meta charset="UTF-8">
	<meta name="viewport" content="width=device-width, initial-scale=1.0">
	<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
	<title>Vulnerability Data Statistics</title>
	<style>
		:root { --cg-border: var(--vscode-panel-border, rgba(128,128,128,0.25)); --cg-surface: var(--vscode-editorWidget-background, rgba(128,128,128,0.08)); }
		* { box-sizing: border-box; margin: 0; padding: 0; }
		body { font-family: var(--vscode-font-family); font-size: var(--vscode-font-size, 13px); color: var(--vscode-foreground); background: var(--vscode-editor-background); }
		.wrap { max-width: 760px; margin: 0 auto; padding: 26px 24px 40px; }
		.head { display: flex; align-items: center; gap: 12px; margin-bottom: 22px; }
		.logo { width: 38px; height: 38px; border-radius: 9px; flex: 0 0 38px; display: flex; align-items: center; justify-content: center; font-size: 20px; background: linear-gradient(135deg, var(--vscode-textLink-foreground, #3794ff), var(--vscode-charts-purple, #b180d7)); }
		.head h1 { font-size: 18px; font-weight: 600; line-height: 1.1; }
		.head .sub { font-size: 0.84em; opacity: 0.65; }
		.cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 14px; margin-bottom: 26px; }
		.card { background: var(--cg-surface); border: 1px solid var(--cg-border); border-radius: 11px; padding: 16px 18px; border-top: 3px solid var(--vscode-textLink-foreground, #3794ff); }
		.card .label { font-size: 0.74em; text-transform: uppercase; letter-spacing: 0.6px; opacity: 0.6; }
		.card .value { font-size: 1.8em; font-weight: 700; margin-top: 4px; }
		.section-title { font-size: 0.78em; text-transform: uppercase; letter-spacing: 0.8px; opacity: 0.6; margin-bottom: 10px; }
		table { width: 100%; border-collapse: collapse; background: var(--cg-surface); border: 1px solid var(--cg-border); border-radius: 11px; overflow: hidden; }
		th, td { text-align: left; padding: 9px 14px; border-bottom: 1px solid var(--cg-border); }
		th { font-size: 0.74em; text-transform: uppercase; letter-spacing: 0.5px; opacity: 0.6; }
		tr:last-child td { border-bottom: none; }
		.mono { font-family: var(--vscode-editor-font-family, monospace); }
		.ok { color: var(--vscode-charts-green, #89d185); }
		.muted { opacity: 0.5; }
	</style>
</head>
<body>
	<div class="wrap">
		<div class="head">
			<div class="logo">📊</div>
			<div>
				<h1>Vulnerability Data Statistics</h1>
				<div class="sub">Last updated: ${lastUpdate}</div>
			</div>
		</div>
		<div class="cards">
			<div class="card"><div class="label">Knowledge Entries</div><div class="value">${stats.totalKnowledge.toLocaleString()}</div></div>
			<div class="card"><div class="label">Vulnerability Data</div><div class="value">${stats.vulnerabilityData.toLocaleString()}</div></div>
			<div class="card"><div class="label">Cache Files</div><div class="value">${(stats.cacheInfo || []).filter(c => c.exists).length}/${(stats.cacheInfo || []).length}</div></div>
		</div>
		<div class="section-title">Cache Status</div>
		<table>
			<thead><tr><th>File</th><th>Status</th><th>Age</th><th>Size</th></tr></thead>
			<tbody>${rows || '<tr><td colspan="4" class="muted">No cache files.</td></tr>'}</tbody>
		</table>
	</div>
</body>
</html>`;
}

function escapeHtml(value: string): string {
	return String(value)
		.replace(/&/g, '&amp;')
		.replace(/</g, '&lt;')
		.replace(/>/g, '&gt;');
}

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
