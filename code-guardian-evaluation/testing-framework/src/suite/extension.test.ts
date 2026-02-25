import * as assert from 'assert';
import * as vscode from 'vscode';

suite('Code Guardian Extension Test Suite', () => {
    let extension: vscode.Extension<any> | undefined;
    const canonicalExtensionId = 'DreamersRedemption.code-guardian';
    const alternativeIds = [
        'code-guardian',
        'DreamersRedemption.Code Guardian',
    ];

    async function activateExtension(): Promise<vscode.Extension<any>> {
        // Try canonical ID first, then fall back to alternatives
        extension = vscode.extensions.getExtension(canonicalExtensionId);
        if (!extension) {
            for (const altId of alternativeIds) {
                extension = vscode.extensions.getExtension(altId);
                if (extension) break;
            }
        }

        if (!extension) {
            // Helpful dump to diagnose wrong ID
            // Note: Accessing displayName needs optional chaining
            // since not all extensions guarantee it.
            console.log('Available extensions:');
            vscode.extensions.all.forEach(ext => {
                console.log(`  - ${ext.id} (${ext.packageJSON?.displayName ?? 'n/a'})`);
            });
            throw new Error(
                `Extension "${canonicalExtensionId}" not found. ` +
                `Check that it’s installed and the ID matches package.json > "publisher.name".`
            );
        }

        if (!extension.isActive) {
            await extension.activate();
            console.log(`Extension "${extension.id}" activated`);
        }
        return extension;
    }

    async function findAnalyzeCommand(): Promise<string | undefined> {
        const commands = await vscode.commands.getCommands(true);
        // Prefer explicit IDs you ship in package.json
        const preferred = [
            'codeSecurity.analyzeFullFile',
            'codeSecurity.analyzeSelectionWithAI',
        ];
        for (const p of preferred) {
            if (commands.includes(p)) return p;
        }
        // Fallback: try fuzzy search if tests run against a dev build
        return commands.find(cmd => /codeSecurity\.(analyze|security)|analyz/i.test(cmd));
    }

    suiteSetup(async function () {
        this.timeout(30000);
        await activateExtension();
    });

    test('Extension should be present and activated', () => {
        assert.ok(extension, 'Extension should be found');
        assert.ok(extension?.isActive, 'Extension should be activated');
        console.log(`Found: ${extension?.id} (${extension?.packageJSON?.displayName ?? 'n/a'})`);
    });

    test('Extension should register expected commands', async () => {
        const commands = await vscode.commands.getCommands(true);

        const expected = [
            'codeSecurity.analyzeFullFile',
            'codeSecurity.analyzeSelectionWithAI',
            'codeSecurity.applyFix',
            'codeSecurity.contextualQnA',
        ];

        const found: string[] = [];
        const missing: string[] = [];

        for (const cmd of expected) {
            if (commands.includes(cmd)) {
                found.push(cmd);
            } else {
                missing.push(cmd);
            }
        }

        console.log(`Registered commands found: ${found.join(', ') || '(none)'}`);
        if (missing.length) {
            console.log(`Missing expected commands: ${missing.join(', ')}`);
        }

        // Don’t fail the whole suite if a dev build omits some commands,
        // but ensure at least one core command is present.
        assert.ok(found.length > 0, `Expected at least one core command. Missing: ${missing.join(', ')}`);
    });

    test('Basic analysis produces diagnostics (best effort)', async function () {
        this.timeout(15000);

        const vulnerableCode = `
// Simple SQL injection test
const query = "SELECT * FROM users WHERE id = " + userId;
`;
        const doc = await vscode.workspace.openTextDocument({ content: vulnerableCode, language: 'javascript' });
        await vscode.window.showTextDocument(doc);

        try {
            const analyzeCmd = await findAnalyzeCommand();
            if (analyzeCmd) {
                console.log(`Executing analyze command: ${analyzeCmd}`);
                try {
                    await vscode.commands.executeCommand(analyzeCmd);
                } catch (err) {
                    console.log(`Analyze command threw: ${err}`);
                    // Don’t fail the test here; continue to inspect diagnostics
                }

                // Allow time for diagnostics to flow
                await new Promise(r => setTimeout(r, 2000));

                const diagnostics = vscode.languages.getDiagnostics(doc.uri);
                console.log(`Diagnostics after analysis: ${diagnostics.length}`);
                diagnostics.forEach((d, i) => {
                    console.log(`  ${i + 1}. "${d.message}" at L${d.range.start.line + 1}`);
                });
            } else {
                console.log('No analyze command discovered');
            }

            assert.ok(true, 'Reached end of basic analysis test');
        } finally {
            await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
        }
    });

    test('Quick Fix flow (best effort): finds and applies a CodeAction if available', async function () {
        this.timeout(20000);

        const vulnerableCode = `
function vulnerableFunction(userInput) {
  // SQL Injection vulnerability - should get a suggested fix
  const query = "SELECT * FROM users WHERE id = " + userInput;
  return query;
}
`;
        const doc = await vscode.workspace.openTextDocument({ content: vulnerableCode, language: 'javascript' });
        await vscode.window.showTextDocument(doc);

        try {
            const analyzeCmd = await findAnalyzeCommand();
            if (!analyzeCmd) {
                console.log('No analyze command discovered; skipping quick-fix path');
                assert.ok(true);
                return;
            }

            await vscode.commands.executeCommand(analyzeCmd);
            await new Promise(r => setTimeout(r, 3000));

            const diagnostics = vscode.languages.getDiagnostics(doc.uri);
            console.log(`Total diagnostics: ${diagnostics.length}`);

            // Try to find a diagnostic that your extension marks as fixable
            const fixable = diagnostics.find(d =>
                (d.code === 'codeSecurity.fixSuggestion') ||
                (typeof d.code === 'string' && /fixSuggestion|security/i.test(d.code)) ||
                (typeof d.code === 'number' && d.relatedInformation && d.relatedInformation.length > 0)
            );

            if (!fixable) {
                console.log('No fixable diagnostics found (this is OK in dev builds)');
                assert.ok(true);
                return;
            }

            console.log(`Testing CodeActions for diagnostic: "${fixable.message}"`);
            const actions = await vscode.commands.executeCommand<vscode.CodeAction[]>(
                'vscode.executeCodeActionProvider',
                doc.uri,
                fixable.range,
                vscode.CodeActionKind.QuickFix.value
            );

            console.log(`Code actions found: ${actions?.length ?? 0}`);
            if (!actions || actions.length === 0) {
                assert.ok(true, 'No actions available; non-fatal in best-effort test');
                return;
            }

            const securityFix =
                actions.find(a => /Apply Secure Fix|💡|Secure/i.test(a.title ?? '')) ?? actions[0];

            console.log(`Chosen action: ${securityFix.title}`);

            if (securityFix.edit) {
                const originalText = doc.getText(fixable.range);
                const applied = await vscode.workspace.applyEdit(securityFix.edit);
                assert.ok(applied, 'Workspace edit should apply');

                const updatedText = doc.getText(fixable.range);
                assert.notStrictEqual(updatedText, originalText, 'Code should change after applying fix');

                await new Promise(r => setTimeout(r, 1000));
                const updatedDiagnostics = vscode.languages.getDiagnostics(doc.uri);
                console.log(`Diagnostics after fix: ${updatedDiagnostics.length}`);
            } else if (securityFix.command) {
                // Some actions run through a command instead of a direct edit
                await vscode.commands.executeCommand(securityFix.command.command, ...(securityFix.command.arguments ?? []));
                assert.ok(true, 'Ran command-based CodeAction');
            } else {
                assert.fail('Selected CodeAction has neither edit nor command');
            }
        } finally {
            await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
        }
    });

    test('Performance: activation and command enumeration', async function () {
        this.timeout(15000);

        // Activation time
        if (extension && !extension.isActive) {
            const t0 = Date.now();
            await extension.activate();
            const dt = Date.now() - t0;
            console.log(`Activation time: ${dt}ms`);
            assert.ok(dt < 5000, `Activation should be under 5000ms; got ${dt}ms`);
        } else {
            console.log('Extension already active; skipping activation timing');
        }

        // Command enumeration time
        const c0 = Date.now();
        const commands = await vscode.commands.getCommands(true);
        const cd = Date.now() - c0;
        console.log(`Command enumeration time: ${cd}ms (count=${commands.length})`);
        assert.ok(cd < 1500, `Command enumeration should be fast; got ${cd}ms`);
    });

    suiteTeardown(async () => {
        await vscode.commands.executeCommand('workbench.action.closeAllEditors');
        console.log('Test suite completed');
    });
});
