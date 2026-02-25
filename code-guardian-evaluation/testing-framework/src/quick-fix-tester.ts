import * as vscode from 'vscode';
import * as assert from 'assert';

/**
 * Quick Fix Testing Module
 * Tests the CodeAction functionality for security fixes
 */
export class QuickFixTester {
    
    /**
     * Test the complete quick fix workflow
     */
    async testQuickFixWorkflow(doc: vscode.TextDocument): Promise<QuickFixTestResult> {
        const result: QuickFixTestResult = {
            diagnosticsFound: 0,
            fixableDiagnostics: 0,
            codeActionsFound: 0,
            fixesApplied: 0,
            success: false,
            details: []
        };

        try {
            // Get diagnostics for the document
            const diagnostics = vscode.languages.getDiagnostics(doc.uri);
            result.diagnosticsFound = diagnostics.length;
            result.details.push(`Found ${diagnostics.length} diagnostics`);

            if (diagnostics.length === 0) {
                result.details.push('No diagnostics found - analysis may not have completed');
                return result;
            }

            // Look for diagnostics with suggested fixes
            const fixableDiagnostics = diagnostics.filter(diag => 
                diag.code === 'codeSecurity.fixSuggestion' &&
                diag.relatedInformation && 
                diag.relatedInformation.length > 0
            );
            
            result.fixableDiagnostics = fixableDiagnostics.length;
            result.details.push(`Found ${fixableDiagnostics.length} diagnostics with suggested fixes`);

            if (fixableDiagnostics.length === 0) {
                result.details.push('No fixable diagnostics found');
                return result;
            }

            // Test each fixable diagnostic
            for (const diagnostic of fixableDiagnostics) {
                const fixResult = await this.testSingleQuickFix(doc, diagnostic);
                result.codeActionsFound += fixResult.codeActionsFound;
                result.fixesApplied += fixResult.fixesApplied;
                result.details.push(...fixResult.details);
            }

            result.success = result.fixesApplied > 0;
            return result;

        } catch (error) {
            result.details.push(`Error during quick fix testing: ${error}`);
            return result;
        }
    }

    /**
     * Test a single diagnostic's quick fix
     */
    private async testSingleQuickFix(
        doc: vscode.TextDocument, 
        diagnostic: vscode.Diagnostic
    ): Promise<SingleFixTestResult> {
        const result: SingleFixTestResult = {
            codeActionsFound: 0,
            fixesApplied: 0,
            details: []
        };

        const range = diagnostic.range;
        result.details.push(`Testing fix for: ${diagnostic.message}`);
        
        if (diagnostic.relatedInformation?.[0]?.message) {
            result.details.push(`Suggested fix: ${diagnostic.relatedInformation[0].message.substring(0, 100)}...`);
        }

        try {
            // Get available code actions for this range
            const codeActions = await vscode.commands.executeCommand<vscode.CodeAction[]>(
                'vscode.executeCodeActionProvider',
                doc.uri,
                range,
                vscode.CodeActionKind.QuickFix.value
            );

            result.codeActionsFound = codeActions?.length || 0;
            result.details.push(`Found ${result.codeActionsFound} code actions`);

            if (!codeActions || codeActions.length === 0) {
                result.details.push('No code actions available');
                return result;
            }

            // Look for our security fix action
            const securityFixAction = codeActions.find(action => 
                action.title?.includes('Apply Secure Fix') ||
                action.title?.includes('💡') ||
                action.kind?.value === vscode.CodeActionKind.QuickFix.value
            );

            if (!securityFixAction) {
                result.details.push('No security fix CodeAction found');
                result.details.push(`Available actions: ${codeActions.map(a => a.title).join(', ')}`);
                return result;
            }

            result.details.push(`Security fix action found: ${securityFixAction.title}`);

            // Test applying the fix
            if (securityFixAction.edit) {
                const originalText = doc.getText(range);
                result.details.push(`Original code: ${originalText.trim()}`);

                const success = await vscode.workspace.applyEdit(securityFixAction.edit);

                if (success) {
                    const fixedText = doc.getText(range);
                    result.details.push(`Fixed code: ${fixedText.trim()}`);
                    result.details.push('Quick fix applied successfully');
                    result.fixesApplied = 1;

                    // Verify the code actually changed
                    if (originalText !== fixedText) {
                        result.details.push('Code was successfully modified');
                    } else {
                        result.details.push('Warning: Code did not change after applying fix');
                    }
                } else {
                    result.details.push('Failed to apply quick fix');
                }
            } else {
                result.details.push('CodeAction has no edit property');
            }

        } catch (error) {
            result.details.push(`Error testing single fix: ${error}`);
        }

        return result;
    }

    /**
     * Create a test case specifically designed to trigger quick fixes
     */
    createQuickFixTestCode(): string {
        return `
// SQL Injection - should trigger a quick fix suggestion
function getUserById(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return database.query(query);
}

// XSS Vulnerability - should trigger a quick fix suggestion  
function displayUserContent(userContent) {
    document.getElementById('content').innerHTML = userContent;
}

// Code Injection - should trigger a quick fix suggestion
function executeUserCode(userCode) {
    return eval(userCode);
}`;
    }

    /**
     * Validate that the LLM provides suggested fixes
     */
    validateDiagnosticStructure(diagnostics: vscode.Diagnostic[]): DiagnosticValidationResult {
        const result: DiagnosticValidationResult = {
            totalDiagnostics: diagnostics.length,
            diagnosticsWithFixes: 0,
            diagnosticsWithProperStructure: 0,
            issues: []
        };

        for (const diag of diagnostics) {
            if (diag.source !== 'codeSecurity') {
                result.issues.push(`Diagnostic missing codeSecurity source: ${diag.message}`);
                continue;
            }

            if (diag.relatedInformation && diag.relatedInformation.length > 0) {
                result.diagnosticsWithFixes++;
                
                if (diag.code === 'codeSecurity.fixSuggestion') {
                    result.diagnosticsWithProperStructure++;
                } else {
                    result.issues.push(`Diagnostic has fix but wrong code: ${diag.code} (should be 'codeSecurity.fixSuggestion')`);
                }
            }
        }

        return result;
    }
}

/**
 * Interfaces for test results
 */
export interface QuickFixTestResult {
    diagnosticsFound: number;
    fixableDiagnostics: number;
    codeActionsFound: number;
    fixesApplied: number;
    success: boolean;
    details: string[];
}

export interface SingleFixTestResult {
    codeActionsFound: number;
    fixesApplied: number;
    details: string[];
}

export interface DiagnosticValidationResult {
    totalDiagnostics: number;
    diagnosticsWithFixes: number;
    diagnosticsWithProperStructure: number;
    issues: string[];
}
