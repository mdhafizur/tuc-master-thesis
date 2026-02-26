#!/usr/bin/env node

/**
 * Quick Fix Testing Script
 * 
 * Standalone script to test the quick fix functionality of the Code Guardian extension
 * Usage: node quick-fix-test.js
 */

const vscode = require('vscode');
const path = require('path');

// Quick fix test cases
const TEST_CASES = [
    {
        id: 'sql-injection',
        name: 'SQL Injection Fix Test',
        code: `function getUserById(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return database.query(query);
}`,
        expectedFix: 'parameterized query'
    },
    {
        id: 'xss-vulnerability',
        name: 'XSS Vulnerability Fix Test',
        code: `function displayUserContent(userContent) {
    document.getElementById('content').innerHTML = userContent;
}`,
        expectedFix: 'text content or sanitization'
    },
    {
        id: 'code-injection',
        name: 'Code Injection Fix Test',
        code: `function executeUserCode(userCode) {
    return eval(userCode);
}`,
        expectedFix: 'safe parsing alternative'
    }
];

/**
 * Test quick fix functionality for a single test case
 */
async function testQuickFix(testCase) {
    console.log(`\n🔍 Testing: ${testCase.name}`);
    console.log(`Code: ${testCase.code.trim()}`);
    
    try {
        // Create test document
        const doc = await vscode.workspace.openTextDocument({
            content: testCase.code,
            language: 'javascript'
        });

        await vscode.window.showTextDocument(doc);

        // Run security analysis
        console.log('  📊 Running security analysis...');
        await vscode.commands.executeCommand('codeSecurity.analyzeFullFile');
        
        // Wait for analysis to complete
        await new Promise(resolve => setTimeout(resolve, 5000));

        // Get diagnostics
        const diagnostics = vscode.languages.getDiagnostics(doc.uri);
        console.log(`  📋 Found ${diagnostics.length} diagnostics`);

        if (diagnostics.length === 0) {
            console.log('  ❌ No security issues detected');
            return { success: false, reason: 'No diagnostics found' };
        }

        // Look for fixable diagnostics
        const fixableDiagnostics = diagnostics.filter(d => 
            d.relatedInformation && d.relatedInformation.length > 0 &&
            d.code === 'codeSecurity.fixSuggestion'
        );

        console.log(`  🔧 Found ${fixableDiagnostics.length} fixable diagnostics`);

        if (fixableDiagnostics.length === 0) {
            console.log('  ❌ No fixable diagnostics found');
            return { success: false, reason: 'No fixable diagnostics' };
        }

        // Test code actions for each fixable diagnostic
        let totalCodeActions = 0;
        let successfulFixes = 0;

        for (const diagnostic of fixableDiagnostics) {
            console.log(`  🎯 Testing fix for: ${diagnostic.message.substring(0, 50)}...`);
            
            const codeActions = await vscode.commands.executeCommand(
                'vscode.executeCodeActionProvider',
                doc.uri,
                diagnostic.range,
                vscode.CodeActionKind.QuickFix.value
            );

            totalCodeActions += codeActions?.length || 0;
            
            if (codeActions && codeActions.length > 0) {
                console.log(`    💡 Found ${codeActions.length} code actions`);
                
                // Look for security fix action
                const securityAction = codeActions.find(action => 
                    action.title && (
                        action.title.includes('Apply Secure Fix') || 
                        action.title.includes('💡')
                    )
                );

                if (securityAction && securityAction.edit) {
                    console.log(`    ✅ Security action found: ${securityAction.title}`);
                    
                    // Test applying the fix
                    const originalText = doc.getText(diagnostic.range);
                    const success = await vscode.workspace.applyEdit(securityAction.edit);
                    
                    if (success) {
                        const fixedText = doc.getText(diagnostic.range);
                        console.log(`    🔄 Fix applied successfully`);
                        console.log(`    📝 Original: ${originalText.trim()}`);
                        console.log(`    📝 Fixed: ${fixedText.trim()}`);
                        successfulFixes++;
                    } else {
                        console.log(`    ❌ Failed to apply fix`);
                    }
                } else {
                    console.log(`    ❌ No security action found`);
                    console.log(`    Available actions: ${codeActions.map(a => a.title).join(', ')}`);
                }
            } else {
                console.log(`    ❌ No code actions available`);
            }
        }

        // Close test document
        await vscode.commands.executeCommand('workbench.action.closeActiveEditor');

        const success = successfulFixes > 0;
        console.log(`  📊 Results: ${successfulFixes}/${fixableDiagnostics.length} fixes applied successfully`);
        
        return {
            success,
            diagnostics: diagnostics.length,
            fixableDiagnostics: fixableDiagnostics.length,
            codeActions: totalCodeActions,
            successfulFixes,
            reason: success ? 'Quick fixes working correctly' : 'No fixes could be applied'
        };

    } catch (error) {
        console.error(`  💥 Error testing ${testCase.name}:`, error);
        return { success: false, reason: error.message };
    }
}

/**
 * Run all quick fix tests
 */
async function runAllQuickFixTests() {
    console.log('🚀 Starting Quick Fix Test Suite');
    console.log('===================================');
    
    const results = [];
    let successCount = 0;
    
    for (const testCase of TEST_CASES) {
        const result = await testQuickFix(testCase);
        results.push({ testCase, result });
        
        if (result.success) {
            successCount++;
        }
        
        // Brief pause between tests
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    // Print summary
    console.log('\n📊 Test Summary');
    console.log('===============');
    console.log(`Total tests: ${TEST_CASES.length}`);
    console.log(`Passed: ${successCount}`);
    console.log(`Failed: ${TEST_CASES.length - successCount}`);
    console.log(`Success rate: ${((successCount / TEST_CASES.length) * 100).toFixed(1)}%`);
    
    console.log('\n📋 Detailed Results:');
    results.forEach(({ testCase, result }) => {
        const status = result.success ? '✅' : '❌';
        console.log(`${status} ${testCase.name}: ${result.reason}`);
        if (result.diagnostics !== undefined) {
            console.log(`   📊 ${result.diagnostics} diagnostics, ${result.fixableDiagnostics} fixable, ${result.successfulFixes} fixed`);
        }
    });
    
    return results;
}

/**
 * Main execution
 */
async function main() {
    try {
        // Check if running in VS Code extension context
        if (typeof vscode === 'undefined') {
            console.error('❌ This script must be run within VS Code extension context');
            process.exit(1);
        }
        
        // Wait for extension to be ready
        console.log('⏳ Waiting for Code Guardian extension to be ready...');
        await new Promise(resolve => setTimeout(resolve, 2000));
        
        // Run tests
        const results = await runAllQuickFixTests();
        
        console.log('\n🎉 Quick fix testing completed!');
        
        return results;
        
    } catch (error) {
        console.error('💥 Quick fix testing failed:', error);
        throw error;
    }
}

// Export for use as module
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        runAllQuickFixTests,
        testQuickFix,
        TEST_CASES
    };
}

// Run if executed directly
if (require.main === module) {
    main().catch(console.error);
}
