import * as vscode from 'vscode';
import { 
    CodeGuardianTestRunner, 
    QuickFixTester, 
    QuickFixTestReport,
    QuickFixTestResult
} from './src/index';

/**
 * Comprehensive Quick Fix Test Runner
 * 
 * This script demonstrates how to use the Code Guardian testing framework
 * to thoroughly test quick fix functionality.
 */

export class QuickFixTestRunner {
    private testRunner: CodeGuardianTestRunner;
    private quickFixTester: QuickFixTester;
    
    constructor() {
        this.testRunner = new CodeGuardianTestRunner();
        this.quickFixTester = new QuickFixTester();
    }

    /**
     * Initialize the test environment
     */
    async initialize(): Promise<void> {
        console.log('🔧 Initializing Quick Fix Test Environment...');
        await this.testRunner.initialize();
        console.log('✅ Quick Fix Test Environment ready');
    }

    /**
     * Run comprehensive quick fix tests
     */
    async runComprehensiveQuickFixTests(): Promise<QuickFixTestReport> {
        console.log('🚀 Starting Comprehensive Quick Fix Tests...');
        
        // Use the test runner's built-in quick fix testing
        const report = await this.testRunner.runQuickFixTests();
        
        console.log('📊 Quick Fix Test Results:');
        console.log(`  Total Tests: ${report.totalTestCases}`);
        console.log(`  Successful: ${report.successCount}`);
        console.log(`  Failed: ${report.failureCount}`);
        console.log(`  Success Rate: ${((report.successCount / report.totalTestCases) * 100).toFixed(1)}%`);
        console.log(`  Total Fixes Applied: ${report.summary.totalFixesApplied}`);
        console.log(`  Fix Success Rate: ${report.summary.fixSuccessRate.toFixed(1)}%`);
        
        return report;
    }

    /**
     * Test a specific piece of vulnerable code
     */
    async testSpecificCode(code: string, language: 'javascript' | 'typescript' = 'javascript'): Promise<QuickFixTestResult> {
        console.log('🔍 Testing specific code for quick fixes...');
        
        try {
            // Create test document
            const doc = await vscode.workspace.openTextDocument({
                content: code,
                language
            });

            await vscode.window.showTextDocument(doc);

            // Run security analysis
            console.log('📊 Running security analysis...');
            await vscode.commands.executeCommand('codeSecurity.analyzeFullFile');
            await new Promise(resolve => setTimeout(resolve, 5000));

            // Test quick fix workflow
            const result = await this.quickFixTester.testQuickFixWorkflow(doc);
            
            // Close document
            await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
            
            console.log('📋 Quick Fix Test Results:');
            console.log(`  Diagnostics Found: ${result.diagnosticsFound}`);
            console.log(`  Fixable Diagnostics: ${result.fixableDiagnostics}`);
            console.log(`  Code Actions Available: ${result.codeActionsFound}`);
            console.log(`  Fixes Applied: ${result.fixesApplied}`);
            console.log(`  Success: ${result.success ? '✅' : '❌'}`);
            
            if (result.details.length > 0) {
                console.log('📝 Details:');
                result.details.forEach(detail => console.log(`  • ${detail}`));
            }
            
            return result;
            
        } catch (error) {
            console.error('💥 Error testing specific code:', error);
            throw error;
        }
    }

    /**
     * Validate diagnostic structure for quick fixes
     */
    async validateDiagnosticStructure(code: string, language: 'javascript' | 'typescript' = 'javascript'): Promise<void> {
        console.log('🔬 Validating diagnostic structure...');
        
        try {
            // Create test document
            const doc = await vscode.workspace.openTextDocument({
                content: code,
                language
            });

            await vscode.window.showTextDocument(doc);

            // Run analysis
            await vscode.commands.executeCommand('codeSecurity.analyzeFullFile');
            await new Promise(resolve => setTimeout(resolve, 5000));

            // Get diagnostics and validate structure
            const diagnostics = vscode.languages.getDiagnostics(doc.uri);
            const validation = this.quickFixTester.validateDiagnosticStructure(diagnostics);
            
            console.log('📊 Diagnostic Structure Validation:');
            console.log(`  Total Diagnostics: ${validation.totalDiagnostics}`);
            console.log(`  Diagnostics with Fixes: ${validation.diagnosticsWithFixes}`);
            console.log(`  Properly Structured: ${validation.diagnosticsWithProperStructure}`);
            
            if (validation.issues.length > 0) {
                console.log('⚠️  Issues Found:');
                validation.issues.forEach(issue => console.log(`  • ${issue}`));
            } else {
                console.log('✅ All diagnostics properly structured');
            }
            
            // Close document
            await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
            
        } catch (error) {
            console.error('💥 Error validating diagnostic structure:', error);
            throw error;
        }
    }

    /**
     * Generate example vulnerable code for testing
     */
    generateTestCode(): { [key: string]: string } {
        return {
            'sql-injection': `
function getUserData(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return database.execute(query);
}`,
            'xss-vulnerability': `
function renderUserContent(content) {
    document.getElementById('output').innerHTML = content;
}`,
            'code-injection': `
function evaluateExpression(expr) {
    return eval(expr);
}`,
            'path-traversal': `
function readUserFile(filename) {
    return fs.readFileSync(filename);
}`,
            'command-injection': `
function executeCommand(cmd) {
    return exec(cmd);
}`
        };
    }

    /**
     * Run interactive quick fix demo
     */
    async runInteractiveDemo(): Promise<void> {
        console.log('🎭 Starting Interactive Quick Fix Demo...');
        
        const testCodes = this.generateTestCode();
        
        for (const [vulnType, code] of Object.entries(testCodes)) {
            console.log(`\n🔍 Testing ${vulnType.toUpperCase()} vulnerability:`);
            console.log('Code:');
            console.log(code.trim());
            
            try {
                const result = await this.testSpecificCode(code);
                
                if (result.success) {
                    console.log('✅ Quick fix functionality working correctly');
                } else {
                    console.log('❌ Quick fix functionality needs attention');
                }
                
                // Pause between demos
                await new Promise(resolve => setTimeout(resolve, 2000));
                
            } catch (error) {
                console.error(`💥 Demo failed for ${vulnType}:`, error);
            }
        }
        
        console.log('\n🎉 Interactive demo completed!');
    }

    /**
     * Cleanup resources
     */
    async cleanup(): Promise<void> {
        await this.testRunner.cleanup();
    }
}

/**
 * Main execution function
 */
export async function runQuickFixTests(): Promise<void> {
    const testRunner = new QuickFixTestRunner();
    
    try {
        await testRunner.initialize();
        
        // Run comprehensive tests
        const report = await testRunner.runComprehensiveQuickFixTests();
        
        // Run interactive demo
        await testRunner.runInteractiveDemo();
        
        console.log('\n📊 Final Summary:');
        console.log(`Quick Fix Tests: ${report.successCount}/${report.totalTestCases} passed`);
        console.log(`Total Fixes Applied: ${report.summary.totalFixesApplied}`);
        console.log(`Overall Success Rate: ${report.summary.fixSuccessRate.toFixed(1)}%`);
        
    } catch (error) {
        console.error('💥 Quick fix testing failed:', error);
        throw error;
    } finally {
        await testRunner.cleanup();
    }
}

// Export for external use
export default QuickFixTestRunner;

// Auto-run if executed directly
if (require.main === module) {
    runQuickFixTests().catch(console.error);
}
