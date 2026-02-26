/**
 * Code Guardian VS Code Extension Testing Framework
 * 
 * This module provides comprehensive testing capabilities for evaluating
 * the Code Guardian extension's security vulnerability detection and
 * repair functionality.
 * 
 * @author Code Guardian Research Team
 * @version 1.0.0
 */

import * as vscode from 'vscode';

// Main test runner
export { CodeGuardianTestRunner } from './test-runner';

// Test configuration and utilities
export { ExtensionTestRunner, TestConfig, defaultTestConfig } from './test-config';
export { ExtensionTestUtils, EditorState, EditorStateDiff } from './extension-utils';

// Command execution framework
export { 
    CommandExecutor,
    ExecutionOptions,
    CommandResult,
    TestCase,
    BatchResult 
} from './command-executor';

// Diagnostic validation
export { 
    DiagnosticValidator,
    ExpectedVulnerability,
    VulnerabilityType,
    VulnerabilityValidation,
    ValidationResult,
    DiagnosticQuality,
    DiagnosticQualityReport,
    DiagnosticComparison 
} from './diagnostic-validator';

// Test data management
export { 
    TestDataManager,
    TestCase as TestDataTestCase,
    TestCategory,
    TestDataStatistics 
} from './test-data-manager';

// Performance measurement
export { 
    PerformanceMeasurer,
    ResourceMonitor,
    PerformanceMeasurement,
    PerformanceStatistics,
    ResourceSnapshot,
    ResourceUsageReport,
    MemoryStatistics,
    CpuStatistics,
    BasicStatistics 
} from './performance-utils';

// Quick Fix Testing
export { 
    QuickFixTester,
    QuickFixTestResult,
    SingleFixTestResult,
    DiagnosticValidationResult
} from './quick-fix-tester';

// Type re-exports for convenience
export type {
    TestReport,
    CategoryTestResult,
    TestCaseResult,
    TestMetrics,
    PerformanceBenchmarkReport,
    PerformanceBenchmarkResult,
    BenchmarkSummary,
    QuickFixTestReport,
    QuickFixTestCase,
    QuickFixTestCaseDefinition,
    QuickFixSummary
} from './test-runner';

// Import types for internal use
import { CodeGuardianTestRunner } from './test-runner';
import { DiagnosticValidator, ExpectedVulnerability, ValidationResult } from './diagnostic-validator';
import { QuickFixTester, QuickFixTestResult } from './quick-fix-tester';

/**
 * Main entry point for the testing framework
 * 
 * @example
 * ```typescript
 * import { CodeGuardianTestRunner } from './testing-framework';
 * 
 * async function runTests() {
 *     const testRunner = new CodeGuardianTestRunner();
 *     await testRunner.initialize();
 *     const report = await testRunner.runComprehensiveTests();
 *     console.log('Test Results:', report);
 * }
 * ```
 */
export async function createTestRunner(): Promise<CodeGuardianTestRunner> {
    const testRunner = new CodeGuardianTestRunner();
    await testRunner.initialize();
    return testRunner;
}

/**
 * Quick test execution helper
 * 
 * @example
 * ```typescript
 * import { quickTest } from './testing-framework';
 * 
 * const results = await quickTest({
 *     testCode: 'eval(userInput)',
 *     expectedVulnerabilities: [{
 *         vulnerabilityType: 'code_injection',
 *         startLine: 0,
 *         endLine: 0
 *     }]
 * });
 * ```
 */
export async function quickTest(options: {
    testCode: string;
    expectedVulnerabilities: ExpectedVulnerability[];
    language?: 'javascript' | 'typescript';
}): Promise<ValidationResult> {
    const testRunner = await createTestRunner();
    
    try {
        const commandResult = await testRunner['commandExecutor'].executeAnalyzeFullFile(
            options.testCode,
            `quick-test.${options.language || 'js'}`,
            { captureDiagnostics: true }
        );
        
        const validator = new DiagnosticValidator();
        const validationResult = validator.validateDetection(
            commandResult.diagnostics,
            options.expectedVulnerabilities
        );
        
        return validationResult;
    } finally {
        await testRunner.cleanup();
    }
}

/**
 * Quick fix test execution helper
 * 
 * @example
 * ```typescript
 * import { quickFixTest } from './testing-framework';
 * 
 * const results = await quickFixTest({
 *     testCode: 'eval(userInput)',
 *     language: 'javascript'
 * });
 * ```
 */
export async function quickFixTest(options: {
    testCode: string;
    language?: 'javascript' | 'typescript';
}): Promise<QuickFixTestResult> {
    const testRunner = await createTestRunner();
    
    try {
        // Create test document
        const doc = await vscode.workspace.openTextDocument({
            content: options.testCode,
            language: options.language || 'javascript'
        });

        await vscode.window.showTextDocument(doc);

        // Run analysis to generate diagnostics
        await vscode.commands.executeCommand('codeSecurity.analyzeFullFile');
        await new Promise(resolve => setTimeout(resolve, 5000));

        // Test quick fix workflow
        const quickFixTester = new QuickFixTester();
        const result = await quickFixTester.testQuickFixWorkflow(doc);
        
        // Close the test document
        await vscode.commands.executeCommand('workbench.action.closeActiveEditor');
        
        return result;
    } finally {
        await testRunner.cleanup();
    }
}

/**
 * Framework version information
 */
export const VERSION = '1.0.0';
export const DESCRIPTION = 'VS Code Extension Testing Framework for Code Guardian';

/**
 * Default configuration constants
 */
export const CONSTANTS = {
    DEFAULT_TIMEOUT: 30000,
    DEFAULT_DIAGNOSTIC_TIMEOUT: 5000,
    MAX_CODE_SIZE: 20000,
    PERFORMANCE_ITERATIONS: 10,
    RESOURCE_MONITOR_INTERVAL: 500
} as const;
