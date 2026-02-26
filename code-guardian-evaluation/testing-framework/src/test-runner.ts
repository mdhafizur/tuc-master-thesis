import * as path from 'path';
import * as vscode from 'vscode';
import { ExtensionTestRunner } from './test-config';
import { ExtensionTestUtils } from './extension-utils';
import { CommandExecutor } from './command-executor';
import { DiagnosticValidator } from './diagnostic-validator';
import { TestDataManager } from './test-data-manager';
import { PerformanceMeasurer, ResourceMonitor } from './performance-utils';
import { QuickFixTester, QuickFixTestResult } from './quick-fix-tester';

/**
 * Main test runner for Code Guardian extension evaluation
 */
export class CodeGuardianTestRunner {
    private extensionTestRunner: ExtensionTestRunner;
    private extensionUtils: ExtensionTestUtils;
    private commandExecutor: CommandExecutor;
    private diagnosticValidator: DiagnosticValidator;
    private testDataManager: TestDataManager;
    private performanceMeasurer: PerformanceMeasurer;
    private resourceMonitor: ResourceMonitor;
    private quickFixTester: QuickFixTester;

    constructor() {
        this.extensionTestRunner = new ExtensionTestRunner();
        this.extensionUtils = new ExtensionTestUtils();
        this.commandExecutor = new CommandExecutor();
        this.diagnosticValidator = new DiagnosticValidator();
        this.testDataManager = new TestDataManager();
        this.performanceMeasurer = new PerformanceMeasurer();
        this.resourceMonitor = new ResourceMonitor();
        this.quickFixTester = new QuickFixTester();
    }

    /**
     * Initialize the test environment
     */
    async initialize(): Promise<void> {
        console.log('🔧 Initializing Code Guardian test environment...');
        
        // Setup test environment
        await this.extensionTestRunner.setupTestEnvironment();
        
        // Initialize test data
        await this.testDataManager.initialize();
        
        // Wait for extension activation
        await this.extensionUtils.waitForExtensionActivation();
        
        console.log('✅ Test environment initialized successfully');
    }

    /**
     * Run comprehensive test suite
     */
    async runComprehensiveTests(): Promise<TestReport> {
        console.log('🚀 Starting comprehensive test suite...');
        
        const startTime = Date.now();
        this.resourceMonitor.startMonitoring(500); // Monitor every 500ms
        
        try {
            // Load all test cases
            const allTestCases = await this.testDataManager.loadAllTestCases();
            
            const testResults: CategoryTestResult[] = [];
            
            // Run tests for each category
            for (const [category, testCases] of allTestCases) {
                console.log(`📂 Testing category: ${category} (${testCases.length} cases)`);
                
                const categoryResult = await this.runCategoryTests(category, testCases);
                testResults.push(categoryResult);
                
                // Brief pause between categories
                await this.wait(1000);
            }
            
            // Calculate overall metrics
            const overallMetrics = this.calculateOverallMetrics(testResults);
            
            // Generate final report
            const resourceReport = this.resourceMonitor.stopMonitoring();
            const totalDuration = Date.now() - startTime;
            
            const report: TestReport = {
                timestamp: new Date(),
                totalDuration,
                totalTestCases: testResults.reduce((sum, r) => sum + r.testCases.length, 0),
                categoryResults: testResults,
                overallMetrics,
                resourceUsage: resourceReport,
                performanceStatistics: this.performanceMeasurer.getAllStatistics()
            };
            
            console.log('✅ Comprehensive test suite completed');
            return report;
            
        } catch (error) {
            this.resourceMonitor.stopMonitoring();
            console.error('💥 Test suite failed:', error);
            throw error;
        }
    }

    /**
     * Run tests for a specific category
     */
    private async runCategoryTests(
        category: string, 
        testCases: any[]
    ): Promise<CategoryTestResult> {
        const categoryStartTime = Date.now();
        const results: TestCaseResult[] = [];
        
        for (const testCase of testCases) {
            try {
                const result = await this.runSingleTestCase(testCase);
                results.push(result);
                
                // Brief pause between test cases
                await this.wait(100);
                
            } catch (error) {
                console.error(`Failed to run test case ${testCase.id}:`, error);
                results.push({
                    testCase,
                    success: false,
                    error: error instanceof Error ? error.message : String(error),
                    duration: 0,
                    validationResult: null,
                    commandResult: null
                });
            }
        }
        
        const categoryDuration = Date.now() - categoryStartTime;
        const successCount = results.filter(r => r.success).length;
        
        // Calculate category metrics
        const validationResults = results
            .map(r => r.validationResult)
            .filter(v => v !== null);
        
        const categoryMetrics = validationResults.length > 0 ? 
            this.calculateCategoryMetrics(validationResults) : null;
        
        return {
            category,
            testCases,
            results,
            duration: categoryDuration,
            successCount,
            failureCount: results.length - successCount,
            metrics: categoryMetrics
        };
    }

    /**
     * Run a single test case
     */
    private async runSingleTestCase(testCase: any): Promise<TestCaseResult> {
        const testStartTime = Date.now();
        
        try {
            // Execute the analysis command
            const commandResult = await this.commandExecutor.executeAnalyzeFullFile(
                testCase.code,
                `${testCase.id}.${testCase.language === 'typescript' ? 'ts' : 'js'}`,
                {
                    captureDiagnostics: true,
                    diagnosticTimeout: 5000
                }
            );
            
            // Validate the results
            const validationResult = this.diagnosticValidator.validateDetection(
                commandResult.diagnostics,
                testCase.expectedVulnerabilities
            );
            
            const duration = Date.now() - testStartTime;
            
            return {
                testCase,
                success: commandResult.success,
                duration,
                validationResult,
                commandResult
            };
            
        } catch (error) {
            const duration = Date.now() - testStartTime;
            
            return {
                testCase,
                success: false,
                error: error instanceof Error ? error.message : String(error),
                duration,
                validationResult: null,
                commandResult: null
            };
        }
    }

    /**
     * Run performance benchmark tests
     */
    async runPerformanceBenchmarks(): Promise<PerformanceBenchmarkReport> {
        console.log('⚡ Running performance benchmarks...');
        
        const performanceTestCases = await this.testDataManager.loadTestCases('performance-tests');
        const benchmarkResults: PerformanceBenchmarkResult[] = [];
        
        // Test different code sizes
        const codeSizes = [100, 500, 1000, 2000, 5000];
        
        for (const size of codeSizes) {
            console.log(`📊 Testing code size: ${size} characters`);
            
            const testCode = this.generateTestCode(size);
            const iterations = 10; // Run each test multiple times
            const measurements: number[] = [];
            
            for (let i = 0; i < iterations; i++) {
                const { measurement } = await this.performanceMeasurer.measureAsync(
                    `performance-test-${size}`,
                    async () => {
                        return await this.commandExecutor.executeAnalyzeFullFile(
                            testCode,
                            `perf-test-${size}-${i}.js`,
                            { captureDiagnostics: true }
                        );
                    }
                );
                
                measurements.push(measurement.duration);
                
                // Small delay between iterations
                await this.wait(100);
            }
            
            // Calculate statistics
            measurements.sort((a, b) => a - b);
            const mean = measurements.reduce((sum, m) => sum + m, 0) / measurements.length;
            const median = measurements[Math.floor(measurements.length / 2)];
            const p95 = measurements[Math.floor(measurements.length * 0.95)];
            
            benchmarkResults.push({
                codeSize: size,
                iterations,
                measurements,
                statistics: {
                    mean,
                    median,
                    p95,
                    min: measurements[0],
                    max: measurements[measurements.length - 1]
                }
            });
        }
        
        return {
            timestamp: new Date(),
            benchmarkResults,
            summary: this.summarizeBenchmarks(benchmarkResults)
        };
    }

    /**
     * Calculate overall metrics from category results
     */
    private calculateOverallMetrics(categoryResults: CategoryTestResult[]): TestMetrics {
        const allValidationResults = categoryResults
            .map(cr => cr.results.map(r => r.validationResult))
            .flat()
            .filter(v => v !== null);
        
        if (allValidationResults.length === 0) {
            return {
                precision: 0,
                recall: 0,
                f1Score: 0,
                truePositives: 0,
                falsePositives: 0,
                falseNegatives: 0
            };
        }
        
        const totalTP = allValidationResults.reduce((sum, v) => sum + v!.truePositives, 0);
        const totalFP = allValidationResults.reduce((sum, v) => sum + v!.falsePositives, 0);
        const totalFN = allValidationResults.reduce((sum, v) => sum + v!.falseNegatives, 0);
        
        const precision = totalTP + totalFP > 0 ? totalTP / (totalTP + totalFP) : 0;
        const recall = totalTP + totalFN > 0 ? totalTP / (totalTP + totalFN) : 0;
        const f1Score = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
        
        return {
            precision,
            recall,
            f1Score,
            truePositives: totalTP,
            falsePositives: totalFP,
            falseNegatives: totalFN
        };
    }

    /**
     * Calculate category-specific metrics
     */
    private calculateCategoryMetrics(validationResults: any[]): TestMetrics {
        const totalTP = validationResults.reduce((sum, v) => sum + v.truePositives, 0);
        const totalFP = validationResults.reduce((sum, v) => sum + v.falsePositives, 0);
        const totalFN = validationResults.reduce((sum, v) => sum + v.falseNegatives, 0);
        
        const precision = totalTP + totalFP > 0 ? totalTP / (totalTP + totalFP) : 0;
        const recall = totalTP + totalFN > 0 ? totalTP / (totalTP + totalFN) : 0;
        const f1Score = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0;
        
        return {
            precision,
            recall,
            f1Score,
            truePositives: totalTP,
            falsePositives: totalFP,
            falseNegatives: totalFN
        };
    }

    /**
     * Generate test code of specific size
     */
    private generateTestCode(targetSize: number): string {
        const baseCode = `function testFunction(input) {
    // This is generated test code
    const result = processInput(input);
    return result;
}`;
        
        let code = baseCode;
        while (code.length < targetSize) {
            code += `\n// Additional comment ${Math.random()}`;
        }
        
        return code.substring(0, targetSize);
    }

    /**
     * Summarize benchmark results
     */
    private summarizeBenchmarks(results: PerformanceBenchmarkResult[]): BenchmarkSummary {
        const allMeasurements = results.map(r => r.statistics.mean);
        
        return {
            totalBenchmarks: results.length,
            averageLatency: allMeasurements.reduce((sum, m) => sum + m, 0) / allMeasurements.length,
            minLatency: Math.min(...allMeasurements),
            maxLatency: Math.max(...allMeasurements),
            scalabilityTrend: this.calculateScalabilityTrend(results)
        };
    }

    /**
     * Calculate scalability trend
     */
    private calculateScalabilityTrend(results: PerformanceBenchmarkResult[]): 'linear' | 'sublinear' | 'superlinear' {
        if (results.length < 2) {
            return 'linear';
        }
        
        // Simple heuristic: compare latency increase ratio to size increase ratio
        const firstResult = results[0];
        const lastResult = results[results.length - 1];
        
        const sizeRatio = lastResult.codeSize / firstResult.codeSize;
        const latencyRatio = lastResult.statistics.mean / firstResult.statistics.mean;
        
        if (latencyRatio < sizeRatio * 0.8) {
            return 'sublinear';
        }
        if (latencyRatio > sizeRatio * 1.2) {
            return 'superlinear';
        }
        return 'linear';
    }

    /**
     * Utility function to wait
     */
    private async wait(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Export test results
     */
    async exportResults(report: TestReport, outputPath: string): Promise<void> {
        const fs = require('fs').promises;
        await fs.writeFile(outputPath, JSON.stringify(report, null, 2));
        console.log(`📄 Test results exported to: ${outputPath}`);
    }

    /**
     * Cleanup resources
     */
    async cleanup(): Promise<void> {
        await this.commandExecutor.cleanup();
        await this.extensionUtils.cleanup();
        await this.extensionTestRunner.cleanupTestEnvironment();
    }

    /**
     * Run quick fix specific tests
     */
    async runQuickFixTests(): Promise<QuickFixTestReport> {
        console.log('🔧 Starting quick fix test suite...');
        
        const startTime = Date.now();
        const testResults: QuickFixTestCase[] = [];
        
        try {
            // Test cases for quick fix functionality
            const quickFixTestCases = [
                {
                    id: 'sql-injection-fix',
                    code: `function getUserById(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return database.query(query);
}`,
                    description: 'SQL injection vulnerability with parameterized query fix',
                    language: 'javascript' as const
                },
                {
                    id: 'xss-fix',
                    code: `function displayUserContent(userContent) {
    document.getElementById('content').innerHTML = userContent;
}`,
                    description: 'XSS vulnerability with proper sanitization fix',
                    language: 'javascript' as const
                },
                {
                    id: 'code-injection-fix',
                    code: `function executeUserCode(userCode) {
    return eval(userCode);
}`,
                    description: 'Code injection vulnerability with safe alternative fix',
                    language: 'javascript' as const
                }
            ];

            // Run each quick fix test case
            for (const testCase of quickFixTestCases) {
                console.log(`🔍 Testing quick fix for: ${testCase.description}`);
                
                try {
                    const result = await this.runSingleQuickFixTest(testCase);
                    testResults.push(result);
                } catch (error) {
                    console.error(`Failed quick fix test ${testCase.id}:`, error);
                    testResults.push({
                        testCase,
                        success: false,
                        error: error instanceof Error ? error.message : String(error),
                        duration: 0,
                        quickFixResult: null
                    });
                }
                
                // Brief pause between tests
                await this.wait(1000);
            }

            const totalDuration = Date.now() - startTime;
            const successCount = testResults.filter(r => r.success).length;
            
            const report: QuickFixTestReport = {
                timestamp: new Date(),
                totalDuration,
                totalTestCases: testResults.length,
                successCount,
                failureCount: testResults.length - successCount,
                testResults,
                summary: this.generateQuickFixSummary(testResults)
            };

            console.log(`✅ Quick fix tests completed: ${successCount}/${testResults.length} passed`);
            return report;

        } catch (error) {
            console.error('💥 Quick fix test suite failed:', error);
            throw error;
        }
    }

    /**
     * Run a single quick fix test case
     */
    private async runSingleQuickFixTest(testCase: QuickFixTestCaseDefinition): Promise<QuickFixTestCase> {
        const testStartTime = Date.now();
        
        try {
            // Create test document
            const doc = await vscode.workspace.openTextDocument({
                content: testCase.code,
                language: testCase.language
            });

            await vscode.window.showTextDocument(doc);

            // Run analysis to generate diagnostics
            await vscode.commands.executeCommand('codeSecurity.analyzeFullFile');
            await this.wait(5000); // Wait for analysis to complete

            // Test quick fix workflow
            const quickFixResult = await this.quickFixTester.testQuickFixWorkflow(doc);
            
            const duration = Date.now() - testStartTime;
            const success = quickFixResult.success && quickFixResult.fixesApplied > 0;

            // Close the test document
            await vscode.commands.executeCommand('workbench.action.closeActiveEditor');

            return {
                testCase,
                success,
                duration,
                quickFixResult
            };

        } catch (error) {
            const duration = Date.now() - testStartTime;
            
            return {
                testCase,
                success: false,
                error: error instanceof Error ? error.message : String(error),
                duration,
                quickFixResult: null
            };
        }
    }

    /**
     * Generate summary of quick fix test results
     */
    private generateQuickFixSummary(testResults: QuickFixTestCase[]): QuickFixSummary {
        const totalDiagnostics = testResults.reduce((sum, r) => 
            sum + (r.quickFixResult?.diagnosticsFound || 0), 0);
        
        const totalFixableDiagnostics = testResults.reduce((sum, r) => 
            sum + (r.quickFixResult?.fixableDiagnostics || 0), 0);
        
        const totalCodeActions = testResults.reduce((sum, r) => 
            sum + (r.quickFixResult?.codeActionsFound || 0), 0);
        
        const totalFixesApplied = testResults.reduce((sum, r) => 
            sum + (r.quickFixResult?.fixesApplied || 0), 0);

        return {
            totalDiagnostics,
            totalFixableDiagnostics,
            totalCodeActions,
            totalFixesApplied,
            fixSuccessRate: totalFixableDiagnostics > 0 ? 
                (totalFixesApplied / totalFixableDiagnostics) * 100 : 0,
            averageFixesPerTest: testResults.length > 0 ? 
                totalFixesApplied / testResults.length : 0
        };
    }
}

// Type definitions for test results
export interface TestReport {
    timestamp: Date;
    totalDuration: number;
    totalTestCases: number;
    categoryResults: CategoryTestResult[];
    overallMetrics: TestMetrics;
    resourceUsage: any;
    performanceStatistics: any;
}

export interface CategoryTestResult {
    category: string;
    testCases: any[];
    results: TestCaseResult[];
    duration: number;
    successCount: number;
    failureCount: number;
    metrics: TestMetrics | null;
}

export interface TestCaseResult {
    testCase: any;
    success: boolean;
    duration: number;
    validationResult: any;
    commandResult: any;
    error?: string;
}

export interface TestMetrics {
    precision: number;
    recall: number;
    f1Score: number;
    truePositives: number;
    falsePositives: number;
    falseNegatives: number;
}

// Quick Fix Testing Types
export interface QuickFixTestReport {
    timestamp: Date;
    totalDuration: number;
    totalTestCases: number;
    successCount: number;
    failureCount: number;
    testResults: QuickFixTestCase[];
    summary: QuickFixSummary;
}

export interface QuickFixTestCase {
    testCase: QuickFixTestCaseDefinition;
    success: boolean;
    duration: number;
    quickFixResult: QuickFixTestResult | null;
    error?: string;
}

export interface QuickFixTestCaseDefinition {
    id: string;
    code: string;
    description: string;
    language: 'javascript' | 'typescript';
}

export interface QuickFixSummary {
    totalDiagnostics: number;
    totalFixableDiagnostics: number;
    totalCodeActions: number;
    totalFixesApplied: number;
    fixSuccessRate: number;
    averageFixesPerTest: number;
}

export interface PerformanceBenchmarkReport {
    timestamp: Date;
    benchmarkResults: PerformanceBenchmarkResult[];
    summary: BenchmarkSummary;
}

export interface PerformanceBenchmarkResult {
    codeSize: number;
    iterations: number;
    measurements: number[];
    statistics: {
        mean: number;
        median: number;
        p95: number;
        min: number;
        max: number;
    };
}

export interface BenchmarkSummary {
    totalBenchmarks: number;
    averageLatency: number;
    minLatency: number;
    maxLatency: number;
    scalabilityTrend: 'linear' | 'sublinear' | 'superlinear';
}
