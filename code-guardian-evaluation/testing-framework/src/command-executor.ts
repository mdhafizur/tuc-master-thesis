import * as vscode from 'vscode';
import { ExtensionTestUtils } from './extension-utils';
import { PerformanceMeasurer } from './performance-utils';

/**
 * Command execution framework for testing Code Guardian extension commands
 */
export class CommandExecutor {
    private testUtils: ExtensionTestUtils;
    private performanceMeasurer: PerformanceMeasurer;
    private diagnosticListener?: vscode.Disposable;
    private commandResults: CommandResult[] = [];

    constructor() {
        this.testUtils = new ExtensionTestUtils();
        this.performanceMeasurer = new PerformanceMeasurer();
    }

    /**
     * Execute the analyzeSelectionWithAI command
     */
    async executeAnalyzeSelection(
        code: string, 
        options: ExecutionOptions = {}
    ): Promise<CommandResult> {
        const operationName = 'analyzeSelectionWithAI';
        
        try {
            // Create a test file with the code
            const editor = await this.testUtils.createTestFile(code, 'test-selection.js');
            
            // Select all the code
            await this.testUtils.selectText(0, 0, editor.document.lineCount - 1, 0);
            
            // Setup diagnostic listener if needed
            if (options.captureDiagnostics) {
                this.setupDiagnosticListener(editor.document.uri);
            }

            // Execute the command with performance measurement
            const { result, measurement } = await this.performanceMeasurer.measureAsync(
                operationName,
                async () => {
                    return await this.testUtils.executeCommand('codeSecurity.analyzeSelectionWithAI');
                },
                { codeLength: code.length, fileName: 'test-selection.js' }
            );

            // Wait for diagnostics if requested
            let diagnostics: vscode.Diagnostic[] = [];
            if (options.captureDiagnostics) {
                await this.testUtils.wait(options.diagnosticTimeout || 3000);
                diagnostics = vscode.languages.getDiagnostics(editor.document.uri);
            }

            const commandResult: CommandResult = {
                command: operationName,
                success: true,
                duration: measurement.duration,
                input: code,
                output: result,
                diagnostics,
                timestamp: new Date(),
                metadata: measurement.metadata
            };

            this.commandResults.push(commandResult);
            return commandResult;

        } catch (error) {
            const commandResult: CommandResult = {
                command: operationName,
                success: false,
                duration: 0,
                input: code,
                error: error instanceof Error ? error.message : String(error),
                diagnostics: [],
                timestamp: new Date(),
                metadata: {}
            };

            this.commandResults.push(commandResult);
            return commandResult;
        } finally {
            this.cleanupDiagnosticListener();
        }
    }

    /**
     * Execute the analyzeFullFile command
     */
    async executeAnalyzeFullFile(
        code: string, 
        fileName: string = 'test-full.js',
        options: ExecutionOptions = {}
    ): Promise<CommandResult> {
        const operationName = 'analyzeFullFile';
        
        try {
            // Create a test file with the code
            const editor = await this.testUtils.createTestFile(code, fileName);
            
            // Setup diagnostic listener if needed
            if (options.captureDiagnostics) {
                this.setupDiagnosticListener(editor.document.uri);
            }

            // Execute the command with performance measurement
            const { result, measurement } = await this.performanceMeasurer.measureAsync(
                operationName,
                async () => {
                    return await this.testUtils.executeCommand('codeSecurity.analyzeFullFile');
                },
                { codeLength: code.length, fileName }
            );

            // Wait for diagnostics if requested
            let diagnostics: vscode.Diagnostic[] = [];
            if (options.captureDiagnostics) {
                await this.testUtils.wait(options.diagnosticTimeout || 5000);
                diagnostics = vscode.languages.getDiagnostics(editor.document.uri);
            }

            const commandResult: CommandResult = {
                command: operationName,
                success: true,
                duration: measurement.duration,
                input: code,
                output: result,
                diagnostics,
                timestamp: new Date(),
                metadata: measurement.metadata
            };

            this.commandResults.push(commandResult);
            return commandResult;

        } catch (error) {
            const commandResult: CommandResult = {
                command: operationName,
                success: false,
                duration: 0,
                input: code,
                error: error instanceof Error ? error.message : String(error),
                diagnostics: [],
                timestamp: new Date(),
                metadata: {}
            };

            this.commandResults.push(commandResult);
            return commandResult;
        } finally {
            this.cleanupDiagnosticListener();
        }
    }

    /**
     * Execute the applyFix command on a specific diagnostic
     */
    async executeApplyFix(
        code: string,
        diagnosticIndex: number = 0,
        options: ExecutionOptions = {}
    ): Promise<CommandResult> {
        const operationName = 'applyFix';
        
        try {
            // First analyze the code to get diagnostics
            const analyzeResult = await this.executeAnalyzeFullFile(code, 'test-fix.js', { 
                captureDiagnostics: true,
                diagnosticTimeout: options.diagnosticTimeout 
            });

            if (!analyzeResult.success || analyzeResult.diagnostics.length === 0) {
                throw new Error('No diagnostics available for fix application');
            }

            if (diagnosticIndex >= analyzeResult.diagnostics.length) {
                throw new Error(`Diagnostic index ${diagnosticIndex} out of range`);
            }

            const targetDiagnostic = analyzeResult.diagnostics[diagnosticIndex];
            const editor = vscode.window.activeTextEditor;
            
            if (!editor) {
                throw new Error('No active editor for fix application');
            }

            // Position cursor at the diagnostic location
            const position = targetDiagnostic.range.start;
            editor.selection = new vscode.Selection(position, position);

            // Execute the fix command with performance measurement
            const { result, measurement } = await this.performanceMeasurer.measureAsync(
                operationName,
                async () => {
                    return await this.testUtils.executeCommand('codeSecurity.applyFix');
                },
                { 
                    diagnosticMessage: targetDiagnostic.message,
                    diagnosticSeverity: targetDiagnostic.severity,
                    originalCodeLength: code.length
                }
            );

            // Capture the updated code
            const updatedCode = editor.document.getText();

            const commandResult: CommandResult = {
                command: operationName,
                success: true,
                duration: measurement.duration,
                input: code,
                output: result,
                updatedCode,
                diagnostics: [targetDiagnostic],
                timestamp: new Date(),
                metadata: measurement.metadata
            };

            this.commandResults.push(commandResult);
            return commandResult;

        } catch (error) {
            const commandResult: CommandResult = {
                command: operationName,
                success: false,
                duration: 0,
                input: code,
                error: error instanceof Error ? error.message : String(error),
                diagnostics: [],
                timestamp: new Date(),
                metadata: {}
            };

            this.commandResults.push(commandResult);
            return commandResult;
        }
    }

    /**
     * Execute the contextualQnA command
     */
    async executeContextualQnA(
        question: string,
        contextFiles: string[] = [],
        options: ExecutionOptions = {}
    ): Promise<CommandResult> {
        const operationName = 'contextualQnA';
        
        try {
            // Execute the command with performance measurement
            const { result, measurement } = await this.performanceMeasurer.measureAsync(
                operationName,
                async () => {
                    return await this.testUtils.executeCommand('codeSecurity.contextualQnA');
                },
                { 
                    questionLength: question.length,
                    contextFileCount: contextFiles.length
                }
            );

            // Note: Contextual Q&A opens a webview, so we need to handle that differently
            // For now, we'll just measure the command execution time

            const commandResult: CommandResult = {
                command: operationName,
                success: true,
                duration: measurement.duration,
                input: question,
                output: result,
                diagnostics: [],
                timestamp: new Date(),
                metadata: { ...measurement.metadata, contextFiles }
            };

            this.commandResults.push(commandResult);
            return commandResult;

        } catch (error) {
            const commandResult: CommandResult = {
                command: operationName,
                success: false,
                duration: 0,
                input: question,
                error: error instanceof Error ? error.message : String(error),
                diagnostics: [],
                timestamp: new Date(),
                metadata: { contextFiles }
            };

            this.commandResults.push(commandResult);
            return commandResult;
        }
    }

    /**
     * Execute a batch of commands for performance testing
     */
    async executeBatch(testCases: TestCase[]): Promise<BatchResult> {
        const batchStartTime = Date.now();
        const results: CommandResult[] = [];
        const errors: Error[] = [];

        for (const testCase of testCases) {
            try {
                let result: CommandResult;

                switch (testCase.command) {
                    case 'analyzeSelectionWithAI':
                        result = await this.executeAnalyzeSelection(testCase.input, testCase.options);
                        break;
                    
                    case 'analyzeFullFile':
                        result = await this.executeAnalyzeFullFile(
                            testCase.input, 
                            testCase.fileName, 
                            testCase.options
                        );
                        break;
                    
                    case 'applyFix':
                        result = await this.executeApplyFix(
                            testCase.input, 
                            testCase.diagnosticIndex || 0, 
                            testCase.options
                        );
                        break;
                    
                    case 'contextualQnA':
                        result = await this.executeContextualQnA(
                            testCase.input, 
                            testCase.contextFiles || [], 
                            testCase.options
                        );
                        break;
                    
                    default:
                        throw new Error(`Unknown command: ${testCase.command}`);
                }

                results.push(result);

                // Add delay between commands if specified
                if (testCase.delayMs) {
                    await this.testUtils.wait(testCase.delayMs);
                }

            } catch (error) {
                const err = error instanceof Error ? error : new Error(String(error));
                errors.push(err);
                console.error(`Batch execution error for ${testCase.command}:`, err);
            }
        }

        const batchDuration = Date.now() - batchStartTime;

        return {
            totalTestCases: testCases.length,
            successfulResults: results.filter(r => r.success).length,
            failedResults: results.filter(r => !r.success).length,
            errors: errors.length,
            totalDuration: batchDuration,
            results,
            errorDetails: errors
        };
    }

    /**
     * Get all command execution results
     */
    getResults(): CommandResult[] {
        return [...this.commandResults];
    }

    /**
     * Get performance statistics for all commands
     */
    getPerformanceStatistics(): Record<string, any> {
        return this.performanceMeasurer.getAllStatistics();
    }

    /**
     * Clear all results and measurements
     */
    clearResults(): void {
        this.commandResults = [];
        this.performanceMeasurer.clearMeasurements();
    }

    /**
     * Export results to JSON
     */
    exportResults(): string {
        return JSON.stringify({
            timestamp: new Date().toISOString(),
            results: this.commandResults,
            statistics: this.getPerformanceStatistics()
        }, null, 2);
    }

    /**
     * Setup diagnostic listener
     */
    private setupDiagnosticListener(uri: vscode.Uri): void {
        this.cleanupDiagnosticListener();
        
        this.diagnosticListener = vscode.languages.onDidChangeDiagnostics(e => {
            if (e.uris.some(u => u.toString() === uri.toString())) {
                console.log('Diagnostics updated for:', uri.toString());
            }
        });
    }

    /**
     * Cleanup diagnostic listener
     */
    private cleanupDiagnosticListener(): void {
        if (this.diagnosticListener) {
            this.diagnosticListener.dispose();
            this.diagnosticListener = undefined;
        }
    }

    /**
     * Cleanup resources
     */
    async cleanup(): Promise<void> {
        this.cleanupDiagnosticListener();
        await this.testUtils.cleanup();
    }
}

/**
 * Interface for command execution options
 */
export interface ExecutionOptions {
    captureDiagnostics?: boolean;
    diagnosticTimeout?: number;
    expectError?: boolean;
    metadata?: Record<string, any>;
}

/**
 * Interface for command execution results
 */
export interface CommandResult {
    command: string;
    success: boolean;
    duration: number;
    input: string;
    output?: any;
    updatedCode?: string;
    error?: string;
    diagnostics: vscode.Diagnostic[];
    timestamp: Date;
    metadata: Record<string, any>;
}

/**
 * Interface for test cases
 */
export interface TestCase {
    command: 'analyzeSelectionWithAI' | 'analyzeFullFile' | 'applyFix' | 'contextualQnA';
    input: string;
    fileName?: string;
    diagnosticIndex?: number;
    contextFiles?: string[];
    options?: ExecutionOptions;
    delayMs?: number;
    expectedOutcome?: 'success' | 'failure';
}

/**
 * Interface for batch execution results
 */
export interface BatchResult {
    totalTestCases: number;
    successfulResults: number;
    failedResults: number;
    errors: number;
    totalDuration: number;
    results: CommandResult[];
    errorDetails: Error[];
}
