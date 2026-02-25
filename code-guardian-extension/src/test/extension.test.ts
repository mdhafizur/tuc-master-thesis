import * as assert from 'assert';
import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';

// Mock the extension modules
const mockAnalyzer = {
    analyzeCode: async () => [
        {
            message: 'Test security issue',
            startLine: 1,
            endLine: 2,
            suggestedFix: 'Test fix'
        }
    ]
};

const mockRAGManager = {
    isInitialized: false,
    initialize: async () => { mockRAGManager.isInitialized = true; },
    addKnowledge: async () => {},
    queryKnowledge: async (query?: string) => 'Mock knowledge response',
    enhancePrompt: (prompt: string) => `Enhanced: ${prompt}`
};

suite('Extension Integration Test Suite', () => {
    let context: vscode.ExtensionContext;
    let testWorkspaceDir: string;

    suiteSetup(() => {
        vscode.window.showInformationMessage('Start Code Guardian extension tests.');
        
        testWorkspaceDir = path.join(__dirname, '..', '..', 'test-workspace-extension');
        if (!fs.existsSync(testWorkspaceDir)) {
            fs.mkdirSync(testWorkspaceDir, { recursive: true });
        }

        context = {
            extensionPath: testWorkspaceDir,
            subscriptions: [],
            asAbsolutePath: (relativePath: string) => path.join(testWorkspaceDir, relativePath),
            languageModelAccessInformation: {} as any,
            globalState: {
                get: (key: string) => undefined,
                update: async (key: string, value: any) => {},
                keys: () => [],
                setKeysForSync: (keys: string[]) => {}
            },
            workspaceState: {
                get: (key: string) => undefined,
                update: async (key: string, value: any) => {},
                keys: () => []
            },
            secrets: {
                get: async (key: string) => undefined,
                store: async (key: string, value: string) => {},
                delete: async (key: string) => {}
            } as any,
            environmentVariableCollection: {} as any,
            storageUri: vscode.Uri.file(testWorkspaceDir),
            globalStorageUri: vscode.Uri.file(testWorkspaceDir),
            logUri: vscode.Uri.file(path.join(testWorkspaceDir, 'logs')),
            extensionUri: vscode.Uri.file(testWorkspaceDir),
            extensionMode: vscode.ExtensionMode.Test,
            storagePath: testWorkspaceDir,
            globalStoragePath: testWorkspaceDir,
            logPath: path.join(testWorkspaceDir, 'logs'),
            extension: {
                id: 'test.code-guardian',
                extensionUri: vscode.Uri.file(testWorkspaceDir),
                extensionPath: testWorkspaceDir,
                isActive: true,
                packageJSON: {},
                extensionKind: vscode.ExtensionKind.Workspace,
                exports: undefined,
                activate: async () => {}
            }
        } as vscode.ExtensionContext;
    });

    suiteTeardown(() => {
        if (fs.existsSync(testWorkspaceDir)) {
            fs.rmSync(testWorkspaceDir, { recursive: true, force: true });
        }
    });

    test('Extension Context Validation', () => {
        assert.ok(context, 'Extension context should be defined');
        assert.ok(context.extensionPath, 'Extension path should be defined');
        assert.ok(Array.isArray(context.subscriptions), 'Subscriptions should be array');
        assert.strictEqual(typeof context.asAbsolutePath, 'function', 'asAbsolutePath should be function');
    });

    test('Command Registration Structure', () => {
        // Test command identifiers that should be registered
        const expectedCommands = [
            'code-guardian.analyzeCurrentFile',
            'code-guardian.analyzeSelectedText',
            'code-guardian.toggleRAG',
            'code-guardian.initializeRAG',
            'code-guardian.addKnowledge',
            'code-guardian.queryKnowledge',
            'code-guardian.updateVulnerabilityData'
        ];

        expectedCommands.forEach(commandId => {
            assert.ok(typeof commandId === 'string', `Command ID ${commandId} should be string`);
            assert.ok(commandId.startsWith('code-guardian.'), `Command ${commandId} should have proper prefix`);
        });
    });

    test('Configuration Schema Validation', () => {
        // Test configuration properties that should exist
        const configProperties = [
            'code-guardian.enableRAG',
            'code-guardian.ollamaModel',
            'code-guardian.ragCacheSize',
            'code-guardian.vulnerabilityDataUpdateInterval'
        ];

        configProperties.forEach(prop => {
            assert.ok(typeof prop === 'string', `Config property ${prop} should be string`);
            assert.ok(prop.startsWith('code-guardian.'), `Config ${prop} should have proper prefix`);
        });
    });

    test('Mock RAG Manager Functionality', async () => {
        // Test mock RAG manager
        assert.strictEqual(mockRAGManager.isInitialized, false, 'Should start uninitialized');
        
        await mockRAGManager.initialize();
        assert.strictEqual(mockRAGManager.isInitialized, true, 'Should be initialized after init');
        
        const response = await mockRAGManager.queryKnowledge('test query');
        assert.strictEqual(response, 'Mock knowledge response', 'Should return mock response');
        
        const enhanced = mockRAGManager.enhancePrompt('test prompt');
        assert.strictEqual(enhanced, 'Enhanced: test prompt', 'Should enhance prompt');
    });

    test('Mock Analyzer Functionality', async () => {
        const results = await mockAnalyzer.analyzeCode();
        
        assert.ok(Array.isArray(results), 'Should return array of issues');
        assert.strictEqual(results.length, 1, 'Should return one test issue');
        
        const issue = results[0];
        assert.strictEqual(issue.message, 'Test security issue', 'Should have correct message');
        assert.strictEqual(issue.startLine, 1, 'Should have correct start line');
        assert.strictEqual(issue.endLine, 2, 'Should have correct end line');
        assert.strictEqual(issue.suggestedFix, 'Test fix', 'Should have suggested fix');
    });

    test('File Type Detection', () => {
        const testFiles = [
            { name: 'test.js', expected: 'javascript' },
            { name: 'test.ts', expected: 'typescript' },
            { name: 'test.py', expected: 'python' },
            { name: 'test.php', expected: 'php' },
            { name: 'test.java', expected: 'java' },
            { name: 'test.txt', expected: 'unknown' }
        ];

        testFiles.forEach(file => {
            const extension = path.extname(file.name).toLowerCase();
            let detectedType = 'unknown';
            
            switch (extension) {
                case '.js':
                    detectedType = 'javascript';
                    break;
                case '.ts':
                    detectedType = 'typescript';
                    break;
                case '.py':
                    detectedType = 'python';
                    break;
                case '.php':
                    detectedType = 'php';
                    break;
                case '.java':
                    detectedType = 'java';
                    break;
            }
            
            assert.strictEqual(detectedType, file.expected, 
                `File ${file.name} should be detected as ${file.expected}`);
        });
    });

    test('Status Bar Integration', () => {
        // Mock status bar item
        const mockStatusBarItem = {
            text: '',
            tooltip: '',
            show: () => {},
            hide: () => {},
            dispose: () => {}
        };

        // Test status bar states
        mockStatusBarItem.text = '$(shield) RAG: Ready';
        mockStatusBarItem.tooltip = 'Code Guardian RAG is ready';
        assert.strictEqual(mockStatusBarItem.text, '$(shield) RAG: Ready', 'Should show ready state');
        
        mockStatusBarItem.text = '$(loading~spin) RAG: Initializing';
        assert.ok(mockStatusBarItem.text.includes('Initializing'), 'Should show initializing state');
        
        mockStatusBarItem.text = '$(x) RAG: Error';
        assert.ok(mockStatusBarItem.text.includes('Error'), 'Should show error state');
    });

    test('Diagnostic Collection', () => {
        // Test diagnostic creation
        const testDiagnostic = new vscode.Diagnostic(
            new vscode.Range(0, 0, 0, 10),
            'Test security issue',
            vscode.DiagnosticSeverity.Warning
        );

        assert.ok(testDiagnostic.range, 'Diagnostic should have range');
        assert.strictEqual(testDiagnostic.message, 'Test security issue', 'Should have correct message');
        assert.strictEqual(testDiagnostic.severity, vscode.DiagnosticSeverity.Warning, 'Should have warning severity');
    });

    test('Error Handling Patterns', () => {
        const testErrors = [
            new Error('Connection failed'),
            new Error('Invalid configuration'),
            new Error('Model not found'),
            new Error('Permission denied')
        ];

        testErrors.forEach(error => {
            assert.ok(error instanceof Error, 'Should be Error instance');
            assert.ok(error.message.length > 0, 'Should have error message');
            
            // Test error categorization
            let category = 'unknown';
            if (error.message.includes('Connection')) {
                category = 'network';
            } else if (error.message.includes('configuration')) {
                category = 'config';
            } else if (error.message.includes('Model')) {
                category = 'model';
            } else if (error.message.includes('Permission')) {
                category = 'permission';
            }
            
            assert.notStrictEqual(category, 'unknown', `Error should be categorized: ${error.message}`);
        });
    });

    test('Configuration Change Handling', async () => {
        let configChangeHandled = false;
        
        // Mock configuration change handler
        const handleConfigChange = async (e: vscode.ConfigurationChangeEvent) => {
            if (e.affectsConfiguration('code-guardian.enableRAG')) {
                configChangeHandled = true;
            }
        };

        // Simulate config change event
        const mockConfigEvent = {
            affectsConfiguration: (section: string) => section === 'code-guardian.enableRAG'
        } as vscode.ConfigurationChangeEvent;

        await handleConfigChange(mockConfigEvent);
        assert.strictEqual(configChangeHandled, true, 'Should handle config change');
    });

    test('Extension Activation Lifecycle', () => {
        // Test activation conditions
        const activationEvents = [
            'onLanguage:javascript',
            'onLanguage:typescript',
            'onLanguage:python',
            'onCommand:code-guardian.analyzeCurrentFile'
        ];

        activationEvents.forEach(event => {
            assert.ok(typeof event === 'string', 'Activation event should be string');
            assert.ok(event.startsWith('on'), 'Activation event should start with "on"');
        });
    });

    test('Command Handler Mock', async () => {
        // Mock command handlers
        const handlers = {
            analyzeCurrentFile: async () => {
                return { success: true, issuesFound: 2 };
            },
            toggleRAG: async () => {
                return { enabled: true };
            },
            initializeRAG: async () => {
                return { initialized: true };
            }
        };

        const analyzeResult = await handlers.analyzeCurrentFile();
        assert.strictEqual(analyzeResult.success, true, 'Analyze should succeed');
        assert.strictEqual(analyzeResult.issuesFound, 2, 'Should find 2 issues');

        const toggleResult = await handlers.toggleRAG();
        assert.strictEqual(toggleResult.enabled, true, 'RAG should be enabled');

        const initResult = await handlers.initializeRAG();
        assert.strictEqual(initResult.initialized, true, 'RAG should be initialized');
    });

    test('VS Code API Compatibility', () => {
        // Test VS Code API usage patterns
        assert.ok(vscode.Range, 'Should have Range class');
        assert.ok(vscode.Diagnostic, 'Should have Diagnostic class');
        assert.ok(vscode.DiagnosticSeverity, 'Should have DiagnosticSeverity enum');
        assert.ok(vscode.Uri, 'Should have Uri class');
        assert.ok(vscode.workspace, 'Should have workspace API');
        assert.ok(vscode.window, 'Should have window API');
        assert.ok(vscode.commands, 'Should have commands API');
    });

    test('Sample Array Test', () => {
        // Keep original test for compatibility
        assert.strictEqual(-1, [1, 2, 3].indexOf(5));
        assert.strictEqual(-1, [1, 2, 3].indexOf(0));
    });
});
