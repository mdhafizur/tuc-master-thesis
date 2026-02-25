import * as path from 'path';
import { runTests } from '@vscode/test-electron';

/**
 * VS Code Extension Test Configuration
 * Configures the test environment for Code Guardian extension evaluation
 */
export interface TestConfig {
    /** Path to the extension root directory */
    extensionDevelopmentPath: string;
    /** Path to the test suite */
    extensionTestsPath: string;
    /** Launch arguments for VS Code */
    launchArgs: string[];
    /** Environment variables */
    env?: Record<string, string>;
    /** Test timeout in milliseconds */
    timeout?: number;
    /** VS Code version to test against */
    version?: string;
}

/**
 * Default test configuration for Code Guardian extension
 */
export const defaultTestConfig: TestConfig = {
    // Path to extension root (parent directory of the testing framework)
    extensionDevelopmentPath: path.resolve(__dirname, '../../../'),
    // Path to the compiled test suite
    extensionTestsPath: path.resolve(__dirname, './test-runner'),
    // Launch VS Code with specific settings
    launchArgs: [
        '--no-sandbox',
        '--disable-updates',
        '--disable-extensions',
        '--disable-workspace-trust',
        '--user-data-dir=' + path.resolve(__dirname, '../results/vscode-test-data'),
        // Open a temporary workspace for testing
        path.resolve(__dirname, '../test-workspaces/sample-workspace')
    ],
    env: {
        // Disable telemetry during testing
        'VSCODE_DISABLE_TELEMETRY': '1',
        // Set testing mode
        'NODE_ENV': 'test',
        // Increase memory limit for large test suites
        'NODE_OPTIONS': '--max-old-space-size=4096'
    },
    timeout: 30000, // 30 second timeout
    version: '1.98.0' // Specific VS Code version for reproducible testing
};

/**
 * Extension Test Runner
 * Handles the lifecycle of VS Code extension testing
 */
export class ExtensionTestRunner {
    private config: TestConfig;

    constructor(config: Partial<TestConfig> = {}) {
        this.config = { ...defaultTestConfig, ...config };
    }

    /**
     * Run the extension test suite
     */
    async runTests(): Promise<void> {
        try {
            console.log('🚀 Starting VS Code Extension Tests...');
            console.log(`Extension Path: ${this.config.extensionDevelopmentPath}`);
            console.log(`Test Path: ${this.config.extensionTestsPath}`);
            
            // Download and run VS Code with the extension
            const exitCode = await runTests({
                extensionDevelopmentPath: this.config.extensionDevelopmentPath,
                extensionTestsPath: this.config.extensionTestsPath,
                launchArgs: this.config.launchArgs,
                version: this.config.version
            });

            if (exitCode === 0) {
                console.log('✅ All tests passed!');
            } else {
                console.error(`❌ Tests failed with exit code: ${exitCode}`);
                process.exit(exitCode);
            }
        } catch (error) {
            console.error('💥 Test execution failed:', error);
            process.exit(1);
        }
    }

    /**
     * Setup test environment
     */
    async setupTestEnvironment(): Promise<void> {
        const fs = require('fs-extra');
        const testDataDir = path.resolve(__dirname, '../results/vscode-test-data');
        const testWorkspaceDir = path.resolve(__dirname, '../test-workspaces');
        
        // Ensure test directories exist
        await fs.ensureDir(testDataDir);
        await fs.ensureDir(testWorkspaceDir);
        
        // Create sample workspace if it doesn't exist
        const sampleWorkspacePath = path.join(testWorkspaceDir, 'sample-workspace');
        await fs.ensureDir(sampleWorkspacePath);
        
        // Create sample JavaScript files for testing
        await this.createSampleTestFiles(sampleWorkspacePath);
        
        console.log('🔧 Test environment setup complete');
    }

    /**
     * Create sample test files with known vulnerabilities
     */
    private async createSampleTestFiles(workspacePath: string): Promise<void> {
        const fs = require('fs-extra');
        
        // Sample vulnerable JavaScript file
        const vulnerableJs = `
// Sample vulnerable JavaScript code for testing
function unsafeEval(userInput) {
    // SECURITY VULNERABILITY: eval() usage
    return eval(userInput);
}

function sqlInjectionVuln(userId) {
    // SECURITY VULNERABILITY: SQL injection
    const query = "SELECT * FROM users WHERE id = " + userId;
    return database.query(query);
}

function xssVulnerability(userInput) {
    // SECURITY VULNERABILITY: XSS
    document.getElementById('output').innerHTML = userInput;
}

module.exports = { unsafeEval, sqlInjectionVuln, xssVulnerability };
`;

        // Sample vulnerable TypeScript file
        const vulnerableTs = `
interface User {
    id: string;
    name: string;
    email: string;
}

class UserService {
    // SECURITY VULNERABILITY: Hardcoded credentials
    private apiKey = "sk-1234567890abcdef";
    
    async getUserData(userId: string): Promise<User> {
        // SECURITY VULNERABILITY: Path traversal
        const filePath = "./users/" + userId + ".json";
        const fs = require('fs');
        const data = fs.readFileSync(filePath, 'utf8');
        return JSON.parse(data);
    }
    
    validateInput(input: any): boolean {
        // SECURITY VULNERABILITY: Prototype pollution
        if (input.constructor && input.constructor.prototype) {
            input.constructor.prototype.isAdmin = true;
        }
        return true;
    }
}

export { UserService, User };
`;

        // Write sample files
        await fs.writeFile(path.join(workspacePath, 'vulnerable.js'), vulnerableJs);
        await fs.writeFile(path.join(workspacePath, 'vulnerable.ts'), vulnerableTs);
        
        // Create package.json for the test workspace
        const packageJson = {
            name: "test-workspace",
            version: "1.0.0",
            description: "Test workspace for Code Guardian extension",
            main: "vulnerable.js",
            dependencies: {}
        };
        await fs.writeFile(
            path.join(workspacePath, 'package.json'), 
            JSON.stringify(packageJson, null, 2)
        );
    }

    /**
     * Cleanup test environment
     */
    async cleanupTestEnvironment(): Promise<void> {
        const fs = require('fs-extra');
        const testDataDir = path.resolve(__dirname, '../results/vscode-test-data');
        
        try {
            await fs.remove(testDataDir);
            console.log('🧹 Test environment cleanup complete');
        } catch (error) {
            console.warn('⚠️ Cleanup warning:', error);
        }
    }
}
