import * as path from 'path';
import { runTests } from '@vscode/test-electron';

async function main() {
    try {
        // The folder containing the Extension Manifest package.json
        // Passed to `--extensionDevelopmentPath`  
        const extensionDevelopmentPath = path.resolve(__dirname, '../../../');

        // The path to test runner
        // Passed to --extensionTestsPath
        const extensionTestsPath = path.resolve(__dirname, './suite/index');

        // Use a shorter temp directory path to avoid IPC socket issues
        const tmpDir = process.platform === 'darwin' ? '/tmp' : require('os').tmpdir();
        const userDataDir = path.join(tmpDir, 'vscode-test-data');

        console.log(`Extension path: ${extensionDevelopmentPath}`);
        console.log(`Test path: ${extensionTestsPath}`);
        console.log(`User data dir: ${userDataDir}`);

        // Download VS Code, unzip it and run the integration test
        await runTests({ 
            extensionDevelopmentPath, 
            extensionTestsPath,
            launchArgs: [
                '--disable-workspace-trust',
                '--no-sandbox',
                '--user-data-dir=' + userDataDir
            ],
            version: '1.98.0' // Use a compatible version
        });
    } catch (err) {
        console.error('Failed to run tests:', err);
        process.exit(1);
    }
}

main();
