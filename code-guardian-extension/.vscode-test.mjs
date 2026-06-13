import { defineConfig } from '@vscode/test-cli';

export default defineConfig({
	files: 'out/test/**/*.test.js',
	// Use a short user-data-dir so the VS Code IPC socket path stays under the
	// 103-char macOS Unix-domain-socket limit (the repo path is long).
	launchArgs: ['--user-data-dir', '/tmp/vsct-cg'],
});
