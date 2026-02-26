import * as vscode from 'vscode';
import * as path from 'path';

/**
 * Extension testing utilities for automated testing of Code Guardian extension
 */
export class ExtensionTestUtils {
    private extension: vscode.Extension<any> | undefined;
    private readonly extensionId = 'DreamersRedemption.code-guardian';

    /**
     * Wait for extension to be activated
     */
    async waitForExtensionActivation(timeout: number = 10000): Promise<vscode.Extension<any>> {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();
            
            const checkActivation = () => {
                this.extension = vscode.extensions.getExtension(this.extensionId);
                
                if (this.extension?.isActive) {
                    resolve(this.extension);
                    return;
                }

                if (Date.now() - startTime > timeout) {
                    reject(new Error(`Extension ${this.extensionId} failed to activate within ${timeout}ms`));
                    return;
                }

                setTimeout(checkActivation, 100);
            };

            checkActivation();
        });
    }

    /**
     * Get the activated extension instance
     */
    getExtension(): vscode.Extension<any> | undefined {
        return this.extension || vscode.extensions.getExtension(this.extensionId);
    }

    /**
     * Execute a command and wait for completion
     */
    async executeCommand(command: string, ...args: any[]): Promise<any> {
        try {
            const result = await vscode.commands.executeCommand(command, ...args);
            return result;
        } catch (error) {
            throw new Error(`Failed to execute command ${command}: ${error}`);
        }
    }

    /**
     * Open a file in the editor
     */
    async openFile(filePath: string): Promise<vscode.TextEditor> {
        const uri = vscode.Uri.file(filePath);
        const document = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(document);
        return editor;
    }

    /**
     * Create a new file with content
     */
    async createTestFile(content: string, fileName: string = 'test.js'): Promise<vscode.TextEditor> {
        const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
        if (!workspaceFolder) {
            throw new Error('No workspace folder available');
        }

        const filePath = path.join(workspaceFolder.uri.fsPath, fileName);
        const uri = vscode.Uri.file(filePath);
        
        await vscode.workspace.fs.writeFile(uri, Buffer.from(content, 'utf8'));
        
        const document = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(document);
        
        return editor;
    }

    /**
     * Select text in the active editor
     */
    async selectText(startLine: number, startChar: number, endLine: number, endChar: number): Promise<void> {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            throw new Error('No active editor');
        }

        const start = new vscode.Position(startLine, startChar);
        const end = new vscode.Position(endLine, endChar);
        const selection = new vscode.Selection(start, end);
        
        editor.selection = selection;
        editor.revealRange(selection, vscode.TextEditorRevealType.InCenter);
    }

    /**
     * Wait for diagnostics to be updated
     */
    async waitForDiagnostics(uri: vscode.Uri, timeout: number = 5000): Promise<vscode.Diagnostic[]> {
        return new Promise((resolve, reject) => {
            const startTime = Date.now();
            
            const checkDiagnostics = () => {
                const diagnostics = vscode.languages.getDiagnostics(uri);
                
                if (diagnostics.length > 0 || Date.now() - startTime > timeout) {
                    resolve(diagnostics);
                    return;
                }

                setTimeout(checkDiagnostics, 100);
            };

            checkDiagnostics();
        });
    }

    /**
     * Clear all diagnostics for a specific collection
     */
    clearDiagnostics(collectionName: string = 'codeSecurity'): void {
        // Find and clear the specific diagnostic collection
        // Note: VS Code doesn't provide a way to get all collections, 
        // so we need to clear the known collection
        const collections = vscode.languages.createDiagnosticCollection(collectionName);
        collections.clear();
        collections.dispose();
    }

    /**
     * Wait for a specific amount of time
     */
    async wait(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Capture current editor state
     */
    captureEditorState(): EditorState {
        const editor = vscode.window.activeTextEditor;
        if (!editor) {
            throw new Error('No active editor');
        }

        return {
            fileName: path.basename(editor.document.fileName),
            content: editor.document.getText(),
            selection: {
                start: {
                    line: editor.selection.start.line,
                    character: editor.selection.start.character
                },
                end: {
                    line: editor.selection.end.line,
                    character: editor.selection.end.character
                }
            },
            cursorPosition: {
                line: editor.selection.active.line,
                character: editor.selection.active.character
            }
        };
    }

    /**
     * Compare two editor states
     */
    compareEditorStates(state1: EditorState, state2: EditorState): EditorStateDiff {
        return {
            contentChanged: state1.content !== state2.content,
            selectionChanged: !this.selectionsEqual(state1.selection, state2.selection),
            cursorMoved: !this.positionsEqual(state1.cursorPosition, state2.cursorPosition)
        };
    }

    private selectionsEqual(sel1: any, sel2: any): boolean {
        return this.positionsEqual(sel1.start, sel2.start) && 
               this.positionsEqual(sel1.end, sel2.end);
    }

    private positionsEqual(pos1: any, pos2: any): boolean {
        return pos1.line === pos2.line && pos1.character === pos2.character;
    }

    /**
     * Cleanup test files
     */
    async cleanup(): Promise<void> {
        try {
            // Close all open editors
            await vscode.commands.executeCommand('workbench.action.closeAllEditors');
            
            // Clear diagnostics
            this.clearDiagnostics();
            
            // Reset selection
            const editor = vscode.window.activeTextEditor;
            if (editor) {
                editor.selection = new vscode.Selection(0, 0, 0, 0);
            }
        } catch (error) {
            console.warn('Cleanup warning:', error);
        }
    }
}

/**
 * Interface for capturing editor state
 */
export interface EditorState {
    fileName: string;
    content: string;
    selection: {
        start: { line: number; character: number };
        end: { line: number; character: number };
    };
    cursorPosition: { line: number; character: number };
}

/**
 * Interface for editor state differences
 */
export interface EditorStateDiff {
    contentChanged: boolean;
    selectionChanged: boolean;
    cursorMoved: boolean;
}
