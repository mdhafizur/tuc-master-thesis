import * as vscode from 'vscode';

/**
 * Log levels for the extension
 */
export enum LogLevel {
    DEBUG = 0,
    INFO = 1,
    WARN = 2,
    ERROR = 3
}

/**
 * Logger class for Code Guardian extension
 * Provides structured logging to VS Code Output Channel and Debug Console
 */
export class Logger {
    private static instance: Logger;
    private outputChannel: vscode.OutputChannel;
    private currentLogLevel: LogLevel = LogLevel.INFO;

    private constructor() {
        this.outputChannel = vscode.window.createOutputChannel('Code Guardian');
    }

    /**
     * Get the singleton logger instance
     */
    public static getInstance(): Logger {
        if (!Logger.instance) {
            Logger.instance = new Logger();
        }
        return Logger.instance;
    }

    /**
     * Set the minimum log level to display
     */
    public setLogLevel(level: LogLevel): void {
        this.currentLogLevel = level;
    }

    /**
     * Show the output channel
     */
    public show(): void {
        this.outputChannel.show();
    }

    /**
     * Log a debug message (verbose information for troubleshooting)
     */
    public debug(message: string, ...args: any[]): void {
        this.log(LogLevel.DEBUG, '🔍', message, args);
    }

    /**
     * Log an info message (general information)
     */
    public info(message: string, ...args: any[]): void {
        this.log(LogLevel.INFO, 'ℹ️', message, args);
    }

    /**
     * Log a warning message
     */
    public warn(message: string, ...args: any[]): void {
        this.log(LogLevel.WARN, '⚠️', message, args);
    }

    /**
     * Log an error message
     */
    public error(message: string, error?: Error | unknown, ...args: any[]): void {
        const errorDetails = error instanceof Error
            ? `\n${error.name}: ${error.message}\n${error.stack}`
            : error
            ? `\n${JSON.stringify(error, null, 2)}`
            : '';
        this.log(LogLevel.ERROR, '❌', `${message}${errorDetails}`, args);
    }

    /**
     * Log a success message
     */
    public success(message: string, ...args: any[]): void {
        this.log(LogLevel.INFO, '✅', message, args);
    }

    /**
     * Log the start of an operation
     */
    public startOperation(operation: string): void {
        this.log(LogLevel.INFO, '🚀', `Starting: ${operation}`, []);
    }

    /**
     * Log the completion of an operation
     */
    public endOperation(operation: string, durationMs?: number): void {
        const duration = durationMs !== undefined ? ` (${durationMs}ms)` : '';
        this.log(LogLevel.INFO, '✅', `Completed: ${operation}${duration}`, []);
    }

    /**
     * Core logging method
     */
    private log(level: LogLevel, icon: string, message: string, args: any[]): void {
        if (level < this.currentLogLevel) {
            return;
        }

        const timestamp = new Date().toISOString();
        const levelName = LogLevel[level];
        const formattedArgs = args.length > 0 ? `\n${JSON.stringify(args, null, 2)}` : '';
        const logMessage = `[${timestamp}] ${icon} ${levelName}: ${message}${formattedArgs}`;

        // Output to VS Code Output Channel
        this.outputChannel.appendLine(logMessage);

        // Also output to Debug Console (console.log)
        switch (level) {
            case LogLevel.DEBUG:
                console.debug(logMessage);
                break;
            case LogLevel.INFO:
                console.log(logMessage);
                break;
            case LogLevel.WARN:
                console.warn(logMessage);
                break;
            case LogLevel.ERROR:
                console.error(logMessage);
                break;
        }
    }

    /**
     * Dispose of resources
     */
    public dispose(): void {
        this.outputChannel.dispose();
    }
}

/**
 * Convenience function to get the logger instance
 */
export function getLogger(): Logger {
    return Logger.getInstance();
}
