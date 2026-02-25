import * as vscode from 'vscode';

/**
 * Diagnostic validation utilities for testing Code Guardian extension diagnostics
 */
export class DiagnosticValidator {
    /**
     * Validate that expected vulnerabilities are detected
     */
    validateDetection(
        diagnostics: vscode.Diagnostic[], 
        expectedVulnerabilities: ExpectedVulnerability[]
    ): ValidationResult {
        const results: VulnerabilityValidation[] = [];
        let truePositives = 0;
        let falsePositives = 0;
        let falseNegatives = 0;

        // Check each expected vulnerability
        for (const expected of expectedVulnerabilities) {
            const matchingDiagnostics = this.findMatchingDiagnostics(diagnostics, expected);
            
            if (matchingDiagnostics.length > 0) {
                truePositives++;
                results.push({
                    expected,
                    detected: true,
                    matchingDiagnostics,
                    type: 'true_positive'
                });
            } else {
                falseNegatives++;
                results.push({
                    expected,
                    detected: false,
                    matchingDiagnostics: [],
                    type: 'false_negative'
                });
            }
        }

        // Check for false positives (diagnostics that don't match any expected vulnerability)
        for (const diagnostic of diagnostics) {
            const matchesExpected = expectedVulnerabilities.some(expected => 
                this.diagnosticMatchesExpected(diagnostic, expected)
            );
            
            if (!matchesExpected) {
                falsePositives++;
                results.push({
                    expected: null,
                    detected: true,
                    matchingDiagnostics: [diagnostic],
                    type: 'false_positive'
                });
            }
        }

        // Calculate metrics
        const precision = truePositives + falsePositives > 0 ? 
            truePositives / (truePositives + falsePositives) : 0;
        const recall = truePositives + falseNegatives > 0 ? 
            truePositives / (truePositives + falseNegatives) : 0;
        const f1Score = precision + recall > 0 ? 
            2 * (precision * recall) / (precision + recall) : 0;

        return {
            truePositives,
            falsePositives,
            falseNegatives,
            precision,
            recall,
            f1Score,
            totalExpected: expectedVulnerabilities.length,
            totalDetected: diagnostics.length,
            validations: results
        };
    }

    /**
     * Find diagnostics that match an expected vulnerability
     */
    private findMatchingDiagnostics(
        diagnostics: vscode.Diagnostic[], 
        expected: ExpectedVulnerability
    ): vscode.Diagnostic[] {
        return diagnostics.filter(diagnostic => 
            this.diagnosticMatchesExpected(diagnostic, expected)
        );
    }

    /**
     * Check if a diagnostic matches an expected vulnerability
     */
    private diagnosticMatchesExpected(
        diagnostic: vscode.Diagnostic, 
        expected: ExpectedVulnerability
    ): boolean {
        // Check line range
        const diagnosticLine = diagnostic.range.start.line;
        const inRange = diagnosticLine >= expected.startLine && 
                       diagnosticLine <= expected.endLine;

        if (!inRange) {
            return false;
        }

        // Check message content if specified
        if (expected.messageContains) {
            const messageMatch = expected.messageContains.some(keyword =>
                diagnostic.message.toLowerCase().includes(keyword.toLowerCase())
            );
            if (!messageMatch) {
                return false;
            }
        }

        // Check severity if specified
        if (expected.severity !== undefined) {
            if (diagnostic.severity !== expected.severity) {
                return false;
            }
        }

        // Check vulnerability type if specified
        if (expected.vulnerabilityType) {
            const typeMatch = this.checkVulnerabilityType(diagnostic, expected.vulnerabilityType);
            if (!typeMatch) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check if diagnostic matches a specific vulnerability type
     */
    private checkVulnerabilityType(
        diagnostic: vscode.Diagnostic, 
        expectedType: VulnerabilityType
    ): boolean {
        const message = diagnostic.message.toLowerCase();
        
        const typeKeywords: Record<VulnerabilityType, string[]> = {
            'sql_injection': ['sql', 'injection', 'query'],
            'xss': ['xss', 'cross-site', 'script', 'innerhtml'],
            'code_injection': ['eval', 'execution', 'injection'],
            'path_traversal': ['path', 'traversal', 'directory'],
            'hardcoded_credentials': ['credential', 'password', 'key', 'secret'],
            'prototype_pollution': ['prototype', 'pollution', '__proto__'],
            'insecure_crypto': ['crypto', 'encryption', 'hash', 'cipher'],
            'dos': ['denial', 'service', 'resource', 'exhaustion'],
            'buffer_overflow': ['buffer', 'overflow', 'bounds'],
            'race_condition': ['race', 'condition', 'concurrent'],
            'other': []
        };

        const keywords = typeKeywords[expectedType] || [];
        return keywords.some(keyword => message.includes(keyword));
    }

    /**
     * Validate diagnostic message quality
     */
    validateDiagnosticQuality(diagnostics: vscode.Diagnostic[]): DiagnosticQualityReport {
        const qualityMetrics: DiagnosticQuality[] = [];

        for (const diagnostic of diagnostics) {
            const quality = this.assessDiagnosticQuality(diagnostic);
            qualityMetrics.push(quality);
        }

        // Calculate overall quality metrics
        const averageClarity = qualityMetrics.reduce((sum, q) => sum + q.clarityScore, 0) / qualityMetrics.length;
        const averageActionability = qualityMetrics.reduce((sum, q) => sum + q.actionabilityScore, 0) / qualityMetrics.length;
        const averageAccuracy = qualityMetrics.reduce((sum, q) => sum + q.accuracyScore, 0) / qualityMetrics.length;

        const highQuality = qualityMetrics.filter(q => q.overallScore >= 0.8).length;
        const mediumQuality = qualityMetrics.filter(q => q.overallScore >= 0.5 && q.overallScore < 0.8).length;
        const lowQuality = qualityMetrics.filter(q => q.overallScore < 0.5).length;

        return {
            totalDiagnostics: diagnostics.length,
            averageClarity,
            averageActionability,
            averageAccuracy,
            highQualityCount: highQuality,
            mediumQualityCount: mediumQuality,
            lowQualityCount: lowQuality,
            individualQualities: qualityMetrics
        };
    }

    /**
     * Assess the quality of a single diagnostic
     */
    private assessDiagnosticQuality(diagnostic: vscode.Diagnostic): DiagnosticQuality {
        const message = diagnostic.message;
        
        // Clarity: Is the message clear and understandable?
        const clarityScore = this.assessClarity(message);
        
        // Actionability: Does the message provide actionable guidance?
        const actionabilityScore = this.assessActionability(message);
        
        // Accuracy: Is the diagnostic likely to be accurate based on heuristics?
        const accuracyScore = this.assessAccuracy(diagnostic);

        const overallScore = (clarityScore + actionabilityScore + accuracyScore) / 3;

        return {
            diagnostic,
            clarityScore,
            actionabilityScore,
            accuracyScore,
            overallScore,
            feedback: this.generateQualityFeedback(clarityScore, actionabilityScore, accuracyScore)
        };
    }

    /**
     * Assess message clarity
     */
    private assessClarity(message: string): number {
        let score = 0.5; // Base score

        // Length check
        if (message.length > 20 && message.length < 200) {
            score += 0.2;
        }
        
        // Contains specific terms
        if (message.includes('vulnerability') || message.includes('security')) {
            score += 0.1;
        }
        
        // Well-formed sentences
        if (message.match(/^[A-Z].*[.!?]$/)) {
            score += 0.1;
        }
        
        // Technical detail without being too verbose
        if (message.split(' ').length > 5 && message.split(' ').length < 25) {
            score += 0.1;
        }

        return Math.min(score, 1.0);
    }

    /**
     * Assess message actionability
     */
    private assessActionability(message: string): number {
        let score = 0.3; // Base score

        // Contains action words
        const actionWords = ['fix', 'replace', 'use', 'avoid', 'should', 'consider', 'instead'];
        if (actionWords.some(word => message.toLowerCase().includes(word))) {
            score += 0.3;
        }

        // Contains specific suggestions
        if (message.includes('→') || message.includes('->') || message.includes('try')) {
            score += 0.2;
        }

        // Contains code examples or specific alternatives
        if (message.includes('`') || message.includes('()')) {
            score += 0.2;
        }

        return Math.min(score, 1.0);
    }

    /**
     * Assess diagnostic accuracy based on heuristics
     */
    private assessAccuracy(diagnostic: vscode.Diagnostic): number {
        let score = 0.7; // Base score - assume reasonably accurate

        // High severity should be reserved for serious issues
        if (diagnostic.severity === vscode.DiagnosticSeverity.Error) {
            const message = diagnostic.message.toLowerCase();
            const seriousKeywords = ['vulnerability', 'injection', 'xss', 'security', 'exploit'];
            if (seriousKeywords.some(keyword => message.includes(keyword))) {
                score += 0.2;
            } else {
                score -= 0.1; // Penalty for potentially over-severe rating
            }
        }

        // Range accuracy - should not be too broad
        const rangeSize = diagnostic.range.end.line - diagnostic.range.start.line;
        if (rangeSize <= 2) {
            score += 0.1;
        } else if (rangeSize > 10) {
            score -= 0.1;
        }

        return Math.min(Math.max(score, 0), 1.0);
    }

    /**
     * Generate quality feedback
     */
    private generateQualityFeedback(clarity: number, actionability: number, accuracy: number): string[] {
        const feedback: string[] = [];

        if (clarity < 0.6) {
            feedback.push('Message could be clearer and more specific');
        }

        if (actionability < 0.6) {
            feedback.push('Message should provide more actionable guidance');
        }

        if (accuracy < 0.6) {
            feedback.push('Diagnostic accuracy may be questionable');
        }

        if (feedback.length === 0) {
            feedback.push('Good quality diagnostic message');
        }

        return feedback;
    }

    /**
     * Compare diagnostics between different runs
     */
    compareDiagnosticRuns(
        baselineDiagnostics: vscode.Diagnostic[],
        testDiagnostics: vscode.Diagnostic[]
    ): DiagnosticComparison {
        const baselineSet = new Set(baselineDiagnostics.map(d => this.diagnosticToString(d)));
        const testSet = new Set(testDiagnostics.map(d => this.diagnosticToString(d)));

        const unchanged: vscode.Diagnostic[] = [];
        const added: vscode.Diagnostic[] = [];
        const removed: vscode.Diagnostic[] = [];

        // Find unchanged and removed
        for (const diagnostic of baselineDiagnostics) {
            const diagString = this.diagnosticToString(diagnostic);
            if (testSet.has(diagString)) {
                unchanged.push(diagnostic);
            } else {
                removed.push(diagnostic);
            }
        }

        // Find added
        for (const diagnostic of testDiagnostics) {
            const diagString = this.diagnosticToString(diagnostic);
            if (!baselineSet.has(diagString)) {
                added.push(diagnostic);
            }
        }

        return {
            baseline: {
                count: baselineDiagnostics.length,
                diagnostics: baselineDiagnostics
            },
            test: {
                count: testDiagnostics.length,
                diagnostics: testDiagnostics
            },
            unchanged: {
                count: unchanged.length,
                diagnostics: unchanged
            },
            added: {
                count: added.length,
                diagnostics: added
            },
            removed: {
                count: removed.length,
                diagnostics: removed
            },
            stability: unchanged.length / Math.max(baselineDiagnostics.length, 1)
        };
    }

    /**
     * Convert diagnostic to string for comparison
     */
    private diagnosticToString(diagnostic: vscode.Diagnostic): string {
        return `${diagnostic.range.start.line}:${diagnostic.range.start.character}-${diagnostic.range.end.line}:${diagnostic.range.end.character}|${diagnostic.message}|${diagnostic.severity}`;
    }
}

/**
 * Interface for expected vulnerabilities
 */
export interface ExpectedVulnerability {
    vulnerabilityType?: VulnerabilityType;
    startLine: number;
    endLine: number;
    messageContains?: string[];
    severity?: vscode.DiagnosticSeverity;
    description?: string;
}

/**
 * Supported vulnerability types
 */
export type VulnerabilityType = 
    | 'sql_injection'
    | 'xss'
    | 'code_injection'
    | 'path_traversal'
    | 'hardcoded_credentials'
    | 'prototype_pollution'
    | 'insecure_crypto'
    | 'dos'
    | 'buffer_overflow'
    | 'race_condition'
    | 'other';

/**
 * Interface for vulnerability validation results
 */
export interface VulnerabilityValidation {
    expected: ExpectedVulnerability | null;
    detected: boolean;
    matchingDiagnostics: vscode.Diagnostic[];
    type: 'true_positive' | 'false_positive' | 'false_negative';
}

/**
 * Interface for validation results
 */
export interface ValidationResult {
    truePositives: number;
    falsePositives: number;
    falseNegatives: number;
    precision: number;
    recall: number;
    f1Score: number;
    totalExpected: number;
    totalDetected: number;
    validations: VulnerabilityValidation[];
}

/**
 * Interface for diagnostic quality assessment
 */
export interface DiagnosticQuality {
    diagnostic: vscode.Diagnostic;
    clarityScore: number;
    actionabilityScore: number;
    accuracyScore: number;
    overallScore: number;
    feedback: string[];
}

/**
 * Interface for diagnostic quality report
 */
export interface DiagnosticQualityReport {
    totalDiagnostics: number;
    averageClarity: number;
    averageActionability: number;
    averageAccuracy: number;
    highQualityCount: number;
    mediumQualityCount: number;
    lowQualityCount: number;
    individualQualities: DiagnosticQuality[];
}

/**
 * Interface for diagnostic comparison
 */
export interface DiagnosticComparison {
    baseline: {
        count: number;
        diagnostics: vscode.Diagnostic[];
    };
    test: {
        count: number;
        diagnostics: vscode.Diagnostic[];
    };
    unchanged: {
        count: number;
        diagnostics: vscode.Diagnostic[];
    };
    added: {
        count: number;
        diagnostics: vscode.Diagnostic[];
    };
    removed: {
        count: number;
        diagnostics: vscode.Diagnostic[];
    };
    stability: number; // Percentage of diagnostics that remained unchanged
}
