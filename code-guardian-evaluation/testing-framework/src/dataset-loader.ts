/**
 * Dataset Loader for Code Guardian Evaluation
 * 
 * This module loads vulnerability datasets from the comprehensive evaluation datasets
 * and provides them in the format expected by the testing framework.
 */

import * as fs from 'fs/promises';
import * as path from 'path';

export interface VulnerabilityDataset {
    metadata: {
        name: string;
        total_samples: number;
        categories: string[];
        languages: string[];
        sources: string[];
        cwe_ids: string[];
        generated_at: string;
        collection_method: string;
    };
    samples: VulnerabilitySample[];
}

export interface VulnerabilitySample {
    id: string;
    cwe_id: string;
    category: string;
    language: string;
    description: string;
    code: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
    source: string;
    vulnerable_lines: number[];
    created_at: string;
}

export interface DatasetSummary {
    totalSamples: number;
    datasets: string[];
    categories: Set<string>;
    cweIds: Set<string>;
    severityDistribution: Record<string, number>;
    languageDistribution: Record<string, number>;
}

export class DatasetLoader {
    private datasetsDir: string;
    private loadedDatasets: Map<string, VulnerabilityDataset> = new Map();

    constructor(datasetsDir: string = '../datasets') {
        // Resolve the datasets directory relative to the evaluation folder
        if (!path.isAbsolute(datasetsDir)) {
            this.datasetsDir = path.resolve(__dirname, datasetsDir);
        } else {
            this.datasetsDir = datasetsDir;
        }
        this.loadedDatasets = new Map();
    }

    /**
     * Load all available datasets
     */
    async loadAllDatasets(): Promise<Map<string, VulnerabilityDataset>> {
        const datasetTypes = ['benchmark', 'adversarial', 'extended', 'real-world'];
        
        for (const datasetType of datasetTypes) {
            try {
                const dataset = await this.loadDataset(datasetType);
                if (dataset) {
                    this.loadedDatasets.set(datasetType, dataset);
                    console.log(`✅ Loaded ${datasetType} dataset: ${dataset.samples.length} samples`);
                }
            } catch (error: any) {
                console.warn(`⚠️ Failed to load ${datasetType} dataset:`, error?.message || error);
            }
        }

        return this.loadedDatasets;
    }

    /**
     * Load a specific dataset by name
     */
    async loadDataset(datasetName: string): Promise<VulnerabilityDataset | null> {
        const datasetPath = path.join(this.datasetsDir, datasetName, `${datasetName}_dataset.json`);
        
        try {
            const content = await fs.readFile(datasetPath, 'utf-8');
            const dataset: VulnerabilityDataset = JSON.parse(content);
            
            // Validate dataset structure
            if (!dataset.metadata || !dataset.samples) {
                throw new Error(`Invalid dataset structure in ${datasetName}`);
            }

            return dataset;
        } catch (error: any) {
            console.error(`Failed to load dataset ${datasetName}:`, error?.message || error);
            return null;
        }
    }

    /**
     * Get samples by category across all loaded datasets
     */
    getSamplesByCategory(category: string): VulnerabilitySample[] {
        const samples: VulnerabilitySample[] = [];
        
        for (const dataset of this.loadedDatasets.values()) {
            const categorySamples = dataset.samples.filter(sample => 
                sample.category === category
            );
            samples.push(...categorySamples);
        }

        return samples;
    }

    /**
     * Get all samples from all loaded datasets
     */
    getAllSamples(): VulnerabilitySample[] {
        const samples: VulnerabilitySample[] = [];
        
        for (const dataset of this.loadedDatasets.values()) {
            samples.push(...dataset.samples);
        }

        return samples;
    }

    /**
     * Get samples by CWE ID across all loaded datasets
     */
    getSamplesByCWE(cweId: string): VulnerabilitySample[] {
        const samples: VulnerabilitySample[] = [];
        
        for (const dataset of this.loadedDatasets.values()) {
            const cweSamples = dataset.samples.filter(sample => 
                sample.cwe_id === cweId
            );
            samples.push(...cweSamples);
        }

        return samples;
    }

    /**
     * Get samples by severity across all loaded datasets
     */
    getSamplesBySeverity(severity: string): VulnerabilitySample[] {
        const samples: VulnerabilitySample[] = [];
        
        for (const dataset of this.loadedDatasets.values()) {
            const severitySamples = dataset.samples.filter(sample => 
                sample.severity === severity
            );
            samples.push(...severitySamples);
        }

        return samples;
    }

    /**
     * Get random samples for testing
     */
    getRandomSamples(count: number, filterBy?: {
        category?: string;
        severity?: string;
        cweId?: string;
        language?: string;
    }): VulnerabilitySample[] {
        let allSamples: VulnerabilitySample[] = [];
        
        // Collect all samples from loaded datasets
        for (const dataset of this.loadedDatasets.values()) {
            allSamples.push(...dataset.samples);
        }

        // Apply filters if provided
        if (filterBy) {
            if (filterBy.category) {
                allSamples = allSamples.filter(s => s.category === filterBy.category);
            }
            if (filterBy.severity) {
                allSamples = allSamples.filter(s => s.severity === filterBy.severity);
            }
            if (filterBy.cweId) {
                allSamples = allSamples.filter(s => s.cwe_id === filterBy.cweId);
            }
            if (filterBy.language) {
                allSamples = allSamples.filter(s => s.language === filterBy.language);
            }
        }

        // Shuffle and return requested count
        const shuffled = allSamples.sort(() => Math.random() - 0.5);
        return shuffled.slice(0, count);
    }

    /**
     * Get summary statistics of all loaded datasets
     */
    getDatasetSummary(): DatasetSummary {
        const summary: DatasetSummary = {
            totalSamples: 0,
            datasets: Array.from(this.loadedDatasets.keys()),
            categories: new Set(),
            cweIds: new Set(),
            severityDistribution: {},
            languageDistribution: {}
        };

        for (const [datasetName, dataset] of this.loadedDatasets.entries()) {
            summary.totalSamples += dataset.samples.length;

            for (const sample of dataset.samples) {
                summary.categories.add(sample.category);
                summary.cweIds.add(sample.cwe_id);
                
                // Count severity distribution
                summary.severityDistribution[sample.severity] = 
                    (summary.severityDistribution[sample.severity] || 0) + 1;
                
                // Count language distribution
                summary.languageDistribution[sample.language] = 
                    (summary.languageDistribution[sample.language] || 0) + 1;
            }
        }

        return summary;
    }

    /**
     * Convert vulnerability samples to the test framework format
     */
    samplesToTestCases(samples: VulnerabilitySample[]): any[] {
        return samples.map(sample => ({
            id: sample.id,
            name: sample.description,
            filePath: `temp_${sample.id}.${sample.language === 'typescript' ? 'ts' : 'js'}`,
            content: sample.code,
            language: sample.language,
            expectedVulnerabilities: [{
                vulnerabilityType: sample.category,
                severity: sample.severity,
                cweId: sample.cwe_id,
                lineNumbers: sample.vulnerable_lines,
                description: sample.description
            }],
            metadata: {
                source: sample.source,
                cweId: sample.cwe_id,
                category: sample.category,
                createdAt: sample.created_at
            }
        }));
    }

    /**
     * Create temporary test files from samples
     */
    async createTestFiles(samples: VulnerabilitySample[], outputDir: string): Promise<string[]> {
        await fs.mkdir(outputDir, { recursive: true });
        const createdFiles: string[] = [];

        for (const sample of samples) {
            const extension = sample.language === 'typescript' ? 'ts' : 'js';
            const fileName = `${sample.id}.${extension}`;
            const filePath = path.join(outputDir, fileName);
            
            // Add metadata as comments
            const fileContent = `/* 
 * Vulnerability Test Case: ${sample.description}
 * CWE ID: ${sample.cwe_id}
 * Category: ${sample.category}
 * Severity: ${sample.severity}
 * Source: ${sample.source}
 * Vulnerable lines: ${sample.vulnerable_lines.join(', ')}
 */

${sample.code}
`;

            await fs.writeFile(filePath, fileContent, 'utf-8');
            createdFiles.push(filePath);
        }

        return createdFiles;
    }

    /**
     * Get dataset statistics for academic reporting
     */
    getAcademicStatistics(): any {
        const summary = this.getDatasetSummary();
        
        return {
            datasetComposition: {
                totalSamples: summary.totalSamples,
                datasetsUsed: summary.datasets,
                uniqueVulnerabilityTypes: summary.categories.size,
                uniqueCWEs: summary.cweIds.size
            },
            vulnerabilityDistribution: {
                byCategory: Array.from(summary.categories).map(cat => ({
                    category: cat,
                    count: this.getSamplesByCategory(cat).length
                })),
                bySeverity: summary.severityDistribution,
                byLanguage: summary.languageDistribution
            },
            datasetSources: this.getDatasetSources(),
            evaluationScope: {
                coversCWEs: Array.from(summary.cweIds).sort(),
                coversCategories: Array.from(summary.categories).sort(),
                totalEvaluationCases: summary.totalSamples
            }
        };
    }

    private getDatasetSources(): any {
        const sources = new Set<string>();
        
        for (const dataset of this.loadedDatasets.values()) {
            dataset.metadata.sources.forEach(source => sources.add(source));
        }

        return Array.from(sources);
    }
}

export default DatasetLoader;
