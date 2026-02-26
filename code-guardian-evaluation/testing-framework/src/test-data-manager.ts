import * as fs from 'fs-extra';
import * as path from 'path';
import { ExpectedVulnerability, VulnerabilityType } from './diagnostic-validator';

/**
 * Test data management system for loading and organizing test cases
 */
export class TestDataManager {
    private dataDir: string;
    private testCases: Map<string, TestCase[]> = new Map();

    constructor(dataDir?: string) {
        this.dataDir = dataDir || path.join(__dirname, '../test-data');
    }

    /**
     * Initialize test data directory structure
     */
    async initialize(): Promise<void> {
        await fs.ensureDir(this.dataDir);
        await fs.ensureDir(path.join(this.dataDir, 'vulnerable-samples'));
        await fs.ensureDir(path.join(this.dataDir, 'secure-samples'));
        await fs.ensureDir(path.join(this.dataDir, 'expected-results'));
        await fs.ensureDir(path.join(this.dataDir, 'benchmarks'));

        // Create sample data if it doesn't exist
        await this.createSampleTestData();
    }

    /**
     * Load test cases from a specific category
     */
    async loadTestCases(category: TestCategory): Promise<TestCase[]> {
        const cacheKey = category;
        if (this.testCases.has(cacheKey)) {
            return this.testCases.get(cacheKey)!;
        }

        const testCases = await this.loadTestCasesFromDisk(category);
        this.testCases.set(cacheKey, testCases);
        return testCases;
    }

    /**
     * Load all available test cases
     */
    async loadAllTestCases(): Promise<Map<TestCategory, TestCase[]>> {
        const categories: TestCategory[] = [
            'vulnerable-samples',
            'secure-samples',
            'edge-cases',
            'performance-tests',
            'regression-tests'
        ];

        const allTestCases = new Map<TestCategory, TestCase[]>();

        for (const category of categories) {
            try {
                const testCases = await this.loadTestCases(category);
                allTestCases.set(category, testCases);
            } catch (error) {
                console.warn(`Failed to load test cases for ${category}:`, error);
                allTestCases.set(category, []);
            }
        }

        return allTestCases;
    }

    /**
     * Load test cases from disk for a specific category
     */
    private async loadTestCasesFromDisk(category: TestCategory): Promise<TestCase[]> {
        const categoryDir = path.join(this.dataDir, category);
        
        if (!(await fs.pathExists(categoryDir))) {
            console.warn(`Test data directory not found: ${categoryDir}`);
            return [];
        }

        const files = await fs.readdir(categoryDir);
        const testCases: TestCase[] = [];

        for (const file of files) {
            if (file.endsWith('.json')) {
                try {
                    const filePath = path.join(categoryDir, file);
                    const data = await fs.readJSON(filePath);
                    
                    if (Array.isArray(data)) {
                        testCases.push(...data);
                    } else if (data.testCases && Array.isArray(data.testCases)) {
                        testCases.push(...data.testCases);
                    } else {
                        testCases.push(data);
                    }
                } catch (error) {
                    console.warn(`Failed to load test case file ${file}:`, error);
                }
            }
        }

        return testCases;
    }

    /**
     * Save test cases to disk
     */
    async saveTestCases(category: TestCategory, testCases: TestCase[]): Promise<void> {
        const categoryDir = path.join(this.dataDir, category);
        await fs.ensureDir(categoryDir);

        const fileName = `${category}-${Date.now()}.json`;
        const filePath = path.join(categoryDir, fileName);

        await fs.writeJSON(filePath, {
            category,
            timestamp: new Date().toISOString(),
            testCases
        }, { spaces: 2 });

        // Update cache
        this.testCases.set(category, testCases);
    }

    /**
     * Create sample test data for development and testing
     */
    private async createSampleTestData(): Promise<void> {
        // Vulnerable samples
        const vulnerableSamples: TestCase[] = [
            {
                id: 'js-sql-injection-01',
                name: 'SQL Injection - String Concatenation',
                description: 'Basic SQL injection vulnerability using string concatenation',
                language: 'javascript',
                code: `function getUserById(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return database.query(query);
}`,
                expectedVulnerabilities: [
                    {
                        vulnerabilityType: 'sql_injection',
                        startLine: 1,
                        endLine: 1,
                        messageContains: ['sql', 'injection'],
                        severity: 1 // Error
                    }
                ],
                category: 'vulnerable-samples',
                tags: ['sql-injection', 'database', 'security']
            },
            {
                id: 'js-xss-01',
                name: 'XSS - innerHTML Assignment',
                description: 'Cross-site scripting vulnerability through innerHTML',
                language: 'javascript',
                code: `function displayUserContent(userInput) {
    document.getElementById('content').innerHTML = userInput;
}`,
                expectedVulnerabilities: [
                    {
                        vulnerabilityType: 'xss',
                        startLine: 1,
                        endLine: 1,
                        messageContains: ['xss', 'innerHTML'],
                        severity: 1 // Error
                    }
                ],
                category: 'vulnerable-samples',
                tags: ['xss', 'dom', 'security']
            },
            {
                id: 'js-eval-01',
                name: 'Code Injection - eval() Usage',
                description: 'Code injection vulnerability through eval() function',
                language: 'javascript',
                code: `function calculateExpression(expression) {
    return eval(expression);
}`,
                expectedVulnerabilities: [
                    {
                        vulnerabilityType: 'code_injection',
                        startLine: 1,
                        endLine: 1,
                        messageContains: ['eval', 'injection'],
                        severity: 1 // Error
                    }
                ],
                category: 'vulnerable-samples',
                tags: ['code-injection', 'eval', 'security']
            },
            {
                id: 'ts-hardcoded-creds-01',
                name: 'Hardcoded Credentials',
                description: 'Security vulnerability with hardcoded API key',
                language: 'typescript',
                code: `class ApiClient {
    private apiKey = "sk-1234567890abcdef";
    
    async fetchData(): Promise<any> {
        return fetch('/api/data', {
            headers: { 'Authorization': 'Bearer ' + this.apiKey }
        });
    }
}`,
                expectedVulnerabilities: [
                    {
                        vulnerabilityType: 'hardcoded_credentials',
                        startLine: 1,
                        endLine: 1,
                        messageContains: ['credential', 'hardcoded'],
                        severity: 1 // Error
                    }
                ],
                category: 'vulnerable-samples',
                tags: ['credentials', 'api-key', 'security']
            }
        ];

        // Secure samples
        const secureSamples: TestCase[] = [
            {
                id: 'js-secure-sql-01',
                name: 'Secure SQL Query',
                description: 'Properly parameterized SQL query',
                language: 'javascript',
                code: `function getUserById(userId) {
    const query = "SELECT * FROM users WHERE id = ?";
    return database.query(query, [userId]);
}`,
                expectedVulnerabilities: [],
                category: 'secure-samples',
                tags: ['sql', 'parameterized', 'secure']
            },
            {
                id: 'js-secure-dom-01',
                name: 'Secure DOM Manipulation',
                description: 'Safe DOM content insertion using textContent',
                language: 'javascript',
                code: `function displayUserContent(userInput) {
    document.getElementById('content').textContent = userInput;
}`,
                expectedVulnerabilities: [],
                category: 'secure-samples',
                tags: ['dom', 'textContent', 'secure']
            }
        ];

        // Edge cases
        const edgeCases: TestCase[] = [
            {
                id: 'js-edge-empty-01',
                name: 'Empty Code',
                description: 'Test with empty code',
                language: 'javascript',
                code: '',
                expectedVulnerabilities: [],
                category: 'edge-cases',
                tags: ['edge-case', 'empty']
            },
            {
                id: 'js-edge-large-01',
                name: 'Large Code File',
                description: 'Test with large code file',
                language: 'javascript',
                code: '// Large file\n' + 'console.log("test");\n'.repeat(1000),
                expectedVulnerabilities: [],
                category: 'edge-cases',
                tags: ['edge-case', 'large-file', 'performance']
            }
        ];

        // Performance tests
        const performanceTests: TestCase[] = [
            {
                id: 'perf-multiple-vulns-01',
                name: 'Multiple Vulnerabilities',
                description: 'Code with multiple different vulnerabilities for performance testing',
                language: 'javascript',
                code: `function multipleVulns(userInput, userId) {
    // SQL injection
    const query = "SELECT * FROM users WHERE id = " + userId;
    
    // XSS vulnerability
    document.getElementById('output').innerHTML = userInput;
    
    // Code injection
    eval(userInput);
    
    return database.query(query);
}`,
                expectedVulnerabilities: [
                    {
                        vulnerabilityType: 'sql_injection',
                        startLine: 2,
                        endLine: 2,
                        messageContains: ['sql', 'injection']
                    },
                    {
                        vulnerabilityType: 'xss',
                        startLine: 5,
                        endLine: 5,
                        messageContains: ['xss', 'innerHTML']
                    },
                    {
                        vulnerabilityType: 'code_injection',
                        startLine: 8,
                        endLine: 8,
                        messageContains: ['eval', 'injection']
                    }
                ],
                category: 'performance-tests',
                tags: ['performance', 'multiple-vulnerabilities']
            }
        ];

        // Save all sample test cases
        await this.saveTestCases('vulnerable-samples', vulnerableSamples);
        await this.saveTestCases('secure-samples', secureSamples);
        await this.saveTestCases('edge-cases', edgeCases);
        await this.saveTestCases('performance-tests', performanceTests);

        console.log('✅ Sample test data created successfully');
    }

    /**
     * Get test case by ID
     */
    async getTestCaseById(testId: string): Promise<TestCase | null> {
        const allTestCases = await this.loadAllTestCases();
        
        for (const [category, testCases] of allTestCases) {
            const testCase = testCases.find(tc => tc.id === testId);
            if (testCase) {
                return testCase;
            }
        }
        
        return null;
    }

    /**
     * Filter test cases by tags
     */
    async getTestCasesByTags(tags: string[]): Promise<TestCase[]> {
        const allTestCases = await this.loadAllTestCases();
        const matchingTestCases: TestCase[] = [];

        for (const [category, testCases] of allTestCases) {
            const filtered = testCases.filter(tc => 
                tc.tags && tags.some(tag => tc.tags!.includes(tag))
            );
            matchingTestCases.push(...filtered);
        }

        return matchingTestCases;
    }

    /**
     * Get test cases by vulnerability type
     */
    async getTestCasesByVulnerabilityType(type: VulnerabilityType): Promise<TestCase[]> {
        const allTestCases = await this.loadAllTestCases();
        const matchingTestCases: TestCase[] = [];

        for (const [category, testCases] of allTestCases) {
            const filtered = testCases.filter(tc => 
                tc.expectedVulnerabilities.some(vuln => vuln.vulnerabilityType === type)
            );
            matchingTestCases.push(...filtered);
        }

        return matchingTestCases;
    }

    /**
     * Generate test case statistics
     */
    async getStatistics(): Promise<TestDataStatistics> {
        const allTestCases = await this.loadAllTestCases();
        
        let totalTestCases = 0;
        let totalVulnerabilities = 0;
        const vulnerabilityTypeCounts: Record<string, number> = {};
        const languageCounts: Record<string, number> = {};
        const categoryCounts: Record<string, number> = {};

        for (const [category, testCases] of allTestCases) {
            categoryCounts[category] = testCases.length;
            totalTestCases += testCases.length;

            for (const testCase of testCases) {
                // Count languages
                languageCounts[testCase.language] = (languageCounts[testCase.language] || 0) + 1;

                // Count vulnerabilities
                totalVulnerabilities += testCase.expectedVulnerabilities.length;
                
                for (const vuln of testCase.expectedVulnerabilities) {
                    if (vuln.vulnerabilityType) {
                        const type = vuln.vulnerabilityType;
                        vulnerabilityTypeCounts[type] = (vulnerabilityTypeCounts[type] || 0) + 1;
                    }
                }
            }
        }

        return {
            totalTestCases,
            totalVulnerabilities,
            categoryCounts,
            languageCounts,
            vulnerabilityTypeCounts
        };
    }

    /**
     * Export test data to a specific format
     */
    async exportTestData(format: 'json' | 'csv', outputPath: string): Promise<void> {
        const allTestCases = await this.loadAllTestCases();
        
        if (format === 'json') {
            const exportData = {
                exportTimestamp: new Date().toISOString(),
                statistics: await this.getStatistics(),
                testCases: Object.fromEntries(allTestCases)
            };
            
            await fs.writeJSON(outputPath, exportData, { spaces: 2 });
        } else if (format === 'csv') {
            // Flatten test cases for CSV export
            const rows: string[] = ['ID,Name,Language,Category,VulnerabilityCount,Tags'];
            
            for (const [category, testCases] of allTestCases) {
                for (const testCase of testCases) {
                    const row = [
                        testCase.id,
                        `"${testCase.name}"`,
                        testCase.language,
                        testCase.category,
                        testCase.expectedVulnerabilities.length.toString(),
                        `"${(testCase.tags || []).join(',')}"` 
                    ].join(',');
                    rows.push(row);
                }
            }
            
            await fs.writeFile(outputPath, rows.join('\n'));
        }
    }

    /**
     * Clear cached test cases
     */
    clearCache(): void {
        this.testCases.clear();
    }
}

/**
 * Interface for test cases
 */
export interface TestCase {
    id: string;
    name: string;
    description: string;
    language: 'javascript' | 'typescript';
    code: string;
    expectedVulnerabilities: ExpectedVulnerability[];
    category: TestCategory;
    tags?: string[];
    metadata?: Record<string, any>;
}

/**
 * Test case categories
 */
export type TestCategory = 
    | 'vulnerable-samples'
    | 'secure-samples'
    | 'edge-cases'
    | 'performance-tests'
    | 'regression-tests';

/**
 * Interface for test data statistics
 */
export interface TestDataStatistics {
    totalTestCases: number;
    totalVulnerabilities: number;
    categoryCounts: Record<string, number>;
    languageCounts: Record<string, number>;
    vulnerabilityTypeCounts: Record<string, number>;
}
