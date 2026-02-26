#!/usr/bin/env node

/**
 * Performance test script for Code Guardian extension
 * Focuses specifically on latency, throughput, and resource usage measurements
 */

import { CodeGuardianTestRunner } from '../src/test-runner';
import { PerformanceMeasurer, ResourceMonitor } from '../src/performance-utils';
import { CommandExecutor } from '../src/command-executor';
import { TestDataManager } from '../src/test-data-manager';
import * as path from 'path';

interface PerformanceTestConfig {
    codeSize: number;
    iterations: number;
    concurrency: number;
    timeout: number;
}

class PerformanceTestSuite {
    private performanceMeasurer: PerformanceMeasurer;
    private resourceMonitor: ResourceMonitor;
    private commandExecutor: CommandExecutor;
    private testDataManager: TestDataManager;

    constructor() {
        this.performanceMeasurer = new PerformanceMeasurer();
        this.resourceMonitor = new ResourceMonitor();
        this.commandExecutor = new CommandExecutor();
        this.testDataManager = new TestDataManager();
    }

    /**
     * Run latency performance tests
     */
    async runLatencyTests(): Promise<LatencyTestReport> {
        console.log('⚡ Running latency performance tests...');

        const configs: PerformanceTestConfig[] = [
            { codeSize: 100, iterations: 20, concurrency: 1, timeout: 5000 },
            { codeSize: 500, iterations: 15, concurrency: 1, timeout: 10000 },
            { codeSize: 1000, iterations: 10, concurrency: 1, timeout: 15000 },
            { codeSize: 2000, iterations: 8, concurrency: 1, timeout: 20000 },
            { codeSize: 5000, iterations: 5, concurrency: 1, timeout: 30000 }
        ];

        const latencyResults: LatencyTestResult[] = [];

        for (const config of configs) {
            console.log(`📊 Testing code size: ${config.codeSize} chars, ${config.iterations} iterations`);
            
            const measurements: number[] = [];
            const testCode = this.generatePerformanceTestCode(config.codeSize);

            for (let i = 0; i < config.iterations; i++) {
                const { measurement } = await this.performanceMeasurer.measureAsync(
                    `latency-test-${config.codeSize}`,
                    async () => {
                        return await this.commandExecutor.executeAnalyzeFullFile(
                            testCode,
                            `latency-test-${config.codeSize}-${i}.js`,
                            { captureDiagnostics: true, diagnosticTimeout: config.timeout }
                        );
                    }
                );

                measurements.push(measurement.duration);
                
                // Brief pause between iterations
                await this.wait(100);
            }

            const statistics = this.calculateLatencyStatistics(measurements);
            latencyResults.push({
                codeSize: config.codeSize,
                iterations: config.iterations,
                measurements,
                statistics
            });
        }

        return {
            timestamp: new Date(),
            testType: 'latency',
            results: latencyResults,
            summary: this.summarizeLatencyResults(latencyResults)
        };
    }

    /**
     * Run throughput performance tests
     */
    async runThroughputTests(): Promise<ThroughputTestReport> {
        console.log('🔄 Running throughput performance tests...');

        const testCases = await this.testDataManager.loadTestCases('performance-tests');
        const concurrencyLevels = [1, 2, 4, 8];
        const throughputResults: ThroughputTestResult[] = [];

        for (const concurrency of concurrencyLevels) {
            console.log(`📊 Testing concurrency level: ${concurrency}`);
            
            const startTime = Date.now();
            this.resourceMonitor.startMonitoring(100);

            // Create promises for concurrent execution
            const promises: Promise<any>[] = [];
            const batchSize = Math.min(testCases.length, 20); // Limit batch size

            for (let i = 0; i < concurrency; i++) {
                const batch = testCases.slice(
                    (i * batchSize / concurrency), 
                    ((i + 1) * batchSize / concurrency)
                );

                const promise = this.executeBatch(batch, i);
                promises.push(promise);
            }

            // Execute all batches concurrently
            const batchResults = await Promise.allSettled(promises);
            const resourceReport = this.resourceMonitor.stopMonitoring();
            const totalDuration = Date.now() - startTime;

            const successfulBatches = batchResults.filter(r => r.status === 'fulfilled').length;
            const totalTestCases = batchSize;
            const throughput = totalTestCases / (totalDuration / 1000); // tests per second

            throughputResults.push({
                concurrencyLevel: concurrency,
                totalTestCases,
                totalDuration,
                throughput,
                successfulBatches,
                failedBatches: batchResults.length - successfulBatches,
                resourceUsage: resourceReport
            });

            // Brief pause between concurrency tests
            await this.wait(2000);
        }

        return {
            timestamp: new Date(),
            testType: 'throughput',
            results: throughputResults,
            summary: this.summarizeThroughputResults(throughputResults)
        };
    }

    /**
     * Run resource usage tests
     */
    async runResourceUsageTests(): Promise<ResourceUsageTestReport> {
        console.log('💾 Running resource usage tests...');

        const testDurations = [10000, 30000, 60000]; // 10s, 30s, 60s
        const resourceResults: ResourceUsageTestResult[] = [];

        for (const duration of testDurations) {
            console.log(`📊 Testing ${duration/1000}s duration`);
            
            this.resourceMonitor.startMonitoring(1000); // Monitor every second
            const startTime = Date.now();

            // Continuously run tests for the specified duration
            const endTime = startTime + duration;
            let testCount = 0;

            while (Date.now() < endTime) {
                try {
                    const testCode = this.generatePerformanceTestCode(1000);
                    await this.commandExecutor.executeAnalyzeFullFile(
                        testCode,
                        `resource-test-${testCount}.js`,
                        { captureDiagnostics: true }
                    );
                    testCount++;
                    
                    // Small delay to prevent overwhelming
                    await this.wait(100);
                } catch (error) {
                    console.warn(`Test ${testCount} failed:`, error);
                }
            }

            const resourceReport = this.resourceMonitor.stopMonitoring();
            const actualDuration = Date.now() - startTime;

            resourceResults.push({
                plannedDuration: duration,
                actualDuration,
                testCount,
                resourceUsage: resourceReport,
                averageTestsPerSecond: testCount / (actualDuration / 1000)
            });

            // Brief pause between duration tests
            await this.wait(3000);
        }

        return {
            timestamp: new Date(),
            testType: 'resource-usage',
            results: resourceResults,
            summary: this.summarizeResourceResults(resourceResults)
        };
    }

    /**
     * Execute a batch of test cases
     */
    private async executeBatch(testCases: any[], batchId: number): Promise<any[]> {
        const results = [];
        
        for (let i = 0; i < testCases.length; i++) {
            const testCase = testCases[i];
            try {
                const result = await this.commandExecutor.executeAnalyzeFullFile(
                    testCase.code,
                    `batch-${batchId}-test-${i}.js`,
                    { captureDiagnostics: true }
                );
                results.push(result);
            } catch (error) {
                console.warn(`Batch ${batchId}, test ${i} failed:`, error);
                results.push({ success: false, error });
            }
        }
        
        return results;
    }

    /**
     * Generate test code of specific size with embedded vulnerabilities
     */
    private generatePerformanceTestCode(targetSize: number): string {
        const vulnerableSnippets = [
            'eval(userInput);',
            'document.getElementById("output").innerHTML = userContent;',
            'const query = "SELECT * FROM users WHERE id = " + userId;',
            'const apiKey = "sk-1234567890abcdef";',
            'fs.readFileSync("./data/" + fileName);'
        ];

        let code = `// Performance test code (target size: ${targetSize})\n`;
        code += 'function performanceTestFunction(userInput, userId, userContent, fileName) {\n';
        
        // Add some vulnerable code
        const snippet = vulnerableSnippets[Math.floor(Math.random() * vulnerableSnippets.length)];
        code += `    ${snippet}\n`;
        
        // Fill to target size with additional code
        let counter = 0;
        while (code.length < targetSize - 100) { // Leave some buffer
            code += `    // Additional code line ${counter++}\n`;
            code += `    const variable${counter} = processData(input${counter});\n`;
            code += `    if (variable${counter}) { console.log("Processing ${counter}"); }\n`;
        }
        
        code += '}\n';
        code += 'module.exports = { performanceTestFunction };';
        
        return code.substring(0, targetSize);
    }

    /**
     * Calculate latency statistics
     */
    private calculateLatencyStatistics(measurements: number[]): LatencyStatistics {
        const sorted = [...measurements].sort((a, b) => a - b);
        const sum = measurements.reduce((acc, val) => acc + val, 0);
        const mean = sum / measurements.length;
        
        return {
            min: sorted[0],
            max: sorted[sorted.length - 1],
            mean,
            median: sorted[Math.floor(sorted.length / 2)],
            p95: sorted[Math.floor(sorted.length * 0.95)],
            p99: sorted[Math.floor(sorted.length * 0.99)],
            standardDeviation: Math.sqrt(
                measurements.reduce((acc, val) => acc + Math.pow(val - mean, 2), 0) / measurements.length
            )
        };
    }

    /**
     * Summarize latency test results
     */
    private summarizeLatencyResults(results: LatencyTestResult[]): LatencySummary {
        const allMeasurements = results.flatMap(r => r.measurements);
        const overallStats = this.calculateLatencyStatistics(allMeasurements);
        
        return {
            totalTests: results.reduce((sum, r) => sum + r.iterations, 0),
            averageLatency: overallStats.mean,
            medianLatency: overallStats.median,
            p95Latency: overallStats.p95,
            scalabilityCoefficient: this.calculateScalabilityCoefficient(results)
        };
    }

    /**
     * Summarize throughput test results
     */
    private summarizeThroughputResults(results: ThroughputTestResult[]): ThroughputSummary {
        const maxThroughput = Math.max(...results.map(r => r.throughput));
        const optimalConcurrency = results.find(r => r.throughput === maxThroughput)?.concurrencyLevel || 1;
        
        return {
            maxThroughput,
            optimalConcurrency,
            scalabilityEfficiency: maxThroughput / results[0].throughput,
            averageResourceUsage: results.reduce((sum, r) => 
                sum + (r.resourceUsage.memory.rss.mean || 0), 0) / results.length
        };
    }

    /**
     * Summarize resource usage test results
     */
    private summarizeResourceResults(results: ResourceUsageTestResult[]): ResourceUsageSummary {
        const peakMemory = Math.max(...results.map(r => r.resourceUsage.memory.rss.max || 0));
        const averageMemory = results.reduce((sum, r) => 
            sum + (r.resourceUsage.memory.rss.mean || 0), 0) / results.length;
        
        return {
            peakMemoryUsage: peakMemory,
            averageMemoryUsage: averageMemory,
            memoryStability: this.calculateMemoryStability(results),
            sustainedPerformance: results[results.length - 1].averageTestsPerSecond
        };
    }

    /**
     * Calculate scalability coefficient
     */
    private calculateScalabilityCoefficient(results: LatencyTestResult[]): number {
        if (results.length < 2) {
            return 1;
        }
        
        const firstResult = results[0];
        const lastResult = results[results.length - 1];
        
        const sizeRatio = lastResult.codeSize / firstResult.codeSize;
        const latencyRatio = lastResult.statistics.mean / firstResult.statistics.mean;
        
        return latencyRatio / sizeRatio;
    }

    /**
     * Calculate memory stability
     */
    private calculateMemoryStability(results: ResourceUsageTestResult[]): number {
        const memoryUsages = results.map(r => r.resourceUsage.memory.rss.mean || 0);
        const mean = memoryUsages.reduce((sum, val) => sum + val, 0) / memoryUsages.length;
        const variance = memoryUsages.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / memoryUsages.length;
        const standardDeviation = Math.sqrt(variance);
        
        return 1 - (standardDeviation / mean); // Higher values = more stable
    }

    /**
     * Utility function to wait
     */
    private async wait(ms: number): Promise<void> {
        return new Promise(resolve => setTimeout(resolve, ms));
    }

    /**
     * Cleanup resources
     */
    async cleanup(): Promise<void> {
        await this.commandExecutor.cleanup();
    }
}

// Type definitions
interface LatencyTestResult {
    codeSize: number;
    iterations: number;
    measurements: number[];
    statistics: LatencyStatistics;
}

interface LatencyStatistics {
    min: number;
    max: number;
    mean: number;
    median: number;
    p95: number;
    p99: number;
    standardDeviation: number;
}

interface LatencyTestReport {
    timestamp: Date;
    testType: 'latency';
    results: LatencyTestResult[];
    summary: LatencySummary;
}

interface LatencySummary {
    totalTests: number;
    averageLatency: number;
    medianLatency: number;
    p95Latency: number;
    scalabilityCoefficient: number;
}

interface ThroughputTestResult {
    concurrencyLevel: number;
    totalTestCases: number;
    totalDuration: number;
    throughput: number;
    successfulBatches: number;
    failedBatches: number;
    resourceUsage: any;
}

interface ThroughputTestReport {
    timestamp: Date;
    testType: 'throughput';
    results: ThroughputTestResult[];
    summary: ThroughputSummary;
}

interface ThroughputSummary {
    maxThroughput: number;
    optimalConcurrency: number;
    scalabilityEfficiency: number;
    averageResourceUsage: number;
}

interface ResourceUsageTestResult {
    plannedDuration: number;
    actualDuration: number;
    testCount: number;
    resourceUsage: any;
    averageTestsPerSecond: number;
}

interface ResourceUsageTestReport {
    timestamp: Date;
    testType: 'resource-usage';
    results: ResourceUsageTestResult[];
    summary: ResourceUsageSummary;
}

interface ResourceUsageSummary {
    peakMemoryUsage: number;
    averageMemoryUsage: number;
    memoryStability: number;
    sustainedPerformance: number;
}

// Main execution function
async function runPerformanceTests(): Promise<void> {
    console.log('⚡ Starting Code Guardian Performance Tests');
    console.log('==========================================');

    const testSuite = new PerformanceTestSuite();
    
    try {
        // Run all performance test types
        console.log('\n1️⃣ Running latency tests...');
        const latencyReport = await testSuite.runLatencyTests();
        
        console.log('\n2️⃣ Running throughput tests...');
        const throughputReport = await testSuite.runThroughputTests();
        
        console.log('\n3️⃣ Running resource usage tests...');
        const resourceReport = await testSuite.runResourceUsageTests();
        
        // Export results
        const resultsDir = path.join(__dirname, '../results');
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        
        const fs = require('fs').promises;
        await fs.writeFile(
            path.join(resultsDir, `latency-results-${timestamp}.json`),
            JSON.stringify(latencyReport, null, 2)
        );
        
        await fs.writeFile(
            path.join(resultsDir, `throughput-results-${timestamp}.json`),
            JSON.stringify(throughputReport, null, 2)
        );
        
        await fs.writeFile(
            path.join(resultsDir, `resource-usage-results-${timestamp}.json`),
            JSON.stringify(resourceReport, null, 2)
        );
        
        // Display summary
        console.log('\n📊 Performance Test Summary');
        console.log('===========================');
        console.log(`Latency - Average: ${latencyReport.summary.averageLatency.toFixed(2)}ms`);
        console.log(`Latency - P95: ${latencyReport.summary.p95Latency.toFixed(2)}ms`);
        console.log(`Throughput - Max: ${throughputReport.summary.maxThroughput.toFixed(2)} tests/sec`);
        console.log(`Throughput - Optimal Concurrency: ${throughputReport.summary.optimalConcurrency}`);
        console.log(`Memory - Peak: ${(resourceReport.summary.peakMemoryUsage / 1024 / 1024).toFixed(2)} MB`);
        console.log(`Memory - Stability: ${(resourceReport.summary.memoryStability * 100).toFixed(2)}%`);
        
        console.log(`\n📄 Results exported to: ${resultsDir}`);
        console.log('\n✅ Performance tests completed successfully');
        
    } catch (error) {
        console.error('\n💥 Performance tests failed:', error);
        process.exit(1);
    } finally {
        await testSuite.cleanup();
    }
}

// Run if this script is executed directly
if (require.main === module) {
    runPerformanceTests().catch(console.error);
}

export { PerformanceTestSuite, runPerformanceTests };
