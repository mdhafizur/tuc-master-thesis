#!/usr/bin/env node

/**
 * Integration test script for Code Guardian extension
 * Run this script to execute comprehensive integration tests
 */

import { CodeGuardianTestRunner } from '../src/test-runner';
import { TestDataManager } from '../src/test-data-manager';
import * as path from 'path';

async function runIntegrationTests(): Promise<void> {
    console.log('🧪 Starting Code Guardian Integration Tests');
    console.log('==========================================');

    const testRunner = new CodeGuardianTestRunner();
    
    try {
        // Initialize test environment
        console.log('\n1️⃣ Initializing test environment...');
        await testRunner.initialize();
        
        // Run comprehensive tests
        console.log('\n2️⃣ Running comprehensive test suite...');
        const testReport = await testRunner.runComprehensiveTests();
        
        // Run performance benchmarks
        console.log('\n3️⃣ Running performance benchmarks...');
        const performanceReport = await testRunner.runPerformanceBenchmarks();
        
        // Generate results summary
        console.log('\n📊 Test Results Summary');
        console.log('=======================');
        console.log(`Total Test Cases: ${testReport.totalTestCases}`);
        console.log(`Total Duration: ${testReport.totalDuration}ms`);
        console.log(`Overall Precision: ${(testReport.overallMetrics.precision * 100).toFixed(2)}%`);
        console.log(`Overall Recall: ${(testReport.overallMetrics.recall * 100).toFixed(2)}%`);
        console.log(`Overall F1 Score: ${(testReport.overallMetrics.f1Score * 100).toFixed(2)}%`);
        
        console.log('\n📈 Performance Summary');
        console.log('======================');
        console.log(`Average Latency: ${performanceReport.summary.averageLatency.toFixed(2)}ms`);
        console.log(`Min Latency: ${performanceReport.summary.minLatency.toFixed(2)}ms`);
        console.log(`Max Latency: ${performanceReport.summary.maxLatency.toFixed(2)}ms`);
        console.log(`Scalability Trend: ${performanceReport.summary.scalabilityTrend}`);
        
        // Export results
        const resultsDir = path.join(__dirname, '../results');
        const timestamp = new Date().toISOString().replace(/[:.]/g, '-');
        
        await testRunner.exportResults(
            testReport, 
            path.join(resultsDir, `integration-test-results-${timestamp}.json`)
        );
        
        const fs = require('fs').promises;
        await fs.writeFile(
            path.join(resultsDir, `performance-results-${timestamp}.json`),
            JSON.stringify(performanceReport, null, 2)
        );
        
        console.log(`\n📄 Results exported to: ${resultsDir}`);
        
        // Determine test success
        const success = testReport.overallMetrics.f1Score > 0.5; // Threshold for success
        
        if (success) {
            console.log('\n✅ Integration tests PASSED');
            process.exit(0);
        } else {
            console.log('\n❌ Integration tests FAILED');
            console.log(`F1 Score ${(testReport.overallMetrics.f1Score * 100).toFixed(2)}% below threshold of 50%`);
            process.exit(1);
        }
        
    } catch (error) {
        console.error('\n💥 Integration test failed:', error);
        process.exit(1);
    } finally {
        await testRunner.cleanup();
    }
}

async function validateTestData(): Promise<void> {
    console.log('\n🔍 Validating test data...');
    
    const testDataManager = new TestDataManager();
    await testDataManager.initialize();
    
    const statistics = await testDataManager.getStatistics();
    
    console.log('Test Data Statistics:');
    console.log(`- Total Test Cases: ${statistics.totalTestCases}`);
    console.log(`- Total Vulnerabilities: ${statistics.totalVulnerabilities}`);
    console.log(`- Languages: ${Object.keys(statistics.languageCounts).join(', ')}`);
    console.log(`- Categories: ${Object.keys(statistics.categoryCounts).join(', ')}`);
    console.log(`- Vulnerability Types: ${Object.keys(statistics.vulnerabilityTypeCounts).join(', ')}`);
    
    if (statistics.totalTestCases === 0) {
        throw new Error('No test cases found! Please ensure test data is properly initialized.');
    }
    
    console.log('✅ Test data validation passed');
}

// Main execution
async function main(): Promise<void> {
    try {
        await validateTestData();
        await runIntegrationTests();
    } catch (error) {
        console.error('Failed to run integration tests:', error);
        process.exit(1);
    }
}

// Run if this script is executed directly
if (require.main === module) {
    main().catch(console.error);
}

export { runIntegrationTests, validateTestData };
