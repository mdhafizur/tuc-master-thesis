# How to Use the Code Guardian Testing Framework

This guide provides step-by-step instructions for using the Code Guardian VS Code Extension Testing Framework to evaluate security vulnerability detection capabilities.

## 🚀 Quick Start

### Prerequisites

1. **VS Code**: Version 1.98.0 or higher
2. **Node.js**: Version 18+ (current: 19.2.0)
3. **Code Guardian Extension**: Must be installed in VS Code
4. **Framework**: Already built in `dist/` directory

### Basic Setup

```bash
cd /Users/hafiz/dev/thesis/vsc-extension/code-guardian/evaluation/testing-framework

# Verify the build
ls dist/  # Should show compiled .js files

# Check if everything is ready
npm run test:integration
```

## 📋 Usage Scenarios

### 1. Run Complete Integration Tests

```bash
# Run all tests (recommended for comprehensive evaluation)
npm run test:integration
```

This will:
- Initialize the test environment
- Run comprehensive test suite across all categories
- Generate performance benchmarks
- Export detailed results to `results/` directory
- Display summary metrics (Precision, Recall, F1 Score)

### 2. Run Performance Benchmarks Only

```bash
# Focus on performance testing
npm run test:performance
```

This will:
- Test latency across different code sizes
- Measure throughput with various concurrency levels
- Monitor resource usage over time
- Generate performance reports

### 3. Custom Test Execution

```bash
# Generic test runner
npm run test
```

Or run specific compiled scripts:

```bash
# Integration tests
node dist/integration-test.js

# Performance tests
node dist/performance-test.js
```

## 🔧 Programmatic Usage

### Basic Example

```typescript
import { CodeGuardianTestRunner } from './dist/index.js';

async function runBasicTest() {
    const testRunner = new CodeGuardianTestRunner();
    
    try {
        // Initialize the testing environment
        await testRunner.initialize();
        
        // Run comprehensive tests
        const report = await testRunner.runComprehensiveTests();
        
        // Display results
        console.log('=== Test Results ===');
        console.log(`Total Test Cases: ${report.totalTestCases}`);
        console.log(`Precision: ${(report.overallMetrics.precision * 100).toFixed(2)}%`);
        console.log(`Recall: ${(report.overallMetrics.recall * 100).toFixed(2)}%`);
        console.log(`F1 Score: ${(report.overallMetrics.f1Score * 100).toFixed(2)}%`);
        
        // Export results
        await testRunner.exportResults(report, './my-test-results.json');
        
    } catch (error) {
        console.error('Test failed:', error);
    } finally {
        await testRunner.cleanup();
    }
}

runBasicTest().catch(console.error);
```

### Testing Individual Commands

```typescript
import { CommandExecutor } from './dist/index.js';

async function testSpecificCode() {
    const executor = new CommandExecutor();
    
    try {
        // Test SQL injection detection
        const vulnerableCode = `
            function getUserById(userId) {
                const query = "SELECT * FROM users WHERE id = " + userId;
                return database.query(query);
            }
        `;
        
        const result = await executor.executeAnalyzeFullFile(
            vulnerableCode,
            'test-sql-injection.js',
            { captureDiagnostics: true, diagnosticTimeout: 5000 }
        );
        
        console.log('Command executed successfully:', result.success);
        console.log('Diagnostics found:', result.diagnostics.length);
        console.log('Execution time:', result.duration, 'ms');
        
        // Display found issues
        result.diagnostics.forEach((diagnostic, i) => {
            console.log(`Issue ${i + 1}: ${diagnostic.message}`);
            console.log(`  Line: ${diagnostic.range.start.line}`);
            console.log(`  Severity: ${diagnostic.severity}`);
        });
        
    } catch (error) {
        console.error('Test failed:', error);
    } finally {
        await executor.cleanup();
    }
}
```

### Validating Detection Accuracy

```typescript
import { DiagnosticValidator, CommandExecutor } from './dist/index.js';

async function validateAccuracy() {
    const executor = new CommandExecutor();
    const validator = new DiagnosticValidator();
    
    const testCode = 'eval(userInput);'; // Known vulnerability
    
    // Execute analysis
    const result = await executor.executeAnalyzeSelection(testCode);
    
    // Define expected vulnerability
    const expectedVulnerabilities = [{
        vulnerabilityType: 'code_injection',
        startLine: 0,
        endLine: 0,
        messageContains: ['eval', 'injection'],
        severity: 1 // Error
    }];
    
    // Validate results
    const validation = validator.validateDetection(
        result.diagnostics, 
        expectedVulnerabilities
    );
    
    console.log('Validation Results:');
    console.log(`True Positives: ${validation.truePositives}`);
    console.log(`False Positives: ${validation.falsePositives}`);
    console.log(`False Negatives: ${validation.falseNegatives}`);
    console.log(`Precision: ${(validation.precision * 100).toFixed(2)}%`);
    console.log(`Recall: ${(validation.recall * 100).toFixed(2)}%`);
    console.log(`F1 Score: ${(validation.f1Score * 100).toFixed(2)}%`);
}
```

### Performance Measurement

```typescript
import { PerformanceMeasurer, ResourceMonitor } from './dist/index.js';

async function measurePerformance() {
    const performanceMeasurer = new PerformanceMeasurer();
    const resourceMonitor = new ResourceMonitor();
    
    // Start monitoring
    resourceMonitor.startMonitoring(1000); // Every second
    
    // Measure an operation
    const { result, measurement } = await performanceMeasurer.measureAsync(
        'analyze-operation',
        async () => {
            // Your operation here
            return await someAnalysisFunction();
        }
    );
    
    // Stop monitoring and get report
    const resourceReport = resourceMonitor.stopMonitoring();
    
    console.log(`Operation took: ${measurement.duration}ms`);
    console.log(`Peak memory: ${resourceReport.memory.rss.max / 1024 / 1024}MB`);
    console.log(`Average CPU: ${resourceReport.cpu.totalUsage.mean}`);
    
    // Get statistics for multiple runs
    const stats = performanceMeasurer.getStatistics('analyze-operation');
    console.log(`Average latency: ${stats.mean}ms`);
    console.log(`P95 latency: ${stats.p95}ms`);
}
```

## 📊 Working with Test Data

### Loading Existing Test Cases

```typescript
import { TestDataManager } from './dist/index.js';

async function workWithTestData() {
    const testDataManager = new TestDataManager();
    await testDataManager.initialize();
    
    // Load vulnerable samples
    const vulnerableCases = await testDataManager.loadTestCases('vulnerable-samples');
    console.log(`Loaded ${vulnerableCases.length} vulnerable test cases`);
    
    // Get statistics
    const stats = await testDataManager.getStatistics();
    console.log('Test Data Statistics:', stats);
    
    // Find specific vulnerability types
    const sqlInjectionCases = await testDataManager.getTestCasesByVulnerabilityType('sql_injection');
    console.log(`Found ${sqlInjectionCases.length} SQL injection test cases`);
    
    // Filter by tags
    const securityCases = await testDataManager.getTestCasesByTags(['security', 'sql-injection']);
    console.log(`Found ${securityCases.length} security-related test cases`);
}
```

### Creating Custom Test Cases

```typescript
import { TestDataManager } from './dist/index.js';

async function createCustomTestCase() {
    const testDataManager = new TestDataManager();
    
    const customTestCase = {
        id: 'custom-xss-01',
        name: 'Custom XSS Test',
        description: 'Testing XSS detection in custom scenario',
        language: 'javascript',
        code: `
            function displayMessage(message) {
                document.getElementById('output').innerHTML = message;
            }
        `,
        expectedVulnerabilities: [{
            vulnerabilityType: 'xss',
            startLine: 2,
            endLine: 2,
            messageContains: ['xss', 'innerHTML'],
            severity: 1
        }],
        category: 'vulnerable-samples',
        tags: ['xss', 'dom', 'custom']
    };
    
    // Save custom test cases
    await testDataManager.saveTestCases('vulnerable-samples', [customTestCase]);
}
```

## 🎯 Common Use Cases

### 1. Evaluate Extension Accuracy

```bash
# Run comprehensive accuracy evaluation
npm run test:integration

# Check results
cat results/integration-test-results-*.json | jq '.overallMetrics'
```

### 2. Performance Benchmarking

```bash
# Run performance tests
npm run test:performance

# Analyze latency results  
cat results/latency-results-*.json | jq '.summary'
```

### 3. Regression Testing

```typescript
// Compare two versions of the extension
async function regressionTest() {
    const testRunner = new CodeGuardianTestRunner();
    await testRunner.initialize();
    
    // Run baseline tests
    const baselineReport = await testRunner.runComprehensiveTests();
    
    // ... update extension ...
    
    // Run new tests
    const newReport = await testRunner.runComprehensiveTests();
    
    // Compare results
    console.log('Regression Analysis:');
    console.log(`Baseline F1: ${baselineReport.overallMetrics.f1Score}`);
    console.log(`New F1: ${newReport.overallMetrics.f1Score}`);
    console.log(`Change: ${newReport.overallMetrics.f1Score - baselineReport.overallMetrics.f1Score}`);
}
```

### 4. Custom Vulnerability Testing

```typescript
async function testCustomVulnerability() {
    const executor = new CommandExecutor();
    const validator = new DiagnosticValidator();
    
    // Your custom vulnerable code
    const customCode = `
        const fs = require('fs');
        function readUserFile(filename) {
            return fs.readFileSync('./uploads/' + filename);
        }
    `;
    
    // Execute analysis
    const result = await executor.executeAnalyzeFullFile(customCode, 'custom-test.js');
    
    // Validate against expected path traversal detection
    const expectedVulns = [{
        vulnerabilityType: 'path_traversal',
        startLine: 2,
        endLine: 2,
        messageContains: ['path', 'traversal', 'directory']
    }];
    
    const validation = validator.validateDetection(result.diagnostics, expectedVulns);
    
    if (validation.truePositives > 0) {
        console.log('✅ Path traversal vulnerability correctly detected');
    } else {
        console.log('❌ Path traversal vulnerability not detected');
    }
}
```

## 📁 Understanding Results

### Result Files Location

```bash
ls results/
# integration-test-results-2025-09-05T12-30-00-000Z.json
# performance-results-2025-09-05T12-30-00-000Z.json
# latency-results-2025-09-05T12-30-00-000Z.json
```

### Key Metrics to Monitor

1. **Accuracy Metrics**:
   - Precision: `overallMetrics.precision`
   - Recall: `overallMetrics.recall`
   - F1 Score: `overallMetrics.f1Score`

2. **Performance Metrics**:
   - Average Latency: `summary.averageLatency`
   - P95 Latency: `summary.p95Latency`
   - Throughput: `summary.maxThroughput`

3. **Quality Metrics**:
   - Diagnostic Clarity: In individual test results
   - False Positive Rate: Calculated from validation results

## 🐛 Troubleshooting

### Common Issues

1. **Extension Not Activating**:
   ```bash
   # Ensure Code Guardian is installed
   code --list-extensions | grep code-guardian
   ```

2. **Test Timeouts**:
   ```typescript
   // Increase timeouts in test configuration
   const config = {
       timeout: 60000,  // 60 seconds
       diagnosticTimeout: 10000  // 10 seconds
   };
   ```

3. **Memory Issues**:
   ```bash
   # Increase Node.js memory limit
   NODE_OPTIONS="--max-old-space-size=4096" npm run test:integration
   ```

4. **Permission Errors**:
   ```bash
   # Ensure proper permissions for VS Code data directory
   chmod -R 755 results/
   ```

### Debug Mode

```typescript
// Enable verbose logging
process.env.DEBUG = 'code-guardian-test';
process.env.NODE_ENV = 'development';

// Run tests with debug output
const testRunner = new CodeGuardianTestRunner();
```

## 📈 Interpreting Results

### Good Performance Indicators

- **F1 Score > 0.7**: Good detection accuracy
- **Precision > 0.8**: Low false positive rate
- **Recall > 0.6**: Good vulnerability coverage
- **P95 Latency < 2000ms**: Acceptable response time
- **Memory stability > 0.8**: Consistent resource usage

### Red Flags

- **F1 Score < 0.5**: Poor overall accuracy
- **High False Positives**: Precision < 0.5
- **High False Negatives**: Recall < 0.4
- **P95 Latency > 5000ms**: Poor performance
- **Memory growth**: Resource leaks

## 🚀 Next Steps

After running the framework:

1. **Analyze Results**: Review metrics and identify improvement areas
2. **Compare Baselines**: Use SAST tools comparison
3. **Optimize Extension**: Based on performance bottlenecks
4. **Expand Test Cases**: Add more vulnerability types
5. **Run Regression Tests**: Before extension updates

## 📚 Advanced Usage

For advanced scenarios, see:
- `src/test-runner.ts`: Main orchestrator customization
- `src/diagnostic-validator.ts`: Custom validation logic
- `src/performance-utils.ts`: Advanced performance metrics
- `README.md`: Complete API reference

---

**Happy Testing!** 🎯 The framework is designed to provide comprehensive evaluation of your Code Guardian extension's security detection capabilities.
