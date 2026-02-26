# Code Guardian VS Code Extension Testing Framework

A comprehensive testing framework for evaluating the Code Guardian VS Code extension's security vulnerability detection and repair capabilities. This framework implements Day 5-7 of the evaluation implementation plan, providing automated testing, performance measurement, and diagnostic validation tools.

## 🎯 Overview

The testing framework provides:

- **Automated Extension Testing**: Programmatic installation, activation, and command execution
- **Diagnostic Validation**: Comprehensive validation of security vulnerability detection
- **Performance Measurement**: Latency, throughput, and resource usage monitoring
- **Test Data Management**: Organized test cases with expected results
- **Integration Testing**: End-to-end testing of extension functionality
- **Performance Benchmarking**: Scalability and performance analysis

## 🏗️ Architecture

```
testing-framework/
├── src/
│   ├── test-config.ts          # Test environment configuration
│   ├── extension-utils.ts      # Extension testing utilities
│   ├── command-executor.ts     # Command execution framework
│   ├── diagnostic-validator.ts # Diagnostic validation utilities
│   ├── performance-utils.ts    # Performance measurement tools
│   ├── test-data-manager.ts    # Test data management
│   ├── test-runner.ts          # Main test runner
│   ├── integration-test.ts     # Integration test script
│   ├── performance-test.ts     # Performance test script
│   └── index.ts               # Framework exports
├── test-data/                 # Test case data
├── results/                   # Test execution results
├── package.json
├── tsconfig.json
└── README.md
```

## 🚀 Quick Start

### Prerequisites

- VS Code 1.98.0+
- Node.js 18+
- TypeScript 5.8+
- Code Guardian extension installed

### Installation

```bash
cd evaluation/testing-framework
npm install
npm run build
```

### Basic Usage

```typescript
import { CodeGuardianTestRunner } from './src';

async function runTests() {
    const testRunner = new CodeGuardianTestRunner();
    await testRunner.initialize();
    
    const report = await testRunner.runComprehensiveTests();
    console.log('Test Results:', report);
    
    await testRunner.cleanup();
}
```

### Running Integration Tests

```bash
# Run comprehensive integration tests
npm run test

# Run performance benchmarks only
npm run test:performance

# Run specific test category
npm run test:integration
```

## 📊 Test Categories

### 1. Vulnerable Code Samples
Test cases containing known security vulnerabilities:
- SQL Injection
- Cross-Site Scripting (XSS)
- Code Injection (eval usage)
- Hardcoded Credentials
- Path Traversal
- Prototype Pollution

### 2. Secure Code Samples
Test cases with secure coding practices:
- Parameterized queries
- Safe DOM manipulation
- Proper input validation
- Secure credential handling

### 3. Edge Cases
Boundary condition testing:
- Empty code files
- Very large files
- Malformed code
- Mixed languages

### 4. Performance Tests
Scalability and performance validation:
- Various code sizes
- Multiple vulnerabilities
- Concurrent execution
- Resource usage monitoring

## 🔧 Configuration

### Test Configuration

```typescript
const testConfig: TestConfig = {
    extensionDevelopmentPath: '/path/to/extension',
    extensionTestsPath: '/path/to/tests',
    launchArgs: ['--no-sandbox', '--disable-updates'],
    timeout: 30000,
    version: '1.98.0'
};
```

### Performance Measurement

```typescript
const performanceMeasurer = new PerformanceMeasurer();

const { result, measurement } = await performanceMeasurer.measureAsync(
    'analyzeCode',
    async () => executor.executeAnalyzeFullFile(code)
);

console.log(`Operation took ${measurement.duration}ms`);
```

### Diagnostic Validation

```typescript
const validator = new DiagnosticValidator();
const validationResult = validator.validateDetection(
    diagnostics,
    expectedVulnerabilities
);

console.log(`Precision: ${validationResult.precision}`);
console.log(`Recall: ${validationResult.recall}`);
console.log(`F1 Score: ${validationResult.f1Score}`);
```

## 📈 Metrics and Reporting

### Accuracy Metrics
- **Precision**: True positives / (True positives + False positives)
- **Recall**: True positives / (True positives + False negatives)
- **F1 Score**: Harmonic mean of precision and recall

### Performance Metrics
- **Latency**: Response time measurements (mean, median, P95, P99)
- **Throughput**: Operations per second under various concurrency levels
- **Resource Usage**: Memory and CPU consumption over time

### Quality Metrics
- **Diagnostic Clarity**: Message understandability score
- **Actionability**: Guidance usefulness score
- **Accuracy**: Diagnostic precision assessment

## 🧪 Test Data Management

### Creating Test Cases

```typescript
const testCase: TestCase = {
    id: 'js-sql-injection-01',
    name: 'SQL Injection - String Concatenation',
    description: 'Basic SQL injection vulnerability',
    language: 'javascript',
    code: 'const query = "SELECT * FROM users WHERE id = " + userId;',
    expectedVulnerabilities: [{
        vulnerabilityType: 'sql_injection',
        startLine: 0,
        endLine: 0,
        messageContains: ['sql', 'injection'],
        severity: DiagnosticSeverity.Error
    }],
    category: 'vulnerable-samples',
    tags: ['sql-injection', 'database']
};
```

### Loading Test Data

```typescript
const testDataManager = new TestDataManager();
await testDataManager.initialize();

const vulnerableSamples = await testDataManager.loadTestCases('vulnerable-samples');
const statistics = await testDataManager.getStatistics();
```

## 🎯 Command Execution

### Analyze Selection

```typescript
const commandExecutor = new CommandExecutor();
const result = await commandExecutor.executeAnalyzeSelection(
    'eval(userInput)',
    { captureDiagnostics: true }
);
```

### Analyze Full File

```typescript
const result = await commandExecutor.executeAnalyzeFullFile(
    codeContent,
    'test-file.js',
    { captureDiagnostics: true, diagnosticTimeout: 5000 }
);
```

### Batch Execution

```typescript
const testCases: TestCase[] = [
    { command: 'analyzeFullFile', input: code1 },
    { command: 'analyzeSelectionWithAI', input: code2 }
];

const batchResult = await commandExecutor.executeBatch(testCases);
console.log(`Success rate: ${batchResult.successfulResults}/${batchResult.totalTestCases}`);
```

## 📊 Performance Benchmarking

### Latency Testing

```typescript
const performanceTestSuite = new PerformanceTestSuite();
const latencyReport = await performanceTestSuite.runLatencyTests();

console.log(`Average latency: ${latencyReport.summary.averageLatency}ms`);
console.log(`P95 latency: ${latencyReport.summary.p95Latency}ms`);
```

### Throughput Testing

```typescript
const throughputReport = await performanceTestSuite.runThroughputTests();
console.log(`Max throughput: ${throughputReport.summary.maxThroughput} tests/sec`);
console.log(`Optimal concurrency: ${throughputReport.summary.optimalConcurrency}`);
```

### Resource Monitoring

```typescript
const resourceMonitor = new ResourceMonitor();
resourceMonitor.startMonitoring(1000); // Monitor every second

// Run tests...

const resourceReport = resourceMonitor.stopMonitoring();
console.log(`Peak memory: ${resourceReport.memory.rss.max / 1024 / 1024} MB`);
```

## 📝 Example Test Execution

```typescript
// Complete test execution example
async function example() {
    const testRunner = new CodeGuardianTestRunner();
    
    try {
        // Initialize environment
        await testRunner.initialize();
        
        // Run comprehensive tests
        const testReport = await testRunner.runComprehensiveTests();
        
        // Run performance benchmarks
        const perfReport = await testRunner.runPerformanceBenchmarks();
        
        // Export results
        await testRunner.exportResults(testReport, 'test-results.json');
        
        // Display summary
        console.log(`Tests: ${testReport.totalTestCases}`);
        console.log(`F1 Score: ${testReport.overallMetrics.f1Score.toFixed(3)}`);
        console.log(`Avg Latency: ${perfReport.summary.averageLatency.toFixed(2)}ms`);
        
    } finally {
        await testRunner.cleanup();
    }
}
```

## 🔍 Troubleshooting

### Common Issues

1. **Extension not activating**: Ensure Code Guardian is installed and VS Code version is compatible
2. **Test timeout**: Increase timeout values in test configuration
3. **Memory issues**: Reduce concurrent test execution or increase Node.js memory limit
4. **VS Code permission errors**: Run tests with appropriate permissions

### Debug Mode

```typescript
// Enable verbose logging
process.env.DEBUG = 'code-guardian-test';

// Increase timeouts for debugging
const config = {
    ...defaultTestConfig,
    timeout: 60000,
    diagnosticTimeout: 10000
};
```

## 📋 API Reference

### Main Classes

- **`CodeGuardianTestRunner`**: Main test orchestrator
- **`CommandExecutor`**: Extension command execution
- **`DiagnosticValidator`**: Result validation
- **`PerformanceMeasurer`**: Performance monitoring
- **`TestDataManager`**: Test data organization
- **`ExtensionTestUtils`**: VS Code extension utilities

### Key Interfaces

- **`TestReport`**: Comprehensive test results
- **`CommandResult`**: Individual command execution results
- **`ValidationResult`**: Diagnostic validation outcome
- **`PerformanceStatistics`**: Performance measurement data

## 🤝 Contributing

1. Add new test cases to appropriate categories
2. Extend validation logic for new vulnerability types
3. Improve performance measurement accuracy
4. Add support for additional VS Code features

## 📄 License

This testing framework is part of the Code Guardian research project and follows the same licensing terms as the main extension.

---

**Note**: This framework implements the Day 5-7 requirements from the Code Guardian evaluation implementation plan, providing comprehensive VS Code extension testing capabilities for security-focused extensions.
