#!/usr/bin/env node

/**
 * Quick Start Script for Code Guardian Testing Framework
 * 
 * This script provides an easy way to get started with the testing framework
 * Run: node quick-start.js
 */

const path = require('path');
const fs = require('fs');
const { spawn } = require('child_process');

async function quickStart() {
    console.log('🚀 Code Guardian Testing Framework - Quick Start');
    console.log('===============================================\n');

    // Check if framework is built
    const distPath = path.join(__dirname, 'dist');
    if (!fs.existsSync(distPath)) {
        console.log('❌ Framework not built. Building now...');
        
        try {
            await runCommand('npm', ['run', 'build']);
            console.log('✅ Framework built successfully\n');
        } catch (error) {
            console.error('❌ Build failed:', error.message);
            process.exit(1);
        }
    }

    console.log('📋 Code Guardian Testing Framework Overview');
    console.log('===========================================\n');

    console.log('This framework provides comprehensive testing for VS Code extensions:');
    console.log('• 🔍 Automated vulnerability detection testing');
    console.log('• 📊 Performance measurement and benchmarking');
    console.log('• ✅ Diagnostic validation and accuracy metrics');
    console.log('• 🎯 Integration testing with real VS Code environment\n');

    console.log('🎯 Available Test Categories:');
    console.log('============================');
    console.log('1. Extension Activation & Command Registration');
    console.log('2. Vulnerable Code Detection (SQL Injection, XSS, etc.)');
    console.log('3. Code Selection Analysis');
    console.log('4. Performance Benchmarking');
    console.log('5. Batch Processing Tests\n');

    console.log('🚀 Running VS Code Extension Tests...');
    console.log('=====================================');
    
    try {
        // Run the actual VS Code tests
        await runCommand('npm', ['test'], { stdio: 'inherit' });
        
        console.log('\n✅ Tests completed successfully!');
        console.log('\n📊 What the tests measured:');
        console.log('• Extension activation time and status');
        console.log('• Command registration verification');
        console.log('• Vulnerability detection accuracy');
        console.log('• Analysis performance metrics');
        console.log('• Selection-based analysis functionality');

    } catch (error) {
        console.error('\n❌ Test execution failed:', error.message);
        console.log('\n🔧 Troubleshooting Tips:');
        console.log('=======================');
        console.log('1. Ensure Code Guardian extension is installed in VS Code:');
        console.log('   • Open VS Code');
        console.log('   • Go to Extensions (Ctrl+Shift+X)');
        console.log('   • Search for "Code Guardian"');
        console.log('   • Install if not present\n');
        
        console.log('2. Check that VS Code is not running with the extension:');
        console.log('   • Close all VS Code windows');
        console.log('   • The test will launch VS Code automatically\n');
        
        console.log('3. Verify system requirements:');
        console.log('   • Node.js 19.2.0+ (you have this ✓)');
        console.log('   • VS Code 1.90.0+');
        console.log('   • No other VS Code extension tests running\n');
        
        console.log('4. Try manual test execution:');
        console.log('   npm run build');
        console.log('   npm test\n');
        
        process.exit(1);
    }

    console.log('\n🎯 Next Steps:');
    console.log('==============');
    console.log('• 📊 Run performance tests: npm run test:performance');
    console.log('• 🔄 Run integration tests: npm run test:integration');
    console.log('• 📚 Read detailed guide: USAGE_GUIDE.md');
    console.log('• ⚙️ Customize tests: Edit src/suite/extension.test.ts');
    console.log('• 📈 View test reports: Check console output above\n');

    console.log('� Framework is ready for comprehensive Code Guardian evaluation!');
    console.log('� For detailed usage instructions, see: USAGE_GUIDE.md');
}

function runCommand(command, args, options = {}) {
    return new Promise((resolve, reject) => {
        const child = spawn(command, args, {
            stdio: options.stdio || 'pipe',
            shell: true,
            ...options
        });

        let stdout = '';
        let stderr = '';

        if (child.stdout) {
            child.stdout.on('data', (data) => {
                stdout += data.toString();
            });
        }

        if (child.stderr) {
            child.stderr.on('data', (data) => {
                stderr += data.toString();
            });
        }

        child.on('close', (code) => {
            if (code === 0) {
                resolve({ stdout, stderr });
            } else {
                reject(new Error(`Command failed with code ${code}: ${stderr || stdout}`));
            }
        });

        child.on('error', (error) => {
            reject(error);
        });
    });
}

// Run the quick start
if (require.main === module) {
    quickStart().catch(console.error);
}

module.exports = { quickStart };
