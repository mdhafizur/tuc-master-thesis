#!/usr/bin/env node

/**
 * Simple runner script for metrics collection
 * 
 * Usage:
 *   npm run collect-metrics
 *   node run-metrics-collection.js
 */

import MetricsEnabledTestRunner from './src/metrics-integration-test';

async function main() {
    console.log('🚀 Code Guardian Metrics Collection');
    console.log('===================================');
    
    const runner = new MetricsEnabledTestRunner();
    
    try {
        await runner.initialize();
        
        console.log('📊 Collecting metrics data...');
        const exportedFiles = await runner.runMetricsCollectionTests();
        
        const summary = runner.getMetricsSummary();
        
        console.log('\n✅ Collection Complete!');
        console.log(`📈 Collected ${summary.totalDataPoints} total data points`);
        console.log('📄 Data exported to:');
        exportedFiles.forEach(file => console.log(`   ${file}`));
        
        console.log('\n🔄 Next: Run Python evaluation framework');
        console.log('   cd ../evaluation && python test_calculators.py');
        
    } catch (error) {
        console.error('❌ Failed:', error);
        process.exit(1);
    } finally {
        await runner.cleanup();
    }
}

if (require.main === module) {
    main().catch(console.error);
}
