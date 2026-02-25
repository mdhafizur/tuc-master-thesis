import * as vscode from 'vscode';

/**
 * Performance measurement utilities for extension testing
 */
export class PerformanceMeasurer {
    private measurements: Map<string, PerformanceMeasurement[]> = new Map();
    private activeTimers: Map<string, number> = new Map();

    /**
     * Start timing an operation
     */
    startTimer(operationName: string): void {
        this.activeTimers.set(operationName, performance.now());
    }

    /**
     * End timing an operation and record the measurement
     */
    endTimer(operationName: string, metadata?: Record<string, any>): PerformanceMeasurement {
        const endTime = performance.now();
        const startTime = this.activeTimers.get(operationName);
        
        if (!startTime) {
            throw new Error(`Timer ${operationName} was not started`);
        }

        const duration = endTime - startTime;
        const measurement: PerformanceMeasurement = {
            operationName,
            duration,
            timestamp: new Date(),
            metadata: metadata || {}
        };

        // Store the measurement
        if (!this.measurements.has(operationName)) {
            this.measurements.set(operationName, []);
        }
        this.measurements.get(operationName)!.push(measurement);

        // Clean up the timer
        this.activeTimers.delete(operationName);

        return measurement;
    }

    /**
     * Measure an async operation
     */
    async measureAsync<T>(
        operationName: string, 
        operation: () => Promise<T>,
        metadata?: Record<string, any>
    ): Promise<{ result: T; measurement: PerformanceMeasurement }> {
        this.startTimer(operationName);
        
        try {
            const result = await operation();
            const measurement = this.endTimer(operationName, metadata);
            return { result, measurement };
        } catch (error) {
            this.endTimer(operationName, { ...metadata, error: error instanceof Error ? error.message : String(error) });
            throw error;
        }
    }

    /**
     * Measure a synchronous operation
     */
    measureSync<T>(
        operationName: string, 
        operation: () => T,
        metadata?: Record<string, any>
    ): { result: T; measurement: PerformanceMeasurement } {
        this.startTimer(operationName);
        
        try {
            const result = operation();
            const measurement = this.endTimer(operationName, metadata);
            return { result, measurement };
        } catch (error) {
            this.endTimer(operationName, { ...metadata, error: error instanceof Error ? error.message : String(error) });
            throw error;
        }
    }

    /**
     * Get all measurements for an operation
     */
    getMeasurements(operationName: string): PerformanceMeasurement[] {
        return this.measurements.get(operationName) || [];
    }

    /**
     * Get statistics for an operation
     */
    getStatistics(operationName: string): PerformanceStatistics {
        const measurements = this.getMeasurements(operationName);
        
        if (measurements.length === 0) {
            throw new Error(`No measurements found for operation: ${operationName}`);
        }

        const durations = measurements.map(m => m.duration);
        durations.sort((a, b) => a - b);

        const sum = durations.reduce((acc, duration) => acc + duration, 0);
        const mean = sum / durations.length;
        
        // Calculate standard deviation
        const variance = durations.reduce((acc, duration) => acc + Math.pow(duration - mean, 2), 0) / durations.length;
        const standardDeviation = Math.sqrt(variance);

        return {
            operationName,
            count: measurements.length,
            min: durations[0],
            max: durations[durations.length - 1],
            mean,
            median: this.getPercentile(durations, 50),
            p95: this.getPercentile(durations, 95),
            p99: this.getPercentile(durations, 99),
            standardDeviation,
            totalTime: sum
        };
    }

    /**
     * Get percentile value from sorted array
     */
    private getPercentile(sortedArray: number[], percentile: number): number {
        const index = (percentile / 100) * (sortedArray.length - 1);
        const lower = Math.floor(index);
        const upper = Math.ceil(index);
        const weight = index % 1;

        if (lower === upper) {
            return sortedArray[lower];
        }

        return sortedArray[lower] * (1 - weight) + sortedArray[upper] * weight;
    }

    /**
     * Clear all measurements
     */
    clearMeasurements(): void {
        this.measurements.clear();
        this.activeTimers.clear();
    }

    /**
     * Export measurements to JSON
     */
    exportMeasurements(): string {
        const data = {
            timestamp: new Date().toISOString(),
            measurements: Object.fromEntries(this.measurements),
            statistics: this.getAllStatistics()
        };
        return JSON.stringify(data, null, 2);
    }

    /**
     * Get statistics for all operations
     */
    getAllStatistics(): Record<string, PerformanceStatistics> {
        const stats: Record<string, PerformanceStatistics> = {};
        
        for (const operationName of this.measurements.keys()) {
            try {
                stats[operationName] = this.getStatistics(operationName);
            } catch (error) {
                console.warn(`Failed to calculate statistics for ${operationName}:`, error);
            }
        }
        
        return stats;
    }
}

/**
 * Resource usage monitor for tracking memory and CPU usage
 */
export class ResourceMonitor {
    private monitoring = false;
    private monitoringInterval?: NodeJS.Timeout;
    private resourceSnapshots: ResourceSnapshot[] = [];

    /**
     * Start monitoring resource usage
     */
    startMonitoring(intervalMs: number = 1000): void {
        if (this.monitoring) {
            return;
        }

        this.monitoring = true;
        this.resourceSnapshots = [];

        this.monitoringInterval = setInterval(() => {
            this.recordResourceSnapshot();
        }, intervalMs);
    }

    /**
     * Stop monitoring resource usage
     */
    stopMonitoring(): ResourceUsageReport {
        if (!this.monitoring) {
            throw new Error('Resource monitoring is not active');
        }

        this.monitoring = false;
        if (this.monitoringInterval) {
            clearInterval(this.monitoringInterval);
            this.monitoringInterval = undefined;
        }

        return this.generateReport();
    }

    /**
     * Record a snapshot of current resource usage
     */
    private recordResourceSnapshot(): void {
        const memUsage = process.memoryUsage();
        
        const snapshot: ResourceSnapshot = {
            timestamp: new Date(),
            memory: {
                rss: memUsage.rss,
                heapUsed: memUsage.heapUsed,
                heapTotal: memUsage.heapTotal,
                external: memUsage.external
            },
            cpu: process.cpuUsage()
        };

        this.resourceSnapshots.push(snapshot);
    }

    /**
     * Generate resource usage report
     */
    private generateReport(): ResourceUsageReport {
        if (this.resourceSnapshots.length === 0) {
            throw new Error('No resource snapshots available');
        }

        const memoryStats = this.calculateMemoryStatistics();
        const cpuStats = this.calculateCpuStatistics();

        return {
            startTime: this.resourceSnapshots[0].timestamp,
            endTime: this.resourceSnapshots[this.resourceSnapshots.length - 1].timestamp,
            duration: this.resourceSnapshots[this.resourceSnapshots.length - 1].timestamp.getTime() - 
                     this.resourceSnapshots[0].timestamp.getTime(),
            snapshotCount: this.resourceSnapshots.length,
            memory: memoryStats,
            cpu: cpuStats,
            snapshots: this.resourceSnapshots
        };
    }

    /**
     * Calculate memory usage statistics
     */
    private calculateMemoryStatistics(): MemoryStatistics {
        const rssValues = this.resourceSnapshots.map(s => s.memory.rss);
        const heapUsedValues = this.resourceSnapshots.map(s => s.memory.heapUsed);
        const heapTotalValues = this.resourceSnapshots.map(s => s.memory.heapTotal);

        return {
            rss: this.calculateStats(rssValues),
            heapUsed: this.calculateStats(heapUsedValues),
            heapTotal: this.calculateStats(heapTotalValues)
        };
    }

    /**
     * Calculate CPU usage statistics
     */
    private calculateCpuStatistics(): CpuStatistics {
        // Calculate CPU usage differences between snapshots
        const cpuDeltas: number[] = [];
        
        for (let i = 1; i < this.resourceSnapshots.length; i++) {
            const prev = this.resourceSnapshots[i - 1].cpu;
            const curr = this.resourceSnapshots[i].cpu;
            
            const userDelta = curr.user - prev.user;
            const systemDelta = curr.system - prev.system;
            const totalDelta = userDelta + systemDelta;
            
            cpuDeltas.push(totalDelta);
        }

        return {
            totalUsage: this.calculateStats(cpuDeltas)
        };
    }

    /**
     * Calculate basic statistics for an array of numbers
     */
    private calculateStats(values: number[]): BasicStatistics {
        const sorted = [...values].sort((a, b) => a - b);
        const sum = values.reduce((acc, val) => acc + val, 0);
        const mean = sum / values.length;

        return {
            min: sorted[0],
            max: sorted[sorted.length - 1],
            mean,
            median: sorted[Math.floor(sorted.length / 2)],
            total: sum
        };
    }
}

/**
 * Interface for performance measurements
 */
export interface PerformanceMeasurement {
    operationName: string;
    duration: number; // in milliseconds
    timestamp: Date;
    metadata: Record<string, any>;
}

/**
 * Interface for performance statistics
 */
export interface PerformanceStatistics {
    operationName: string;
    count: number;
    min: number;
    max: number;
    mean: number;
    median: number;
    p95: number;
    p99: number;
    standardDeviation: number;
    totalTime: number;
}

/**
 * Interface for resource snapshots
 */
export interface ResourceSnapshot {
    timestamp: Date;
    memory: {
        rss: number;
        heapUsed: number;
        heapTotal: number;
        external: number;
    };
    cpu: NodeJS.CpuUsage;
}

/**
 * Interface for resource usage report
 */
export interface ResourceUsageReport {
    startTime: Date;
    endTime: Date;
    duration: number;
    snapshotCount: number;
    memory: MemoryStatistics;
    cpu: CpuStatistics;
    snapshots: ResourceSnapshot[];
}

/**
 * Interface for memory statistics
 */
export interface MemoryStatistics {
    rss: BasicStatistics;
    heapUsed: BasicStatistics;
    heapTotal: BasicStatistics;
}

/**
 * Interface for CPU statistics
 */
export interface CpuStatistics {
    totalUsage: BasicStatistics;
}

/**
 * Interface for basic statistics
 */
export interface BasicStatistics {
    min: number;
    max: number;
    mean: number;
    median: number;
    total: number;
}
