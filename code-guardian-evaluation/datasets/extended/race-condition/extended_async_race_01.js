// Async race condition in data processing
// CWE: CWE-362
// Severity: medium
// Source: Extended Research Pattern
// Vulnerable lines: [9, 19]

// Extended: Async race condition
class DataProcessor {
    constructor() {
        this.processing = false;
        this.queue = [];
    }
    
    async processData(data) {
        // Vulnerable: Race condition in async processing
        if (this.processing) {
            this.queue.push(data);
            return;
        }
        
        this.processing = true;
        
        try {
            await this.heavyProcessing(data);
            
            // Vulnerable: Queue processing without proper synchronization
            while (this.queue.length > 0) {
                const nextData = this.queue.shift();
                await this.heavyProcessing(nextData);
            }
        } finally {
            this.processing = false;
        }
    }
}