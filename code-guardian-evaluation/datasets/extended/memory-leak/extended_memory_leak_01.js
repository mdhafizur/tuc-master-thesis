// Memory leak via event listener accumulation
// CWE: CWE-401
// Severity: medium
// Source: Extended Research Pattern
// Vulnerable lines: [9, 16]

// Extended: Memory leak pattern
class EventManager {
    constructor() {
        this.listeners = [];
    }
    
    addDynamicListener(element, event, callback) {
        // Vulnerable: Listeners accumulate without cleanup
        element.addEventListener(event, callback);
        this.listeners.push({ element, event, callback });
    }
    
    updateContent(data) {
        data.forEach(item => {
            const element = document.createElement('div');
            // Vulnerable: New listeners on each update
            this.addDynamicListener(element, 'click', () => {
                console.log(item);
            });
            document.body.appendChild(element);
        });
    }
}