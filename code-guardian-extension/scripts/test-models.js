#!/usr/bin/env node

// Test script to verify Ollama models work with code analysis
const { Ollama } = require('ollama');

const ollama = new Ollama();

const testCode = `
function getUserData(userId) {
    const query = "SELECT * FROM users WHERE id = " + userId;
    return db.query(query);
}

function displayMessage(userInput) {
    document.getElementById('output').innerHTML = userInput;
}
`;

const systemPrompt = `You are a secure code analyzer. Detect security issues in code and return them in JSON format like this:
[
  {
    "message": "Issue description",
    "startLine": 1,
    "endLine": 3,
    "suggestedFix": "Optional suggested secure version"
  }
]`;

async function testModel(modelName) {
    console.log(`\n🧪 Testing ${modelName}...`);
    
    try {
        const startTime = Date.now();
        
        const response = await ollama.chat({
            model: modelName,
            messages: [
                {
                    role: 'system',
                    content: systemPrompt
                },
                {
                    role: 'user',
                    content: `Analyze the following JavaScript code for security vulnerabilities:\n\n${testCode}`
                }
            ],
            options: {
                temperature: 0.1,
                num_predict: 500
            }
        });
        
        const endTime = Date.now();
        const duration = endTime - startTime;
        
        console.log(`✅ ${modelName} - Response time: ${duration}ms`);
        console.log(`📝 Response: ${response.message.content.substring(0, 200)}...`);
        
        // Try to parse as JSON
        try {
            const cleanContent = response.message.content.replace(/```json\n?/g, '').replace(/```\n?/g, '').trim();
            const issues = JSON.parse(cleanContent);
            if (Array.isArray(issues)) {
                console.log(`🔍 Found ${issues.length} security issues`);
                issues.forEach((issue, index) => {
                    console.log(`   ${index + 1}. ${issue.message} (Line ${issue.startLine})`);
                });
            }
        } catch (parseError) {
            console.log(`⚠️  Response not in expected JSON format, but model responded successfully`);
        }
        
        return { success: true, duration, model: modelName };
        
    } catch (error) {
        console.log(`❌ ${modelName} failed: ${error.message}`);
        return { success: false, error: error.message, model: modelName };
    }
}

async function runTests() {
    console.log('🚀 Testing Code Guardian with lightweight models...');
    
    const modelsToTest = [
        'gemma3:1b',
        'llama3.2:1b',
        'codellama:7b'
    ];
    
    const results = [];
    
    for (const model of modelsToTest) {
        const result = await testModel(model);
        results.push(result);
        
        // Add delay between tests
        await new Promise(resolve => setTimeout(resolve, 1000));
    }
    
    console.log('\n📊 Test Results Summary:');
    console.log('========================');
    
    const successful = results.filter(r => r.success);
    const failed = results.filter(r => !r.success);
    
    if (successful.length > 0) {
        console.log('\n✅ Working Models:');
        successful.forEach(result => {
            console.log(`   • ${result.model} - ${result.duration}ms`);
        });
        
        // Find fastest model
        const fastest = successful.reduce((prev, current) => 
            prev.duration < current.duration ? prev : current
        );
        console.log(`\n🏆 Fastest Model: ${fastest.model} (${fastest.duration}ms)`);
    }
    
    if (failed.length > 0) {
        console.log('\n❌ Failed Models:');
        failed.forEach(result => {
            console.log(`   • ${result.model} - ${result.error}`);
        });
    }
    
    console.log(`\n📈 Success Rate: ${successful.length}/${results.length} (${Math.round(successful.length/results.length*100)}%)`);
    
    if (successful.length > 0) {
        console.log(`\n💡 Recommendation: Use ${successful[0].model} for Code Guardian testing`);
    }
}

// Run the tests
runTests().catch(console.error);