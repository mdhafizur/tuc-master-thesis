// Insufficient input validation in API
// CWE: CWE-20
// Severity: medium
// Source: Extended Research Pattern
// Vulnerable lines: [15]

// Extended: Input validation bypass
const express = require('express');
const app = express();

app.post('/api/users', (req, res) => {
    const { name, email, age, role } = req.body;
    
    // Vulnerable: Insufficient validation
    if (!name || !email) {
        return res.status(400).json({ error: 'Name and email required' });
    }
    
    // Vulnerable: No validation on role escalation
    const user = {
        name: name,
        email: email,
        age: parseInt(age) || 0,
        role: role || 'user', // Can be manipulated to 'admin'
        created: new Date()
    };
    
    saveUser(user);
    res.json({ success: true, user: user });
});