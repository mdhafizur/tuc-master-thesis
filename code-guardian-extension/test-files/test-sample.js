// Sample JavaScript file with security vulnerabilities for testing

const express = require('express');
const mysql = require('mysql');
const app = express();

// SQL Injection vulnerability
app.get('/user/:id', (req, res) => {
    const userId = req.params.id;
    const query = `SELECT * FROM users WHERE id = ${userId}`; // Direct SQL injection risk
    
    connection.query(query, (error, results) => {
        if (error) throw error;
        res.json(results);
    });
});

// XSS vulnerability  
app.post('/comment', (req, res) => {
    const comment = req.body.comment;
    // Directly outputting user input without sanitization
    res.send(`<div>Comment: ${comment}</div>`);
});

// Insecure authentication
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    
    // Plain text password comparison
    if (username === 'admin' && password === 'password123') {
        // No session management or token
        res.json({ success: true, isAdmin: true });
    } else {
        res.status(401).json({ success: false });
    }
});

// Insecure file upload
app.post('/upload', (req, res) => {
    const file = req.files.upload;
    // No file type validation
    file.mv(`./uploads/${file.name}`, (err) => {
        if (err) return res.status(500).send(err);
        res.send('File uploaded!');
    });
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
