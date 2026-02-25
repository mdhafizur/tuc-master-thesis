// React DOM XSS vulnerability (Big-Vul style)
// CWE: CWE-79
// Severity: high
// Source: Big-Vul Pattern (CVE-2018-6341)
// CVE: CVE-2018-6341
// Vulnerable lines: [10, 20]

// Big-Vul style React XSS vulnerability
import React from 'react';

function UserProfile({ userData }) {
    // Vulnerable: dangerouslySetInnerHTML without sanitization
    return (
        <div className="profile">
            <h1>Welcome, {userData.name}</h1>
            <div 
                className="bio"
                dangerouslySetInnerHTML={{__html: userData.bio}}
            />
        </div>
    );
}

function CommentComponent({ comment }) {
    // Vulnerable: Direct HTML insertion
    const commentHtml = comment.text.replace(/\n/g, '<br>');
    
    return <div dangerouslySetInnerHTML={{__html: commentHtml}} />;
}