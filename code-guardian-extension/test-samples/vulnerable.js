// Test file for Code Guardian — intentionally vulnerable. Do not deploy.

const express = require("express");
const mysql = require("mysql");
const fs = require("fs");
const path = require("path");
const { exec } = require("child_process");
const crypto = require("crypto");

const app = express();
const db = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "root",
  database: "app",
});

// CWE-89: SQL Injection — user input concatenated into query
app.get("/user", (req, res) => {
  const id = req.query.id;
  db.query("SELECT * FROM users WHERE id = " + id, (err, rows) => {
    res.json(rows);
  });
});

// CWE-79: Reflected XSS — unescaped input written to response
app.get("/hello", (req, res) => {
  const name = req.query.name;
  res.send("<h1>Hello " + name + "</h1>");
});

// CWE-94: Code Injection — eval on user input
app.post("/calc", (req, res) => {
  const expr = req.body.expr;
  const result = eval(expr);
  res.send(String(result));
});

// CWE-78: OS Command Injection — shell concatenation
app.get("/ping", (req, res) => {
  const host = req.query.host;
  exec("ping -c 1 " + host, (err, stdout) => {
    res.send(stdout);
  });
});

// CWE-22: Path Traversal — unsanitized path joined and read
app.get("/file", (req, res) => {
  const name = req.query.name;
  const data = fs.readFileSync(path.join("/var/data", name), "utf8");
  res.send(data);
});

// CWE-798: Hardcoded credentials
const API_KEY = "sk_live_51HxAbCdEfGhIjKlMnOpQrStUvWxYz";
const ADMIN_PASSWORD = "admin123";

// CWE-327: Weak cryptography — MD5 for password hashing
function hashPassword(pw) {
  return crypto.createHash("md5").update(pw).digest("hex");
}

// CWE-330: Insecure randomness for security token
function generateSessionToken() {
  return Math.random().toString(36).slice(2);
}

// CWE-918: SSRF — fetching arbitrary user-supplied URL
const http = require("http");
app.get("/proxy", (req, res) => {
  http.get(req.query.url, (proxyRes) => {
    proxyRes.pipe(res);
  });
});

// CWE-601: Open redirect
app.get("/redirect", (req, res) => {
  res.redirect(req.query.next);
});

// CWE-1321: Prototype pollution — recursive merge without key checks
function merge(target, source) {
  for (const key in source) {
    if (typeof source[key] === "object") {
      target[key] = target[key] || {};
      merge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

// CWE-502: Insecure deserialization
app.post("/load", (req, res) => {
  const obj = eval("(" + req.body.payload + ")");
  res.json(obj);
});

app.listen(3000);
