/**
 * Insecure Node.js Application - For Security Scanner Testing Only
 * Contains multiple intentional vulnerabilities
 */

const express = require('express');
const mysql = require('mysql');
const { exec } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Hardcoded credentials
const DB_PASSWORD = 'SuperSecret123!';
const API_KEY = 'sk_live_4eC39HqLyjWDarhtT657tMo5k';
const AWS_ACCESS_KEY = 'AKIAIOSFODNN7EXAMPLE';
const AWS_SECRET = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
const JWT_SECRET = 'my-super-secret-jwt-key';

// Database connection with hardcoded credentials
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'admin123',
  database: 'myapp'
});

// SQL Injection vulnerability
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  // Vulnerable to SQL injection
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  db.query(query, (err, results) => {
    if (err) throw err;
    res.json(results);
  });
});

// Command Injection
app.get('/ping', (req, res) => {
  const host = req.query.host || 'localhost';
  // Vulnerable to command injection
  exec(`ping -c 1 ${host}`, (error, stdout, stderr) => {
    res.send(stdout);
  });
});

// Path Traversal
app.get('/file', (req, res) => {
  const filename = req.query.name;
  // Vulnerable to path traversal
  const filepath = path.join(__dirname, 'uploads', filename);
  fs.readFile(filepath, 'utf8', (err, data) => {
    if (err) return res.status(404).send('File not found');
    res.send(data);
  });
});

// XSS vulnerability
app.get('/search', (req, res) => {
  const query = req.query.q || '';
  // Vulnerable to XSS
  res.send(`<h1>Search results for: ${query}</h1>`);
});

// Prototype Pollution
app.post('/merge', (req, res) => {
  const target = {};
  const source = req.body;
  // Vulnerable to prototype pollution
  function merge(target, source) {
    for (let key in source) {
      if (typeof source[key] === 'object') {
        target[key] = merge(target[key] || {}, source[key]);
      } else {
        target[key] = source[key];
      }
    }
    return target;
  }
  const result = merge(target, source);
  res.json(result);
});

// Insecure deserialization
app.post('/deserialize', (req, res) => {
  const serialized = req.body.data;
  // Using eval - dangerous!
  const obj = eval(`(${serialized})`);
  res.json(obj);
});

// NoSQL Injection (MongoDB)
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // Vulnerable to NoSQL injection
  const query = {
    username: username,
    password: password
  };
  // db.collection('users').findOne(query) would be vulnerable
  res.send('Login processed');
});

// Weak cryptography
function hashPassword(password) {
  // Using weak MD5
  return crypto.createHash('md5').update(password).digest('hex');
}

// Insecure random token generation
function generateToken() {
  // Using Math.random() - not cryptographically secure
  return Math.random().toString(36).substring(7);
}

// SSRF vulnerability
app.get('/fetch', async (req, res) => {
  const url = req.query.url;
  const https = require('https');
  // Vulnerable to SSRF
  https.get(url, (response) => {
    let data = '';
    response.on('data', chunk => data += chunk);
    response.on('end', () => res.send(data));
  });
});

// Regular Expression Denial of Service (ReDoS)
app.get('/validate', (req, res) => {
  const input = req.query.input;
  // Catastrophic backtracking
  const regex = /^(a+)+$/;
  const isValid = regex.test(input);
  res.json({ valid: isValid });
});

// Insecure file upload
app.post('/upload', (req, res) => {
  const file = req.files.upload;
  // No validation on file type or size
  file.mv(`./uploads/${file.name}`, (err) => {
    if (err) return res.status(500).send(err);
    res.send('File uploaded');
  });
});

// Mass assignment vulnerability
app.post('/user/update', (req, res) => {
  const userId = req.body.id;
  // Directly using user input - allows mass assignment
  const updates = req.body;
  // Could allow updating isAdmin, role, etc.
  res.json({ message: 'User updated', updates });
});

// Hardcoded encryption key
const ENCRYPTION_KEY = 'this-is-my-encryption-key-1234567890ab';

// Information disclosure in error
app.get('/error', (req, res) => {
  try {
    throw new Error('Database connection failed at mysql://root:password@localhost:3306/mydb');
  } catch (e) {
    // Exposing stack trace and sensitive info
    res.status(500).send(e.stack);
  }
});

// Using vulnerable packages
// lodash 4.17.15 has prototype pollution
const _ = require('lodash');

// Cookie without security flags
app.get('/set-cookie', (req, res) => {
  res.cookie('session', 'sensitive-data', {
    httpOnly: false,  // Accessible via JavaScript
    secure: false,    // Not HTTPS only
    sameSite: 'none'  // No CSRF protection
  });
  res.send('Cookie set');
});

// CORS misconfiguration
app.use((req, res, next) => {
  // Allowing all origins
  res.header('Access-Control-Allow-Origin', '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  next();
});

// Logging sensitive data
app.post('/process-payment', (req, res) => {
  const { cardNumber, cvv, amount } = req.body;
  // Logging sensitive payment data
  console.log(`Processing payment: Card ${cardNumber}, CVV ${cvv}, Amount ${amount}`);
  res.json({ success: true });
});

// Unvalidated redirect
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  // Open redirect vulnerability
  res.redirect(url);
});

// Server-side template injection
app.get('/template', (req, res) => {
  const name = req.query.name;
  const ejs = require('ejs');
  // Vulnerable to template injection
  const template = `<h1>Hello <%= name %></h1>`;
  const html = ejs.render(template, { name });
  res.send(html);
});

// Running with debug enabled
app.listen(3000, '0.0.0.0', () => {
  console.log('Server running on port 3000');
  console.log(`Database password: ${DB_PASSWORD}`); // Logging secrets
  console.log(`API Key: ${API_KEY}`);
});

module.exports = app;
