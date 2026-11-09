// =============================================================================
// Deliberately vulnerable demo server — labeled one-finding-per-CWE fixture.
// Purpose: validate Black Duck (SCA) + Coverity (SAST) detection & policy.
// DO NOT DEPLOY. No live DB/network required to trip static taint analysis.
//
// Each route below is a single, clean source->sink pair in the dialect
// Coverity models (Express req.query as taint source; built-in / mysql2 sinks).
// The two RCE sinks are marked [CRITICAL] — highest impact, policy-rated top.
// Finding <-> route <-> CWE map is in README.md.
// =============================================================================

const express = require('express');
const { exec } = require('child_process');
const fs = require('fs');
const http = require('http');
const crypto = require('crypto');
const mysql = require('mysql2');

// SCA: minimist@1.2.0 -> CVE-2020-7598 + CVE-2021-44906 (prototype pollution).
const parseArgs = require('minimist');

const app = express();

// --- CWE-798: Hard-coded Credentials -----------------------------------------
// Literal DB creds. Connection need not be live for static analysis.
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'SuperSecret123',   // hard-coded secret
  database: 'app',
});

// --- CWE-78: OS Command Injection ----------------------------- [CRITICAL] ---
// req.query.host -> child_process.exec. Unauthenticated RCE.
// e.g. /ping?host=localhost;id
app.get('/ping', (req, res) => {
  const host = req.query.host || 'localhost';
  exec('ping -c 1 ' + host, (err, stdout, stderr) => {
    res.type('text/plain').send(stdout || stderr || String(err));
  });
});

// --- CRITICAL SAST: Code Injection via vm (CWE-94) ---
// req.query.code -> vm.runInNewContext. Unauthenticated RCE.
// e.g. /run?code=process.mainModule.require('child_process').execSync('id').toString()
app.get('/run', (req, res) => {
  const vm = require('vm');                 // Node core module — no dependency added
  const code = req.query.code || '1+1';
  const result = vm.runInNewContext(code);  // tainted data into vm code-exec sink
  res.type('text/plain').send(String(result));
});

// --- CRITICAL SAST: OS Command Injection (CWE-78) ---
// req.query.domain -> child_process.exec. Unauthenticated RCE.
// e.g. /lookup?domain=example.com;id
app.get('/lookup', (req, res) => {
  const domain = req.query.domain || 'example.com';
  exec('nslookup ' + domain, (err, stdout, stderr) => {  // tainted data into exec sink
    res.type('text/plain').send(stdout || stderr || String(err));
  });
});


app.get('/user', (req, res) => {
  const name = req.query.name || '';
  const sql = "SELECT id, username, email FROM users WHERE username = '" + name + "'";
  db.query(sql, (err, rows) => {
    res.json(err ? { error: err.message } : rows);
  });
});

// --- CWE-22: Path Traversal --------------------------------------------------
// req.query.file -> fs.readFile. e.g. /read?file=../../etc/passwd
app.get('/read', (req, res) => {
  const file = req.query.file || 'README.md';
  fs.readFile(file, 'utf8', (err, data) => {
    res.type('text/plain').send(err ? err.message : data);
  });
});

// --- CWE-918: Server-Side Request Forgery ------------------------------------
// req.query.url -> http.get. e.g. /fetch?url=http://169.254.169.254/
app.get('/fetch', (req, res) => {
  const target = req.query.url || 'http://localhost/';
  http.get(target, (r) => {
    let body = '';
    r.on('data', (c) => (body += c));
    r.on('end', () => res.type('text/plain').send(body));
  }).on('error', (e) => res.type('text/plain').send(e.message));
});

// --- CWE-79: Reflected Cross-Site Scripting ----------------------------------
// req.query.name -> res.send() with HTML. e.g. /greet?name=<script>alert(1)</script>
app.get('/greet', (req, res) => {
  const name = req.query.name || 'world';
  res.type('text/html').send('<h1>Hello ' + name + '</h1>');
});

// --- CWE-601: Open Redirect --------------------------------------------------
// req.query.next -> res.redirect. e.g. /go?next=https://evil.example
app.get('/go', (req, res) => {
  res.redirect(req.query.next || '/');
});

// --- CWE-327/328: Weak Hashing Algorithm -------------------------------------
// MD5 used for a "password" hash.
app.get('/hash', (req, res) => {
  const pw = req.query.pw || 'password';
  const digest = crypto.createHash('md5').update(pw).digest('hex');
  res.type('text/plain').send(digest);
});

// --- CWE-338: Insecure Randomness --------------------------------------------
// Math.random() used to mint a session token.
app.get('/token', (req, res) => {
  const token = Math.random().toString(36).slice(2);
  res.type('text/plain').send(token);
});

app.get('/', (req, res) => {
  res.type('text/plain').send(
    'vuln-demo fixture. Routes: /ping /calc /user /read /fetch /greet /go /hash /token\n'
  );
});

const argv = parseArgs(process.argv.slice(2));
const port = argv.port || 3000;

// --- CWE-319: Cleartext Transmission -----------------------------------------
// Plain HTTP listener (no TLS).
http.createServer(app).listen(port, () => {
  console.log('vuln-demo listening on http://localhost:' + port);
});