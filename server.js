// Deliberately vulnerable demo server for SAST/SCA scanner validation.
// Written against Coverity-recognized source/sink pairs (Express req.query
// as taint source; child_process.exec and mysql2 .query() as sinks).
// DO NOT deploy. Needs no live DB to trip static analysis.

const express = require('express');
const { exec } = require('child_process');
const mysql = require('mysql2');

// SCA note: minimist@1.2.0 carries CVE-2020-7598 and CVE-2021-44906
// (prototype pollution). Present so Black Duck SCA has something to flag.
const parseArgs = require('minimist');

const app = express();

// Connection is never required to be live for static taint analysis.
const db = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'root',
  database: 'app',
});

app.get('/ping', (req, res) => {
  // --- CRITICAL SAST: OS command injection (CWE-78) ---
  // Express query param (taint source) concatenated into a shell command.
  // e.g. /ping?host=localhost;id  -> runs `id`
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
  // --- CRITICAL SAST: SQL injection (CWE-89) ---
  // Express query param (taint source) concatenated into the SQL string
  // passed to mysql2 .query() (recognized SQLI sink).
  // e.g. /user?name=alice' OR '1'='1  -> returns every row
  const name = req.query.name || '';
  const sql = "SELECT id, username, email FROM users WHERE username = '" + name + "'";
  db.query(sql, (err, rows) => {
    if (err) return res.status(400).type('text/plain').send('query error: ' + err.message);
    res.json(rows);
  });
});

app.get('/', (req, res) => {
  res.type('text/plain').send('vuln-demo: try GET /ping?host=localhost  or  GET /user?name=alice\n');
});

const argv = parseArgs(process.argv.slice(2));
const port = argv.port || 3000;
app.listen(port, () => console.log(`vuln-demo listening on http://localhost:${port}`));