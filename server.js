// Deliberately vulnerable demo server.
// Purpose: give a SAST tool and an SCA tool critical findings to catch.
// DO NOT deploy. Run only on an isolated machine.

const http = require('http');
const { URL } = require('url');
const { exec } = require('child_process');
const Database = require('better-sqlite3');

// SCA note: this pulls in minimist@1.2.0 (CVE-2021-44906, prototype
// pollution, CVSS 9.8 critical). Present so an SCA scan has something to flag.
const parseArgs = require('minimist');

// Seed a throwaway in-memory DB so the SQLi route actually runs.
const db = new Database(':memory:');
db.exec(`
  CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, email TEXT);
  INSERT INTO users (username, email) VALUES
    ('alice', 'alice@example.com'),
    ('bob',   'bob@example.com');
`);

const server = http.createServer((req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);

  if (url.pathname === '/ping') {
    // --- CRITICAL SAST FINDING #1: OS command injection (CWE-78) ---
    // Untrusted query param concatenated straight into a shell command.
    // e.g. /ping?host=localhost;id   ->   runs `id`
    const host = url.searchParams.get('host') || 'localhost';
    exec('ping -c 1 ' + host, (err, stdout, stderr) => {
      res.writeHead(200, { 'Content-Type': 'text/plain' });
      res.end(stdout || stderr || String(err));
    });
    return;
  }

  if (url.pathname === '/user') {
    // --- CRITICAL SAST FINDING #2: SQL injection (CWE-89) ---
    // Untrusted query param concatenated straight into the SQL string.
    // e.g. /user?name=alice' OR '1'='1   ->   dumps every row
    const name = url.searchParams.get('name') || '';
    const sql = "SELECT id, username, email FROM users WHERE username = '" + name + "'";
    try {
      const rows = db.prepare(sql).all();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(rows, null, 2));
    } catch (e) {
      res.writeHead(400, { 'Content-Type': 'text/plain' });
      res.end('query error: ' + e.message);
    }
    return;
  }

  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('vuln-demo: try GET /ping?host=localhost  or  GET /user?name=alice\n');
});

const argv = parseArgs(process.argv.slice(2));
const port = argv.port || 3000;

server.listen(port, () => {
  console.log(`vuln-demo listening on http://localhost:${port}`);
});
