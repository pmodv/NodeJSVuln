# vuln-demo

Deliberately vulnerable Node.js fixture for validating **Black Duck** (SCA) and
**Coverity** (SAST) detection and policy mapping. **Do not deploy.** No live
database or network is required for static analysis to flag the findings.

## Finding ↔ route ↔ CWE map

| # | Route            | CWE            | Class                         | Expected severity |
|---|------------------|----------------|-------------------------------|-------------------|
| 1 | `/ping`          | CWE-78         | OS Command Injection          | **Critical** (RCE) |
| 2 | `/calc`          | CWE-94         | Code Injection (`eval`)       | **Critical** (RCE) |
| 3 | `/user`          | CWE-89         | SQL Injection                 | High              |
| 4 | `/read`          | CWE-22         | Path Traversal                | High              |
| 5 | `/fetch`         | CWE-918        | Server-Side Request Forgery   | High/Medium       |
| 6 | `/greet`         | CWE-79         | Reflected XSS                 | Medium/High       |
| 7 | `/go`            | CWE-601        | Open Redirect                 | Medium            |
| 8 | `/hash`          | CWE-327/328    | Weak Hashing (MD5)            | Medium            |
| 9 | `/token`         | CWE-338        | Insecure Randomness           | Low/Medium        |
| – | `createConnection` | CWE-798      | Hard-coded Credentials        | Low/Medium        |
| – | `http.createServer` | CWE-319     | Cleartext Transmission (TLS)  | Low               |
| – | `minimist 1.2.0` | CVE-2020-7598 / CVE-2021-44906 | SCA prototype pollution | High |

The two RCE sinks (`/ping`, `/calc`) are the intended **Critical** findings.

## Run

```bash
npm install          # resolves express/mysql2 so Coverity can model sinks
npm audit            # SCA sanity check: CVE-2021-44906 (critical)
node server.js
```

## Scan

```bash
# Coverity (adjust to your CLI/version)
cov-build --dir idir --fs-capture-search . --no-command
cov-analyze --dir idir --webapp-security --enable-callgraph-metrics
cov-commit-defects --dir idir --stream <stream> ...
```

> Coverity needs dependencies installed (`node_modules` present) before capture,
> or it falls back to under-recognizing library sinks.