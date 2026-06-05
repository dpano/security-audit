# Security Audit

A Python-based web security scanner that performs vulnerability assessments against a target URL. Checks cover security headers, SSL/TLS configuration, cookie hygiene, CORS policy, and the full OWASP Top 10 (2021).

## Features

### Web mode (default)
- **Security Headers** — validates 9 critical headers (HSTS, CSP, X-Frame-Options, Permissions-Policy, etc.) with quality analysis on values
- **SSL/TLS Analysis** — certificate expiry, protocol version, deprecated TLS 1.0/1.1 detection
- **Cookie Security** — Secure, HttpOnly, SameSite flag inspection
- **CORS Misconfiguration** — wildcard detection, origin reflection testing
- **HTTP Method Enumeration** — discovers dangerous methods (PUT, DELETE, TRACE)
- **Redirect Chain Analysis** — HTTP→HTTPS enforcement, redirect hop inspection
- **Information Leakage** — server version, framework exposure, debug headers
- **Content Analysis** — API keys, source maps, debug indicators in response body
- **Technology Fingerprinting** — CDN/platform detection (Cloudflare, Vercel, AWS, etc.)
- **OWASP Top 10 (2021)** — full category coverage (A01–A10)

### API mode (`--api`)
- **Authentication enforcement** — tests whether endpoints reject unauthenticated requests
- **Sensitive data exposure** — scans JSON responses for passwords, tokens, PII, internal paths
- **Rate limiting** — checks headers and fires 15 rapid requests to verify enforcement
- **HTTP verb tampering** — tests PUT/DELETE/PATCH access and method-override headers
- **Injection probes** — NoSQL injection, SSTI, path traversal, XXE, command injection
- **Mass assignment / overexposure** — detects privileged and internal fields in JSON responses
- **Error handling** — triggers error conditions and checks for verbose stack traces / SQL errors
- **Endpoint discovery** — probes common API paths (docs, admin, metrics, GraphQL, OpenAPI)

## Requirements

- Python 3.8+
- `requests` library

## Installation

```bash
pip install requests
```

## Usage

```bash
python main.py <url> [options]
```

### Web audit (default)

```bash
python main.py https://example.com
python main.py example.com                          # auto-prepends https://
python main.py https://example.com --timeout 15
python main.py https://example.com -o ./my-reports
```

### API audit (`--api`)

```bash
# Unauthenticated API scan
python main.py https://api.example.com/v1 --api

# Bearer token (JWT)
python main.py https://api.example.com/v1 --api --bearer eyJhbGci...

# API key header
python main.py https://api.example.com/v1 --api --api-key mykey123

# Custom auth header
python main.py https://api.example.com/v1 --api --header "X-Session-Token: abc"

# Multiple custom headers
python main.py https://api.example.com/v1 --api --header "X-Tenant: acme" --header "X-Version: 2"
```

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `url` | | Target URL to audit (required) |
| `--api` | | Enable API mode |
| `--bearer TOKEN` | | Bearer token for authenticated API testing |
| `--api-key KEY` | | API key (sets `X-API-Key` header) |
| `--header 'N: V'` | | Custom request header, repeatable |
| `--timeout` | `-t` | Request timeout in seconds (default: 10) |
| `--output-dir` | `-o` | Report output directory (default: `./reports`) |
| `--help` | `-h` | Show help message |

## Output

The tool produces:

1. **Terminal output** — color-coded findings with severity tags and a risk score summary
2. **JSON report** — structured data at `reports/audit_<domain>_<timestamp>.json`
3. **HTML report** — styled, self-contained report at `reports/audit_<domain>_<timestamp>.html`

### Risk Scoring

Each finding is assigned a severity (CRITICAL, HIGH, MEDIUM, LOW, INFO) and a weighted risk score determines the overall rating:

| Score | Rating |
|-------|--------|
| 0 | Excellent |
| 1–5 | Good |
| 6–15 | Fair |
| 16–30 | Poor |
| 31+ | Critical |

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before scanning any target. The tool sends non-destructive HTTP requests but probes sensitive paths and injects test payloads — use responsibly.

## License

MIT
