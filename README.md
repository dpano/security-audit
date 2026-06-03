# Security Audit

A Python-based web security scanner that performs vulnerability assessments against a target URL. Checks cover security headers, SSL/TLS configuration, cookie hygiene, CORS policy, and the full OWASP Top 10 (2021).

## Features

- **Security Headers** — validates 9 critical headers (HSTS, CSP, X-Frame-Options, Permissions-Policy, etc.) with quality analysis on values
- **SSL/TLS Analysis** — certificate expiry, protocol version, deprecated TLS 1.0/1.1 detection
- **Cookie Security** — Secure, HttpOnly, SameSite flag inspection
- **CORS Misconfiguration** — wildcard detection, origin reflection testing
- **HTTP Method Enumeration** — discovers dangerous methods (PUT, DELETE, TRACE)
- **Redirect Chain Analysis** — HTTP→HTTPS enforcement, redirect hop inspection
- **Information Leakage** — server version, framework exposure, debug headers
- **Content Analysis** — API keys, source maps, debug indicators in response body
- **Technology Fingerprinting** — CDN/platform detection (Cloudflare, Vercel, AWS, etc.)
- **OWASP Top 10 (2021)** — full category coverage:
  - A01: Broken Access Control (sensitive path probing, directory listing)
  - A02: Cryptographic Failures (HTTPS, mixed content, HSTS)
  - A03: Injection (reflected XSS probe, SQL error detection)
  - A04: Insecure Design (rate limiting, CAPTCHA)
  - A05: Security Misconfiguration (stack traces, debug headers)
  - A06: Vulnerable Components (client-side library version detection)
  - A07: Auth Failures (CSRF tokens, session ID exposure)
  - A08: Data Integrity (Subresource Integrity on external scripts)
  - A09: Logging & Monitoring (security.txt presence)
  - A10: SSRF (URL-accepting parameters, open redirect vectors)

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

### Examples

```bash
# Basic scan
python main.py https://example.com

# Auto-prepends https:// if no scheme provided
python main.py example.com

# Custom timeout
python main.py https://example.com --timeout 15

# Custom report output directory
python main.py https://example.com --output-dir ./my-reports
```

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `url` | | Target URL to audit (required) |
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
