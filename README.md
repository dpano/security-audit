# Security Audit

A Python-based web security scanner that performs vulnerability assessments against a target URL. Supports both web app and API scanning modes with OWASP Top 10 (2021) coverage.

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

# Cookie-based authentication
python main.py https://api.example.com/v1 --api --header "Cookie: session=abc123"

# Multiple cookies
python main.py https://api.example.com/v1 --api --header "Cookie: session=abc123; csrf_token=xyz"

# Custom auth header
python main.py https://api.example.com/v1 --api --header "X-Session-Token: abc"

# Multiple custom headers
python main.py https://api.example.com/v1 --api --header "X-Tenant: acme" --header "X-Version: 2"

# POST with JSON body
python main.py https://api.example.com/v1/login --api -X POST --json '{"username":"admin","password":"test"}'

# POST with form data
python main.py https://api.example.com/v1/search --api -X POST --data 'q=test&page=1'

# POST with authentication
python main.py https://api.example.com/v1/orders --api -X POST --bearer eyJhbGci... --json '{"item":"abc","qty":1}'
```

### Authenticated web scan (form login)

For apps that redirect to a login page, use `--login-url` to POST credentials first. The tool captures the session cookies and uses them for the actual audit.

```powershell
# Form-encoded login (most common)
python main.py https://example.com/dashboard `
  --login-url https://example.com/login `
  --login-data "username=admin&password=secret"

# JSON login endpoint
python main.py https://example.com/dashboard `
  --login-url https://example.com/api/auth/login `
  --login-json '{"username":"admin","password":"secret"}'

# Local dev server with form login
python main.py http://localhost:4200/dashboard `
  --login-url http://localhost:4200/auth/login `
  --login-data "username=admin&password=secret"

# Combine with API mode for protected API endpoints
python main.py http://localhost:4200/api/v1/users --api `
  --login-url http://localhost:4200/auth/login `
  --login-json '{"username":"admin","password":"secret"}'
```

The tool warns you if the scan target still looks like a login page after authentication (indicating credentials may be wrong or the session wasn't set correctly).

Plain HTTP servers (e.g. `http://localhost`) automatically skip SSL checks — no extra flags needed:

```bash
python main.py http://localhost:4200/api/v1/users --api --header "Cookie: session=abc123"
```

Use `--no-ssl` to explicitly skip SSL checks on any target:

```bash
python main.py https://staging.internal --api --no-ssl --header "Cookie: session=abc123"
```

### PowerShell note

Wrap URLs containing `&` or `$` in single quotes to prevent shell interpretation:

```powershell
python main.py 'http://localhost:4200/api/v1/items?$top=10&$skip=0' --api --header "Cookie: session=abc123"
```

### Options

| Flag | Short | Description |
|------|-------|-------------|
| `url` | | Target URL to audit (required) |
| `--login-url URL` | | Login endpoint to POST credentials to before scanning |
| `--login-data 'u=x&p=y'` | | Form-encoded credentials for `--login-url` |
| `--login-json '{"u":"x"}'` | | JSON credentials for `--login-url` |
| `--api` | | Enable API mode |
| `--method METHOD` | `-X` | HTTP method for the audit request (default: `GET`) |
| `--json '{"k":"v"}'` | | JSON body for the audit request — sets `Content-Type: application/json` |
| `--data 'key=value'` | `-d` | Raw form body for the audit request |
| `--bearer TOKEN` | | Bearer token — sets `Authorization: Bearer <token>` |
| `--api-key KEY` | | API key — sets `X-API-Key: <key>` |
| `--header 'N: V'` | | Custom request header, repeatable |
| `--no-ssl` | | Skip SSL/TLS checks (auto-enabled for `http://` targets) |
| `--timeout` | `-t` | Request timeout in seconds (default: 10) |
| `--output-dir` | `-o` | Report output directory (default: `./reports`) |
| `--vercel-bypass SECRET` | | Vercel deployment protection bypass secret |
| `--help` | `-h` | Show help message |

## Output

Reports are written to `./reports/` after every scan (or the path set with `--output-dir`).

| Format | Filename pattern | Contents |
|--------|-----------------|----------|
| Terminal | — | Live findings with severity tags and summary |
| JSON | `audit_<mode>_<domain>_<timestamp>.json` | Structured data, machine-readable |
| HTML | `audit_<mode>_<domain>_<timestamp>.html` | Styled report, open in any browser |

`<mode>` is `web` or `api` depending on the scan mode used.

### Risk Scoring

Each finding carries a severity weight. The total determines the overall rating:

| Score | Rating |
|-------|--------|
| 0 | Excellent |
| 1–5 | Good |
| 6–15 | Fair |
| 16–30 | Poor |
| 31+ | Critical |

| Severity | Weight |
|----------|--------|
| CRITICAL | 10 |
| HIGH | 5 |
| MEDIUM | 2 |
| LOW | 1 |
| INFO | 0 |

## Disclaimer

This tool is intended for authorized security testing only. Always obtain proper authorization before scanning any target. The tool sends non-destructive HTTP requests but does probe sensitive paths and inject test payloads — use responsibly.

## License

MIT
