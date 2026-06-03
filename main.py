import requests
import sys
import ssl
import socket
import re
import json
import os
from urllib.parse import urlparse
from datetime import datetime, timezone


# ─── Configuration ───────────────────────────────────────────────────────────

REQUEST_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAudit/2.0"
REPORT_OUTPUT_DIR = None  # Set via CLI; defaults to ./reports at runtime


# ─── Utility ─────────────────────────────────────────────────────────────────

def print_section(title):
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}\n")


def severity_tag(level):
    tags = {"CRITICAL": "[!!!]", "HIGH": "[!!]", "MEDIUM": "[!]", "LOW": "[~]", "INFO": "[i]"}
    return tags.get(level, "[?]")


class AuditResult:
    def __init__(self):
        self.findings = []

    def add(self, category, check, status, severity="INFO", detail=""):
        self.findings.append({
            "category": category,
            "check": check,
            "status": status,
            "severity": severity,
            "detail": detail,
        })

    def summary(self):
        passed = sum(1 for f in self.findings if f["status"] == "PASS")
        failed = sum(1 for f in self.findings if f["status"] == "FAIL")
        warnings = sum(1 for f in self.findings if f["status"] == "WARN")
        return passed, failed, warnings

    def export_json(self, filepath, url):
        """Export findings as a structured JSON report."""
        passed, failed, warnings = self.summary()
        severity_weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        risk_score = sum(
            severity_weights.get(f["severity"], 0)
            for f in self.findings if f["status"] in ("FAIL", "WARN")
        )

        report = {
            "audit_metadata": {
                "target": url,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tool": "SecurityAudit/2.0",
            },
            "summary": {
                "total_checks": passed + failed + warnings,
                "passed": passed,
                "failed": failed,
                "warnings": warnings,
                "risk_score": risk_score,
            },
            "findings": self.findings,
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"  [✓] JSON report saved to: {filepath}")

    def export_html(self, filepath, url):
        """Export findings as a self-contained HTML report."""
        passed, failed, warnings = self.summary()
        severity_weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        risk_score = sum(
            severity_weights.get(f["severity"], 0)
            for f in self.findings if f["status"] in ("FAIL", "WARN")
        )
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Group findings by category
        categories = {}
        for f in self.findings:
            categories.setdefault(f["category"], []).append(f)

        severity_colors = {
            "CRITICAL": "#dc2626",
            "HIGH": "#ea580c",
            "MEDIUM": "#ca8a04",
            "LOW": "#2563eb",
            "INFO": "#6b7280",
        }
        status_icons = {"PASS": "✓", "FAIL": "✗", "WARN": "⚠", "INFO": "ℹ"}

        # Build findings HTML
        findings_html = ""
        for category, items in categories.items():
            rows = ""
            for item in items:
                color = severity_colors.get(item["severity"], "#6b7280")
                icon = status_icons.get(item["status"], "?")
                status_class = item["status"].lower()
                detail_cell = f'<td class="detail">{item["detail"]}</td>' if item["detail"] else '<td class="detail">—</td>'
                rows += (
                    f'<tr class="{status_class}">'
                    f'<td class="icon">{icon}</td>'
                    f'<td>{item["check"]}</td>'
                    f'<td><span class="badge" style="background:{color}">{item["severity"]}</span></td>'
                    f'<td class="status-{status_class}">{item["status"]}</td>'
                    f'{detail_cell}'
                    f'</tr>\n'
                )
            findings_html += f"""
            <div class="category">
                <h2>{category}</h2>
                <table>
                    <thead><tr><th></th><th>Check</th><th>Severity</th><th>Status</th><th>Detail</th></tr></thead>
                    <tbody>{rows}</tbody>
                </table>
            </div>
            """

        # Determine rating
        if risk_score == 0:
            rating, rating_class = "EXCELLENT", "excellent"
        elif risk_score <= 5:
            rating, rating_class = "GOOD", "good"
        elif risk_score <= 15:
            rating, rating_class = "FAIR", "fair"
        elif risk_score <= 30:
            rating, rating_class = "POOR", "poor"
        else:
            rating, rating_class = "CRITICAL", "critical"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit Report — {url}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #1e293b; padding: 2rem; }}
    .container {{ max-width: 1000px; margin: 0 auto; }}
    h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
    .meta {{ color: #64748b; font-size: 0.875rem; margin-bottom: 1.5rem; }}
    .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .card {{ background: #fff; border-radius: 8px; padding: 1.25rem; box-shadow: 0 1px 3px rgba(0,0,0,0.08); text-align: center; }}
    .card .value {{ font-size: 1.75rem; font-weight: 700; }}
    .card .label {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }}
    .card.passed .value {{ color: #16a34a; }}
    .card.failed .value {{ color: #dc2626; }}
    .card.warnings .value {{ color: #ca8a04; }}
    .rating {{ font-size: 1.1rem; font-weight: 600; padding: 0.5rem 1rem; border-radius: 6px; display: inline-block; margin-bottom: 2rem; }}
    .rating.excellent {{ background: #dcfce7; color: #166534; }}
    .rating.good {{ background: #dbeafe; color: #1e40af; }}
    .rating.fair {{ background: #fef9c3; color: #854d0e; }}
    .rating.poor {{ background: #fed7aa; color: #9a3412; }}
    .rating.critical {{ background: #fecaca; color: #991b1b; }}
    .category {{ margin-bottom: 2rem; }}
    .category h2 {{ font-size: 1.1rem; margin-bottom: 0.75rem; padding-bottom: 0.5rem; border-bottom: 2px solid #e2e8f0; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
    th {{ background: #f1f5f9; text-align: left; padding: 0.6rem 0.75rem; font-size: 0.75rem; text-transform: uppercase; color: #64748b; }}
    td {{ padding: 0.6rem 0.75rem; border-top: 1px solid #f1f5f9; font-size: 0.875rem; }}
    td.icon {{ width: 2rem; text-align: center; font-size: 1rem; }}
    td.detail {{ color: #64748b; font-size: 0.8rem; max-width: 250px; }}
    tr.pass td.icon {{ color: #16a34a; }}
    tr.fail td.icon {{ color: #dc2626; }}
    tr.warn td.icon {{ color: #ca8a04; }}
    .status-pass {{ color: #16a34a; font-weight: 600; }}
    .status-fail {{ color: #dc2626; font-weight: 600; }}
    .status-warn {{ color: #ca8a04; font-weight: 600; }}
    .badge {{ color: #fff; font-size: 0.7rem; padding: 0.15rem 0.5rem; border-radius: 4px; font-weight: 600; }}
    footer {{ margin-top: 3rem; text-align: center; color: #94a3b8; font-size: 0.75rem; }}
</style>
</head>
<body>
<div class="container">
    <h1>Security Vulnerability Audit</h1>
    <p class="meta">Target: <strong>{url}</strong> &mdash; {timestamp}</p>

    <div class="summary">
        <div class="card"><div class="value">{passed + failed + warnings}</div><div class="label">Total Checks</div></div>
        <div class="card passed"><div class="value">{passed}</div><div class="label">Passed</div></div>
        <div class="card failed"><div class="value">{failed}</div><div class="label">Failed</div></div>
        <div class="card warnings"><div class="value">{warnings}</div><div class="label">Warnings</div></div>
        <div class="card"><div class="value">{risk_score}</div><div class="label">Risk Score</div></div>
    </div>

    <div class="rating {rating_class}">Overall Rating: {rating}</div>

    {findings_html}

    <footer>Generated by SecurityAudit/2.0 &mdash; {timestamp}</footer>
</div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"  [✓] HTML report saved to: {filepath}")


# ─── Checks ──────────────────────────────────────────────────────────────────

def check_security_headers(headers, result):
    """Evaluate presence and quality of critical security headers."""
    print_section("Security Headers")

    security_headers = {
        "Strict-Transport-Security": {
            "severity": "HIGH",
            "missing_msg": "No HSTS — vulnerable to protocol downgrade and cookie hijacking.",
        },
        "Content-Security-Policy": {
            "severity": "HIGH",
            "missing_msg": "No CSP — increased risk of XSS and data injection attacks.",
        },
        "X-Frame-Options": {
            "severity": "MEDIUM",
            "missing_msg": "No X-Frame-Options — vulnerable to clickjacking.",
        },
        "X-Content-Type-Options": {
            "severity": "MEDIUM",
            "missing_msg": "No X-Content-Type-Options — vulnerable to MIME-type sniffing.",
        },
        "Referrer-Policy": {
            "severity": "LOW",
            "missing_msg": "No Referrer-Policy — may leak URL parameters to third parties.",
        },
        "Permissions-Policy": {
            "severity": "MEDIUM",
            "missing_msg": "No Permissions-Policy — browser features (camera, mic, geolocation) not restricted.",
        },
        "Cross-Origin-Opener-Policy": {
            "severity": "LOW",
            "missing_msg": "No COOP — cross-origin windows may access this context.",
        },
        "Cross-Origin-Resource-Policy": {
            "severity": "LOW",
            "missing_msg": "No CORP — resources may be embedded by any origin.",
        },
        "Cross-Origin-Embedder-Policy": {
            "severity": "LOW",
            "missing_msg": "No COEP — cross-origin isolation not enforced.",
        },
    }

    for header, info in security_headers.items():
        if header in headers:
            value = headers[header]
            print(f"  [+] PASS: {header}")
            print(f"       Value: {value}")
            result.add("Headers", header, "PASS", detail=value)

            # Quality checks on specific header values
            if header == "Strict-Transport-Security":
                if "max-age" in value.lower():
                    max_age = int(re.search(r"max-age=(\d+)", value).group(1)) if re.search(r"max-age=(\d+)", value) else 0
                    if max_age < 31536000:
                        print(f"       {severity_tag('MEDIUM')} max-age is {max_age}s (recommend >= 31536000)")
                        result.add("Headers", f"{header} max-age strength", "WARN", "MEDIUM",
                                   f"max-age={max_age}, recommend >= 31536000")
                if "includesubdomains" not in value.lower():
                    print(f"       {severity_tag('LOW')} includeSubDomains not set")

            if header == "Content-Security-Policy":
                if "'unsafe-inline'" in value:
                    print(f"       {severity_tag('MEDIUM')} CSP allows 'unsafe-inline' — weakens XSS protection")
                    result.add("Headers", "CSP unsafe-inline", "WARN", "MEDIUM")
                if "'unsafe-eval'" in value:
                    print(f"       {severity_tag('HIGH')} CSP allows 'unsafe-eval' — significant XSS risk")
                    result.add("Headers", "CSP unsafe-eval", "WARN", "HIGH")
                if "default-src" not in value and "script-src" not in value:
                    print(f"       {severity_tag('MEDIUM')} CSP missing default-src or script-src directive")
        else:
            sev = info["severity"]
            print(f"  [-] FAIL: {header}")
            print(f"       {severity_tag(sev)} {info['missing_msg']}")
            result.add("Headers", header, "FAIL", sev, info["missing_msg"])


def check_information_leakage(headers, result):
    """Detect headers that reveal server internals."""
    print_section("Information Leakage")

    leakage_headers = {
        "Server": "Reveals web server software and version.",
        "X-Powered-By": "Reveals backend framework or language.",
        "X-AspNet-Version": "Reveals ASP.NET version.",
        "X-AspNetMvc-Version": "Reveals ASP.NET MVC version.",
        "X-Generator": "Reveals CMS or site generator.",
        "X-Drupal-Cache": "Reveals Drupal CMS usage.",
        "X-Varnish": "Reveals Varnish cache layer.",
    }

    found_any = False
    for header, msg in leakage_headers.items():
        if header in headers:
            found_any = True
            value = headers[header]
            print(f"  {severity_tag('MEDIUM')} {header}: {value}")
            print(f"       {msg}")
            result.add("Leakage", header, "WARN", "MEDIUM", f"{value} — {msg}")

    if not found_any:
        print("  [+] No common information leakage headers detected.")


def check_cookie_security(response, result):
    """Analyze Set-Cookie headers for security flags."""
    print_section("Cookie Security")

    cookies = response.headers.get("Set-Cookie", "")
    if not cookies:
        # Also check the response cookies jar
        if not response.cookies:
            print("  [i] No cookies set by this response.")
            return

    cookie_headers = response.headers.get("Set-Cookie") if "Set-Cookie" in response.headers else None

    # requests library merges headers; use raw response for multiple Set-Cookie
    raw_cookies = []
    if hasattr(response, "raw") and hasattr(response.raw, "headers"):
        raw_cookies = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []

    if not raw_cookies and cookie_headers:
        raw_cookies = [cookie_headers]

    if not raw_cookies:
        print("  [i] No Set-Cookie headers found in response.")
        return

    for cookie_str in raw_cookies:
        name = cookie_str.split("=")[0].strip()
        lower = cookie_str.lower()
        print(f"  Cookie: {name}")

        issues = []
        if "secure" not in lower:
            issues.append(("HIGH", "Missing 'Secure' flag — cookie sent over HTTP"))
        if "httponly" not in lower:
            issues.append(("MEDIUM", "Missing 'HttpOnly' flag — accessible via JavaScript"))
        if "samesite" not in lower:
            issues.append(("MEDIUM", "Missing 'SameSite' attribute — vulnerable to CSRF"))

        if issues:
            for sev, msg in issues:
                print(f"       {severity_tag(sev)} {msg}")
                result.add("Cookies", f"{name} — {msg}", "FAIL", sev)
        else:
            print(f"       [+] All security flags present.")
            result.add("Cookies", name, "PASS")


def check_cors(url, headers, result):
    """Test for overly permissive CORS configuration."""
    print_section("CORS Configuration")

    acao = headers.get("Access-Control-Allow-Origin", None)
    acac = headers.get("Access-Control-Allow-Credentials", "").lower()

    if acao is None:
        print("  [+] No CORS headers present (restrictive by default).")
        result.add("CORS", "No ACAO header", "PASS")
        return

    print(f"  Access-Control-Allow-Origin: {acao}")

    if acao == "*":
        if acac == "true":
            print(f"  {severity_tag('CRITICAL')} Wildcard origin with credentials allowed — full CORS bypass!")
            result.add("CORS", "Wildcard + credentials", "FAIL", "CRITICAL")
        else:
            print(f"  {severity_tag('MEDIUM')} Wildcard origin — any site can read responses.")
            result.add("CORS", "Wildcard origin", "WARN", "MEDIUM")
    else:
        print(f"  [i] Origin restricted to: {acao}")
        result.add("CORS", "Origin restricted", "PASS", detail=acao)

    # Test if server reflects arbitrary origin
    try:
        evil_origin = "https://evil.attacker.com"
        test_resp = requests.get(
            url, timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT, "Origin": evil_origin},
        )
        reflected = test_resp.headers.get("Access-Control-Allow-Origin", "")
        if reflected == evil_origin:
            print(f"  {severity_tag('HIGH')} Server reflects arbitrary Origin header — CORS misconfiguration!")
            result.add("CORS", "Origin reflection", "FAIL", "HIGH",
                       "Server echoes attacker-controlled Origin")
    except requests.exceptions.RequestException:
        pass


def check_ssl_tls(hostname, result):
    """Analyze SSL/TLS certificate and protocol support."""
    print_section("SSL/TLS Analysis")

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                print(f"  Protocol: {protocol}")
                result.add("SSL/TLS", f"Protocol: {protocol}", "PASS")

                # Certificate expiry
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=timezone.utc)
                days_remaining = (not_after - datetime.now(timezone.utc)).days
                print(f"  Certificate expires: {cert['notAfter']} ({days_remaining} days remaining)")

                if days_remaining <= 0:
                    print(f"  {severity_tag('CRITICAL')} Certificate has EXPIRED!")
                    result.add("SSL/TLS", "Certificate expired", "FAIL", "CRITICAL")
                elif days_remaining <= 30:
                    print(f"  {severity_tag('HIGH')} Certificate expires within 30 days!")
                    result.add("SSL/TLS", "Certificate expiring soon", "WARN", "HIGH",
                               f"{days_remaining} days remaining")
                else:
                    result.add("SSL/TLS", "Certificate validity", "PASS",
                               detail=f"{days_remaining} days remaining")

                # Subject and SANs
                subject = dict(x[0] for x in cert["subject"])
                print(f"  Subject: {subject.get('commonName', 'N/A')}")

                san_list = cert.get("subjectAltName", [])
                san_domains = [v for t, v in san_list if t == "DNS"]
                if san_domains:
                    print(f"  SANs: {', '.join(san_domains[:5])}")
                    if len(san_domains) > 5:
                        print(f"       ... and {len(san_domains) - 5} more")

    except ssl.SSLError as e:
        print(f"  {severity_tag('CRITICAL')} SSL Error: {e}")
        result.add("SSL/TLS", "SSL connection failed", "FAIL", "CRITICAL", str(e))
    except (socket.timeout, socket.error) as e:
        print(f"  {severity_tag('HIGH')} Connection error: {e}")
        result.add("SSL/TLS", "Connection failed", "FAIL", "HIGH", str(e))

    # Check for deprecated protocols
    deprecated_protocols = [
        (ssl.PROTOCOL_TLSv1, "TLSv1.0"),
        (ssl.PROTOCOL_TLSv1_1, "TLSv1.1"),
    ] if hasattr(ssl, "PROTOCOL_TLSv1") else []

    for proto, name in deprecated_protocols:
        try:
            ctx = ssl.SSLContext(proto)
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    print(f"  {severity_tag('HIGH')} Deprecated {name} is supported!")
                    result.add("SSL/TLS", f"{name} supported", "FAIL", "HIGH",
                               "Deprecated protocol still accepted")
        except (ssl.SSLError, OSError):
            pass  # Good — deprecated protocol rejected


def check_http_methods(url, result):
    """Enumerate allowed HTTP methods for potential misconfigurations."""
    print_section("HTTP Methods")

    dangerous_methods = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}

    try:
        resp = requests.options(url, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT})
        allow = resp.headers.get("Allow", "")
        if allow:
            methods = {m.strip().upper() for m in allow.split(",")}
            print(f"  Allowed methods: {', '.join(sorted(methods))}")

            risky = methods & dangerous_methods
            if risky:
                for m in risky:
                    print(f"  {severity_tag('MEDIUM')} Potentially dangerous method enabled: {m}")
                    result.add("HTTP Methods", f"{m} enabled", "WARN", "MEDIUM")
            else:
                result.add("HTTP Methods", "No dangerous methods exposed", "PASS")
        else:
            print("  [i] Server did not return Allow header.")
            result.add("HTTP Methods", "No Allow header", "INFO")

        # TRACE test
        try:
            trace_resp = requests.request("TRACE", url, timeout=REQUEST_TIMEOUT)
            if trace_resp.status_code == 200:
                print(f"  {severity_tag('MEDIUM')} TRACE method returns 200 — Cross-Site Tracing risk")
                result.add("HTTP Methods", "TRACE enabled", "FAIL", "MEDIUM",
                           "Cross-Site Tracing (XST) possible")
        except requests.exceptions.RequestException:
            pass

    except requests.exceptions.RequestException as e:
        print(f"  [i] OPTIONS request failed: {e}")


def check_redirect_chain(url, result):
    """Analyze the redirect chain for security issues."""
    print_section("Redirect Chain")

    try:
        resp = requests.get(
            url, timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            allow_redirects=True,
        )

        if resp.history:
            print(f"  Redirect chain ({len(resp.history)} hops):")
            for i, r in enumerate(resp.history):
                location = r.headers.get("Location", "N/A")
                print(f"    {i + 1}. [{r.status_code}] {r.url} → {location}")

                # Check for HTTP→HTTP redirect (should be HTTP→HTTPS)
                if r.url.startswith("http://") and location.startswith("http://"):
                    print(f"       {severity_tag('HIGH')} Redirect stays on HTTP — no upgrade to HTTPS")
                    result.add("Redirects", "HTTP-to-HTTP redirect", "FAIL", "HIGH")

            print(f"    Final: [{resp.status_code}] {resp.url}")
            result.add("Redirects", "Chain analyzed", "PASS",
                       detail=f"{len(resp.history)} redirects")
        else:
            print("  [+] No redirects — direct response.")
            result.add("Redirects", "No redirects", "PASS")

        # Check if HTTP version redirects to HTTPS
        if url.startswith("https://"):
            http_url = url.replace("https://", "http://", 1)
            try:
                http_resp = requests.get(
                    http_url, timeout=REQUEST_TIMEOUT,
                    headers={"User-Agent": USER_AGENT},
                    allow_redirects=False,
                )
                if http_resp.status_code in (301, 302, 307, 308):
                    loc = http_resp.headers.get("Location", "")
                    if loc.startswith("https://"):
                        print(f"  [+] HTTP→HTTPS redirect in place (Status: {http_resp.status_code})")
                        result.add("Redirects", "HTTP to HTTPS redirect", "PASS")
                    else:
                        print(f"  {severity_tag('HIGH')} HTTP redirect does not upgrade to HTTPS!")
                        result.add("Redirects", "HTTP no HTTPS upgrade", "FAIL", "HIGH")
                elif http_resp.status_code == 200:
                    print(f"  {severity_tag('HIGH')} Site accessible over plain HTTP without redirect!")
                    result.add("Redirects", "HTTP accessible without redirect", "FAIL", "HIGH")
            except requests.exceptions.RequestException:
                print("  [i] Could not test HTTP→HTTPS redirect.")

    except requests.exceptions.RequestException as e:
        print(f"  [!] Redirect check failed: {e}")


def check_content_analysis(response, result):
    """Analyze response body for security-relevant patterns."""
    print_section("Content Analysis")

    body = response.text[:50000]  # Limit analysis scope

    patterns = {
        "Email addresses": (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "LOW"),
        "Potential API keys": (r"(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"]?[\w-]{20,}", "HIGH"),
        "Inline JavaScript event handlers": (r"on(?:click|load|error|mouseover)\s*=", "LOW"),
        "HTML comments": (r"<!--[\s\S]*?-->", "LOW"),
        "Source map references": (r"//[#@]\s*sourceMappingURL\s*=", "MEDIUM"),
        "Debug/development indicators": (r"(?:DEBUG|DEVELOPMENT|TODO|FIXME|HACK)\s*[:=]", "MEDIUM"),
    }

    found_any = False
    for name, (pattern, severity) in patterns.items():
        matches = re.findall(pattern, body, re.IGNORECASE)
        if matches:
            found_any = True
            count = len(matches)
            print(f"  {severity_tag(severity)} {name}: {count} occurrence(s) found")
            if name == "HTML comments" and count <= 3:
                for m in matches[:3]:
                    snippet = m[:80].replace("\n", " ")
                    print(f"       \"{snippet}...\"")
            result.add("Content", name, "WARN", severity, f"{count} occurrences")

    if not found_any:
        print("  [+] No concerning patterns detected in response body.")


def check_owasp_top10(url, response, headers, result):
    """Check against OWASP Top 10 (2021) categories with active and passive tests."""
    print_section("OWASP Top 10 (2021) Assessment")

    body = response.text[:50000]
    parsed = urlparse(url)

    # ─── A01:2021 — Broken Access Control ────────────────────────────────────
    print("  ── A01:2021 — Broken Access Control ──")

    # Check for directory listing indicators
    dir_listing_patterns = [
        r"<title>Index of /",
        r"<h1>Index of",
        r"Directory listing for",
        r"\[To Parent Directory\]",
    ]
    dir_listing_found = any(re.search(p, body, re.IGNORECASE) for p in dir_listing_patterns)
    if dir_listing_found:
        print(f"  {severity_tag('HIGH')} Directory listing appears to be enabled")
        result.add("OWASP A01", "Directory listing enabled", "FAIL", "HIGH",
                   "Exposes file structure to attackers")
    else:
        result.add("OWASP A01", "No directory listing detected", "PASS")

    # CORS already checked — map to OWASP category
    acao = headers.get("Access-Control-Allow-Origin", "")
    if acao == "*":
        result.add("OWASP A01", "Permissive CORS (mapped)", "WARN", "MEDIUM",
                   "Wildcard Access-Control-Allow-Origin")

    # Check common sensitive paths for improper access control
    sensitive_paths = [
        "/.env", "/admin", "/wp-admin", "/.git/config",
        "/server-status", "/phpinfo.php", "/.htaccess",
        "/api/v1/users", "/graphql",
    ]
    exposed_paths = []
    for path in sensitive_paths:
        try:
            test_url = f"{parsed.scheme}://{parsed.hostname}{path}"
            resp = requests.get(
                test_url, timeout=5,
                headers={"User-Agent": USER_AGENT},
                allow_redirects=False,
            )
            if resp.status_code == 200:
                exposed_paths.append(path)
        except requests.exceptions.RequestException:
            pass

    if exposed_paths:
        for p in exposed_paths:
            print(f"  {severity_tag('HIGH')} Sensitive path accessible: {p}")
            result.add("OWASP A01", f"Exposed path: {p}", "FAIL", "HIGH",
                       "Returned HTTP 200 without authentication")
    else:
        print(f"  [+] Common sensitive paths not publicly exposed")
        result.add("OWASP A01", "Sensitive paths protected", "PASS")

    # ─── A02:2021 — Cryptographic Failures ───────────────────────────────────
    print("\n  ── A02:2021 — Cryptographic Failures ──")

    # HTTPS enforcement
    if parsed.scheme == "https":
        print(f"  [+] HTTPS in use")
        result.add("OWASP A02", "HTTPS enforced", "PASS")
    else:
        print(f"  {severity_tag('CRITICAL')} Site served over plain HTTP")
        result.add("OWASP A02", "No HTTPS", "FAIL", "CRITICAL",
                   "Data transmitted in cleartext")

    # HSTS presence (already checked in headers, map to OWASP)
    if "Strict-Transport-Security" not in headers:
        result.add("OWASP A02", "No HSTS (mapped)", "FAIL", "HIGH",
                   "Vulnerable to SSL stripping")

    # Check for mixed content indicators
    mixed_content = re.findall(r'(?:src|href|action)\s*=\s*["\']http://', body, re.IGNORECASE)
    if mixed_content:
        print(f"  {severity_tag('MEDIUM')} Mixed content: {len(mixed_content)} HTTP resource(s) on HTTPS page")
        result.add("OWASP A02", "Mixed content detected", "WARN", "MEDIUM",
                   f"{len(mixed_content)} insecure resource references")
    else:
        print(f"  [+] No mixed content detected")
        result.add("OWASP A02", "No mixed content", "PASS")

    # ─── A03:2021 — Injection ────────────────────────────────────────────────
    print("\n  ── A03:2021 — Injection ──")

    # Test for reflected input in response (basic XSS reflection probe)
    xss_canary = "<script>kiro_xss_probe</script>"
    sqli_canary = "' OR '1'='1"
    injection_url = f"{url}{'&' if '?' in url else '?'}q={requests.utils.quote(xss_canary)}"

    try:
        inj_resp = requests.get(injection_url, timeout=REQUEST_TIMEOUT,
                                headers={"User-Agent": USER_AGENT}, allow_redirects=True)
        if xss_canary in inj_resp.text:
            print(f"  {severity_tag('CRITICAL')} XSS reflection detected — input echoed unescaped!")
            result.add("OWASP A03", "Reflected XSS", "FAIL", "CRITICAL",
                       "Injected script tag reflected in response body")
        else:
            print(f"  [+] No reflected XSS in basic probe")
            result.add("OWASP A03", "No reflected XSS detected", "PASS")
    except requests.exceptions.RequestException:
        print(f"  [i] Could not complete XSS reflection test")

    # Check for SQL error messages in response
    sql_error_patterns = [
        r"SQL syntax.*MySQL",
        r"Warning.*\Wmysqli?_",
        r"PostgreSQL.*ERROR",
        r"ORA-\d{5}",
        r"Microsoft.*ODBC.*SQL Server",
        r"Unclosed quotation mark",
        r"SQLITE_ERROR",
        r"pg_query\(\)",
        r"SQLite3::query",
    ]
    sql_errors_found = [p for p in sql_error_patterns if re.search(p, body, re.IGNORECASE)]
    if sql_errors_found:
        print(f"  {severity_tag('CRITICAL')} SQL error messages in response — potential injection point")
        result.add("OWASP A03", "SQL error messages exposed", "FAIL", "CRITICAL",
                   "Database errors visible to users")
    else:
        result.add("OWASP A03", "No SQL error leakage", "PASS")

    # CSP as XSS mitigation (already checked, map here)
    if "Content-Security-Policy" not in headers:
        result.add("OWASP A03", "No CSP (injection mitigation)", "WARN", "HIGH",
                   "CSP is a key defense against XSS")

    # ─── A04:2021 — Insecure Design ─────────────────────────────────────────
    print("\n  ── A04:2021 — Insecure Design ──")

    # Check for rate limiting headers
    rate_limit_headers = ["X-RateLimit-Limit", "X-Rate-Limit-Limit",
                          "RateLimit-Limit", "Retry-After", "X-RateLimit-Remaining"]
    has_rate_limit = any(h in headers for h in rate_limit_headers)
    if has_rate_limit:
        print(f"  [+] Rate limiting headers present")
        result.add("OWASP A04", "Rate limiting indicators", "PASS")
    else:
        print(f"  {severity_tag('LOW')} No rate limiting headers detected")
        result.add("OWASP A04", "No rate limiting headers", "WARN", "LOW",
                   "May be vulnerable to brute force / abuse")

    # Check for CAPTCHA or anti-automation indicators
    captcha_patterns = [r"captcha", r"recaptcha", r"hcaptcha", r"turnstile"]
    has_captcha = any(re.search(p, body, re.IGNORECASE) for p in captcha_patterns)
    if has_captcha:
        print(f"  [+] CAPTCHA/anti-automation detected")
        result.add("OWASP A04", "Anti-automation present", "PASS")
    else:
        result.add("OWASP A04", "No CAPTCHA detected", "INFO",
                   detail="Consider adding for sensitive forms")

    # ─── A05:2021 — Security Misconfiguration ────────────────────────────────
    print("\n  ── A05:2021 — Security Misconfiguration ──")

    # Check for default error pages / stack traces
    error_indicators = [
        r"Traceback \(most recent call last\)",
        r"at .+\(.+:\d+:\d+\)",  # JS stack trace
        r"Exception in thread",
        r"<b>Fatal error</b>",
        r"Stack Trace:",
        r"Server Error in .+ Application",
    ]
    stack_trace_found = any(re.search(p, body, re.IGNORECASE) for p in error_indicators)
    if stack_trace_found:
        print(f"  {severity_tag('HIGH')} Stack trace / error details exposed in response")
        result.add("OWASP A05", "Stack trace exposed", "FAIL", "HIGH",
                   "Detailed error information visible to users")
    else:
        print(f"  [+] No stack traces or verbose errors in response")
        result.add("OWASP A05", "No verbose errors", "PASS")

    # X-Content-Type-Options / X-Frame-Options (map to misconfiguration)
    if "X-Content-Type-Options" not in headers:
        result.add("OWASP A05", "Missing X-Content-Type-Options (mapped)", "WARN", "MEDIUM")
    if "Permissions-Policy" not in headers:
        result.add("OWASP A05", "Missing Permissions-Policy (mapped)", "WARN", "MEDIUM")

    # Check for unnecessary HTTP response headers
    debug_headers = ["X-Debug-Token", "X-Debug-Token-Link", "X-Powered-By-Plesk"]
    for dh in debug_headers:
        if dh in headers:
            print(f"  {severity_tag('MEDIUM')} Debug header present: {dh}")
            result.add("OWASP A05", f"Debug header: {dh}", "FAIL", "MEDIUM")

    # ─── A06:2021 — Vulnerable and Outdated Components ───────────────────────
    print("\n  ── A06:2021 — Vulnerable and Outdated Components ──")

    # Detect known library versions in page source
    component_patterns = {
        "jQuery": r"jquery[.-](\d+\.\d+\.\d+)",
        "Bootstrap": r"bootstrap[.-](\d+\.\d+\.\d+)",
        "Angular": r"angular[.-](\d+\.\d+\.\d+)",
        "React": r"react[.-](\d+\.\d+\.\d+)",
        "Vue.js": r"vue[.-](\d+\.\d+\.\d+)",
        "Lodash": r"lodash[.-](\d+\.\d+\.\d+)",
        "Moment.js": r"moment[.-](\d+\.\d+\.\d+)",
    }

    found_components = []
    for lib, pattern in component_patterns.items():
        match = re.search(pattern, body, re.IGNORECASE)
        if match:
            version = match.group(1)
            found_components.append((lib, version))

    if found_components:
        for lib, ver in found_components:
            print(f"  [i] Detected: {lib} v{ver}")
            result.add("OWASP A06", f"{lib} v{ver} detected", "INFO",
                       detail="Verify against known CVEs")
    else:
        print(f"  [+] No client-side library versions exposed in HTML")
        result.add("OWASP A06", "No exposed library versions", "PASS")

    # Server version exposure (mapped)
    if "Server" in headers:
        server_val = headers["Server"]
        version_match = re.search(r"[\d]+\.[\d]+", server_val)
        if version_match:
            print(f"  {severity_tag('MEDIUM')} Server version exposed: {server_val}")
            result.add("OWASP A06", f"Server version: {server_val}", "WARN", "MEDIUM",
                       "Check for known CVEs against this version")

    # ─── A07:2021 — Identification and Authentication Failures ────────────────
    print("\n  ── A07:2021 — Identification and Authentication Failures ──")

    # Check for login forms without CSRF tokens
    form_pattern = re.findall(r'<form[^>]*>.*?</form>', body, re.IGNORECASE | re.DOTALL)
    login_forms = [f for f in form_pattern if re.search(r'(?:password|passwd|login|signin)', f, re.IGNORECASE)]

    if login_forms:
        for form in login_forms[:3]:
            has_csrf = bool(re.search(r'(?:csrf|_token|authenticity_token|__RequestVerificationToken)', form, re.IGNORECASE))
            if not has_csrf:
                print(f"  {severity_tag('HIGH')} Login form without visible CSRF token")
                result.add("OWASP A07", "Login form missing CSRF token", "FAIL", "HIGH",
                           "Authentication form may be vulnerable to CSRF")
            else:
                print(f"  [+] Login form has CSRF token")
                result.add("OWASP A07", "Login form has CSRF protection", "PASS")
    else:
        result.add("OWASP A07", "No login forms on this page", "INFO")

    # Session cookie flags (already checked, but map to OWASP)
    # Check for session ID in URL
    if re.search(r'[?&;](?:jsessionid|phpsessid|sid|session_id)=', url + body, re.IGNORECASE):
        print(f"  {severity_tag('HIGH')} Session ID exposed in URL")
        result.add("OWASP A07", "Session ID in URL", "FAIL", "HIGH",
                   "Session fixation / leakage via Referer")

    # ─── A08:2021 — Software and Data Integrity Failures ─────────────────────
    print("\n  ── A08:2021 — Software and Data Integrity Failures ──")

    # Check for Subresource Integrity on external scripts
    external_scripts = re.findall(
        r'<script[^>]+src\s*=\s*["\'](?:https?://[^"\']+)["\'][^>]*>', body, re.IGNORECASE
    )
    scripts_without_sri = []
    for script_tag in external_scripts:
        if "integrity=" not in script_tag.lower():
            src_match = re.search(r'src\s*=\s*["\']([^"\']+)', script_tag, re.IGNORECASE)
            if src_match:
                # Exclude same-origin scripts
                src_domain = urlparse(src_match.group(1)).hostname
                if src_domain and src_domain != parsed.hostname:
                    scripts_without_sri.append(src_match.group(1)[:80])

    if scripts_without_sri:
        print(f"  {severity_tag('MEDIUM')} {len(scripts_without_sri)} external script(s) without SRI")
        for s in scripts_without_sri[:3]:
            print(f"       {s}")
        result.add("OWASP A08", "External scripts without SRI", "FAIL", "MEDIUM",
                   f"{len(scripts_without_sri)} scripts lack integrity verification")
    elif external_scripts:
        print(f"  [+] External scripts have Subresource Integrity")
        result.add("OWASP A08", "SRI present on external scripts", "PASS")
    else:
        result.add("OWASP A08", "No external scripts detected", "PASS")

    # ─── A09:2021 — Security Logging and Monitoring Failures ──────────────────
    print("\n  ── A09:2021 — Security Logging & Monitoring Failures ──")

    # This is mostly architectural — we can only check indicators
    # Check for security.txt
    try:
        sec_txt_resp = requests.get(
            f"{parsed.scheme}://{parsed.hostname}/.well-known/security.txt",
            timeout=5, headers={"User-Agent": USER_AGENT},
        )
        if sec_txt_resp.status_code == 200 and "contact:" in sec_txt_resp.text.lower():
            print(f"  [+] security.txt present — vulnerability reporting channel exists")
            result.add("OWASP A09", "security.txt present", "PASS")
        else:
            print(f"  {severity_tag('LOW')} No security.txt — no public vulnerability reporting channel")
            result.add("OWASP A09", "No security.txt", "WARN", "LOW",
                       "No public channel for security researchers to report issues")
    except requests.exceptions.RequestException:
        result.add("OWASP A09", "Could not check security.txt", "INFO")

    # ─── A10:2021 — Server-Side Request Forgery (SSRF) ────────────────────────
    print("\n  ── A10:2021 — Server-Side Request Forgery (SSRF) ──")

    # Check for URL parameters that might accept URLs (SSRF entry points)
    ssrf_params = re.findall(
        r'(?:name|id)\s*=\s*["\']?(?:url|uri|path|link|src|dest|redirect|target|fetch|proxy|load|open|callback)["\']?',
        body, re.IGNORECASE,
    )
    if ssrf_params:
        print(f"  {severity_tag('MEDIUM')} {len(ssrf_params)} potential SSRF input parameter(s) detected")
        result.add("OWASP A10", "Potential SSRF parameters", "WARN", "MEDIUM",
                   f"{len(ssrf_params)} URL-accepting parameters found in forms")
    else:
        print(f"  [+] No obvious SSRF-prone parameters detected")
        result.add("OWASP A10", "No obvious SSRF vectors", "PASS")

    # Check for open redirect potential
    redirect_params = re.findall(
        r'[?&](?:redirect|next|url|return|returnTo|goto|continue|dest)\s*=',
        body + url, re.IGNORECASE,
    )
    if redirect_params:
        print(f"  {severity_tag('MEDIUM')} Potential open redirect parameters found")
        result.add("OWASP A10", "Open redirect parameters", "WARN", "MEDIUM",
                   "URL redirect parameters may be exploitable")


def check_server_fingerprint(headers, result):
    """Attempt to fingerprint server technology from response characteristics."""
    print_section("Technology Fingerprinting")

    techs = []

    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")

    if server:
        techs.append(f"Server: {server}")
    if powered:
        techs.append(f"Framework: {powered}")

    # Additional fingerprinting from headers
    header_signatures = {
        "X-Drupal-Cache": "Drupal CMS",
        "X-Generator": headers.get("X-Generator", ""),
        "X-Shopify-Stage": "Shopify",
        "X-Wix-Request-Id": "Wix",
        "CF-RAY": "Cloudflare CDN",
        "X-Vercel-Id": "Vercel",
        "X-Amz-Cf-Id": "AWS CloudFront",
        "X-Azure-Ref": "Azure CDN",
        "X-Fastly-Request-ID": "Fastly CDN",
    }

    for header, tech in header_signatures.items():
        if header in headers:
            techs.append(f"Infrastructure: {tech}")

    if techs:
        for t in techs:
            print(f"  [i] {t}")
            result.add("Fingerprint", t, "INFO")
    else:
        print("  [+] Minimal technology exposure detected.")
        result.add("Fingerprint", "Minimal exposure", "PASS")


# ─── Main Audit Orchestrator ─────────────────────────────────────────────────

def run_audit(url):
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        print("[!] Invalid URL. Please include the scheme (https://...).")
        sys.exit(1)

    print(f"\n{'═' * 60}")
    print(f"   SECURITY VULNERABILITY AUDIT")
    print(f"   Target: {url}")
    print(f"   Date:   {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'═' * 60}")

    result = AuditResult()

    # Initial request
    try:
        response = requests.get(
            url, timeout=REQUEST_TIMEOUT,
            headers={"User-Agent": USER_AGENT},
        )
        headers = response.headers
        print(f"\n  [i] HTTP {response.status_code} — {len(response.content)} bytes received")
    except requests.exceptions.RequestException as e:
        print(f"\n[!] Connection failed: {e}")
        sys.exit(1)

    # Run all checks
    check_security_headers(headers, result)
    check_information_leakage(headers, result)
    check_cookie_security(response, result)
    check_cors(url, headers, result)
    check_ssl_tls(hostname, result)
    check_http_methods(url, result)
    check_redirect_chain(url, result)
    check_content_analysis(response, result)
    check_owasp_top10(url, response, headers, result)
    check_server_fingerprint(headers, result)

    # Final summary
    print_section("AUDIT SUMMARY")
    passed, failed, warnings = result.summary()
    total = passed + failed + warnings

    print(f"  Total checks performed: {total}")
    print(f"  ✓ Passed:   {passed}")
    print(f"  ✗ Failed:   {failed}")
    print(f"  ⚠ Warnings: {warnings}")

    # Risk score (simple weighted calculation)
    severity_weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    risk_score = sum(
        severity_weights.get(f["severity"], 0)
        for f in result.findings if f["status"] in ("FAIL", "WARN")
    )

    print(f"\n  Risk Score: {risk_score}")
    if risk_score == 0:
        print("  Rating: EXCELLENT — No issues detected.")
    elif risk_score <= 5:
        print("  Rating: GOOD — Minor issues only.")
    elif risk_score <= 15:
        print("  Rating: FAIR — Moderate issues should be addressed.")
    elif risk_score <= 30:
        print("  Rating: POOR — Significant vulnerabilities present.")
    else:
        print("  Rating: CRITICAL — Immediate remediation required.")

    # Top findings
    critical_findings = [f for f in result.findings if f["status"] == "FAIL" and f["severity"] in ("CRITICAL", "HIGH")]
    if critical_findings:
        print(f"\n  Priority Remediation ({len(critical_findings)} critical/high issues):")
        for f in critical_findings:
            print(f"    • [{f['severity']}] {f['check']}")
            if f["detail"]:
                print(f"      {f['detail']}")

    # Export reports
    print_section("EXPORT")
    report_dir = REPORT_OUTPUT_DIR or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "reports"
    )
    os.makedirs(report_dir, exist_ok=True)

    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    domain_slug = parsed.hostname.replace(".", "_")

    json_path = os.path.join(report_dir, f"audit_{domain_slug}_{timestamp_slug}.json")
    html_path = os.path.join(report_dir, f"audit_{domain_slug}_{timestamp_slug}.html")

    result.export_json(json_path, url)
    result.export_html(html_path, url)

    print(f"\n{'═' * 60}\n")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="Security Vulnerability Audit — scan a URL for common web security issues and OWASP Top 10.",
        epilog="Example: python main.py https://example.com",
    )
    parser.add_argument(
        "url",
        nargs="?",
        default=None,
        help="Target URL to audit (e.g. https://example.com)",
    )
    parser.add_argument(
        "--timeout", "-t",
        type=int,
        default=10,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--output-dir", "-o",
        default=None,
        help="Directory for report output (default: ./reports)",
    )

    args = parser.parse_args()

    if not args.url:
        parser.print_help()
        print("\n[!] Error: URL argument is required.")
        sys.exit(1)

    # Normalize URL
    target = args.url.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # Apply CLI options
    REQUEST_TIMEOUT = args.timeout
    if args.output_dir:
        REPORT_OUTPUT_DIR = args.output_dir

    run_audit(target)
