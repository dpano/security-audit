"""Check: OWASP Top 10 (2021) assessment."""

import re
import requests
from urllib.parse import urlparse

from config import REQUEST_TIMEOUT, build_headers, print_section, severity_tag


def check_owasp_top10(url, response, headers, result):
    """Check against OWASP Top 10 (2021) categories with active and passive tests."""
    print_section("OWASP Top 10 (2021) Assessment")

    body = response.text[:50000]
    parsed = urlparse(url)

    _check_a01_broken_access_control(url, body, headers, parsed, result)
    _check_a02_cryptographic_failures(body, headers, parsed, result)
    _check_a03_injection(url, body, headers, result)
    _check_a04_insecure_design(body, headers, result)
    _check_a05_security_misconfiguration(body, headers, result)
    _check_a06_vulnerable_components(body, headers, result)
    _check_a07_auth_failures(url, body, result)
    _check_a08_integrity_failures(body, parsed, result)
    _check_a09_logging_monitoring(parsed, result)
    _check_a10_ssrf(url, body, result)


def _check_a01_broken_access_control(url, body, headers, parsed, result):
    print("  ── A01:2021 — Broken Access Control ──")

    dir_listing_patterns = [
        r"<title>Index of /",
        r"<h1>Index of",
        r"Directory listing for",
        r"\[To Parent Directory\]",
    ]
    if any(re.search(p, body, re.IGNORECASE) for p in dir_listing_patterns):
        print(f"  {severity_tag('HIGH')} Directory listing appears to be enabled")
        result.add("OWASP A01", "Directory listing enabled", "FAIL", "HIGH",
                   "Exposes file structure to attackers")
    else:
        result.add("OWASP A01", "No directory listing detected", "PASS")

    acao = headers.get("Access-Control-Allow-Origin", "")
    if acao == "*":
        result.add("OWASP A01", "Permissive CORS (mapped)", "WARN", "MEDIUM",
                   "Wildcard Access-Control-Allow-Origin")

    sensitive_paths = [
        "/.env", "/admin", "/wp-admin", "/.git/config",
        "/server-status", "/phpinfo.php", "/.htaccess",
        "/api/v1/users", "/graphql",
    ]

    # First, get a baseline 404 response to detect soft-404 pages (SPAs that
    # return 200 for every route with a custom "not found" page).
    soft_404_signature = None
    try:
        bogus_url = f"{parsed.scheme}://{parsed.hostname}/__nonexistent_path_audit_probe_7x3k__"
        bogus_resp = requests.get(
            bogus_url, timeout=5,
            headers=build_headers(),
            allow_redirects=False,
        )
        if bogus_resp.status_code == 200:
            # This app returns 200 for unknown paths — it's a soft-404 SPA.
            # Store the body length as a fingerprint to compare against.
            soft_404_signature = len(bogus_resp.content)
    except requests.exceptions.RequestException:
        pass

    exposed_paths = []
    for path in sensitive_paths:
        try:
            test_url = f"{parsed.scheme}://{parsed.hostname}{path}"
            resp = requests.get(
                test_url, timeout=5,
                headers=build_headers(),
                allow_redirects=False,
            )
            if resp.status_code == 200:
                # Filter out soft-404 responses (same-size page as a known bogus path)
                if soft_404_signature is not None:
                    # If body size is within 100 bytes of the soft-404, it's the same page
                    if abs(len(resp.content) - soft_404_signature) < 100:
                        continue
                # Additional soft-404 detection via content
                resp_lower = resp.text[:5000].lower()
                soft_404_indicators = [
                    "not found", "404", "page not found", "does not exist",
                    "page doesn't exist", "cannot be found",
                ]
                if any(indicator in resp_lower for indicator in soft_404_indicators):
                    continue
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


def _check_a02_cryptographic_failures(body, headers, parsed, result):
    print("\n  ── A02:2021 — Cryptographic Failures ──")

    if parsed.scheme == "https":
        print(f"  [+] HTTPS in use")
        result.add("OWASP A02", "HTTPS enforced", "PASS")
    else:
        print(f"  {severity_tag('CRITICAL')} Site served over plain HTTP")
        result.add("OWASP A02", "No HTTPS", "FAIL", "CRITICAL",
                   "Data transmitted in cleartext")

    if "Strict-Transport-Security" not in headers:
        result.add("OWASP A02", "No HSTS (mapped)", "FAIL", "HIGH",
                   "Vulnerable to SSL stripping")

    mixed_content = re.findall(r'(?:src|href|action)\s*=\s*["\']http://', body, re.IGNORECASE)
    if mixed_content:
        print(f"  {severity_tag('MEDIUM')} Mixed content: {len(mixed_content)} HTTP resource(s) on HTTPS page")
        result.add("OWASP A02", "Mixed content detected", "WARN", "MEDIUM",
                   f"{len(mixed_content)} insecure resource references")
    else:
        print(f"  [+] No mixed content detected")
        result.add("OWASP A02", "No mixed content", "PASS")


def _check_a03_injection(url, body, headers, result):
    print("\n  ── A03:2021 — Injection ──")

    xss_canary = "<script>kiro_xss_probe</script>"
    injection_url = f"{url}{'&' if '?' in url else '?'}q={requests.utils.quote(xss_canary)}"

    try:
        inj_resp = requests.get(injection_url, timeout=REQUEST_TIMEOUT,
                                headers=build_headers(),
                                allow_redirects=True)
        if xss_canary in inj_resp.text:
            print(f"  {severity_tag('CRITICAL')} XSS reflection detected — input echoed unescaped!")
            result.add("OWASP A03", "Reflected XSS", "FAIL", "CRITICAL",
                       "Injected script tag reflected in response body")
        else:
            print(f"  [+] No reflected XSS in basic probe")
            result.add("OWASP A03", "No reflected XSS detected", "PASS")
    except requests.exceptions.RequestException:
        print(f"  [i] Could not complete XSS reflection test")

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
    if any(re.search(p, body, re.IGNORECASE) for p in sql_error_patterns):
        print(f"  {severity_tag('CRITICAL')} SQL error messages in response — potential injection point")
        result.add("OWASP A03", "SQL error messages exposed", "FAIL", "CRITICAL",
                   "Database errors visible to users")
    else:
        result.add("OWASP A03", "No SQL error leakage", "PASS")

    if "Content-Security-Policy" not in headers:
        result.add("OWASP A03", "No CSP (injection mitigation)", "WARN", "HIGH",
                   "CSP is a key defense against XSS")


def _check_a04_insecure_design(body, headers, result):
    print("\n  ── A04:2021 — Insecure Design ──")

    rate_limit_headers = ["X-RateLimit-Limit", "X-Rate-Limit-Limit",
                          "RateLimit-Limit", "Retry-After", "X-RateLimit-Remaining"]
    if any(h in headers for h in rate_limit_headers):
        print(f"  [+] Rate limiting headers present")
        result.add("OWASP A04", "Rate limiting indicators", "PASS")
    else:
        print(f"  {severity_tag('LOW')} No rate limiting headers detected")
        result.add("OWASP A04", "No rate limiting headers", "WARN", "LOW",
                   "May be vulnerable to brute force / abuse")

    captcha_patterns = [r"captcha", r"recaptcha", r"hcaptcha", r"turnstile"]
    if any(re.search(p, body, re.IGNORECASE) for p in captcha_patterns):
        print(f"  [+] CAPTCHA/anti-automation detected")
        result.add("OWASP A04", "Anti-automation present", "PASS")
    else:
        result.add("OWASP A04", "No CAPTCHA detected", "INFO",
                   detail="Consider adding for sensitive forms")


def _check_a05_security_misconfiguration(body, headers, result):
    print("\n  ── A05:2021 — Security Misconfiguration ──")

    error_indicators = [
        r"Traceback \(most recent call last\)",
        r"at .+\(.+:\d+:\d+\)",
        r"Exception in thread",
        r"<b>Fatal error</b>",
        r"Stack Trace:",
        r"Server Error in .+ Application",
    ]
    if any(re.search(p, body, re.IGNORECASE) for p in error_indicators):
        print(f"  {severity_tag('HIGH')} Stack trace / error details exposed in response")
        result.add("OWASP A05", "Stack trace exposed", "FAIL", "HIGH",
                   "Detailed error information visible to users")
    else:
        print(f"  [+] No stack traces or verbose errors in response")
        result.add("OWASP A05", "No verbose errors", "PASS")

    if "X-Content-Type-Options" not in headers:
        result.add("OWASP A05", "Missing X-Content-Type-Options (mapped)", "WARN", "MEDIUM")
    if "Permissions-Policy" not in headers:
        result.add("OWASP A05", "Missing Permissions-Policy (mapped)", "WARN", "MEDIUM")

    debug_headers = ["X-Debug-Token", "X-Debug-Token-Link", "X-Powered-By-Plesk"]
    for dh in debug_headers:
        if dh in headers:
            print(f"  {severity_tag('MEDIUM')} Debug header present: {dh}")
            result.add("OWASP A05", f"Debug header: {dh}", "FAIL", "MEDIUM")


def _check_a06_vulnerable_components(body, headers, result):
    print("\n  ── A06:2021 — Vulnerable and Outdated Components ──")

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
            found_components.append((lib, match.group(1)))

    if found_components:
        for lib, ver in found_components:
            print(f"  [i] Detected: {lib} v{ver}")
            result.add("OWASP A06", f"{lib} v{ver} detected", "INFO",
                       detail="Verify against known CVEs")
    else:
        print(f"  [+] No client-side library versions exposed in HTML")
        result.add("OWASP A06", "No exposed library versions", "PASS")

    if "Server" in headers:
        server_val = headers["Server"]
        if re.search(r"[\d]+\.[\d]+", server_val):
            print(f"  {severity_tag('MEDIUM')} Server version exposed: {server_val}")
            result.add("OWASP A06", f"Server version: {server_val}", "WARN", "MEDIUM",
                       "Check for known CVEs against this version")


def _check_a07_auth_failures(url, body, result):
    print("\n  ── A07:2021 — Identification and Authentication Failures ──")

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

    if re.search(r'[?&;](?:jsessionid|phpsessid|sid|session_id)=', url + body, re.IGNORECASE):
        print(f"  {severity_tag('HIGH')} Session ID exposed in URL")
        result.add("OWASP A07", "Session ID in URL", "FAIL", "HIGH",
                   "Session fixation / leakage via Referer")


def _check_a08_integrity_failures(body, parsed, result):
    print("\n  ── A08:2021 — Software and Data Integrity Failures ──")

    external_scripts = re.findall(
        r'<script[^>]+src\s*=\s*["\'](?:https?://[^"\']+)["\'][^>]*>', body, re.IGNORECASE
    )
    scripts_without_sri = []
    for script_tag in external_scripts:
        if "integrity=" not in script_tag.lower():
            src_match = re.search(r'src\s*=\s*["\']([^"\']+)', script_tag, re.IGNORECASE)
            if src_match:
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


def _check_a09_logging_monitoring(parsed, result):
    print("\n  ── A09:2021 — Security Logging & Monitoring Failures ──")

    try:
        sec_txt_resp = requests.get(
            f"{parsed.scheme}://{parsed.hostname}/.well-known/security.txt",
            timeout=5, headers=build_headers(),
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


def _check_a10_ssrf(url, body, result):
    print("\n  ── A10:2021 — Server-Side Request Forgery (SSRF) ──")

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

    redirect_params = re.findall(
        r'[?&](?:redirect|next|url|return|returnTo|goto|continue|dest)\s*=',
        body + url, re.IGNORECASE,
    )
    if redirect_params:
        print(f"  {severity_tag('MEDIUM')} Potential open redirect parameters found")
        result.add("OWASP A10", "Open redirect parameters", "WARN", "MEDIUM",
                   "URL redirect parameters may be exploitable")
