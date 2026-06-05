"""Check: API-specific security assessment."""

import re
import json
import requests
from urllib.parse import urlparse, urljoin

from config import REQUEST_TIMEOUT, build_headers, print_section, severity_tag


def check_api_security(url, response, headers, result, auth_header=None):
    """Run API-focused security checks against the target endpoint."""
    print_section("API Security Assessment")

    body = response.text[:100000]
    parsed = urlparse(url)
    content_type = headers.get("Content-Type", "")
    is_json = "application/json" in content_type
    is_xml = "application/xml" in content_type or "text/xml" in content_type

    _check_api_content_type(headers, body, result)
    _check_api_authentication(url, headers, auth_header, result)
    _check_api_response_exposure(body, is_json, is_xml, result)
    _check_api_error_handling(url, result)
    _check_api_rate_limiting(url, headers, result)
    _check_api_verb_tampering(url, result)
    _check_api_injection(url, result)
    _check_api_mass_assignment(url, body, is_json, result)
    _check_api_endpoints(url, parsed, auth_header, result)


def _check_api_content_type(headers, body, result):
    """Verify the API enforces proper content-type handling."""
    print("  ── Content-Type & Response Format ──\n")

    content_type = headers.get("Content-Type", "")

    if not content_type:
        print(f"  {severity_tag('MEDIUM')} No Content-Type header in response")
        result.add("API", "Missing Content-Type", "FAIL", "MEDIUM",
                   "Client cannot reliably parse the response")
    elif "application/json" in content_type or "application/xml" in content_type:
        print(f"  [+] Content-Type: {content_type}")
        result.add("API", "Content-Type set", "PASS", detail=content_type)
    else:
        print(f"  {severity_tag('LOW')} Unexpected Content-Type for API: {content_type}")
        result.add("API", f"Unexpected Content-Type: {content_type}", "WARN", "LOW")

    # Check for charset declaration
    if "charset" not in content_type.lower():
        print(f"  {severity_tag('LOW')} No charset specified in Content-Type")
        result.add("API", "No charset in Content-Type", "WARN", "LOW",
                   "May cause encoding confusion")

    # Validate JSON is parseable
    if "application/json" in content_type:
        try:
            json.loads(body)
            print(f"  [+] Response is valid JSON")
            result.add("API", "Valid JSON response", "PASS")
        except json.JSONDecodeError:
            print(f"  {severity_tag('MEDIUM')} Response declared as JSON but is not valid JSON")
            result.add("API", "Invalid JSON response", "WARN", "MEDIUM")


def _check_api_authentication(url, headers, auth_header, result):
    """Check authentication enforcement on the endpoint."""
    print("\n  ── Authentication & Authorization ──\n")

    # Test access without any authentication
    try:
        no_auth_headers = build_headers()
        # Explicitly strip Authorization if it was added via auth_header
        no_auth_headers.pop("Authorization", None)
        no_auth_headers.pop("X-API-Key", None)

        resp = requests.get(url, timeout=REQUEST_TIMEOUT, headers=no_auth_headers)

        if resp.status_code in (401, 403):
            print(f"  [+] Endpoint returns {resp.status_code} without credentials — auth enforced")
            result.add("API Auth", "Unauthenticated request rejected", "PASS",
                       detail=f"HTTP {resp.status_code}")
        elif resp.status_code == 200 and auth_header:
            print(f"  {severity_tag('HIGH')} Endpoint returns 200 without credentials — auth not enforced!")
            result.add("API Auth", "Endpoint accessible without auth", "FAIL", "HIGH",
                       "Data returned without any authentication token")
        else:
            print(f"  [i] Unauthenticated response: HTTP {resp.status_code}")
            result.add("API Auth", f"Unauthenticated response: {resp.status_code}", "INFO")

    except requests.exceptions.RequestException as e:
        print(f"  [i] Auth enforcement check failed: {e}")

    # Check WWW-Authenticate header on 401
    www_auth = headers.get("WWW-Authenticate", "")
    if www_auth:
        print(f"  [+] WWW-Authenticate: {www_auth}")
        result.add("API Auth", "WWW-Authenticate header present", "PASS", detail=www_auth)

    # Check for JWT in Authorization header response (should not echo back tokens)
    auth_resp = headers.get("Authorization", "")
    if auth_resp:
        print(f"  {severity_tag('HIGH')} Authorization header echoed back in response")
        result.add("API Auth", "Auth token in response headers", "FAIL", "HIGH",
                   "Server should not echo back Authorization headers")

    # Check cache-control for authenticated responses
    cache_control = headers.get("Cache-Control", "").lower()
    if auth_header and ("no-store" not in cache_control and "private" not in cache_control):
        print(f"  {severity_tag('MEDIUM')} Authenticated response may be cached — missing Cache-Control: no-store")
        result.add("API Auth", "Authenticated response cacheable", "WARN", "MEDIUM",
                   "Cache-Control should include 'no-store' for authenticated endpoints")
    elif auth_header:
        print(f"  [+] Cache-Control properly restricts caching of authenticated response")
        result.add("API Auth", "Cache-Control restricts caching", "PASS")


def _check_api_response_exposure(body, is_json, is_xml, result):
    """Scan response body for sensitive data that should not be returned."""
    print("\n  ── Sensitive Data Exposure in Response ──\n")

    if not body.strip():
        print("  [i] Empty response body — skipping exposure check")
        return

    patterns = {
        "Password field": (r'"(?:password|passwd|pwd)"\s*:\s*"[^"]+"', "CRITICAL"),
        "Private/secret key": (r'"(?:secret|private_key|api_secret|client_secret)"\s*:\s*"[^"]+"', "CRITICAL"),
        "Access token": (r'"(?:access_token|auth_token|bearer_token)"\s*:\s*"[^"]+"', "HIGH"),
        "Credit card number": (r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b', "CRITICAL"),
        "Social Security Number": (r'\b\d{3}-\d{2}-\d{4}\b', "CRITICAL"),
        "Email addresses": (r'"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"', "MEDIUM"),
        "Internal IP address": (r'"(?:10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+)"', "MEDIUM"),
        "Stack trace in JSON": (r'"(?:stack|stacktrace|trace)"\s*:\s*"[^"]{50,}"', "HIGH"),
        "Internal path": (r'"[^"]*(?:/var/|/etc/|/home/|C:\\\\)[^"]*"', "MEDIUM"),
    }

    found_any = False
    for name, (pattern, severity) in patterns.items():
        matches = re.findall(pattern, body, re.IGNORECASE)
        if matches:
            found_any = True
            print(f"  {severity_tag(severity)} {name} found in response ({len(matches)} occurrence(s))")
            # Show a redacted snippet for critical findings
            if severity == "CRITICAL":
                snippet = matches[0][:60] + "..." if len(matches[0]) > 60 else matches[0]
                snippet = re.sub(r':\s*"[^"]{4,}"', ': "[REDACTED]"', snippet)
                print(f"       Sample: {snippet}")
            result.add("API Exposure", name, "FAIL", severity,
                       f"{len(matches)} occurrence(s) in response body")

    if not found_any:
        print(f"  [+] No sensitive data patterns detected in response body")
        result.add("API Exposure", "No sensitive data patterns", "PASS")


def _check_api_error_handling(url, result):
    """Probe common error conditions to evaluate error message verbosity."""
    print("\n  ── Error Handling ──\n")

    error_probes = [
        ("Invalid path param", f"{url.rstrip('/')}/999999999"),
        ("SQL injection probe", f"{url}{'&' if '?' in url else '?'}id=1%27%20OR%20%271%27%3D%271"),
        ("Malformed JSON body", None),  # handled via POST below
    ]

    sql_error_patterns = [
        r"SQL syntax", r"mysql_fetch", r"ORA-\d{5}",
        r"PostgreSQL.*ERROR", r"SQLite3::", r"Unclosed quotation mark",
    ]
    stack_trace_patterns = [
        r"Traceback \(most recent call last\)",
        r"at .+\(.+\.(?:java|cs|py|js|ts):\d+\)",
        r"Stack Trace:", r"Exception in thread",
    ]

    for probe_name, probe_url in error_probes[:2]:
        try:
            resp = requests.get(probe_url, timeout=REQUEST_TIMEOUT, headers=build_headers())
            body = resp.text[:5000]

            sql_found = any(re.search(p, body, re.IGNORECASE) for p in sql_error_patterns)
            trace_found = any(re.search(p, body, re.IGNORECASE) for p in stack_trace_patterns)

            if sql_found:
                print(f"  {severity_tag('CRITICAL')} SQL error in response to '{probe_name}'")
                result.add("API Errors", f"SQL error on {probe_name}", "FAIL", "CRITICAL",
                           "Database error messages exposed")
            elif trace_found:
                print(f"  {severity_tag('HIGH')} Stack trace in response to '{probe_name}'")
                result.add("API Errors", f"Stack trace on {probe_name}", "FAIL", "HIGH",
                           "Internal error details exposed")
            else:
                print(f"  [+] '{probe_name}': HTTP {resp.status_code} — no verbose error")
                result.add("API Errors", f"Clean error: {probe_name}", "PASS",
                           detail=f"HTTP {resp.status_code}")
        except requests.exceptions.RequestException:
            pass

    # Test malformed JSON POST
    try:
        resp = requests.post(
            url, timeout=REQUEST_TIMEOUT,
            headers=build_headers(**{"Content-Type": "application/json"}),
            data="{invalid json{{",
        )
        body = resp.text[:5000]
        trace_found = any(re.search(p, body, re.IGNORECASE) for p in stack_trace_patterns)
        if trace_found:
            print(f"  {severity_tag('HIGH')} Stack trace in response to malformed JSON POST")
            result.add("API Errors", "Stack trace on malformed JSON", "FAIL", "HIGH")
        else:
            print(f"  [+] Malformed JSON POST: HTTP {resp.status_code} — no verbose error")
            result.add("API Errors", "Clean error on malformed JSON", "PASS",
                       detail=f"HTTP {resp.status_code}")
    except requests.exceptions.RequestException:
        pass


def _check_api_rate_limiting(url, headers, result):
    """Verify rate limiting is in place by firing rapid requests."""
    print("\n  ── Rate Limiting ──\n")

    # Check headers first
    rl_headers = {
        "X-RateLimit-Limit": headers.get("X-RateLimit-Limit"),
        "X-RateLimit-Remaining": headers.get("X-RateLimit-Remaining"),
        "RateLimit-Limit": headers.get("RateLimit-Limit"),
        "Retry-After": headers.get("Retry-After"),
    }
    declared = {k: v for k, v in rl_headers.items() if v is not None}

    if declared:
        for k, v in declared.items():
            print(f"  [+] {k}: {v}")
        result.add("API Rate Limit", "Rate limit headers present", "PASS",
                   detail=", ".join(f"{k}={v}" for k, v in declared.items()))
    else:
        print(f"  {severity_tag('MEDIUM')} No rate limit headers on initial response")
        result.add("API Rate Limit", "No rate limit headers", "WARN", "MEDIUM",
                   "Endpoint may be vulnerable to brute force or abuse")

    # Fire 15 rapid requests and check if any returns 429
    print(f"  [*] Sending 15 rapid requests to test enforcement...")
    hit_limit = False
    try:
        for _ in range(15):
            resp = requests.get(url, timeout=5, headers=build_headers())
            if resp.status_code == 429:
                hit_limit = True
                print(f"  [+] Rate limit enforced — received HTTP 429 after rapid requests")
                result.add("API Rate Limit", "Rate limit enforced (429)", "PASS")
                break
    except requests.exceptions.RequestException:
        pass

    if not hit_limit:
        print(f"  {severity_tag('MEDIUM')} No 429 received after 15 rapid requests — rate limiting may not be enforced")
        result.add("API Rate Limit", "Rate limit not triggered in test", "WARN", "MEDIUM",
                   "15 rapid requests did not produce a 429 response")


def _check_api_verb_tampering(url, result):
    """Test HTTP verb tampering — can restricted verbs bypass access control."""
    print("\n  ── HTTP Verb Security ──\n")

    verbs = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"]
    verb_results = {}

    for verb in verbs:
        try:
            resp = requests.request(
                verb, url, timeout=REQUEST_TIMEOUT, headers=build_headers()
            )
            verb_results[verb] = resp.status_code
        except requests.exceptions.RequestException:
            verb_results[verb] = None

    for verb, code in verb_results.items():
        if code is None:
            continue
        if verb in ("PUT", "DELETE", "PATCH") and code == 200:
            print(f"  {severity_tag('HIGH')} {verb} returns 200 — may allow unauthorized data modification")
            result.add("API Verbs", f"{verb} returns 200", "FAIL", "HIGH",
                       "Destructive verb accessible without restriction")
        elif verb == "OPTIONS" and code == 200:
            print(f"  [i] OPTIONS {code} — check Allow header for exposed verbs")
            result.add("API Verbs", "OPTIONS enabled", "INFO")
        else:
            print(f"  [+] {verb}: {code}")

    # Check for verb override headers (some frameworks honor these)
    override_headers = ["X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"]
    try:
        override_resp = requests.get(
            url, timeout=REQUEST_TIMEOUT,
            headers=build_headers(**{"X-HTTP-Method-Override": "DELETE"}),
        )
        if override_resp.status_code == 200:
            print(f"  {severity_tag('HIGH')} X-HTTP-Method-Override: DELETE returned 200 — verb override honored!")
            result.add("API Verbs", "HTTP method override accepted", "FAIL", "HIGH",
                       "Server honors X-HTTP-Method-Override — DELETE override returned 200")
        else:
            result.add("API Verbs", "Method override not honored", "PASS")
    except requests.exceptions.RequestException:
        pass


def _check_api_injection(url, result):
    """Test for injection vulnerabilities via query parameters."""
    print("\n  ── Injection Probes ──\n")

    base = url.rstrip("/")
    sep = "&" if "?" in base else "?"

    probes = [
        ("NoSQL injection", f"{base}{sep}filter[$gt]=", [r"mongodb", r"\[\$", r"BSONError"]),
        ("SSTI probe", f"{base}{sep}q={{7*7}}", [r"\b49\b"]),
        ("Path traversal", f"{base}{sep}file=../../etc/passwd", [r"root:.*:0:0"]),
        ("XXE indicator", f"{base}{sep}data=%3C%3Fxml", [r"DOCTYPE", r"ENTITY"]),
        ("Command injection", f"{base}{sep}cmd=id%3Bid", [r"uid=\d+", r"gid=\d+"]),
    ]

    for probe_name, probe_url, indicators in probes:
        try:
            resp = requests.get(probe_url, timeout=REQUEST_TIMEOUT, headers=build_headers())
            body = resp.text[:5000]
            triggered = any(re.search(p, body, re.IGNORECASE) for p in indicators)
            if triggered:
                print(f"  {severity_tag('CRITICAL')} {probe_name} — response contains exploit indicators!")
                result.add("API Injection", probe_name, "FAIL", "CRITICAL",
                           "Response matched known exploitation signature")
            else:
                print(f"  [+] {probe_name}: no indicators (HTTP {resp.status_code})")
                result.add("API Injection", f"No {probe_name}", "PASS")
        except requests.exceptions.RequestException:
            pass


def _check_api_mass_assignment(url, body, is_json, result):
    """Check for signs of mass assignment / over-posting vulnerability."""
    print("\n  ── Mass Assignment & Data Overexposure ──\n")

    if not is_json or not body.strip():
        print("  [i] Skipping — response is not JSON")
        return

    try:
        data = json.loads(body)
    except json.JSONDecodeError:
        return

    # Flatten nested dicts one level
    fields = []
    items = data if isinstance(data, list) else [data]
    for item in items[:5]:
        if isinstance(item, dict):
            fields.extend(item.keys())

    privileged_fields = [
        "role", "is_admin", "admin", "permissions", "scope", "groups",
        "is_staff", "is_superuser", "access_level", "privilege",
    ]
    internal_fields = [
        "password", "password_hash", "hashed_password", "salt",
        "secret", "private_key", "internal_id", "__v", "_id",
        "created_by_ip", "last_login_ip",
    ]

    exposed_privileged = [f for f in fields if f.lower() in privileged_fields]
    exposed_internal = [f for f in fields if f.lower() in internal_fields]

    if exposed_privileged:
        print(f"  {severity_tag('HIGH')} Privileged fields in response: {', '.join(exposed_privileged)}")
        result.add("API Mass Assignment", "Privileged fields exposed", "FAIL", "HIGH",
                   f"Fields: {', '.join(exposed_privileged)}")
    else:
        print(f"  [+] No privileged fields detected in response")
        result.add("API Mass Assignment", "No privileged fields exposed", "PASS")

    if exposed_internal:
        print(f"  {severity_tag('MEDIUM')} Internal fields in response: {', '.join(exposed_internal)}")
        result.add("API Mass Assignment", "Internal fields exposed", "WARN", "MEDIUM",
                   f"Fields: {', '.join(exposed_internal)}")


def _check_api_endpoints(url, parsed, auth_header, result):
    """Discover common API endpoints and check if they're protected."""
    print("\n  ── Common API Endpoint Discovery ──\n")

    base = f"{parsed.scheme}://{parsed.hostname}"
    if parsed.port and parsed.port not in (80, 443):
        base += f":{parsed.port}"

    # Detect API base path prefix (e.g. /api, /api/v1, /v2)
    path_parts = [p for p in parsed.path.strip("/").split("/") if p]
    api_prefix = ""
    for part in path_parts:
        if re.match(r"^(?:api|v\d+|rest)$", part, re.IGNORECASE):
            api_prefix = f"/{part}"
            break

    common_paths = [
        f"{api_prefix}/users",
        f"{api_prefix}/user",
        f"{api_prefix}/accounts",
        f"{api_prefix}/admin",
        f"{api_prefix}/health",
        f"{api_prefix}/status",
        f"{api_prefix}/metrics",
        f"{api_prefix}/docs",
        f"{api_prefix}/swagger",
        f"{api_prefix}/swagger.json",
        f"{api_prefix}/openapi.json",
        f"{api_prefix}/openapi.yaml",
        f"{api_prefix}/graphql",
        f"{api_prefix}/debug",
        f"{api_prefix}/config",
    ]

    # Build request headers — with and without auth
    auth_hdrs = build_headers()
    if auth_header:
        auth_hdrs.update(auth_header)

    print(f"  Probing {len(common_paths)} common API paths...")
    exposed = []
    docs_found = []

    for path in common_paths:
        probe_url = base + path
        try:
            # Test without auth first
            resp_no_auth = requests.get(probe_url, timeout=5, headers=build_headers(), allow_redirects=False)

            if resp_no_auth.status_code == 200:
                ct = resp_no_auth.headers.get("Content-Type", "")
                body_snippet = resp_no_auth.text[:500].lower()

                # Check if it's a docs/schema endpoint
                is_docs = any(kw in path for kw in ["/swagger", "/openapi", "/docs", "/graphql"])
                has_schema = any(kw in body_snippet for kw in ["openapi", "swagger", "graphql", "paths", "components"])

                if is_docs and has_schema:
                    docs_found.append(path)
                    print(f"  {severity_tag('MEDIUM')} API docs exposed: {path}")
                    result.add("API Endpoints", f"Docs exposed: {path}", "WARN", "MEDIUM",
                               "API schema/docs accessible without authentication")
                elif any(kw in path for kw in ["/admin", "/debug", "/config", "/metrics"]):
                    exposed.append(path)
                    print(f"  {severity_tag('HIGH')} Sensitive endpoint public: {path}")
                    result.add("API Endpoints", f"Sensitive path public: {path}", "FAIL", "HIGH",
                               "Admin/debug endpoint returned 200 without auth")
                else:
                    print(f"  [i] {path}: 200 OK")
            elif resp_no_auth.status_code in (401, 403):
                print(f"  [+] {path}: {resp_no_auth.status_code} — protected")
            # 404 / others: skip silently
        except requests.exceptions.RequestException:
            pass

    if not exposed and not docs_found:
        print(f"  [+] No sensitive endpoints found exposed")
        result.add("API Endpoints", "No sensitive endpoints exposed", "PASS")
