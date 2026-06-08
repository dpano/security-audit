"""Security Vulnerability Audit — CLI entry point and orchestrator."""

import sys
import os
import json
import argparse
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

import config
from config import build_headers, print_section
from result import AuditResult
from checks import (
    check_security_headers,
    check_information_leakage,
    check_cookie_security,
    check_cors,
    check_ssl_tls,
    check_http_methods,
    check_redirect_chain,
    check_content_analysis,
    check_owasp_top10,
    check_server_fingerprint,
    check_api_security,
)


def perform_login(login_url, login_data, login_json):
    """
    POST credentials to login_url, return an authenticated requests.Session.
    Raises SystemExit on failure.
    """
    print(f"\n  [*] Logging in to: {login_url}")
    session = requests.Session()
    session.headers.update(build_headers())

    try:
        if login_json is not None:
            resp = session.post(login_url, json=login_json,
                                timeout=config.REQUEST_TIMEOUT, allow_redirects=True)
        else:
            resp = session.post(login_url, data=login_data,
                                timeout=config.REQUEST_TIMEOUT, allow_redirects=True)
    except requests.exceptions.RequestException as e:
        print(f"[!] Login request failed: {e}")
        sys.exit(1)

    if resp.status_code in (401, 403):
        print(f"[!] Login failed — server returned HTTP {resp.status_code}.")
        print("    Check your --login-data / --login-json credentials.")
        sys.exit(1)

    if not session.cookies:
        print(f"  {('[~]')} Warning: login succeeded (HTTP {resp.status_code}) but no session cookies were set.")
        print("    The scan will continue but may not be authenticated.")
    else:
        cookie_names = ", ".join(c.name for c in session.cookies)
        print(f"  [+] Login successful (HTTP {resp.status_code}) — cookies acquired: {cookie_names}")

    return session


def run_audit(url, api_mode=False, auth_header=None, skip_ssl=False,
              method="GET", body=None, json_body=None, session=None):
    parsed = urlparse(url)
    hostname = parsed.hostname
    is_http = url.startswith("http://")  # plain HTTP — SSL/HTTPS checks not applicable

    if not hostname:
        print("[!] Invalid URL. Please include the scheme (https://...).")
        sys.exit(1)

    mode_label = "API SECURITY AUDIT" if api_mode else "SECURITY VULNERABILITY AUDIT"
    print(f"\n{'═' * 60}")
    print(f"   {mode_label}")
    print(f"   Target: {url}")
    print(f"   Method: {method.upper()}")
    if session:
        print(f"   Auth:   session cookies (form login)")
    elif auth_header:
        print(f"   Auth:   custom headers")
    if api_mode:
        print(f"   Mode:   API")
    print(f"   Date:   {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'═' * 60}")

    result = AuditResult()

    # Build request headers — include auth if provided
    req_headers = build_headers()
    if auth_header:
        req_headers.update(auth_header)

    # Initial request — use session if logged in, otherwise plain requests
    try:
        req_kwargs = dict(timeout=config.REQUEST_TIMEOUT, headers=req_headers)
        if json_body is not None:
            req_kwargs["json"] = json_body
            req_headers.setdefault("Content-Type", "application/json")
        elif body is not None:
            req_kwargs["data"] = body

        requester = session if session else requests
        response = requester.request(method.upper(), url, **req_kwargs)
        headers = response.headers
        print(f"\n  [i] HTTP {response.status_code} — {len(response.content)} bytes received")
        ct = headers.get("Content-Type", "unknown")
        print(f"  [i] Content-Type: {ct}")

        # Warn if we still landed on a login page after authentication
        if session and response.status_code in (401, 403):
            print(f"  [!] Warning: authenticated request returned {response.status_code} — session may be invalid.")
        if session:
            body_lower = response.text[:2000].lower()
            login_indicators = ["login", "sign in", "signin", "log in", "password"]
            if any(kw in body_lower for kw in login_indicators) and response.status_code == 200:
                print(f"  [~] Warning: response may be a login page — audit results could be inaccurate.")

    except requests.exceptions.RequestException as e:
        print(f"\n[!] Connection failed: {e}")
        sys.exit(1)

    # Pass session into checks that make their own requests, so they stay authenticated
    if session:
        config.SESSION = session

    if api_mode:
        check_security_headers(headers, result, skip_https_checks=is_http)
        check_information_leakage(headers, result)
        check_cookie_security(response, result)
        check_cors(url, headers, result)
        if not skip_ssl:
            check_ssl_tls(hostname, result)
        check_http_methods(url, result)
        check_redirect_chain(url, result, skip_https_checks=is_http)
        check_api_security(url, response, headers, result, auth_header=auth_header)
    else:
        check_security_headers(headers, result, skip_https_checks=is_http)
        check_information_leakage(headers, result)
        check_cookie_security(response, result)
        check_cors(url, headers, result)
        if not skip_ssl:
            check_ssl_tls(hostname, result)
        check_http_methods(url, result)
        check_redirect_chain(url, result, skip_https_checks=is_http)
        check_content_analysis(response, result)
        check_owasp_top10(url, response, headers, result, skip_https_checks=is_http)
        check_server_fingerprint(headers, result)

    # Final summary
    print_section("AUDIT SUMMARY")
    passed, failed, warnings = result.summary()
    total = passed + failed + warnings

    print(f"  Total checks performed: {total}")
    print(f"  ✓ Passed:   {passed}")
    print(f"  ✗ Failed:   {failed}")
    print(f"  ⚠ Warnings: {warnings}")

    risk_score = result.risk_score()
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
    critical_findings = [
        f for f in result.findings
        if f["status"] == "FAIL" and f["severity"] in ("CRITICAL", "HIGH")
    ]
    if critical_findings:
        print(f"\n  Priority Remediation ({len(critical_findings)} critical/high issues):")
        for f in critical_findings:
            print(f"    • [{f['severity']}] {f['check']}")
            if f["detail"]:
                print(f"      {f['detail']}")

    # Export reports
    print_section("EXPORT")
    report_dir = config.REPORT_OUTPUT_DIR or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "reports"
    )
    os.makedirs(report_dir, exist_ok=True)

    timestamp_slug = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    domain_slug = parsed.hostname.replace(".", "_")
    mode_slug = "api" if api_mode else "web"

    json_path = os.path.join(report_dir, f"audit_{mode_slug}_{domain_slug}_{timestamp_slug}.json")
    html_path = os.path.join(report_dir, f"audit_{mode_slug}_{domain_slug}_{timestamp_slug}.html")

    result.export_json(json_path, url)
    result.export_html(html_path, url)

    print(f"\n{'═' * 60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Security Vulnerability Audit — scan a web app or API for security issues.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Standard web scan
  python main.py https://example.com

  # API scan with Bearer token
  python main.py https://api.example.com/v1 --api --bearer eyJhbGci...

  # API scan with cookie auth
  python main.py https://api.example.com/v1 --api --header "Cookie: session=abc"

  # POST request scan
  python main.py https://api.example.com/v1/login --api -X POST --json '{"user":"admin","pass":"test"}'

  # Form login then scan a protected page (PowerShell: use backtick ` for line continuation)
  python main.py https://example.com/dashboard --login-url https://example.com/login --login-data "username=admin&password=secret"

  # Form login with JSON credentials
  python main.py https://example.com/dashboard --login-url https://example.com/api/auth/login --login-json '{"username":"admin","password":"secret"}'
        """,
    )
    parser.add_argument(
        "url", nargs="?", default=None,
        help="Target URL to audit after login (or direct scan target)",
    )

    # ── Login flow ──────────────────────────────────────────────────────────
    login_group = parser.add_argument_group("Form login (authenticate before scanning)")
    login_group.add_argument(
        "--login-url", metavar="URL",
        help="URL to POST credentials to (e.g. https://example.com/login)",
    )
    login_group.add_argument(
        "--login-data", metavar="'user=x&pass=y'",
        help="Form-encoded credentials to POST to --login-url",
    )
    login_group.add_argument(
        "--login-json", metavar="JSON",
        help='JSON credentials to POST to --login-url (e.g. \'{"username":"x","password":"y"}\')',
    )

    # ── Auth headers ────────────────────────────────────────────────────────
    auth_group = parser.add_argument_group("Token / header authentication")
    auth_group.add_argument(
        "--bearer", metavar="TOKEN",
        help="Bearer token — sets Authorization: Bearer <token>",
    )
    auth_group.add_argument(
        "--api-key", metavar="KEY",
        help="API key — sets X-API-Key: <key>",
    )
    auth_group.add_argument(
        "--header", metavar="'Name: Value'", action="append", dest="headers",
        help="Custom request header, repeatable",
    )

    # ── Mode and request ────────────────────────────────────────────────────
    mode_group = parser.add_argument_group("Scan mode and request options")
    mode_group.add_argument(
        "--api", action="store_true",
        help="Enable API mode",
    )
    mode_group.add_argument(
        "--method", "-X", default="GET", metavar="METHOD",
        help="HTTP method for the audit request (default: GET)",
    )
    mode_group.add_argument(
        "--data", "-d", default=None, metavar="BODY",
        help="Raw request body for the audit request",
    )
    mode_group.add_argument(
        "--json", default=None, metavar="JSON", dest="json_data",
        help="JSON request body for the audit request",
    )
    mode_group.add_argument(
        "--no-ssl", action="store_true",
        help="Skip SSL/TLS checks (auto-enabled for http:// targets)",
    )
    mode_group.add_argument(
        "--timeout", "-t", type=int, default=10,
        help="Request timeout in seconds (default: 10)",
    )
    mode_group.add_argument(
        "--output-dir", "-o", default=None,
        help="Report output directory (default: ./reports)",
    )
    mode_group.add_argument(
        "--vercel-bypass", default=None, metavar="SECRET",
        help="Vercel deployment protection bypass secret",
    )

    args = parser.parse_args()

    if not args.url:
        parser.print_help()
        print("\n[!] Error: URL argument is required.")
        sys.exit(1)

    # Validate login args
    if args.login_url and not (args.login_data or args.login_json):
        print("[!] --login-url requires --login-data or --login-json.")
        sys.exit(1)
    if (args.login_data or args.login_json) and not args.login_url:
        print("[!] --login-data / --login-json require --login-url.")
        sys.exit(1)
    if args.login_data and args.login_json:
        print("[!] Use either --login-data or --login-json, not both.")
        sys.exit(1)

    # Normalize URLs
    def normalize(u):
        u = u.strip()
        return u if u.startswith(("http://", "https://")) else "https://" + u

    target = normalize(args.url)
    login_url = normalize(args.login_url) if args.login_url else None

    skip_ssl = args.no_ssl or target.startswith("http://")

    # Apply global config
    config.REQUEST_TIMEOUT = args.timeout
    if args.output_dir:
        config.REPORT_OUTPUT_DIR = args.output_dir
    if args.vercel_bypass:
        config.EXTRA_HEADERS["x-vercel-protection-bypass"] = args.vercel_bypass

    # Build auth header dict
    auth_header = {}
    if args.bearer:
        auth_header["Authorization"] = f"Bearer {args.bearer}"
    if args.api_key:
        auth_header["X-API-Key"] = args.api_key
    if args.headers:
        for h in args.headers:
            if ":" in h:
                name, _, value = h.partition(":")
                auth_header[name.strip()] = value.strip()
    config.EXTRA_HEADERS.update(auth_header)

    # Parse JSON bodies
    json_body = None
    if args.json_data:
        try:
            json_body = json.loads(args.json_data)
        except ValueError as e:
            print(f"[!] Invalid JSON in --json: {e}")
            sys.exit(1)

    login_json = None
    if args.login_json:
        try:
            login_json = json.loads(args.login_json)
        except ValueError as e:
            print(f"[!] Invalid JSON in --login-json: {e}")
            sys.exit(1)

    # Perform login if requested
    session = None
    if login_url:
        session = perform_login(login_url, args.login_data, login_json)
        # Propagate session cookies into EXTRA_HEADERS for checks that
        # don't receive the session object directly
        cookie_header = "; ".join(f"{c.name}={c.value}" for c in session.cookies)
        if cookie_header:
            config.EXTRA_HEADERS["Cookie"] = cookie_header

    run_audit(
        target,
        api_mode=args.api,
        auth_header=auth_header if auth_header else None,
        skip_ssl=skip_ssl,
        method=args.method,
        body=args.data,
        json_body=json_body,
        session=session,
    )


if __name__ == "__main__":
    main()
