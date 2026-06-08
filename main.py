"""Security Vulnerability Audit — CLI entry point and orchestrator."""

import sys
import os
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


def run_audit(url, api_mode=False, auth_header=None, skip_ssl=False, method="GET", body=None, json_body=None):
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
    if api_mode:
        print(f"   Mode:   API  {'(authenticated)' if auth_header else '(unauthenticated)'}")
    print(f"   Date:   {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"{'═' * 60}")

    result = AuditResult()

    # Build request headers — include auth if provided
    req_headers = build_headers()
    if auth_header:
        req_headers.update(auth_header)

    # Initial request — supports GET, POST, PUT, PATCH etc.
    try:
        req_kwargs = dict(
            timeout=config.REQUEST_TIMEOUT,
            headers=req_headers,
        )
        if json_body is not None:
            req_kwargs["json"] = json_body
            req_headers.setdefault("Content-Type", "application/json")
        elif body is not None:
            req_kwargs["data"] = body

        response = requests.request(method.upper(), url, **req_kwargs)
        headers = response.headers
        print(f"\n  [i] HTTP {response.status_code} — {len(response.content)} bytes received")
        ct = headers.get("Content-Type", "unknown")
        print(f"  [i] Content-Type: {ct}")
    except requests.exceptions.RequestException as e:
        print(f"\n[!] Connection failed: {e}")
        sys.exit(1)

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
  python main.py https://example.com
  python main.py https://api.example.com/v1/users --api
  python main.py https://api.example.com/v1 --api --bearer eyJhbGci...
  python main.py https://api.example.com/v1 --api --api-key mykey123
  python main.py https://api.example.com/v1 --api --header "Cookie: session=abc"
  python main.py https://api.example.com/v1/login --api -X POST --json '{"user":"admin","pass":"test"}'
  python main.py https://api.example.com/v1/search --api -X POST --data 'q=test&page=1'
        """,
    )
    parser.add_argument(
        "url", nargs="?", default=None,
        help="Target URL to audit (e.g. https://example.com or https://api.example.com/v1)",
    )
    parser.add_argument(
        "--api", action="store_true",
        help="Enable API mode — skips HTML checks, runs API-specific security tests",
    )
    parser.add_argument(
        "--bearer", metavar="TOKEN",
        help="Bearer token for authenticated API testing (sets Authorization: Bearer <token>)",
    )
    parser.add_argument(
        "--api-key", metavar="KEY",
        help="API key for authentication (sets X-API-Key: <key>)",
    )
    parser.add_argument(
        "--header", metavar="'Name: Value'", action="append", dest="headers",
        help="Custom header for requests, can be repeated (e.g. --header 'X-Tenant-ID: abc')",
    )
    parser.add_argument(
        "--method", "-X", default="GET", metavar="METHOD",
        help="HTTP method for the initial request (default: GET). E.g. POST, PUT, PATCH",
    )
    parser.add_argument(
        "--data", "-d", default=None, metavar="BODY",
        help="Request body as a raw string (e.g. 'name=John&age=30'). Sets Content-Type to application/x-www-form-urlencoded if not overridden.",
    )
    parser.add_argument(
        "--json", default=None, metavar="JSON", dest="json_data",
        help='Request body as JSON string (e.g. \'{"name":"John"}\'). Automatically sets Content-Type: application/json.',
    )
    parser.add_argument(
        "--no-ssl", action="store_true",
        help="Skip SSL/TLS checks (use for local HTTP servers)",
    )
    parser.add_argument(
        "--timeout", "-t", type=int, default=10,
        help="Request timeout in seconds (default: 10)",
    )
    parser.add_argument(
        "--output-dir", "-o", default=None,
        help="Directory for report output (default: ./reports)",
    )
    parser.add_argument(
        "--vercel-bypass", default=None, metavar="SECRET",
        help="Vercel deployment protection bypass secret",
    )

    args = parser.parse_args()

    if not args.url:
        parser.print_help()
        print("\n[!] Error: URL argument is required.")
        sys.exit(1)

    # Normalize URL — only prepend https:// if no scheme at all
    target = args.url.strip()
    if not target.startswith(("http://", "https://")):
        target = "https://" + target

    # Auto-enable --no-ssl for plain http:// targets
    skip_ssl = args.no_ssl or target.startswith("http://")

    # Apply global config options
    config.REQUEST_TIMEOUT = args.timeout
    if args.output_dir:
        config.REPORT_OUTPUT_DIR = args.output_dir
    if args.vercel_bypass:
        config.EXTRA_HEADERS["x-vercel-protection-bypass"] = args.vercel_bypass

    # Build auth header dict from CLI flags
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

    # Merge any auth headers into EXTRA_HEADERS so all checks pick them up
    config.EXTRA_HEADERS.update(auth_header)

    # Parse JSON body if provided
    json_body = None
    if args.json_data:
        try:
            import json as _json
            json_body = _json.loads(args.json_data)
        except ValueError as e:
            print(f"[!] Invalid JSON in --json: {e}")
            sys.exit(1)

    run_audit(
        target,
        api_mode=args.api,
        auth_header=auth_header if auth_header else None,
        skip_ssl=skip_ssl,
        method=args.method,
        body=args.data,
        json_body=json_body,
    )


if __name__ == "__main__":
    main()
