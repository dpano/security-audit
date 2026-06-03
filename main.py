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
)


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
            url, timeout=config.REQUEST_TIMEOUT,
            headers=build_headers(),
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

    json_path = os.path.join(report_dir, f"audit_{domain_slug}_{timestamp_slug}.json")
    html_path = os.path.join(report_dir, f"audit_{domain_slug}_{timestamp_slug}.html")

    result.export_json(json_path, url)
    result.export_html(html_path, url)

    print(f"\n{'═' * 60}\n")


def main():
    parser = argparse.ArgumentParser(
        description="Security Vulnerability Audit — scan a URL for common web security issues and OWASP Top 10.",
        epilog="Example: python main.py https://example.com",
    )
    parser.add_argument(
        "url", nargs="?", default=None,
        help="Target URL to audit (e.g. https://example.com)",
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
        help="Vercel deployment protection bypass secret (x-vercel-protection-bypass header)",
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
    config.REQUEST_TIMEOUT = args.timeout
    if args.output_dir:
        config.REPORT_OUTPUT_DIR = args.output_dir
    if args.vercel_bypass:
        config.EXTRA_HEADERS["x-vercel-protection-bypass"] = args.vercel_bypass

    # Auto-detect Vercel-protected deployments
    if not args.vercel_bypass and "vercel" in target.lower():
        try:
            probe = requests.get(target, timeout=config.REQUEST_TIMEOUT,
                                 headers={"User-Agent": config.USER_AGENT}, allow_redirects=False)
            if probe.status_code == 401 and "x-vercel-id" in {k.lower() for k in probe.headers}:
                print("\n[!] Vercel deployment protection detected (HTTP 401).")
                print("    This deployment requires a bypass secret to audit.")
                print("    Re-run with: --vercel-bypass YOUR_SECRET")
                print("    (Find it in Vercel → Project Settings → Deployment Protection → Protection Bypass for Automation)")
                sys.exit(1)
        except requests.exceptions.RequestException:
            pass

    run_audit(target)


if __name__ == "__main__":
    main()
