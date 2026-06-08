"""Check: Security headers presence and quality."""

import re

from config import print_section, severity_tag

# Headers that are only meaningful on HTTPS — skip for plain HTTP targets
_HTTPS_ONLY_HEADERS = {"Strict-Transport-Security"}


def check_security_headers(headers, result, skip_https_checks=False):
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
        # Skip HTTPS-only headers when scanning a plain HTTP target
        if skip_https_checks and header in _HTTPS_ONLY_HEADERS:
            print(f"  [i] SKIP: {header} (not applicable for HTTP targets)")
            result.add("Headers", header, "INFO", detail="Skipped — HTTP target")
            continue

        if header in headers:
            value = headers[header]
            print(f"  [+] PASS: {header}")
            print(f"       Value: {value}")
            result.add("Headers", header, "PASS", detail=value)

            if header == "Strict-Transport-Security":
                if "max-age" in value.lower():
                    match = re.search(r"max-age=(\d+)", value)
                    max_age = int(match.group(1)) if match else 0
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
