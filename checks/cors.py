"""Check: CORS configuration."""

import requests

from config import REQUEST_TIMEOUT, build_headers, print_section, severity_tag


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
            headers=build_headers(Origin=evil_origin),
        )
        reflected = test_resp.headers.get("Access-Control-Allow-Origin", "")
        if reflected == evil_origin:
            print(f"  {severity_tag('HIGH')} Server reflects arbitrary Origin header — CORS misconfiguration!")
            result.add("CORS", "Origin reflection", "FAIL", "HIGH",
                       "Server echoes attacker-controlled Origin")
    except requests.exceptions.RequestException:
        pass
