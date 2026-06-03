"""Check: HTTP methods enumeration."""

import requests

from config import REQUEST_TIMEOUT, build_headers, print_section, severity_tag


def check_http_methods(url, result):
    """Enumerate allowed HTTP methods for potential misconfigurations."""
    print_section("HTTP Methods")

    dangerous_methods = {"PUT", "DELETE", "TRACE", "CONNECT", "PATCH"}

    try:
        resp = requests.options(url, timeout=REQUEST_TIMEOUT,
                                headers=build_headers())
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
            trace_resp = requests.request("TRACE", url, timeout=REQUEST_TIMEOUT,
                                          headers=build_headers())
            if trace_resp.status_code == 200:
                print(f"  {severity_tag('MEDIUM')} TRACE method returns 200 — Cross-Site Tracing risk")
                result.add("HTTP Methods", "TRACE enabled", "FAIL", "MEDIUM",
                           "Cross-Site Tracing (XST) possible")
        except requests.exceptions.RequestException:
            pass

    except requests.exceptions.RequestException as e:
        print(f"  [i] OPTIONS request failed: {e}")
