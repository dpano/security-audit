"""Check: Cookie security flags."""

from config import print_section, severity_tag


def check_cookie_security(response, result):
    """Analyze Set-Cookie headers for security flags."""
    print_section("Cookie Security")

    cookies = response.headers.get("Set-Cookie", "")
    if not cookies:
        if not response.cookies:
            print("  [i] No cookies set by this response.")
            return

    cookie_headers = response.headers.get("Set-Cookie") if "Set-Cookie" in response.headers else None

    # requests library merges headers; use raw response for multiple Set-Cookie
    raw_cookies = []
    if hasattr(response, "raw") and hasattr(response.raw, "headers"):
        raw_cookies = (
            response.raw.headers.getlist("Set-Cookie")
            if hasattr(response.raw.headers, "getlist")
            else []
        )

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
