"""Check: Redirect chain analysis."""

import requests

from config import REQUEST_TIMEOUT, build_headers, print_section, severity_tag


def check_redirect_chain(url, result, skip_https_checks=False):
    """Analyze the redirect chain for security issues."""
    print_section("Redirect Chain")

    try:
        resp = requests.get(
            url, timeout=REQUEST_TIMEOUT,
            headers=build_headers(),
            allow_redirects=True,
        )

        if resp.history:
            print(f"  Redirect chain ({len(resp.history)} hops):")
            for i, r in enumerate(resp.history):
                location = r.headers.get("Location", "N/A")
                print(f"    {i + 1}. [{r.status_code}] {r.url} → {location}")

                if r.url.startswith("http://") and location.startswith("http://"):
                    print(f"       {severity_tag('HIGH')} Redirect stays on HTTP — no upgrade to HTTPS")
                    result.add("Redirects", "HTTP-to-HTTP redirect", "FAIL", "HIGH")

            print(f"    Final: [{resp.status_code}] {resp.url}")
            result.add("Redirects", "Chain analyzed", "PASS",
                       detail=f"{len(resp.history)} redirects")
        else:
            print("  [+] No redirects — direct response.")
            result.add("Redirects", "No redirects", "PASS")

        # HTTP→HTTPS enforcement check — only relevant for https:// targets
        if skip_https_checks:
            print("  [i] HTTP→HTTPS redirect check skipped (HTTP target)")
        elif url.startswith("https://"):
            http_url = url.replace("https://", "http://", 1)
            try:
                http_resp = requests.get(
                    http_url, timeout=REQUEST_TIMEOUT,
                    headers=build_headers(),
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
