"""Check: Information leakage via HTTP headers."""

from config import print_section, severity_tag


def check_information_leakage(headers, result):
    """Detect headers that reveal server internals."""
    print_section("Information Leakage")

    leakage_headers = {
        "Server": "Reveals web server software and version.",
        "X-Powered-By": "Reveals backend framework or language.",
        "X-AspNet-Version": "Reveals ASP.NET version.",
        "X-AspNetMvc-Version": "Reveals ASP.NET MVC version.",
        "X-Generator": "Reveals CMS or site generator.",
        "X-Drupal-Cache": "Reveals Drupal CMS usage.",
        "X-Varnish": "Reveals Varnish cache layer.",
    }

    found_any = False
    for header, msg in leakage_headers.items():
        if header in headers:
            found_any = True
            value = headers[header]
            print(f"  {severity_tag('MEDIUM')} {header}: {value}")
            print(f"       {msg}")
            result.add("Leakage", header, "WARN", "MEDIUM", f"{value} — {msg}")

    if not found_any:
        print("  [+] No common information leakage headers detected.")
