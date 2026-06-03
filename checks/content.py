"""Check: Response body content analysis."""

import re

from config import print_section, severity_tag


def check_content_analysis(response, result):
    """Analyze response body for security-relevant patterns."""
    print_section("Content Analysis")

    body = response.text[:50000]

    patterns = {
        "Email addresses": (r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", "LOW"),
        "Potential API keys": (r"(?:api[_-]?key|apikey|api_secret)\s*[:=]\s*['\"]?[\w-]{20,}", "HIGH"),
        "Inline JavaScript event handlers": (r"on(?:click|load|error|mouseover)\s*=", "LOW"),
        "HTML comments": (r"<!--[\s\S]*?-->", "LOW"),
        "Source map references": (r"//[#@]\s*sourceMappingURL\s*=", "MEDIUM"),
        "Debug/development indicators": (r"(?:DEBUG|DEVELOPMENT|TODO|FIXME|HACK)\s*[:=]", "MEDIUM"),
    }

    found_any = False
    for name, (pattern, severity) in patterns.items():
        matches = re.findall(pattern, body, re.IGNORECASE)
        if matches:
            found_any = True
            count = len(matches)
            print(f"  {severity_tag(severity)} {name}: {count} occurrence(s) found")
            if name == "HTML comments" and count <= 3:
                for m in matches[:3]:
                    snippet = m[:80].replace("\n", " ")
                    print(f"       \"{snippet}...\"")
            result.add("Content", name, "WARN", severity, f"{count} occurrences")

    if not found_any:
        print("  [+] No concerning patterns detected in response body.")
