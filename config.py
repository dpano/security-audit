"""Global configuration and shared request utilities."""

import requests

REQUEST_TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) SecurityAudit/2.0"
REPORT_OUTPUT_DIR = None  # Set via CLI; defaults to ./reports at runtime
EXTRA_HEADERS = {}  # Additional headers injected into every request (e.g. Vercel bypass)
SESSION = None  # Authenticated requests.Session — set after form login


def build_headers(**overrides):
    """Build request headers merging User-Agent, cache-busting, extra headers, and overrides."""
    h = {
        "User-Agent": USER_AGENT,
        "Cache-Control": "no-cache, no-store, must-revalidate",
        "Pragma": "no-cache",
    }
    h.update(EXTRA_HEADERS)
    h.update(overrides)
    return h


def print_section(title):
    print(f"\n{'═' * 60}")
    print(f"  {title}")
    print(f"{'═' * 60}\n")


def severity_tag(level):
    tags = {"CRITICAL": "[!!!]", "HIGH": "[!!]", "MEDIUM": "[!]", "LOW": "[~]", "INFO": "[i]"}
    return tags.get(level, "[?]")
