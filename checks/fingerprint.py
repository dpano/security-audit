"""Check: Server technology fingerprinting."""

from config import print_section


def check_server_fingerprint(headers, result):
    """Attempt to fingerprint server technology from response characteristics."""
    print_section("Technology Fingerprinting")

    techs = []

    server = headers.get("Server", "")
    powered = headers.get("X-Powered-By", "")

    if server:
        techs.append(f"Server: {server}")
    if powered:
        techs.append(f"Framework: {powered}")

    header_signatures = {
        "X-Drupal-Cache": "Drupal CMS",
        "X-Generator": headers.get("X-Generator", ""),
        "X-Shopify-Stage": "Shopify",
        "X-Wix-Request-Id": "Wix",
        "CF-RAY": "Cloudflare CDN",
        "X-Vercel-Id": "Vercel",
        "X-Amz-Cf-Id": "AWS CloudFront",
        "X-Azure-Ref": "Azure CDN",
        "X-Fastly-Request-ID": "Fastly CDN",
    }

    for header, tech in header_signatures.items():
        if header in headers:
            techs.append(f"Infrastructure: {tech}")

    if techs:
        for t in techs:
            print(f"  [i] {t}")
            result.add("Fingerprint", t, "INFO")
    else:
        print("  [+] Minimal technology exposure detected.")
        result.add("Fingerprint", "Minimal exposure", "PASS")
