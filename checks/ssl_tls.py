"""Check: SSL/TLS certificate and protocol analysis."""

import ssl
import socket
from datetime import datetime, timezone

from config import REQUEST_TIMEOUT, print_section, severity_tag


def check_ssl_tls(hostname, result):
    """Analyze SSL/TLS certificate and protocol support."""
    print_section("SSL/TLS Analysis")

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=REQUEST_TIMEOUT) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()

                print(f"  Protocol: {protocol}")
                result.add("SSL/TLS", f"Protocol: {protocol}", "PASS")

                # Certificate expiry
                not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                not_after = not_after.replace(tzinfo=timezone.utc)
                days_remaining = (not_after - datetime.now(timezone.utc)).days
                print(f"  Certificate expires: {cert['notAfter']} ({days_remaining} days remaining)")

                if days_remaining <= 0:
                    print(f"  {severity_tag('CRITICAL')} Certificate has EXPIRED!")
                    result.add("SSL/TLS", "Certificate expired", "FAIL", "CRITICAL")
                elif days_remaining <= 30:
                    print(f"  {severity_tag('HIGH')} Certificate expires within 30 days!")
                    result.add("SSL/TLS", "Certificate expiring soon", "WARN", "HIGH",
                               f"{days_remaining} days remaining")
                else:
                    result.add("SSL/TLS", "Certificate validity", "PASS",
                               detail=f"{days_remaining} days remaining")

                # Subject and SANs
                subject = dict(x[0] for x in cert["subject"])
                print(f"  Subject: {subject.get('commonName', 'N/A')}")

                san_list = cert.get("subjectAltName", [])
                san_domains = [v for t, v in san_list if t == "DNS"]
                if san_domains:
                    print(f"  SANs: {', '.join(san_domains[:5])}")
                    if len(san_domains) > 5:
                        print(f"       ... and {len(san_domains) - 5} more")

    except ssl.SSLError as e:
        print(f"  {severity_tag('CRITICAL')} SSL Error: {e}")
        result.add("SSL/TLS", "SSL connection failed", "FAIL", "CRITICAL", str(e))
    except (socket.timeout, socket.error) as e:
        print(f"  {severity_tag('HIGH')} Connection error: {e}")
        result.add("SSL/TLS", "Connection failed", "FAIL", "HIGH", str(e))

    # Check for deprecated protocols
    deprecated_protocols = [
        (ssl.PROTOCOL_TLSv1, "TLSv1.0"),
        (ssl.PROTOCOL_TLSv1_1, "TLSv1.1"),
    ] if hasattr(ssl, "PROTOCOL_TLSv1") else []

    for proto, name in deprecated_protocols:
        try:
            ctx = ssl.SSLContext(proto)
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    print(f"  {severity_tag('HIGH')} Deprecated {name} is supported!")
                    result.add("SSL/TLS", f"{name} supported", "FAIL", "HIGH",
                               "Deprecated protocol still accepted")
        except (ssl.SSLError, OSError):
            pass  # Good — deprecated protocol rejected
