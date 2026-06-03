"""HTML report generation for security audit findings."""

from datetime import datetime, timezone


def generate_html_report(result, url):
    """Generate a self-contained HTML report string from an AuditResult."""
    passed, failed, warnings = result.summary()
    risk_score = result.risk_score()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # Group findings by category
    categories = {}
    for f in result.findings:
        categories.setdefault(f["category"], []).append(f)

    severity_colors = {
        "CRITICAL": "#dc2626",
        "HIGH": "#ea580c",
        "MEDIUM": "#ca8a04",
        "LOW": "#2563eb",
        "INFO": "#6b7280",
    }
    status_icons = {"PASS": "✓", "FAIL": "✗", "WARN": "⚠", "INFO": "ℹ"}

    # Build findings HTML
    findings_html = ""
    for category, items in categories.items():
        rows = ""
        for item in items:
            color = severity_colors.get(item["severity"], "#6b7280")
            icon = status_icons.get(item["status"], "?")
            status_class = item["status"].lower()
            detail_cell = (
                f'<td class="detail">{item["detail"]}</td>'
                if item["detail"]
                else '<td class="detail">—</td>'
            )
            rows += (
                f'<tr class="{status_class}">'
                f'<td class="icon">{icon}</td>'
                f'<td>{item["check"]}</td>'
                f'<td><span class="badge" style="background:{color}">{item["severity"]}</span></td>'
                f'<td class="status-{status_class}">{item["status"]}</td>'
                f'{detail_cell}'
                f'</tr>\n'
            )
        findings_html += f"""
        <div class="category">
            <h2>{category}</h2>
            <table>
                <thead><tr><th></th><th>Check</th><th>Severity</th><th>Status</th><th>Detail</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>
        """

    # Determine rating
    if risk_score == 0:
        rating, rating_class = "EXCELLENT", "excellent"
    elif risk_score <= 5:
        rating, rating_class = "GOOD", "good"
    elif risk_score <= 15:
        rating, rating_class = "FAIR", "fair"
    elif risk_score <= 30:
        rating, rating_class = "POOR", "poor"
    else:
        rating, rating_class = "CRITICAL", "critical"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Audit Report — {url}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: #f8fafc; color: #1e293b; padding: 2rem; }}
    .container {{ max-width: 1000px; margin: 0 auto; }}
    h1 {{ font-size: 1.5rem; margin-bottom: 0.25rem; }}
    .meta {{ color: #64748b; font-size: 0.875rem; margin-bottom: 1.5rem; }}
    .summary {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }}
    .card {{ background: #fff; border-radius: 8px; padding: 1.25rem; box-shadow: 0 1px 3px rgba(0,0,0,0.08); text-align: center; }}
    .card .value {{ font-size: 1.75rem; font-weight: 700; }}
    .card .label {{ font-size: 0.75rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.05em; margin-top: 0.25rem; }}
    .card.passed .value {{ color: #16a34a; }}
    .card.failed .value {{ color: #dc2626; }}
    .card.warnings .value {{ color: #ca8a04; }}
    .rating {{ font-size: 1.1rem; font-weight: 600; padding: 0.5rem 1rem; border-radius: 6px; display: inline-block; margin-bottom: 2rem; }}
    .rating.excellent {{ background: #dcfce7; color: #166534; }}
    .rating.good {{ background: #dbeafe; color: #1e40af; }}
    .rating.fair {{ background: #fef9c3; color: #854d0e; }}
    .rating.poor {{ background: #fed7aa; color: #9a3412; }}
    .rating.critical {{ background: #fecaca; color: #991b1b; }}
    .category {{ margin-bottom: 2rem; }}
    .category h2 {{ font-size: 1.1rem; margin-bottom: 0.75rem; padding-bottom: 0.5rem; border-bottom: 2px solid #e2e8f0; }}
    table {{ width: 100%; border-collapse: collapse; background: #fff; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.08); }}
    th {{ background: #f1f5f9; text-align: left; padding: 0.6rem 0.75rem; font-size: 0.75rem; text-transform: uppercase; color: #64748b; }}
    td {{ padding: 0.6rem 0.75rem; border-top: 1px solid #f1f5f9; font-size: 0.875rem; }}
    td.icon {{ width: 2rem; text-align: center; font-size: 1rem; }}
    td.detail {{ color: #64748b; font-size: 0.8rem; max-width: 250px; }}
    tr.pass td.icon {{ color: #16a34a; }}
    tr.fail td.icon {{ color: #dc2626; }}
    tr.warn td.icon {{ color: #ca8a04; }}
    .status-pass {{ color: #16a34a; font-weight: 600; }}
    .status-fail {{ color: #dc2626; font-weight: 600; }}
    .status-warn {{ color: #ca8a04; font-weight: 600; }}
    .badge {{ color: #fff; font-size: 0.7rem; padding: 0.15rem 0.5rem; border-radius: 4px; font-weight: 600; }}
    footer {{ margin-top: 3rem; text-align: center; color: #94a3b8; font-size: 0.75rem; }}
</style>
</head>
<body>
<div class="container">
    <h1>Security Vulnerability Audit</h1>
    <p class="meta">Target: <strong>{url}</strong> &mdash; {timestamp}</p>

    <div class="summary">
        <div class="card"><div class="value">{passed + failed + warnings}</div><div class="label">Total Checks</div></div>
        <div class="card passed"><div class="value">{passed}</div><div class="label">Passed</div></div>
        <div class="card failed"><div class="value">{failed}</div><div class="label">Failed</div></div>
        <div class="card warnings"><div class="value">{warnings}</div><div class="label">Warnings</div></div>
        <div class="card"><div class="value">{risk_score}</div><div class="label">Risk Score</div></div>
    </div>

    <div class="rating {rating_class}">Overall Rating: {rating}</div>

    {findings_html}

    <footer>Generated by SecurityAudit/2.0 &mdash; {timestamp}</footer>
</div>
</body>
</html>"""
