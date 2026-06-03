"""AuditResult: collects findings and exports JSON/HTML reports."""

import json
from datetime import datetime, timezone

from report import generate_html_report


class AuditResult:
    def __init__(self):
        self.findings = []

    def add(self, category, check, status, severity="INFO", detail=""):
        self.findings.append({
            "category": category,
            "check": check,
            "status": status,
            "severity": severity,
            "detail": detail,
        })

    def summary(self):
        passed = sum(1 for f in self.findings if f["status"] == "PASS")
        failed = sum(1 for f in self.findings if f["status"] == "FAIL")
        warnings = sum(1 for f in self.findings if f["status"] == "WARN")
        return passed, failed, warnings

    def risk_score(self):
        severity_weights = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        return sum(
            severity_weights.get(f["severity"], 0)
            for f in self.findings if f["status"] in ("FAIL", "WARN")
        )

    def export_json(self, filepath, url):
        """Export findings as a structured JSON report."""
        passed, failed, warnings = self.summary()

        report = {
            "audit_metadata": {
                "target": url,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "tool": "SecurityAudit/2.0",
            },
            "summary": {
                "total_checks": passed + failed + warnings,
                "passed": passed,
                "failed": failed,
                "warnings": warnings,
                "risk_score": self.risk_score(),
            },
            "findings": self.findings,
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"  [✓] JSON report saved to: {filepath}")

    def export_html(self, filepath, url):
        """Export findings as a self-contained HTML report."""
        html = generate_html_report(self, url)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"  [✓] HTML report saved to: {filepath}")
