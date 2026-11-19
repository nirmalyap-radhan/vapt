"""Shared finding/severity model used by all checks."""

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

SEVERITY_COLORS = {
    "Critical": "#7A0C0C",
    "High": "#C0392B",
    "Medium": "#E08E0B",
    "Low": "#2E7D32",
    "Info": "#2C6FBB",
}


class Finding:
    def __init__(self, title, severity, category, url, description, evidence="", remediation=""):
        assert severity in SEVERITY_ORDER, f"Unknown severity: {severity}"
        self.title = title
        self.severity = severity
        self.category = category          # e.g. OWASP category label
        self.url = url
        self.description = description
        self.evidence = evidence
        self.remediation = remediation

    def to_dict(self):
        return {
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "url": self.url,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
        }


def sort_findings(findings):
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
