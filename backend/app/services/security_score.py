from typing import Any, Dict, List

SEVERITY_PENALTIES = {
    "Critical": 25,
    "High": 15,
    "Medium": 8,
    "Low": 4,
    "Info": 0,
}


def get_risk_level(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 80:
        return "Good"
    if score >= 70:
        return "Moderate"
    if score >= 50:
        return "Weak"
    return "Critical"


def calculate_header_score(headers_result: Any) -> Dict[str, Any]:
    score = 30
    findings = getattr(headers_result, "findings", [])
    penalties = []
    for finding in findings:
        status = getattr(finding, "status", finding.get("status", "") if isinstance(finding, dict) else "")
        severity = getattr(finding, "severity", finding.get("severity", "") if isinstance(finding, dict) else "")
        name = getattr(finding, "name", finding.get("name", "") if isinstance(finding, dict) else "")
        if status == "Missing":
            penalty = SEVERITY_PENALTIES.get(severity, 0)
            score -= penalty
            penalties.append({"name": name, "severity": severity, "penalty": penalty})
    return {"category": "Security Headers", "score": max(score, 0), "max_score": 30, "penalties": penalties}


def calculate_cookie_score(cookies_findings: List[Any]) -> Dict[str, Any]:
    score = 20
    penalties = []
    for finding in cookies_findings:
        status = getattr(finding, "status", finding.get("status", "") if isinstance(finding, dict) else "")
        severity = getattr(finding, "severity", finding.get("severity", "") if isinstance(finding, dict) else "")
        name = getattr(finding, "name", finding.get("name", "") if isinstance(finding, dict) else "")
        if status == "Missing":
            penalty = SEVERITY_PENALTIES.get(severity, 0)
            score -= penalty
            penalties.append({"name": name, "severity": severity, "penalty": penalty})
    return {"category": "Cookie Security", "score": max(score, 0), "max_score": 20, "penalties": penalties}


def calculate_ssl_score(ssl_result: Dict[str, Any]) -> Dict[str, Any]:
    score = 25
    penalties = []
    if not ssl_result.get("https_enabled"):
        score -= 25
        penalties.append({"name": "HTTPS Not Enabled", "severity": "Critical", "penalty": 25})
    if ssl_result.get("expired") is True:
        score -= 25
        penalties.append({"name": "Expired SSL Certificate", "severity": "Critical", "penalty": 25})
    days_remaining = ssl_result.get("days_remaining")
    if isinstance(days_remaining, int):
        if days_remaining <= 7:
            score -= 15
            penalties.append({"name": "Certificate Expires Within 7 Days", "severity": "High", "penalty": 15})
        elif days_remaining <= 30:
            score -= 8
            penalties.append({"name": "Certificate Expires Within 30 Days", "severity": "Medium", "penalty": 8})
    tls_version = ssl_result.get("tls_version")
    if tls_version in ["SSLv2", "SSLv3", "TLSv1", "TLSv1.1"]:
        score -= 20
        penalties.append({"name": f"Weak TLS: {tls_version}", "severity": "Critical", "penalty": 20})
    return {"category": "SSL/TLS", "score": max(score, 0), "max_score": 25, "penalties": penalties}


def calculate_technology_score(tech_result: Dict[str, Any]) -> Dict[str, Any]:
    score = 25
    penalties = []
    techs = tech_result.get("technologies_detected", [])
    for tech in techs:
        name = tech.get("name", "").lower()
        version = tech.get("version")
        if name in ["server header", "x-powered-by"]:
            score -= 4
            penalties.append({"name": f"Tech Disclosure: {tech.get('name')}", "severity": "Low", "penalty": 4})
        if version:
            if "php" in name and str(version).startswith(("5.", "7.0", "7.1", "7.2", "7.3", "7.4")):
                score -= 15
                penalties.append({"name": f"Outdated PHP: {version}", "severity": "High", "penalty": 15})
            if "python" in name and str(version).startswith("2."):
                score -= 15
                penalties.append({"name": f"End-of-Life Python: {version}", "severity": "High", "penalty": 15})
            if "apache" in name and str(version).startswith(("2.2", "2.0")):
                score -= 15
                penalties.append({"name": f"Outdated Apache: {version}", "severity": "High", "penalty": 15})
    return {"category": "Technology Exposure", "score": max(score, 0), "max_score": 25, "penalties": penalties}


def calculate_security_score(
    headers_result: Any,
    cookies_findings: List[Any],
    ssl_result: Dict[str, Any],
    tech_result: Dict[str, Any],
) -> Dict[str, Any]:
    categories = [
        calculate_header_score(headers_result),
        calculate_cookie_score(cookies_findings),
        calculate_ssl_score(ssl_result),
        calculate_technology_score(tech_result),
    ]
    total = sum(c["score"] for c in categories)
    max_total = sum(c["max_score"] for c in categories)
    normalized = round((total / max_total) * 100) if max_total else 0
    return {"score": normalized, "risk_level": get_risk_level(normalized), "categories": categories}

