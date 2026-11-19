from typing import Any, Dict, List, Optional
from urllib.parse import urlparse
import dns.resolver

def extract_domain(url: str) -> str:
    parsed = urlparse(url)
    hostname = parsed.hostname or url
    return hostname[4:] if hostname.startswith("www.") else hostname

def query_records(domain: str, record_type: str) -> List[str]:
    try:
        return [a.to_text() for a in dns.resolver.resolve(domain, record_type)]
    except Exception:
        return []

def find_spf(txt_records: List[str]) -> Optional[str]:
    for r in txt_records:
        clean = r.replace('"', '')
        if clean.lower().startswith("v=spf1"):
            return clean
    return None

def find_dmarc(domain: str) -> Optional[str]:
    for r in query_records(f"_dmarc.{domain}", "TXT"):
        clean = r.replace('"', '')
        if clean.lower().startswith("v=dmarc1"):
            return clean
    return None

def analyze_dns_security(url: str) -> Dict[str, Any]:
    domain = extract_domain(url)
    a_records = query_records(domain, "A")
    aaaa_records = query_records(domain, "AAAA")
    mx_records = query_records(domain, "MX")
    ns_records = query_records(domain, "NS")
    txt_records = query_records(domain, "TXT")
    spf = find_spf(txt_records)
    dmarc = find_dmarc(domain)
    findings = []

    if not mx_records:
        findings.append({"name": "MX Records Missing", "severity": "Medium", "status": "Missing",
            "description": "No MX records detected.", "recommendation": "Configure MX records if the domain sends email."})
    if not spf:
        findings.append({"name": "SPF Record Missing", "severity": "High", "status": "Missing",
            "description": "No SPF record — domain is vulnerable to email spoofing.",
            "recommendation": "Add a TXT record starting with v=spf1 to authorize mail servers."})
    if not dmarc:
        findings.append({"name": "DMARC Record Missing", "severity": "High", "status": "Missing",
            "description": "No DMARC record — no policy to handle unauthenticated mail.",
            "recommendation": "Add a TXT record at _dmarc.yourdomain.com with v=DMARC1 policy."})

    risk_level = "Low"
    if not spf and not dmarc:
        risk_level = "High"
    elif not spf or not dmarc:
        risk_level = "Medium"

    return {
        "target_url": url, "domain": domain,
        "a_records": a_records, "aaaa_records": aaaa_records,
        "mx_records": mx_records, "ns_records": ns_records, "txt_records": txt_records,
        "spf_record": spf, "dmarc_record": dmarc,
        "risk_level": risk_level, "findings": findings,
    }
