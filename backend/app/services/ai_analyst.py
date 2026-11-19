import os
import json
import logging
from typing import Any, Dict, List, Optional
import httpx
from app.core.config import settings

logger = logging.getLogger("ai_analyst")


def _serialize_item(item: Any) -> Any:
    if hasattr(item, "model_dump"):
        return item.model_dump()
    if hasattr(item, "dict"):
        return item.dict()
    if isinstance(item, dict):
        return {k: _serialize_item(v) for k, v in item.items()}
    if isinstance(item, (list, tuple)):
        return [_serialize_item(x) for x in item]
    if isinstance(item, (str, int, float, bool)) or item is None:
        return item
    return str(item)


def generate_ai_analysis(
    security_score: Dict[str, Any],
    headers_result: Any,
    cookies_findings: List[Any],
    ssl_result: Dict[str, Any],
    tech_result: Dict[str, Any],
    dns_result: Optional[Dict[str, Any]] = None,
    ports_result: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    Intelligent LLM security analyst engine.
    Utilizes Groq (openai/gpt-oss-120b) and Gemini for natural language penetration testing analysis,
    with automatic failover to the multi-signal heuristic analyzer.
    """
    groq_key = (settings.GROQ_API_KEY or os.getenv("GROQ_API_KEY", "")).strip()
    gemini_key = (settings.GEMINI_API_KEY or os.getenv("GEMINI_API_KEY", "")).strip()

    score = security_score.get("score", 0) if isinstance(security_score, dict) else (security_score or 0)
    risk_level = security_score.get("risk_level", "Unknown") if isinstance(security_score, dict) else "Unknown"

    headers_findings = getattr(headers_result, "findings", [])
    if isinstance(headers_result, dict):
        headers_findings = headers_result.get("findings", [])

    techs = tech_result.get("technologies_detected", []) if isinstance(tech_result, dict) else []
    dns_findings = (dns_result or {}).get("findings", [])
    open_ports = (ports_result or {}).get("open_ports", [])

    # Clean serializable versions
    clean_headers = [_serialize_item(h) for h in headers_findings]
    clean_cookies = [_serialize_item(c) for c in cookies_findings]
    clean_ssl = _serialize_item(ssl_result)
    clean_techs = _serialize_item(techs)
    clean_ports = _serialize_item(open_ports)

    # Priority 1: High-speed Groq LLM (gpt-oss-120b)
    if groq_key:
        llm_res = _call_groq(groq_key, score, risk_level, clean_headers, clean_cookies, clean_ssl, clean_techs, clean_ports)
        if llm_res:
            return llm_res

    # Priority 2: Google Gemini
    if gemini_key:
        llm_res = _call_gemini(gemini_key, score, risk_level, clean_headers, clean_cookies, clean_ssl, clean_techs, clean_ports)
        if llm_res:
            return llm_res

    # Fallback: Dynamic heuristic correlation
    return _generate_contextual_analysis(score, risk_level, headers_findings, cookies_findings, ssl_result, techs, dns_findings, open_ports)


def _call_groq(
    api_key: str,
    score: int,
    risk_level: str,
    headers: list,
    cookies: list,
    ssl: dict,
    techs: list,
    ports: list,
) -> Optional[Dict[str, Any]]:
    try:
        url = "https://api.groq.com/openai/v1/chat/completions"
        prompt = f"""You are a Principal Cyber Security Penetration Tester and VAPT Analyst.
Analyze these real scan results for the target domain and output STRICTLY a valid JSON object:
- Security Score: {score}/100 ({risk_level})
- Detected Technologies: {json.dumps(techs)}
- SSL/TLS Configuration: {json.dumps(ssl)}
- Security Headers Findings: {json.dumps(headers[:12])}
- Cookie Findings: {json.dumps(cookies[:6])}
- Open Ports: {json.dumps(ports)}

Provide a deeply contextual, professional report. Return STRICTLY a JSON object with this exact structure:
{{
  "executive_summary": "In-depth executive narrative detailing specific tech stack, transport security, and exposure",
  "security_score": {score},
  "risk_level": "{risk_level}",
  "key_findings": ["specific technical finding 1", "specific technical finding 2", ...],
  "priority_recommendations": ["actionable technical remediation 1", "actionable technical remediation 2", ...],
  "business_impact": "impact on compliance, brand reputation, data confidentiality, and risk exposure"
}}
"""
        with httpx.Client(timeout=15) as client:
            resp = client.post(
                url,
                headers={"Authorization": f"Bearer {api_key}"},
                json={
                    "model": "openai/gpt-oss-120b",
                    "messages": [{"role": "user", "content": prompt}],
                    "response_format": {"type": "json_object"},
                    "temperature": 0.3,
                },
            )
            if resp.status_code == 200:
                content = resp.json()["choices"][0]["message"]["content"]
                parsed = json.loads(content)
                parsed["security_score"] = score
                parsed["risk_level"] = risk_level
                return parsed
    except Exception as e:
        logger.warning(f"Groq LLM analysis failed: {e}")
    return None


def _call_gemini(
    api_key: str,
    score: int,
    risk_level: str,
    headers: list,
    cookies: list,
    ssl: dict,
    techs: list,
    ports: list,
) -> Optional[Dict[str, Any]]:
    try:
        url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        prompt = f"""You are an expert Cyber Security Penetration Tester and VAPT Analyst.
Analyze these vulnerability scan results and produce a professional JSON object:
- Security Score: {score}/100 ({risk_level})
- Detected Technologies: {json.dumps(techs)}
- SSL/TLS: {json.dumps(ssl)}
- Headers: {json.dumps(headers[:10])}
- Open Ports: {json.dumps(ports)}

Return STRICTLY a JSON object:
{{
  "executive_summary": "Tailored executive summary referencing the specific domain and tech stack",
  "security_score": {score},
  "risk_level": "{risk_level}",
  "key_findings": ["..."],
  "priority_recommendations": ["..."],
  "business_impact": "..."
}}
"""
        with httpx.Client(timeout=15) as client:
            resp = client.post(url, json={"contents": [{"parts": [{"text": prompt}]}]})
            if resp.status_code == 200:
                text = resp.json()["candidates"][0]["content"]["parts"][0]["text"].strip()
                if "```json" in text:
                    text = text.split("```json")[1].split("```")[0].strip()
                elif "```" in text:
                    text = text.split("```")[1].split("```")[0].strip()
                parsed = json.loads(text)
                parsed["security_score"] = score
                parsed["risk_level"] = risk_level
                return parsed
    except Exception as e:
        logger.warning(f"Gemini API analysis failed: {e}")
    return None


def _generate_contextual_analysis(
    score: int,
    risk_level: str,
    headers_findings: List[Any],
    cookies_findings: List[Any],
    ssl_result: Dict[str, Any],
    techs: List[Dict[str, Any]],
    dns_findings: List[Any],
    open_ports: List[Dict[str, Any]],
) -> Dict[str, Any]:
    key_findings = []
    recommendations = []

    # SSL context
    if ssl_result.get("https_supported") or ssl_result.get("https_enabled"):
        tls_ver = ssl_result.get("tls_version", "TLS")
        issuer = ssl_result.get("issuer", "Trusted CA")
        days = ssl_result.get("days_remaining")
        key_findings.append(f"HTTPS is enabled with valid certificate from {issuer} ({tls_ver}, {days} days remaining).")
    else:
        key_findings.append("HTTPS is not properly enforced or SSL handshake failed.")
        recommendations.append("Enforce HTTPS with a valid certificate and 301 redirection.")

    # Headers context
    missing_headers = []
    present_headers = []
    for f in headers_findings:
        status = getattr(f, "status", f.get("status") if isinstance(f, dict) else "")
        name = getattr(f, "name", f.get("name") if isinstance(f, dict) else "")
        rec = getattr(f, "recommendation", f.get("recommendation") if isinstance(f, dict) else "")
        if status == "Missing":
            missing_headers.append(name)
            if rec:
                recommendations.append(rec)
        elif status == "Present":
            present_headers.append(name)

    if "content-security-policy" in missing_headers:
        key_findings.append("Missing Content-Security-Policy (CSP) exposes the application to XSS and data injection.")
    if "strict-transport-security" in missing_headers:
        key_findings.append("Missing HSTS allows protocol downgrade attacks (SSL stripping).")
    if "x-frame-options" in missing_headers:
        key_findings.append("Missing X-Frame-Options allows clickjacking attacks via iframe embedding.")

    # Technologies
    tech_names = [t.get("name") for t in techs if isinstance(t, dict) and t.get("name")]
    if tech_names:
        key_findings.append(f"Detected stack components: {', '.join(tech_names[:4])}.")

    summary = (
        f"The endpoint exhibits an overall security rating of {score}/100 ({risk_level}). "
        f"Key active controls include {', '.join(present_headers[:3]) or 'baseline networking'}. "
        f"Addressing missing headers like {', '.join(missing_headers[:3])} is recommended to strengthen posture."
    )

    return {
        "executive_summary": summary,
        "security_score": score,
        "risk_level": risk_level,
        "key_findings": list(dict.fromkeys(key_findings))[:6],
        "priority_recommendations": list(dict.fromkeys(recommendations))[:6],
        "business_impact": "Unmitigated header and transport configuration gaps can expose users to clickjacking, session theft, and XSS.",
    }
