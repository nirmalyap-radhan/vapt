import asyncio
from typing import Any, Dict

from app.services.header_scanner import scan_security_headers
from app.services.cookie_scanner import scan_cookies
from app.services.ssl_scanner import scan_ssl_tls
from app.services.technology_scanner import scan_technologies
from app.services.security_score import calculate_security_score
from app.services.ai_analyst import generate_ai_analysis
from app.services.dns_scanner import analyze_dns_security
from app.services.port_scanner import scan_open_ports
from app.services.whois_scanner import run_whois


async def run_full_scan(url: str, timeout: int = 8) -> Dict[str, Any]:
    # Run all passive recon & checks concurrently for maximum performance
    headers_task = scan_security_headers(url=url, timeout=timeout)
    cookies_task = scan_cookies(url=url, timeout=timeout)
    tech_task = scan_technologies(url=url, timeout=timeout)
    ssl_task = asyncio.to_thread(scan_ssl_tls, url, timeout)
    dns_task = asyncio.to_thread(analyze_dns_security, url)
    ports_task = asyncio.to_thread(scan_open_ports, url, 1.0)
    whois_task = asyncio.to_thread(run_whois, url)

    (
        headers_result,
        cookies_result,
        technologies_result,
        ssl_result,
        dns_result,
        ports_result,
        whois_result,
    ) = await asyncio.gather(
        headers_task,
        cookies_task,
        tech_task,
        ssl_task,
        dns_task,
        ports_task,
        whois_task,
        return_exceptions=True,
    )

    # Handle any isolated failures gracefully
    if isinstance(headers_result, Exception):
        headers_result = {"findings": [], "status_code": 0, "error": str(headers_result)}
    if isinstance(cookies_result, Exception):
        cookies_result = []
    if isinstance(technologies_result, Exception):
        technologies_result = {"technologies_detected": []}
    if isinstance(ssl_result, Exception):
        ssl_result = {"https_supported": False, "grade": "F", "finding": f"SSL check error: {ssl_result}"}
    if isinstance(dns_result, Exception):
        dns_result = {"records": {}, "findings": []}
    if isinstance(ports_result, Exception):
        ports_result = {"open_ports": []}
    if isinstance(whois_result, Exception):
        whois_result = {"error": str(whois_result)}

    security_score = calculate_security_score(
        headers_result=headers_result,
        cookies_findings=cookies_result,
        ssl_result=ssl_result,
        tech_result=technologies_result,
    )

    ai_analysis = generate_ai_analysis(
        security_score=security_score,
        headers_result=headers_result,
        cookies_findings=cookies_result,
        ssl_result=ssl_result,
        tech_result=technologies_result,
        dns_result=dns_result,
        ports_result=ports_result,
    )

    return {
        "target_url": url,
        "security_score": security_score,
        "ai_analysis": ai_analysis,
        "headers": headers_result,
        "cookies": {"target_url": url, "findings": cookies_result},
        "ssl_tls": ssl_result,
        "technologies": technologies_result,
        "dns": dns_result,
        "ports": ports_result,
        "whois": whois_result,
    }
