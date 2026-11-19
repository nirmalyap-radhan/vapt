import re
from typing import Any, Dict, List, Optional

import httpx


def _add_detection(
    detections: List[Dict[str, Any]],
    name: str,
    source: str,
    evidence: str,
    version: Optional[str] = None,
    confidence: str = "Medium",
    severity: str = "Info",
):
    detections.append(
        {
            "name": name,
            "version": version,
            "source": source,
            "evidence": evidence,
            "confidence": confidence,
            "severity": severity,
        }
    )


def scan_header_technologies(headers: dict) -> List[Dict[str, Any]]:
    detections: List[Dict[str, Any]] = []

    server = headers.get("server", "")
    powered_by = headers.get("x-powered-by", "")
    via = headers.get("via", "")
    cf_ray = headers.get("cf-ray", "")
    x_generator = headers.get("x-generator", "")

    if server:
        _add_detection(
            detections,
            "Server Header",
            "header:server",
            server,
            confidence="High",
            severity="Low",
        )

        apache_match = re.search(r"Apache/?\s*([0-9.]+)?", server, re.I)
        nginx_match = re.search(r"nginx/?\s*([0-9.]+)?", server, re.I)
        microsoft_iis_match = re.search(r"Microsoft-IIS/?\s*([0-9.]+)?", server, re.I)

        if apache_match:
            _add_detection(
                detections,
                "Apache HTTP Server",
                "header:server",
                server,
                apache_match.group(1),
                "High",
                "Low",
            )

        if nginx_match:
            _add_detection(
                detections,
                "Nginx",
                "header:server",
                server,
                nginx_match.group(1),
                "High",
                "Low",
            )

        if microsoft_iis_match:
            _add_detection(
                detections,
                "Microsoft IIS",
                "header:server",
                server,
                microsoft_iis_match.group(1),
                "High",
                "Low",
            )

    if powered_by:
        _add_detection(
            detections,
            "X-Powered-By",
            "header:x-powered-by",
            powered_by,
            confidence="High",
            severity="Medium",
        )

        php_match = re.search(r"PHP/?\s*([0-9.]+)?", powered_by, re.I)
        express_match = re.search(r"Express", powered_by, re.I)
        asp_match = re.search(r"ASP\.NET", powered_by, re.I)

        if php_match:
            _add_detection(
                detections,
                "PHP",
                "header:x-powered-by",
                powered_by,
                php_match.group(1),
                "High",
                "Medium",
            )

        if express_match:
            _add_detection(
                detections,
                "Express.js",
                "header:x-powered-by",
                powered_by,
                confidence="High",
                severity="Medium",
            )

        if asp_match:
            _add_detection(
                detections,
                "ASP.NET",
                "header:x-powered-by",
                powered_by,
                confidence="High",
                severity="Medium",
            )

    if "cloudflare" in server.lower() or cf_ray:
        _add_detection(
            detections,
            "Cloudflare",
            "headers",
            f"server={server}; cf-ray={cf_ray}",
            confidence="High",
            severity="Info",
        )

    if via:
        _add_detection(
            detections,
            "Proxy/CDN Via Header",
            "header:via",
            via,
            confidence="Medium",
            severity="Info",
        )

    if x_generator:
        _add_detection(
            detections,
            "Generator Header",
            "header:x-generator",
            x_generator,
            confidence="Medium",
            severity="Low",
        )

    return detections


def scan_html_technologies(html: str) -> List[Dict[str, Any]]:
    detections: List[Dict[str, Any]] = []

    html_lower = html.lower()

    generator_match = re.search(
        r'<meta[^>]+name=["\'"]generator["\'"][^>]+content=["\'"]([^"\']+)["\'"]',
        html,
        re.I,
    )

    if generator_match:
        generator = generator_match.group(1)

        _add_detection(
            detections,
            "Generator Meta Tag",
            "html:meta-generator",
            generator,
            confidence="High",
            severity="Low",
        )

        wordpress_match = re.search(r"WordPress\s*([0-9.]+)?", generator, re.I)

        if wordpress_match:
            _add_detection(
                detections,
                "WordPress",
                "html:meta-generator",
                generator,
                wordpress_match.group(1),
                "High",
                "Low",
            )

    if "wp-content" in html_lower or "wp-includes" in html_lower:
        _add_detection(
            detections,
            "WordPress",
            "html:fingerprint",
            "wp-content or wp-includes found in HTML",
            confidence="High",
            severity="Low",
        )

    if "__next" in html_lower or "_next/static" in html_lower:
        _add_detection(
            detections,
            "Next.js",
            "html:fingerprint",
            "__next or _next/static found in HTML",
            confidence="High",
            severity="Info",
        )

    if "data-reactroot" in html_lower or "react" in html_lower:
        _add_detection(
            detections,
            "React",
            "html:fingerprint",
            "React-related marker found in HTML",
            confidence="Medium",
            severity="Info",
        )

    if "laravel" in html_lower:
        _add_detection(
            detections,
            "Laravel",
            "html:fingerprint",
            "Laravel marker found in HTML",
            confidence="Medium",
            severity="Low",
        )

    if "django" in html_lower or "csrfmiddlewaretoken" in html_lower:
        _add_detection(
            detections,
            "Django",
            "html:fingerprint",
            "Django-related marker found in HTML",
            confidence="Medium",
            severity="Low",
        )

    if "jquery" in html_lower:
        jquery_match = re.search(r"jquery[-.]([0-9.]+)", html_lower)

        _add_detection(
            detections,
            "jQuery",
            "html:script",
            "jQuery script reference found",
            jquery_match.group(1) if jquery_match else None,
            "Medium",
            "Info",
        )

    if "bootstrap" in html_lower:
        bootstrap_match = re.search(r"bootstrap[-.]([0-9.]+)", html_lower)

        _add_detection(
            detections,
            "Bootstrap",
            "html:asset",
            "Bootstrap asset reference found",
            bootstrap_match.group(1) if bootstrap_match else None,
            "Medium",
            "Info",
        )

    return detections


def remove_duplicates(detections: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    unique = []

    for item in detections:
        key = (
            item.get("name"),
            item.get("version"),
            item.get("source"),
            item.get("evidence"),
        )

        if key not in seen:
            seen.add(key)
            unique.append(item)

    return unique


async def scan_technologies(url: str, timeout: int = 10) -> Dict[str, Any]:
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "VAPTProX-Scanner/2.0 (security-research)"},
        ) as client:
            response = await client.get(url)

    except httpx.RequestError as exc:
        raise ValueError(f"Could not connect to target URL: {exc}") from exc

    headers = {key.lower(): value for key, value in response.headers.items()}
    content_type = headers.get("content-type", "")
    html = response.text if "text/html" in content_type.lower() else ""

    detections: List[Dict[str, Any]] = []

    detections.extend(scan_header_technologies(headers))

    if html:
        detections.extend(scan_html_technologies(html))

    detections = remove_duplicates(detections)

    return {
        "target_url": url,
        "final_url": str(response.url),
        "status_code": response.status_code,
        "content_type": content_type,
        "technologies_detected": detections,
        "total_detected": len(detections),
    }
