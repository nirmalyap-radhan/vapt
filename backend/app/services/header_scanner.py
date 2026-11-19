import httpx
from app.schemas.scan import HeaderFinding, ScanResponse

SECURITY_HEADERS = {
    "strict-transport-security": {
        "severity": "High",
        "description": "HTTP Strict Transport Security forces HTTPS. Missing HSTS allows protocol downgrade attacks.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
    },
    "content-security-policy": {
        "severity": "High",
        "description": "CSP prevents XSS and content injection. Missing CSP significantly increases XSS risk.",
        "recommendation": "Add a strict Content-Security-Policy restricting script-src, style-src, img-src, etc.",
    },
    "x-frame-options": {
        "severity": "Medium",
        "description": "X-Frame-Options prevents clickjacking attacks by controlling iframe embedding.",
        "recommendation": "Set X-Frame-Options: DENY or SAMEORIGIN",
    },
    "x-content-type-options": {
        "severity": "Medium",
        "description": "Prevents MIME-sniffing attacks where browsers misinterpret content types.",
        "recommendation": "Set X-Content-Type-Options: nosniff",
    },
    "referrer-policy": {
        "severity": "Low",
        "description": "Controls how much referrer info is shared. Missing allows full URL leakage.",
        "recommendation": "Set Referrer-Policy: strict-origin-when-cross-origin",
    },
    "permissions-policy": {
        "severity": "Low",
        "description": "Permissions-Policy controls access to browser APIs (camera, mic, geolocation).",
        "recommendation": "Set Permissions-Policy to restrict unnecessary browser features.",
    },
}

DISCLOSURE_HEADERS = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version"]

async def scan_security_headers(url: str, timeout: int = 10) -> ScanResponse:
    try:
        async with httpx.AsyncClient(
            timeout=timeout,
            follow_redirects=True,
            headers={"User-Agent": "VAPTProX-Scanner/2.0 (security-research)"},
        ) as client:
            response = await client.get(url)
    except httpx.RequestError as exc:
        raise ValueError(f"Could not connect to target: {exc}") from exc

    headers = {k.lower(): v for k, v in response.headers.items()}
    findings = []

    for header_name, meta in SECURITY_HEADERS.items():
        value = headers.get(header_name)
        if value:
            findings.append(HeaderFinding(
                name=header_name, status="Present", severity="Info",
                description=f"{header_name} is configured.",
                recommendation="Verify the header value matches your security policy.",
                value=value,
            ))
        else:
            findings.append(HeaderFinding(
                name=header_name, status="Missing", severity=meta["severity"],
                description=meta["description"],
                recommendation=meta["recommendation"],
                value=None,
            ))

    for dh in DISCLOSURE_HEADERS:
        val = headers.get(dh)
        if val:
            findings.append(HeaderFinding(
                name=dh, status="Disclosure", severity="Medium",
                description=f"Header '{dh}' discloses technology information: {val}",
                recommendation=f"Remove or suppress the {dh} header to reduce fingerprinting.",
                value=val,
            ))

    cors = headers.get("access-control-allow-origin", "")
    if cors == "*":
        findings.append(HeaderFinding(
            name="access-control-allow-origin", status="Misconfigured", severity="High",
            description="CORS is set to wildcard (*), allowing any origin to make cross-origin requests.",
            recommendation="Restrict Access-Control-Allow-Origin to specific trusted origins.",
            value=cors,
        ))

    return ScanResponse(
        target_url=url,
        final_url=str(response.url),
        status_code=response.status_code,
        findings=findings,
    )
