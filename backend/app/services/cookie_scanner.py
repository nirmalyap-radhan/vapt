from typing import List
import httpx
from app.schemas.scan import HeaderFinding

async def scan_cookies(url: str, timeout: int = 10) -> List[HeaderFinding]:
    findings = []
    try:
        async with httpx.AsyncClient(
            timeout=timeout, follow_redirects=True,
            headers={"User-Agent": "VAPTProX-Scanner/2.0"},
        ) as client:
            response = await client.get(url)
    except httpx.RequestError as exc:
        raise ValueError(f"Could not connect: {exc}") from exc

    cookies = response.headers.get_list("set-cookie")
    if not cookies:
        findings.append(HeaderFinding(
            name="Set-Cookie", status="Not Found", severity="Info",
            description="No cookies were set by this target.",
            recommendation="No action required unless the application uses sessions.",
            value=None,
        ))
        return findings

    for cookie in cookies:
        cookie_lower = cookie.lower()
        name = cookie.split("=")[0].strip() if "=" in cookie else "unknown"

        if "secure" not in cookie_lower:
            findings.append(HeaderFinding(
                name=f"Cookie '{name}' - Secure Flag",
                status="Missing", severity="High",
                description=f"Cookie '{name}' is missing the Secure flag, allowing transmission over HTTP.",
                recommendation="Add the Secure flag to prevent cookie transmission over unencrypted connections.",
                value=cookie[:200],
            ))
        if "httponly" not in cookie_lower:
            findings.append(HeaderFinding(
                name=f"Cookie '{name}' - HttpOnly Flag",
                status="Missing", severity="High",
                description=f"Cookie '{name}' missing HttpOnly — JavaScript can read and exfiltrate it.",
                recommendation="Add HttpOnly to block JavaScript access to this cookie.",
                value=cookie[:200],
            ))
        if "samesite" not in cookie_lower:
            findings.append(HeaderFinding(
                name=f"Cookie '{name}' - SameSite Attribute",
                status="Missing", severity="Medium",
                description=f"Cookie '{name}' missing SameSite attribute, weakening CSRF protection.",
                recommendation="Set SameSite=Lax or SameSite=Strict.",
                value=cookie[:200],
            ))

    if not findings:
        findings.append(HeaderFinding(
            name="Cookie Security", status="Secure", severity="Info",
            description="All cookies include Secure, HttpOnly, and SameSite attributes.",
            recommendation="Continue monitoring cookie configuration.",
            value=None,
        ))
    return findings
