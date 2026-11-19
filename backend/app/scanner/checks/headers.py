"""Security header / misconfiguration checks (A05:2021)."""
from app.scanner.core.finding import Finding

REQUIRED_HEADERS = {
    "Content-Security-Policy": ("Medium", "Mitigates XSS and data-injection attacks."),
    "X-Frame-Options": ("Medium", "Prevents clickjacking attacks."),
    "X-Content-Type-Options": ("Low", "Prevents MIME-sniffing attacks."),
    "Strict-Transport-Security": ("Low", "Forces HTTPS, prevents SSL-stripping."),
    "Referrer-Policy": ("Low", "Controls referrer info leakage."),
}


def check_headers(url, resp):
    findings = []
    for header, (severity, purpose) in REQUIRED_HEADERS.items():
        if header not in resp.headers:
            findings.append(Finding(
                title=f"Missing Security Header: {header}",
                severity=severity,
                category="A05:2021 - Security Misconfiguration",
                url=url,
                description=f"The response does not set '{header}'. {purpose}",
                evidence=f"Response headers: {', '.join(resp.headers.keys())}",
                remediation=f"Set the '{header}' header globally via middleware or reverse proxy.",
            ))

    server = resp.headers.get("Server", "")
    if server:
        findings.append(Finding(
            title="Server Banner Discloses Software Version",
            severity="Low",
            category="A05:2021 - Security Misconfiguration",
            url=url,
            description=f"'Server' header reveals: '{server}'. Aids attacker fingerprinting.",
            evidence=f"Server: {server}",
            remediation="Suppress or generalize the Server header at the web server/proxy level.",
        ))

    set_cookie = resp.headers.get("Set-Cookie", "")
    if set_cookie:
        if "secure" not in set_cookie.lower():
            findings.append(Finding(
                title="Session Cookie Missing 'Secure' Flag",
                severity="Medium",
                category="A05:2021 - Security Misconfiguration",
                url=url,
                description="Cookie set without Secure flag — can be sent over plain HTTP.",
                evidence=set_cookie[:150],
                remediation="Add Secure flag to all session cookies and serve exclusively over HTTPS.",
            ))
        if "httponly" not in set_cookie.lower():
            findings.append(Finding(
                title="Session Cookie Missing 'HttpOnly' Flag",
                severity="High",
                category="A05:2021 - Security Misconfiguration",
                url=url,
                description="Cookie without HttpOnly — JavaScript (including XSS payloads) can read it.",
                evidence=set_cookie[:150],
                remediation="Add HttpOnly flag to all session cookies.",
            ))
        if "samesite" not in set_cookie.lower():
            findings.append(Finding(
                title="Session Cookie Missing 'SameSite' Attribute",
                severity="Low",
                category="A05:2021 - Security Misconfiguration",
                url=url,
                description="Cookie without SameSite attribute weakens CSRF protection.",
                evidence=set_cookie[:150],
                remediation="Set SameSite=Lax or SameSite=Strict on session cookies.",
            ))
    return findings


def check_debug_and_errors(url, resp):
    findings = []
    lowered = resp.text.lower()
    markers = ["werkzeug", "traceback (most recent call last)", "debugger pin", "django version", "stack trace"]
    if any(m in lowered for m in markers):
        findings.append(Finding(
            title="Debug Mode / Verbose Error Page Exposed",
            severity="High",
            category="A05:2021 - Security Misconfiguration",
            url=url,
            description="A verbose debug/error page was detected, potentially leaking source code and env vars.",
            evidence=resp.text[:200].replace("\n", " "),
            remediation="Disable debug mode in production and show generic error pages.",
        ))
    return findings

