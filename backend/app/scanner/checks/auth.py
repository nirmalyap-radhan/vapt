"""Broken/weak authentication checks (A07:2021)."""
from app.scanner.core.finding import Finding

COMMON_CREDS = [
    ("admin", "admin"), ("admin", "admin123"), ("admin", "password"),
    ("admin", "123456"), ("root", "root"), ("test", "test"),
]


def _find_login_form(forms):
    for form in forms:
        names = [inp["name"].lower() for inp in form["inputs"]]
        has_user = any("user" in n or "email" in n or "login" in n for n in names)
        has_pass = any("pass" in n for n in names)
        if has_user and has_pass and form["method"] == "POST":
            return form
    return None


def run(client, forms):
    findings = []
    login_form = _find_login_form(forms)
    if not login_form:
        return findings

    user_field = next(
        (inp["name"] for inp in login_form["inputs"]
         if "user" in inp["name"].lower() or "email" in inp["name"].lower() or "login" in inp["name"].lower()),
        None
    )
    pass_field = next(
        (inp["name"] for inp in login_form["inputs"] if "pass" in inp["name"].lower()),
        None
    )
    if not user_field or not pass_field:
        return findings

    for username, password in COMMON_CREDS:
        try:
            resp = client.post(login_form["url"], data={user_field: username, pass_field: password}, allow_redirects=False)
        except Exception:
            continue
        if resp.status_code in (301, 302, 303):
            findings.append(Finding(
                title="Default / Weak Credentials Accepted",
                severity="Critical",
                category="A07:2021 - Identification and Authentication Failures",
                url=login_form["url"],
                description=f"Login with '{username}:{password}' succeeded — common default credential accepted.",
                evidence=f"POST {user_field}={username} → {resp.status_code} redirect to {resp.headers.get('Location','?')}",
                remediation="Remove default accounts, enforce strong passwords, add rate limiting and lockout.",
            ))
            break

    attempts_blocked = False
    last_status = None
    for i in range(6):
        try:
            resp = client.post(login_form["url"], data={user_field: "probe_user_xyz", pass_field: f"wrong{i}"}, allow_redirects=False)
        except Exception:
            continue
        last_status = resp.status_code
        if resp.status_code == 429 or "lock" in resp.text.lower() or "too many" in resp.text.lower():
            attempts_blocked = True
            break

    if not attempts_blocked and last_status is not None:
        findings.append(Finding(
            title="No Account Lockout / Rate Limiting on Login",
            severity="Medium",
            category="A07:2021 - Identification and Authentication Failures",
            url=login_form["url"],
            description="Six rapid failed login attempts produced no throttling, CAPTCHA, or lockout.",
            evidence=f"6 attempts, no HTTP 429 or lockout detected (last status: {last_status}).",
            remediation="Add rate limiting, progressive lockout/backoff, and CAPTCHA after failed attempts.",
        ))

    return findings

