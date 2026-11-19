"""CSRF check: flags state-changing (POST) forms that carry no CSRF token
and whose session cookie has no SameSite protection either."""
from app.scanner.core.finding import Finding

TOKEN_HINTS = ["csrf", "token", "authenticity", "_token", "nonce"]


def run(client, forms, cookies_samesite_ok):
    findings = []
    for form in forms:
        if form["method"] != "POST":
            continue
        field_names = [inp["name"].lower() for inp in form["inputs"]]
        has_token = any(any(hint in name for hint in TOKEN_HINTS) for name in field_names)
        if not has_token and not cookies_samesite_ok:
            findings.append(Finding(
                title="Cross-Site Request Forgery (CSRF)",
                severity="Medium",
                category="A01:2021 - Broken Access Control (CSRF)",
                url=form["url"],
                description=(
                    f"The state-changing form at {form['url']} has no CSRF token field, and the "
                    "session cookie does not enforce a strict SameSite policy. A malicious page "
                    "could auto-submit this form on behalf of a logged-in victim."
                ),
                evidence=f"Form fields: {', '.join(field_names) or '(none)'}",
                remediation=(
                    "Add a per-session, per-request CSRF token validated server-side on every "
                    "state-changing request (e.g. Flask-WTF's CSRFProtect). Also set the session "
                    "cookie's SameSite attribute to 'Lax' or 'Strict'."
                ),
            ))
    return findings
