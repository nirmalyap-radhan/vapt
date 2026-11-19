"""SQL Injection detection.

Two techniques, both safe (no destructive payloads):
  1. Error-based: send a payload likely to break a naive SQL string and look
     for DB error signatures in the response.
  2. Boolean-based: compare response to a "true" condition vs a "false"
     condition payload and see if the page content meaningfully differs
     (classic ' OR '1'='1 style auth bypass detection).
"""
import re
from app.scanner.core.finding import Finding

ERROR_SIGNATURES = [
    r"sql syntax", r"sqlite3\.", r"sqlite_error", r"unclosed quotation mark",
    r"quoted string not properly terminated", r"mysql_fetch", r"odbc drivers error",
    r"pg_query\(\)", r"warning: mysqli", r"syntax error.*sql",
]

ERROR_PAYLOADS = ["'", "\"", "' OR '1'='1", "1' -- ", "' ; --"]
BYPASS_PAYLOAD_USER = "admin' -- "
BYPASS_PAYLOAD_PASS = "anything"


def _looks_like_db_error(text):
    lowered = text.lower()
    return any(re.search(sig, lowered) for sig in ERROR_SIGNATURES)


def run(client, forms):
    findings = []
    tested_urls = set()

    for form in forms:
        if not form["inputs"]:
            continue

        # --- Error-based injection across every text-ish field ---
        for payload in ERROR_PAYLOADS:
            data = {inp["name"]: payload for inp in form["inputs"] if inp["type"] not in ("submit", "hidden")}
            if not data:
                continue
            try:
                if form["method"] == "POST":
                    resp = client.post(form["url"], data=data)
                else:
                    resp = client.get(form["url"], params=data)
            except Exception:
                continue

            if _looks_like_db_error(resp.text):
                key = (form["url"], "error")
                if key in tested_urls:
                    continue
                tested_urls.add(key)
                findings.append(Finding(
                    title="SQL Injection (error-based)",
                    severity="Critical",
                    category="A03:2021 - Injection",
                    url=form["url"],
                    description=(
                        f"Submitting the payload {payload!r} to the form at {form['url']} "
                        "produced a raw database error message in the response, indicating "
                        "unsanitized input is being concatenated directly into a SQL query."
                    ),
                    evidence=resp.text[:300].replace("\n", " "),
                    remediation=(
                        "Use parameterized queries / prepared statements (never string-concatenate "
                        "user input into SQL). Apply least-privilege DB accounts and disable verbose "
                        "DB error output in production."
                    ),
                ))
                break  # one error-based finding per form is enough

        # --- Boolean/auth-bypass style injection (targets login-like forms) ---
        field_names = [inp["name"] for inp in form["inputs"]]
        user_field = next((n for n in field_names if "user" in n.lower() or "email" in n.lower() or "login" in n.lower()), None)
        pass_field = next((n for n in field_names if "pass" in n.lower()), None)
        if user_field and pass_field and form["method"] == "POST":
            baseline_data = {n: "definitely_not_a_real_user_zzz" for n in field_names}
            bypass_data = dict(baseline_data)
            bypass_data[user_field] = BYPASS_PAYLOAD_USER
            bypass_data[pass_field] = BYPASS_PAYLOAD_PASS
            try:
                baseline_resp = client.post(form["url"], data=baseline_data, allow_redirects=False)
                bypass_resp = client.post(form["url"], data=bypass_data, allow_redirects=False)
            except Exception:
                baseline_resp = bypass_resp = None

            if baseline_resp is not None and bypass_resp is not None:
                baseline_is_redirect = baseline_resp.status_code in (301, 302, 303)
                bypass_is_redirect = bypass_resp.status_code in (301, 302, 303)
                # if a bogus user fails to redirect but the SQLi payload DOES redirect
                # (i.e. "logs in"), that's a very strong auth-bypass signal
                if (not baseline_is_redirect) and bypass_is_redirect:
                    findings.append(Finding(
                        title="SQL Injection — Authentication Bypass",
                        severity="Critical",
                        category="A03:2021 - Injection / A07:2021 - Auth Failures",
                        url=form["url"],
                        description=(
                            f"Submitting {user_field}={BYPASS_PAYLOAD_USER!r} to the login form "
                            "authenticated successfully without a valid password, indicating the "
                            "backend query is vulnerable to a classic SQL injection auth bypass "
                            "(e.g. `... WHERE username = '<input>' AND password = '<input>'`)."
                        ),
                        evidence=f"Bypass response status: {bypass_resp.status_code}, "
                                  f"redirected to: {bypass_resp.headers.get('Location', 'n/a')}",
                        remediation=(
                            "Use parameterized queries for all authentication logic. Never build "
                            "SQL by string formatting/concatenation of user input."
                        ),
                    ))

    return findings
