"""Reflected Cross-Site Scripting (XSS) detection.

Sends a unique, harmless marker payload containing HTML special characters
and checks whether it comes back UNESCAPED in the response (i.e. the raw
`<script>` tag survives rather than being turned into `&lt;script&gt;`).
"""
import uuid
from app.scanner.core.finding import Finding


def _payload(marker):
    return f"<script>/*{marker}*/alert('xss')</script>"


def run(client, forms):
    findings = []
    seen_urls = set()

    for form in forms:
        text_inputs = [inp for inp in form["inputs"] if inp["type"] in ("text", "search", "textarea", "email", "")]
        if not text_inputs:
            continue

        marker = uuid.uuid4().hex[:8]
        payload = _payload(marker)
        data = {inp["name"]: payload for inp in text_inputs}
        # fill any other required-looking fields with junk so the request goes through
        for inp in form["inputs"]:
            if inp["name"] not in data:
                data[inp["name"]] = "test"

        try:
            if form["method"] == "POST":
                resp = client.post(form["url"], data=data)
            else:
                resp = client.get(form["url"], params=data)
        except Exception:
            continue

        if payload in resp.text and form["url"] not in seen_urls:
            seen_urls.add(form["url"])
            findings.append(Finding(
                title="Reflected/Stored Cross-Site Scripting (XSS)",
                severity="High",
                category="A03:2021 - Injection (XSS)",
                url=form["url"],
                description=(
                    f"A `<script>` payload submitted via the form at {form['url']} was "
                    "reflected back in the HTTP response completely unescaped, meaning "
                    "arbitrary JavaScript would execute in a victim's browser."
                ),
                evidence=f"Payload echoed verbatim: {payload}",
                remediation=(
                    "HTML-escape all user-controllable output at render time (auto-escaping "
                    "template engines like Jinja2 do this by default — remove any `|safe` / "
                    "`dangerouslySetInnerHTML` on user input). Add a Content-Security-Policy "
                    "header as defense in depth."
                ),
            ))

    return findings
