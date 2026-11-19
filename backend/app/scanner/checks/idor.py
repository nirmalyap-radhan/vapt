"""Basic Insecure Direct Object Reference (IDOR) detection."""
import re
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from app.scanner.core.finding import Finding

ID_PARAM_PATTERN = re.compile(r"^(id|user_id|uid|account|profile|order|invoice)$", re.I)


def run(client, pages):
    findings = []
    checked = set()

    for url in pages:
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        id_params = [p for p in qs if ID_PARAM_PATTERN.match(p)]
        if not id_params:
            continue

        param = id_params[0]
        try:
            original_val = int(qs[param][0])
        except (ValueError, IndexError):
            continue

        base_key = (parsed.path, param)
        if base_key in checked:
            continue
        checked.add(base_key)

        other_val = original_val + 1
        new_qs = dict(qs)
        new_qs[param] = [str(other_val)]
        new_query = urlencode({k: v[0] for k, v in new_qs.items()})
        probe_url = urlunparse(parsed._replace(query=new_query))

        try:
            original_resp = client.get(url)
            probe_resp = client.get(probe_url)
        except Exception:
            continue

        if (
            probe_resp.status_code == 200
            and original_resp.status_code == 200
            and probe_resp.text.strip() != original_resp.text.strip()
            and len(probe_resp.text) > 50
        ):
            findings.append(Finding(
                title="Insecure Direct Object Reference (IDOR)",
                severity="High",
                category="A01:2021 - Broken Access Control (IDOR)",
                url=probe_url,
                description=(
                    f"Changing '{param}' from {original_val} to {other_val} on {parsed.path} "
                    "returned different user data with no authorization check."
                ),
                evidence=f"GET {probe_url} → 200 OK with different content",
                remediation=(
                    "Verify server-side that the authenticated user is authorized to access "
                    "the specific object, or use non-guessable UUIDs with authorization checks."
                ),
            ))

    return findings

