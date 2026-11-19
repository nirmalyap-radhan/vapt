import whois
from urllib.parse import urlparse


def run_whois(url: str) -> dict:
    parsed = urlparse(url)
    domain = parsed.hostname or url
    if domain.startswith("www."):
        domain = domain[4:]
    try:
        w = whois.whois(domain)
        creation = str(w.creation_date) if w.creation_date else None
        expiration = str(w.expiration_date) if w.expiration_date else None
        ns = w.name_servers if isinstance(w.name_servers, list) else ([w.name_servers] if w.name_servers else [])
        status = w.status if isinstance(w.status, list) else ([w.status] if w.status else [])
        return {
            "domain": domain,
            "registrar": str(w.registrar or ""),
            "creation_date": creation,
            "expiration_date": expiration,
            "name_servers": [str(n) for n in ns if n],
            "status": [str(s) for s in status if s],
            "org": str(w.org or ""),
            "country": str(w.country or ""),
        }
    except Exception as e:
        return {"domain": domain, "error": str(e)}

