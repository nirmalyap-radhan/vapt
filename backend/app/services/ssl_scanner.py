import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

def scan_ssl_tls(url: str, timeout: int = 10) -> dict:
    parsed = urlparse(url)
    hostname = parsed.hostname
    if not hostname:
        raise ValueError("Invalid URL — hostname not found.")
    port = parsed.port or 443

    result = {
        "target_url": url, "host": hostname, "port": port,
        "https_enabled": False, "tls_version": None,
        "issuer": None, "subject": None, "not_before": None, "not_after": None,
        "days_remaining": None, "expired": None,
        "severity": "High", "finding": "SSL/TLS connection could not be verified.",
        "grade": "F", "vulnerabilities": [],
    }

    def _extract_name(name_tuple):
        return ", ".join(f"{k}={v}" for item in name_tuple for k, v in item)

    context = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                tls_version = ssock.version()

        not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        not_before = datetime.strptime(cert["notBefore"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        days_remaining = (not_after - now).days
        expired = days_remaining < 0

        severity = "Info"
        finding = "SSL/TLS certificate is valid and secure."
        grade = "A+"

        if tls_version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
            severity = "Critical"; finding = f"Weak TLS version in use: {tls_version}"; grade = "F"
        elif tls_version == "TLSv1.2":
            grade = "B"
        elif expired:
            severity = "Critical"; finding = "SSL/TLS certificate is EXPIRED."; grade = "F"
        elif days_remaining <= 7:
            severity = "High"; finding = f"Certificate expires in {days_remaining} days!"; grade = "C"
        elif days_remaining <= 30:
            severity = "Medium"; finding = f"Certificate expires in {days_remaining} days."; grade = "B"

        vulns = []
        if expired:
            vulns.append({"issue": "Expired Certificate", "severity": "Critical"})
        if tls_version in ("TLSv1", "TLSv1.1"):
            vulns.append({"issue": f"Deprecated TLS: {tls_version}", "severity": "Critical"})

        return {
            **result,
            "https_enabled": True, "tls_version": tls_version,
            "issuer": _extract_name(cert.get("issuer", [])),
            "subject": _extract_name(cert.get("subject", [])),
            "not_before": not_before.isoformat(), "not_after": not_after.isoformat(),
            "days_remaining": days_remaining, "expired": expired,
            "severity": severity, "finding": finding, "grade": grade,
            "vulnerabilities": vulns,
        }
    except ssl.SSLError as exc:
        result["finding"] = f"SSL error: {exc}"
        return result
    except socket.timeout:
        result["finding"] = "Connection timed out during SSL check."
        return result
    except Exception as exc:
        result["finding"] = f"SSL scan failed: {exc}"
        return result
