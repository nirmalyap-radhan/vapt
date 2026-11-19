import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List
from urllib.parse import urlparse

PORTS = {
    21: ("FTP", "High", "FTP transmits credentials in plaintext. Prefer SFTP/SCP."),
    22: ("SSH", "Info", "SSH is open — ensure only key-based auth is allowed."),
    23: ("Telnet", "Critical", "Telnet transmits all data including passwords in plaintext."),
    25: ("SMTP", "Medium", "SMTP open. Verify relay restrictions to prevent spam abuse."),
    53: ("DNS", "Info", "DNS port open. Verify zone transfer is disabled."),
    80: ("HTTP", "Info", "HTTP open — ensure HTTPS redirect is in place."),
    110: ("POP3", "Medium", "POP3 without TLS exposes email credentials."),
    143: ("IMAP", "Medium", "IMAP without TLS exposes email credentials."),
    443: ("HTTPS", "Info", "HTTPS is open and expected."),
    445: ("SMB", "Critical", "SMB exposed — vulnerable to EternalBlue (CVE-2017-0144) and ransomware."),
    1433: ("MSSQL", "Critical", "MS SQL Server exposed to the internet — high risk."),
    1521: ("Oracle DB", "Critical", "Oracle DB port exposed — restrict to internal network."),
    3306: ("MySQL", "Critical", "MySQL exposed — should never be publicly accessible."),
    3389: ("RDP", "Critical", "RDP exposed — vulnerable to BlueKeep (CVE-2019-0708) and brute force."),
    5432: ("PostgreSQL", "High", "PostgreSQL exposed — restrict to application server only."),
    5900: ("VNC", "Critical", "VNC often lacks strong auth — remote desktop risk."),
    6379: ("Redis", "Critical", "Redis typically has no auth — full data access if exposed."),
    8080: ("HTTP-Alt", "Medium", "Alternate HTTP port open — may expose dev/admin interfaces."),
    8443: ("HTTPS-Alt", "Info", "Alternate HTTPS port open."),
    27017: ("MongoDB", "Critical", "MongoDB often lacks auth — full database exposure risk."),
}

def extract_hostname(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or url.replace("https://", "").replace("http://", "").split("/")[0]

def _check_port(host: str, port: int, service: str, severity: str, description: str, timeout: float = 0.8):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return {
                "port": port,
                "service": service,
                "severity": severity,
                "description": description,
                "recommendation": "Restrict access to this port using firewall rules if not required." if severity not in ("Info",) else "No action required.",
            }
    except Exception:
        return None

def scan_open_ports(url: str, timeout: float = 0.8) -> Dict[str, Any]:
    host = extract_hostname(url)
    open_ports: List[Dict[str, Any]] = []

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [
            executor.submit(_check_port, host, port, meta[0], meta[1], meta[2], timeout)
            for port, meta in PORTS.items()
        ]
        for future in as_completed(futures):
            res = future.result()
            if res:
                open_ports.append(res)

    open_ports.sort(key=lambda p: p["port"])

    risk_level = "Low"
    sevs = [p["severity"] for p in open_ports]
    if "Critical" in sevs: risk_level = "Critical"
    elif "High" in sevs: risk_level = "High"
    elif "Medium" in sevs: risk_level = "Medium"

    return {
        "target_url": url,
        "host": host,
        "total_open": len(open_ports),
        "risk_level": risk_level,
        "open_ports": open_ports,
    }
