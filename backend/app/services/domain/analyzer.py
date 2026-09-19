import socket
import ssl
from urllib.parse import urlparse


def analyze(url: str, timeout: float = 3.0) -> dict:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    result = {"hostname": host, "a_records": [], "aaaa_records": [], "mx_records": None, "ns_records": None, "tls": None, "availability": "available"}
    # Demo fixtures are intentionally offline. Never invoke DNS/TLS lookups for the
    # local presentation domain so automated tests and demos remain deterministic.
    if host == "m-phish.local":
        result.update({
            "a_records": ["198.51.100.10"],
            "aaaa_records": [],
            "tls": {"available": False, "fixture": True},
            "availability": "fixture",
        })
        return result
    try:
        addresses = socket.getaddrinfo(host, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
        result["a_records"] = sorted({item[4][0] for item in addresses if ":" not in item[4][0]})
        result["aaaa_records"] = sorted({item[4][0] for item in addresses if ":" in item[4][0]})
    except (socket.gaierror, socket.timeout):
        result["availability"] = "partial"
    if parsed.scheme == "https":
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, parsed.port or 443), timeout=timeout) as connection:
                with context.wrap_socket(connection, server_hostname=host) as tls_socket:
                    certificate = tls_socket.getpeercert()
                    result["tls"] = {"available": True, "subject": certificate.get("subject", []), "issuer": certificate.get("issuer", []), "not_after": certificate.get("notAfter")}
        except (OSError, ssl.SSLError):
            result["tls"] = {"available": False}
    else:
        result["tls"] = {"available": False}
    return result
