"""One target policy shared by resolution and pinned network connections."""

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit


class TargetRejected(ValueError):
    pass


def parse_target(url):
    if not isinstance(url, str) or len(url) > 4096 or any(ord(c) < 33 for c in url) or "\\" in url:
        raise TargetRejected("Malformed or oversized target.")
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").encode("idna").decode("ascii").lower().rstrip(".")
        if (
            parsed.scheme not in ("http", "https")
            or not host
            or parsed.username is not None
            or parsed.password is not None
        ):
            raise TargetRejected("Only HTTP(S) URLs without credentials are accepted.")
        if (
            parsed.port not in (None, 80, 443)
            or "%" in host
            or host in ("localhost", "localhost.localdomain")
            or host.endswith((".local", ".localhost", ".internal", ".home", ".lan"))
            or "." not in host
            and ":" not in host
        ):
            raise TargetRejected("Target host or port is not permitted.")
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            address = None
        if address is not None and not public_address(str(address)):
            raise TargetRejected("Non-public destinations are not permitted.")
        return parsed, host
    except (ValueError, UnicodeError) as error:
        raise TargetRejected(str(error)) from None


def public_address(value):
    address = ipaddress.ip_address(value)
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        return public_address(str(address.ipv4_mapped))
    return (
        address.is_global
        and not address.is_multicast
        and not address.is_reserved
        and not address.is_unspecified
        and not address.is_loopback
        and not address.is_link_local
    )


def resolve_public(url):
    parsed, host = parse_target(url)
    addresses = socket.getaddrinfo(
        host,
        parsed.port or (443 if parsed.scheme == "https" else 80),
        type=socket.SOCK_STREAM,
    )
    ips = sorted({entry[4][0] for entry in addresses})
    if not ips or any(not public_address(ip) for ip in ips):
        raise TargetRejected("Resolution includes a non-public destination.")
    return parsed, host, ips


def redact_url(url):
    """Persist only origin. Path/query/fragment may carry passwords, tokens or IDs."""
    parsed, host = parse_target(str(url))
    authority = "[" + host + "]" if ":" in host else host
    if parsed.port and parsed.port != (443 if parsed.scheme == "https" else 80):
        authority += ":" + str(parsed.port)
    return urlunsplit((parsed.scheme, authority, "/", "", ""))
