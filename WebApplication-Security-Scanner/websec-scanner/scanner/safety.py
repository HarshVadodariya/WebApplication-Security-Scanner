"""Guard rails: the scanner must not become an SSRF / internal-network probe."""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse


class TargetError(ValueError):
    """Raised when a target URL is not acceptable to scan."""


def allow_private() -> bool:
    # Opt-in only, for scanning your own localhost / lab / staging hosts.
    return os.environ.get("ALLOW_PRIVATE_TARGETS") == "1"


def validate_target(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise TargetError("URL must start with http:// or https:// and include a host.")
    if parsed.username or parsed.password:
        raise TargetError("URLs with embedded credentials are not allowed.")
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    try:
        infos = socket.getaddrinfo(parsed.hostname, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise TargetError(f"Could not resolve host '{parsed.hostname}'.")
    if not allow_private():
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if not ip.is_global:
                raise TargetError(
                    "Target resolves to a private/loopback/reserved address. "
                    "Set ALLOW_PRIVATE_TARGETS=1 to scan internal hosts you own."
                )
    return url
