"""Reusable security guards for Python services (stdlib only; requests/httpx optional)."""
from __future__ import annotations

import hashlib
import hmac
import ipaddress
import socket
import time
from pathlib import Path
from urllib.parse import urlsplit


# --------------------------------------------------------------------------- SSRF
def _is_public(ip: str) -> bool:
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped:
        addr = addr.ipv4_mapped
    return addr.is_global and not addr.is_multicast


def assert_safe_url(raw: str, allow_hosts: list[str] | None = None) -> str:
    """Validate a user-supplied URL before any server-side request. Returns the URL or raises ValueError."""
    parts = urlsplit(raw)
    if parts.scheme not in ("http", "https"):
        raise ValueError("scheme not allowed")
    if parts.username or parts.password:
        raise ValueError("credentials in URL not allowed")
    host = parts.hostname or ""
    if allow_hosts and not any(host == h or host.endswith("." + h) for h in allow_hosts):
        raise ValueError("host not allowed")
    try:
        infos = socket.getaddrinfo(host, parts.port or (443 if parts.scheme == "https" else 80), proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise ValueError("unresolvable host") from exc
    if not infos or not all(_is_public(info[4][0]) for info in infos):
        raise ValueError("destination not allowed")
    return raw


def safe_get(raw: str, allow_hosts: list[str] | None = None, timeout: float = 5.0, max_bytes: int = 5 * 1024 * 1024):
    """requests-based GET with SSRF checks, no redirects, timeout and size cap."""
    import requests  # local import: optional dependency

    url = assert_safe_url(raw, allow_hosts)
    with requests.get(url, timeout=timeout, allow_redirects=False, stream=True) as resp:
        if 300 <= resp.status_code < 400:
            raise ValueError("redirects not allowed")
        body = resp.raw.read(max_bytes + 1, decode_content=True)
        if len(body) > max_bytes:
            raise ValueError("response too large")
        return resp.status_code, resp.headers, body


# --------------------------------------------------------------------------- Path traversal
def safe_resolve(base_dir: str | Path, user_path: str) -> Path:
    if "\x00" in user_path:
        raise ValueError("invalid path")
    base = Path(base_dir).resolve()
    target = (base / user_path).resolve()
    if target != base and base not in target.parents:
        raise ValueError("path escapes base directory")
    return target


# --------------------------------------------------------------------------- Open redirect
def safe_redirect_target(target: str | None, fallback: str = "/", allowed_origins: tuple[str, ...] = ()) -> str:
    if not target or len(target) > 2048:
        return fallback
    if target.startswith("/") and not target.startswith("//") and not target.startswith("/\\"):
        return target
    parts = urlsplit(target)
    origin = f"{parts.scheme}://{parts.netloc}"
    return target if origin in allowed_origins else fallback


# --------------------------------------------------------------------------- Webhooks
def verify_webhook(raw_body: bytes, signature: str, secret: str, timestamp: int | None = None, tolerance: int = 300) -> bool:
    if timestamp is not None and abs(time.time() - timestamp) > tolerance:
        return False
    payload = f"{timestamp}.".encode() + raw_body if timestamp is not None else raw_body
    expected = "sha256=" + hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature)
