"""Canonical URL handling that preserves the submitted resource components."""

import ipaddress
import re
from urllib.parse import urlsplit


_DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])"
)


def normalize_domain_name(value: str) -> str:
    try:
        domain = value.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as exc:
        raise ValueError("Invalid IDNA hostname") from exc
    if not _DOMAIN_PATTERN.fullmatch(domain):
        raise ValueError("Invalid hostname")
    return domain


def canonicalize_http_url(value: str) -> tuple[str, str]:
    """Lowercase only scheme/host and preserve path, query, fragment, and escapes.

    Credentials, control characters, backslashes, invalid ports, and URLs over
    the persisted asset limit are rejected. The return value is the canonical
    URL and its normalized hostname.
    """
    if not isinstance(value, str):
        raise ValueError("URL must be text")
    value = value.strip()
    if not value or len(value) > 2048:
        raise ValueError("URL is empty or too long")
    if "\\" in value or any(ord(char) < 0x20 or ord(char) == 0x7f for char in value):
        raise ValueError("URL contains unsafe characters")
    try:
        parts = urlsplit(value)
        scheme = parts.scheme.lower()
        if scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("URL must use HTTP(S) and include a hostname")
        if parts.username is not None or parts.password is not None:
            raise ValueError("Credential-bearing URLs are not accepted")
        raw_host = parts.hostname
        if "%" in raw_host:
            raise ValueError("Scoped IP addresses are not accepted as URL hosts")
        try:
            address = ipaddress.ip_address(raw_host)
            hostname = address.compressed
            host_for_authority = f"[{hostname}]" if address.version == 6 else hostname
        except ValueError:
            hostname = normalize_domain_name(raw_host)
            host_for_authority = hostname
        port = parts.port
    except (UnicodeError, ValueError) as exc:
        raise ValueError("URL host, credentials, or port are invalid") from exc

    if port is not None and not 1 <= port <= 65535:
        raise ValueError("URL port is invalid")
    if port is not None and not ((scheme == "http" and port == 80) or (scheme == "https" and port == 443)):
        host_for_authority = f"{host_for_authority}:{port}"

    canonical = f"{scheme}://{host_for_authority}{parts.path or '/'}"
    before_fragment = value.split("#", 1)[0]
    if "?" in before_fragment:
        canonical += "?" + parts.query
    if "#" in value:
        canonical += "#" + parts.fragment
    if len(canonical) > 2048:
        raise ValueError("Canonical URL is too long")
    return canonical, hostname
