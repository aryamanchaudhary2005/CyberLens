"""Bounded public HTTP(S) client with cancellable DNS and DNS-pinned sockets."""

import asyncio
from dataclasses import dataclass, field
import ipaddress
import socket
import ssl
import threading
import time
from urllib.parse import urljoin, urlsplit

import dns.asyncresolver
import dns.exception
import dns.resolver


METADATA_HOSTS = {"metadata.google.internal", "metadata", "instance-data"}
REDIRECT_CODES = {301, 302, 303, 307, 308}
SENSITIVE_HEADERS = {"authorization", "proxy-authorization", "cookie", "x-apikey", "x-api-key", "hibp-api-key", "apikey"}


class UnsafeDestination(ValueError):
    """The requested host or redirect does not meet the public-target policy."""


class OutboundTimeout(TimeoutError):
    """The whole outbound operation exceeded its shared deadline."""


@dataclass
class SafeResponse:
    status: int
    headers: dict[str, str]
    body: bytes
    final_url: str
    redirects: list[str]
    peer_certificate: bytes | None = None
    tls_version: str | None = None
    redirect_hops: list[dict[str, object]] = field(default_factory=list)
    tls_hostname: str | None = None
    negotiated_protocol: str | None = None
    http_protocol: str = "HTTP/1.1"


async def _lookup_addresses(host: str, timeout: float) -> list[str]:
    """Resolve A and AAAA with a cancellable DNS query bounded by ``timeout``."""
    resolver = dns.asyncresolver.Resolver(configure=True)
    lookup_name = host.rstrip(".") + "."

    async def query(record_type: str) -> tuple[list[str], Exception | None]:
        try:
            answer = await resolver.resolve(lookup_name, record_type, lifetime=timeout, search=False)
            return [item.address for item in answer], None
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            return [], None
        except (dns.exception.Timeout, dns.resolver.NoNameservers, OSError) as exc:
            return [], exc

    outcomes = await asyncio.gather(query("A"), query("AAAA"))
    failures = [error for _addresses, error in outcomes if error is not None]
    if failures:
        # An incomplete A/AAAA answer cannot be considered safely public.
        raise UnsafeDestination("Hostname lookup failed") from failures[0]
    return list(dict.fromkeys(address for addresses, _error in outcomes for address in addresses))


def resolve_public_addresses(host: str, port: int, *, timeout: float = 8.0) -> list[str]:
    normalized = host.rstrip(".").lower()
    if normalized in METADATA_HOSTS or normalized.endswith(".localhost") or normalized.endswith(".local"):
        raise UnsafeDestination("Local and metadata hostnames are blocked")
    try:
        address = ipaddress.ip_address(normalized.split("%", 1)[0])
        addresses = [address.compressed]
    except ValueError:
        if timeout <= 0:
            raise OutboundTimeout("Outbound deadline expired before hostname lookup")
        try:
            ascii_host = normalized.encode("idna").decode("ascii")
            addresses = asyncio.run(asyncio.wait_for(_lookup_addresses(ascii_host, timeout), timeout=timeout))
        except asyncio.TimeoutError as exc:
            raise OutboundTimeout("Hostname lookup exceeded the outbound deadline") from exc
        except (UnicodeError, dns.exception.DNSException, OSError) as exc:
            raise UnsafeDestination("Hostname lookup failed") from exc
    if not addresses:
        raise UnsafeDestination("Hostname did not resolve")
    for value in addresses:
        address = ipaddress.ip_address(value.split("%", 1)[0])
        if address.version == 6 and address.ipv4_mapped:
            address = address.ipv4_mapped
        if not address.is_global:
            raise UnsafeDestination("Private, loopback, link-local, reserved, or non-public address blocked")
    return addresses


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise OutboundTimeout("Outbound request exceeded its total deadline")
    return remaining


def _abort_socket(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
    try:
        sock.close()
    except OSError:
        pass


def _origin(url: str) -> tuple[str, str, int | None]:
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError:
        port = None
    hostname = (parsed.hostname or "").rstrip(".").encode("idna").decode("ascii").lower()
    return scheme, hostname, port


class _SocketReader:
    """Small HTTP/1.x reader that reapplies one absolute deadline per socket read."""

    def __init__(self, sock: socket.socket | ssl.SSLSocket, deadline: float) -> None:
        self.sock = sock
        self.deadline = deadline
        self.buffer = bytearray()

    def _receive(self) -> bool:
        self.sock.settimeout(_remaining(self.deadline))
        chunk = self.sock.recv(64 * 1024)
        if not chunk:
            return False
        self.buffer.extend(chunk)
        return True

    def line(self, limit: int = 16_384) -> bytes:
        while True:
            end = self.buffer.find(b"\n")
            if end >= 0:
                if end + 1 > limit:
                    raise ValueError("Remote response header exceeded the configured limit")
                result = bytes(self.buffer[:end + 1])
                del self.buffer[:end + 1]
                return result
            if len(self.buffer) >= limit or not self._receive():
                raise ValueError("Remote response ended before its headers were complete")

    def exact(self, size: int) -> bytes:
        while len(self.buffer) < size:
            if not self._receive():
                raise ValueError("Remote response body was truncated")
        result = bytes(self.buffer[:size])
        del self.buffer[:size]
        return result

    def through_eof(self, max_bytes: int) -> bytes:
        body = bytearray()
        if self.buffer:
            body.extend(self.buffer)
            self.buffer.clear()
        while len(body) <= max_bytes:
            self.sock.settimeout(_remaining(self.deadline))
            chunk = self.sock.recv(min(64 * 1024, max_bytes + 1 - len(body)))
            if not chunk:
                return bytes(body)
            body.extend(chunk)
        return bytes(body)


def _read_response(sock: socket.socket | ssl.SSLSocket, deadline: float, max_bytes: int) -> tuple[int, dict[str, str], bytes, str]:
    reader = _SocketReader(sock, deadline)
    status_line = reader.line(8_192).decode("iso-8859-1").strip()
    pieces = status_line.split(" ", 2)
    if len(pieces) < 2 or pieces[0] not in {"HTTP/1.0", "HTTP/1.1"} or not pieces[1].isdigit():
        raise ValueError("Remote server returned a malformed HTTP status line")
    status = int(pieces[1])
    if not 100 <= status <= 599:
        raise ValueError("Remote server returned an invalid HTTP status")

    headers: dict[str, str] = {}
    total_header_bytes = len(status_line)
    while True:
        raw_line = reader.line(16_384)
        total_header_bytes += len(raw_line)
        if total_header_bytes > 64 * 1024:
            raise ValueError("Remote response headers exceeded the configured limit")
        if raw_line in {b"\r\n", b"\n"}:
            break
        line = raw_line.decode("iso-8859-1").rstrip("\r\n")
        if line[:1] in {" ", "\t"} or ":" not in line:
            raise ValueError("Remote server returned a malformed HTTP header")
        name, value = line.split(":", 1)
        key = name.strip().lower()
        if not key or any(char.isspace() for char in key):
            raise ValueError("Remote server returned a malformed HTTP header name")
        value = value.strip()
        headers[key] = f"{headers[key]}, {value}" if key in headers else value

    transfer_encoding = headers.get("transfer-encoding", "").lower()
    if transfer_encoding and transfer_encoding != "chunked":
        raise ValueError("Remote server used an unsupported transfer encoding")
    if transfer_encoding == "chunked":
        body = bytearray()
        trailer_bytes = 0
        while True:
            size_text = reader.line(8_192).split(b";", 1)[0].strip()
            try:
                chunk_size = int(size_text, 16)
            except ValueError as exc:
                raise ValueError("Remote server returned a malformed chunk size") from exc
            if chunk_size < 0 or len(body) + chunk_size > max_bytes:
                raise ValueError("Remote response exceeded the configured size limit")
            if chunk_size == 0:
                while True:
                    trailer = reader.line(16_384)
                    trailer_bytes += len(trailer)
                    if trailer_bytes > 64 * 1024:
                        raise ValueError("Remote response trailers exceeded the configured limit")
                    if trailer in {b"\r\n", b"\n"}:
                        break
                break
            body.extend(reader.exact(chunk_size))
            if reader.exact(2) != b"\r\n":
                raise ValueError("Remote server returned a malformed chunk")
        return status, headers, bytes(body), pieces[0]

    content_length = headers.get("content-length")
    if content_length is not None:
        try:
            length = int(content_length)
        except ValueError as exc:
            raise ValueError("Remote server returned an invalid content length") from exc
        if length < 0 or length > max_bytes:
            raise ValueError("Remote response exceeded the configured size limit")
        return status, headers, reader.exact(length), pieces[0]
    body = reader.through_eof(max_bytes)
    if len(body) > max_bytes:
        raise ValueError("Remote response exceeded the configured size limit")
    return status, headers, body, pieces[0]


def _single_request(url: str, *, timeout: float, max_bytes: int, verify_tls: bool,
                    headers: dict[str, str] | None = None, deadline: float | None = None,
                    method: str = "GET", body: bytes | None = None,
                    send_range_header: bool = True) -> SafeResponse:
    if method not in {"GET", "POST"} or (method == "GET" and body is not None):
        raise ValueError("Only GET or JSON POST requests are supported")
    parsed = urlsplit(url)
    scheme = parsed.scheme.lower()
    if scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise UnsafeDestination("Only credential-free HTTP(S) URLs are allowed")
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise UnsafeDestination("Invalid destination port") from exc
    if not 1 <= port <= 65535:
        raise UnsafeDestination("Invalid destination port")
    deadline = deadline if deadline is not None else time.monotonic() + timeout
    addresses = resolve_public_addresses(parsed.hostname, port, timeout=_remaining(deadline))
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    if any(ord(char) < 0x21 or ord(char) == 0x7f for char in path):
        raise UnsafeDestination("URL path or query contains unsafe control characters")
    host_header = parsed.hostname.encode("idna").decode("ascii")
    if ":" in host_header and not host_header.startswith("["):
        host_header = f"[{host_header}]"
    if (scheme == "https" and port != 443) or (scheme == "http" and port != 80):
        host_header += f":{port}"

    last_error: OSError | None = None
    transport_sock: socket.socket | ssl.SSLSocket | None = None
    for address in addresses:
        raw = None
        wrapped = None
        try:
            raw = socket.create_connection((address, port), timeout=_remaining(deadline))
            if scheme == "https":
                context = ssl.create_default_context() if verify_tls else ssl._create_unverified_context()
                context.set_alpn_protocols(["http/1.1"])
                raw.settimeout(_remaining(deadline))
                wrapped = context.wrap_socket(raw, server_hostname=parsed.hostname, do_handshake_on_connect=False)
                wrapped.settimeout(_remaining(deadline))
                handshake_timer = threading.Timer(_remaining(deadline), _abort_socket, args=(wrapped,))
                handshake_timer.daemon = True
                handshake_timer.start()
                try:
                    wrapped.do_handshake()
                finally:
                    handshake_timer.cancel()
                transport_sock = wrapped
            else:
                transport_sock = raw
            break
        except (OSError, ssl.SSLError) as exc:
            last_error = exc
            if wrapped is not None:
                wrapped.close()
            elif raw is not None:
                raw.close()
    if transport_sock is None:
        if time.monotonic() >= deadline:
            raise OutboundTimeout("Outbound connection exceeded its total deadline") from last_error
        raise last_error or OSError("Connection failed")

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        _abort_socket(transport_sock)
        raise OutboundTimeout("Outbound request exceeded its total deadline")
    deadline_fired = threading.Event()

    def abort_at_deadline() -> None:
        deadline_fired.set()
        _abort_socket(transport_sock)

    cancellation = threading.Timer(remaining, abort_at_deadline)
    cancellation.daemon = True
    cancellation.start()
    try:
        request_headers = {
            "Host": host_header,
            "user-agent": "CyberLens-Academic/0.1",
            "accept": "application/json, text/html, */*",
        }
        if method == "GET":
            if send_range_header:
                request_headers["range"] = f"bytes=0-{max_bytes - 1}"
        else:
            request_headers["content-type"] = "application/json"
            request_headers["content-length"] = str(len(body or b""))
        for key, value in (headers or {}).items():
            if key.lower() not in {"host", "connection", "range", "transfer-encoding", "content-length"}:
                if "\r" in value or "\n" in value:
                    raise ValueError("HTTP header values cannot contain line breaks")
                request_headers[key.lower()] = value
        request_headers["Connection"] = "close"
        request = f"{method} {path} HTTP/1.1\r\n" + "".join(
            f"{key}: {value}\r\n" for key, value in request_headers.items()
        ) + "\r\n"
        transport_sock.settimeout(_remaining(deadline))
        transport_sock.sendall(request.encode("iso-8859-1") + (body or b""))
        peer_certificate = transport_sock.getpeercert(binary_form=True) if scheme == "https" else None
        tls_version = transport_sock.version() if scheme == "https" else None
        negotiated_protocol = transport_sock.selected_alpn_protocol() if scheme == "https" else None
        status, response_headers, body, http_protocol = _read_response(transport_sock, deadline, max_bytes)
        return SafeResponse(
            status=status,
            headers=response_headers,
            body=body,
            final_url=url,
            redirects=[],
            peer_certificate=peer_certificate,
            tls_version=tls_version,
            tls_hostname=parsed.hostname if scheme == "https" else None,
            negotiated_protocol=negotiated_protocol,
            http_protocol=http_protocol,
        )
    except (socket.timeout, TimeoutError) as exc:
        raise OutboundTimeout("Outbound request exceeded its total deadline") from exc
    except OSError as exc:
        # On Windows a socket closed by the deadline timer can surface as
        # WinError 10038 before monotonic time advances to the exact deadline.
        if deadline_fired.is_set() or time.monotonic() >= deadline:
            raise OutboundTimeout("Outbound request exceeded its total deadline") from exc
        raise
    finally:
        cancellation.cancel()
        transport_sock.close()


def safe_get(
    url: str,
    *,
    timeout: float = 8.0,
    max_bytes: int = 1_000_000,
    max_redirects: int = 3,
    verify_tls: bool = True,
    headers: dict[str, str] | None = None,
    deadline: float | None = None,
    send_range_header: bool = True,
) -> SafeResponse:
    """Issue one bounded GET under a total deadline, rechecking every redirect."""
    if timeout <= 0 or max_bytes < 1 or max_redirects < 0:
        raise ValueError("Timeout, response size, and redirect limit must be positive")
    operation_deadline = min(deadline, time.monotonic() + timeout) if deadline is not None else time.monotonic() + timeout
    current = url
    redirects: list[str] = []
    redirect_hops: list[dict[str, object]] = []
    carries_credentials = any(key.lower() in SENSITIVE_HEADERS for key in (headers or {}))
    for step in range(max_redirects + 1):
        response = _single_request(current, timeout=_remaining(operation_deadline), max_bytes=max_bytes,
                                   verify_tls=verify_tls, headers=headers, deadline=operation_deadline,
                                   send_range_header=send_range_header)
        response.redirects = list(redirects)
        response.redirect_hops = list(redirect_hops)
        if response.status not in REDIRECT_CODES:
            return response
        location = response.headers.get("location")
        if not location or step >= max_redirects:
            raise ValueError("Redirect limit exceeded or redirect location missing")
        next_url = urljoin(current, location)
        next_parts = urlsplit(next_url)
        if next_parts.scheme.lower() not in {"http", "https"} or not next_parts.hostname:
            raise UnsafeDestination("Redirect uses a blocked protocol")
        if carries_credentials:
            if urlsplit(current).scheme.lower() == "https" and next_parts.scheme.lower() == "http":
                raise UnsafeDestination("Authenticated HTTPS request cannot downgrade to HTTP")
            if _origin(next_url) != _origin(current):
                raise UnsafeDestination("Authenticated request cannot redirect outside its provider origin")
        redirect_hops.append({"from_url": current, "status_code": response.status, "to_url": next_url})
        redirects.append(next_url)
        current = next_url
    raise ValueError("Redirect limit exceeded")


def safe_post_json(
    url: str,
    payload: dict,
    *,
    timeout: float = 8.0,
    max_bytes: int = 1_000_000,
    max_body_bytes: int = 64 * 1024,
    max_redirects: int = 0,
    verify_tls: bool = True,
    headers: dict[str, str] | None = None,
    deadline: float | None = None,
) -> SafeResponse:
    """POST one bounded JSON object through the same DNS-pinned safe client.

    POST redirects are deliberately restricted to same-origin 307/308 hops so
    the JSON body cannot be silently replayed to another provider or changed to
    an unsafe method. Each hop is resolved and validated by ``_single_request``.
    """
    import json

    if timeout <= 0 or max_bytes < 1 or max_body_bytes < 1 or max_redirects < 0:
        raise ValueError("Timeout, body/response sizes, and redirect limit must be positive")
    if not isinstance(payload, dict):
        raise ValueError("Only a JSON object may be sent by the outbound POST client")
    if any(key.lower() in {"content-type", "content-length"} for key in (headers or {})):
        raise ValueError("JSON POST content headers are controlled by the safe client")
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(body) > max_body_bytes:
        raise ValueError("JSON request exceeded the configured body size limit")
    operation_deadline = min(deadline, time.monotonic() + timeout) if deadline is not None else time.monotonic() + timeout
    current = url
    redirects: list[str] = []
    redirect_hops: list[dict[str, object]] = []
    origin = _origin(url)
    for step in range(max_redirects + 1):
        response = _single_request(current, timeout=_remaining(operation_deadline), max_bytes=max_bytes,
                                   verify_tls=verify_tls, headers={"accept": "application/json", **(headers or {})},
                                   deadline=operation_deadline, method="POST", body=body)
        response.redirects = list(redirects)
        response.redirect_hops = list(redirect_hops)
        if response.status not in REDIRECT_CODES:
            return response
        location = response.headers.get("location")
        if not location or step >= max_redirects:
            raise ValueError("Redirect limit exceeded or redirect location missing")
        if response.status not in {307, 308}:
            raise UnsafeDestination("JSON POST redirects must preserve the request method")
        next_url = urljoin(current, location)
        next_parts = urlsplit(next_url)
        if next_parts.scheme.lower() not in {"http", "https"} or not next_parts.hostname:
            raise UnsafeDestination("Redirect uses a blocked protocol")
        if next_parts.scheme.lower() == "http" and urlsplit(current).scheme.lower() == "https":
            raise UnsafeDestination("JSON POST cannot downgrade from HTTPS to HTTP")
        if _origin(next_url) != origin:
            raise UnsafeDestination("JSON POST cannot redirect outside its provider origin")
        redirect_hops.append({"from_url": current, "status_code": response.status, "to_url": next_url})
        redirects.append(next_url)
        current = next_url
    raise ValueError("Redirect limit exceeded")
