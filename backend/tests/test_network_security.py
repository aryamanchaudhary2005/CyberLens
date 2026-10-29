import asyncio
import socket
import threading
import time

import pytest

from app import network


@pytest.mark.parametrize("address", ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fc00::1", "fe80::1"])
def test_private_and_metadata_ip_literals_are_blocked(address):
    with pytest.raises(network.UnsafeDestination):
        network.resolve_public_addresses(address, 443)


def test_dns_result_with_private_address_is_blocked(monkeypatch):
    async def private_result(_host, _timeout):
        return ["192.168.1.5"]

    monkeypatch.setattr(network, "_lookup_addresses", private_result)
    with pytest.raises(network.UnsafeDestination, match="non-public address blocked"):
        network.resolve_public_addresses("rebind.example", 443)


def test_dns_lookup_is_cancelled_at_its_deadline(monkeypatch):
    cancelled = []

    async def slow_lookup(_host, _timeout):
        try:
            await asyncio.sleep(1)
        except asyncio.CancelledError:
            cancelled.append(True)
            raise

    monkeypatch.setattr(network, "_lookup_addresses", slow_lookup)
    started = time.monotonic()
    with pytest.raises(network.OutboundTimeout):
        network.resolve_public_addresses("slow.example", 443, timeout=0.03)
    assert time.monotonic() - started < 0.3
    assert cancelled == [True]


@pytest.mark.parametrize(("host", "expected"), [
    ("8.8.8.8", ["8.8.8.8"]),
    ("2606:4700:4700::1111", ["2606:4700:4700::1111"]),
])
def test_public_ipv4_and_ipv6_literals_are_supported(host, expected):
    assert network.resolve_public_addresses(host, 443) == expected


def test_redirect_destination_is_validated_again(monkeypatch):
    original = network._single_request

    def fake_request(url, **kwargs):
        if url == "https://public.example/":
            return network.SafeResponse(302, {"location": "http://127.0.0.1/admin"}, b"", url, [])
        return original(url, **kwargs)

    monkeypatch.setattr(network, "_single_request", fake_request)
    with pytest.raises(network.UnsafeDestination):
        network.safe_get("https://public.example/")


def test_credential_bearing_urls_are_rejected():
    with pytest.raises(network.UnsafeDestination, match="credential-free"):
        network.safe_get("https://user:password@example.com/")


def test_authenticated_https_redirect_cannot_downgrade(monkeypatch):
    def redirect(url, **_kwargs):
        return network.SafeResponse(302, {"location": "http://provider.example/path"}, b"", url, [])

    monkeypatch.setattr(network, "_single_request", redirect)
    with pytest.raises(network.UnsafeDestination, match="downgrade"):
        network.safe_get("https://provider.example/start", headers={"x-apikey": "secret"})


def test_redirect_hops_capture_status_and_target(monkeypatch):
    def redirect(url, **_kwargs):
        if url.endswith("/start"):
            return network.SafeResponse(302, {"location": "/final"}, b"", url, [])
        return network.SafeResponse(200, {}, b"ok", url, [])

    monkeypatch.setattr(network, "_single_request", redirect)
    response = network.safe_get("https://public.example/start")
    assert response.redirects == ["https://public.example/final"]
    assert response.redirect_hops == [{"from_url": "https://public.example/start", "status_code": 302,
                                      "to_url": "https://public.example/final"}]


def test_response_protocol_records_server_http_version():
    client_sock, server_sock = socket.socketpair()
    try:
        server_sock.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok")
        status, headers, body, protocol = network._read_response(client_sock, time.monotonic() + 1, 100)
        assert (status, body, protocol) == (200, b"ok", "HTTP/1.0")
        assert headers["content-length"] == "2"
    finally:
        client_sock.close()
        server_sock.close()


def test_get_without_range_header_does_not_add_body_headers(monkeypatch):
    class FakeSocket:
        def __init__(self):
            self.request = bytearray()
            self.response = bytearray(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

        def settimeout(self, _timeout):
            pass

        def sendall(self, data):
            self.request.extend(data)

        def recv(self, size):
            chunk = bytes(self.response[:size])
            del self.response[:size]
            return chunk

        def close(self):
            pass

    fake_socket = FakeSocket()
    monkeypatch.setattr(network, "resolve_public_addresses", lambda *_args, **_kwargs: ["93.184.216.34"])
    monkeypatch.setattr(network.socket, "create_connection", lambda *_args, **_kwargs: fake_socket)
    response = network.safe_get("http://public.example/range/ABCDE", max_bytes=128_000,
                                send_range_header=False, headers={"Add-Padding": "true"})
    assert response.status == 200
    headers = fake_socket.request.decode("iso-8859-1").lower()
    assert "get /range/abcde http/1.1" in headers
    assert "add-padding: true" in headers
    assert "range:" not in headers and "content-length:" not in headers and "content-type:" not in headers


def test_non_http_redirect_protocol_is_blocked(monkeypatch):
    monkeypatch.setattr(network, "_single_request", lambda url, **_kwargs: network.SafeResponse(
        302, {"location": "javascript:alert(1)"}, b"", url, []))
    with pytest.raises(network.UnsafeDestination, match="blocked protocol"):
        network.safe_get("https://public.example/start")


def test_slow_response_is_cancelled_at_overall_deadline(monkeypatch):
    client_sock, server_sock = socket.socketpair()
    server_sock.settimeout(1)
    peer_closed = threading.Event()

    def fake_connect(_address, timeout=None):
        client_sock.settimeout(timeout)
        return client_sock

    def serve():
        try:
            request = bytearray()
            while b"\r\n\r\n" not in request:
                request.extend(server_sock.recv(4096))
            server_sock.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 20\r\n\r\n")
            # A slow trickle stays within individual read timeouts but exceeds the total budget.
            for _ in range(20):
                try:
                    server_sock.sendall(b"x")
                except OSError:
                    break
                time.sleep(0.02)
        except OSError:
            pass
        finally:
            try:
                peer_closed.set() if server_sock.recv(1) == b"" else None
            except OSError:
                peer_closed.set()
            server_sock.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    monkeypatch.setattr(network, "resolve_public_addresses", lambda *_args, **_kwargs: ["93.184.216.34"])
    monkeypatch.setattr(network.socket, "create_connection", fake_connect)
    started = time.monotonic()
    with pytest.raises(network.OutboundTimeout):
        network.safe_get("http://public.example/slow", timeout=0.12, max_bytes=100)
    elapsed = time.monotonic() - started
    thread.join(timeout=1)
    assert elapsed < 0.5
    assert peer_closed.is_set()


def test_redirect_re_resolves_host_and_blocks_dns_rebinding(monkeypatch):
    resolutions = iter([["93.184.216.34"], ["10.0.0.7"]])
    connected = []

    async def changing_dns(_host, _timeout):
        return next(resolutions)

    monkeypatch.setattr(network, "_lookup_addresses", changing_dns)

    class TinyResponseServer:
        def __init__(self, response_bytes):
            self.client, self.server = socket.socketpair()
            self.response_bytes = response_bytes

        def connect(self, _address, timeout=None):
            connected.append(True)
            self.client.settimeout(timeout)
            self.server.settimeout(1)
            def respond():
                try:
                    request = bytearray()
                    while b"\r\n\r\n" not in request:
                        request.extend(self.server.recv(4096))
                    self.server.sendall(self.response_bytes)
                except OSError:
                    pass
                finally:
                    self.server.close()
            threading.Thread(target=respond, daemon=True).start()
            return self.client

    server = TinyResponseServer(b"HTTP/1.1 302 Found\r\nLocation: /next\r\nContent-Length: 0\r\n\r\n")
    monkeypatch.setattr(network.socket, "create_connection", server.connect)
    with pytest.raises(network.UnsafeDestination, match="non-public address blocked"):
        network.safe_get("http://rebind.example/start", timeout=1)
    assert len(connected) == 1


def test_safe_json_post_uses_bounded_json_body_and_preserves_request_fields(monkeypatch):
    captured = []
    monkeypatch.setattr(network, "_single_request", lambda url, **kwargs: (
        captured.append((url, kwargs)) or network.SafeResponse(200, {}, b'{"vulns":[]}', url, [])))
    result = network.safe_post_json("https://provider.example/query", {
        "package": {"ecosystem": "npm", "name": "safe-package"}, "version": "1.2.3"}, max_body_bytes=256)
    assert result.status == 200
    assert captured[0][1]["method"] == "POST"
    assert captured[0][1]["body"] == b'{"package":{"ecosystem":"npm","name":"safe-package"},"version":"1.2.3"}'
    assert captured[0][1]["headers"]["accept"] == "application/json"
    assert captured[0][1]["deadline"] is not None


def test_safe_json_post_rejects_unsafe_redirects_and_unbounded_body(monkeypatch):
    monkeypatch.setattr(network, "_single_request", lambda url, **_kwargs: network.SafeResponse(
        302, {"location": "https://other.example/collect"}, b"", url, []))
    with pytest.raises(ValueError, match="Redirect limit"):
        network.safe_post_json("https://provider.example/query", {"package": {"name": "safe"}})

    monkeypatch.setattr(network, "_single_request", lambda url, **_kwargs: network.SafeResponse(
        307, {"location": "https://other.example/collect"}, b"", url, []))
    with pytest.raises(network.UnsafeDestination, match="provider origin"):
        network.safe_post_json("https://provider.example/query", {"package": {"name": "safe"}}, max_redirects=1)

    monkeypatch.setattr(network, "_single_request", lambda *_args, **_kwargs: pytest.fail("oversize body sent"))
    with pytest.raises(ValueError, match="body size"):
        network.safe_post_json("https://provider.example/query", {"value": "x" * 300}, max_body_bytes=64)
