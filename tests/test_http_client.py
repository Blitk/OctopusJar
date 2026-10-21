
from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread

import httpx
import pytest

from octopusjar.http_client import (
    ConnectionFailure,
    HttpClient,
    MalformedResponseError,
    RequestTimeoutError,
    ResponseTooLargeError,
    TargetAuthorizationError,
    USER_AGENT,
)


class LocalHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/ok")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if self.path == "/external-redirect":
            self.send_response(302)
            self.send_header("Location", "http://example.invalid/")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if self.path == "/large":
            body = b"x" * 128
        else:
            body = b'{"status":"ok"}'

        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Avoid printing request paths or query parameters during tests.
        return


@pytest.fixture
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), LocalHandler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()

    try:
        host, port = server.server_address
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def make_local_client(base_url: str, **kwargs) -> HttpClient:
    from urllib.parse import urlsplit

    parsed = urlsplit(base_url)
    host = parsed.hostname
    port = parsed.port
    return HttpClient(
        target=base_url,
        allowed_hosts=[f"{host}:{port}"],
        allow_private_targets=True,
        requests_per_second=1000,
        **kwargs,
    )


def test_get_from_authorized_local_server(local_server):
    with make_local_client(local_server) as client:
        result = client.get("/ok")

    assert result.status_code == 200
    assert result.body == b'{"status":"ok"}'
    assert result.text == '{"status":"ok"}'
    assert result.url.endswith("/ok")


def test_user_agent_is_explicit(local_server):
    with make_local_client(local_server) as client:
        assert client._client.headers["User-Agent"] == USER_AGENT


def test_redirect_is_followed_and_recorded(local_server):
    with make_local_client(local_server) as client:
        result = client.get("/redirect")

    assert result.status_code == 200
    assert len(result.redirect_history) == 1
    assert result.url.endswith("/ok")


def test_external_redirect_is_blocked(local_server):
    with make_local_client(local_server) as client:
        with pytest.raises(TargetAuthorizationError):
            client.get("/external-redirect")


def test_response_size_limit(local_server):
    with make_local_client(local_server, max_response_bytes=32) as client:
        with pytest.raises(ResponseTooLargeError):
            client.get("/large")


def test_private_target_requires_explicit_lab_authorization():
    with pytest.raises(TargetAuthorizationError):
        HttpClient(
            target="http://127.0.0.1:8080/",
            requests_per_second=1000,
        )


def test_missing_target_is_rejected():
    with pytest.raises(ValueError, match="target URL is required"):
        HttpClient(target="")


def test_invalid_scheme_is_rejected():
    with pytest.raises(TargetAuthorizationError):
        HttpClient(target="file:///etc/passwd")


def test_url_credentials_are_rejected():
    with pytest.raises(TargetAuthorizationError):
        HttpClient(target="https://user:secret@example.com/")


def test_closed_client_rejects_requests(local_server):
    client = make_local_client(local_server)
    client.close()

    with pytest.raises(Exception, match="closed"):
        client.get()


def test_timeout_is_mapped_to_safe_exception(local_server, monkeypatch):
    client = make_local_client(local_server)

    def raise_timeout(*args, **kwargs):
        raise httpx.ReadTimeout("sensitive URL or data should not be exposed")

    monkeypatch.setattr(client._client, "stream", raise_timeout)

    try:
        with pytest.raises(RequestTimeoutError) as caught:
            client.get()
        assert "sensitive URL" not in str(caught.value)
    finally:
        client.close()


def test_connection_refused_is_mapped(local_server, monkeypatch):
    client = make_local_client(local_server)

    def raise_connection_error(*args, **kwargs):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(client._client, "stream", raise_connection_error)

    try:
        with pytest.raises(ConnectionFailure):
            client.get()
    finally:
        client.close()


def test_malformed_response_is_mapped(local_server, monkeypatch):
    client = make_local_client(local_server)

    def raise_protocol_error(*args, **kwargs):
        raise httpx.RemoteProtocolError("malformed response")

    monkeypatch.setattr(client._client, "stream", raise_protocol_error)

    try:
        with pytest.raises(MalformedResponseError):
            client.get()
    finally:
        client.close()
