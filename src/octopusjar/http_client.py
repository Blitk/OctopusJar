
"""HTTP client with explicit target authorization and bounded responses.

DNS checks reduce SSRF risk but do not pin the resolved address to the
socket connection. Use network isolation for strong protection against
DNS rebinding and other network-level attacks.
"""

from __future__ import annotations

import ipaddress
import socket
import threading
import time
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urljoin, urlsplit

import httpx


USER_AGENT = "OctopusJar/0.1.0 (+authorized REST API security analysis)"


class HttpClientError(Exception):
    """Base exception for safe, classified client failures."""


class TargetAuthorizationError(HttpClientError):
    """The URL or resolved destination is outside the authorized scope."""


class DNSResolutionError(HttpClientError):
    """The destination hostname could not be resolved."""


class ConnectionFailure(HttpClientError):
    """A connection could not be established."""


class RequestTimeoutError(HttpClientError):
    """A connection, read, write, or pool timeout occurred."""


class TLSValidationError(HttpClientError):
    """TLS certificate or handshake validation failed."""


class MalformedResponseError(HttpClientError):
    """The server returned an invalid or undecodable HTTP response."""


class ResponseTooLargeError(HttpClientError):
    """The response exceeded the configured byte limit."""


class RedirectLimitError(HttpClientError):
    """The response exceeded the configured redirect limit."""


class RateLimitConfigurationError(ValueError):
    """The configured request rate is invalid."""


@dataclass(frozen=True, slots=True)
class HttpResult:
    """A bounded HTTP response, with secrets omitted from diagnostics."""

    url: str
    status_code: int
    headers: Mapping[str, str]
    body: bytes
    redirect_history: tuple[str, ...]
    elapsed_seconds: float

    @property
    def text(self) -> str:
        """Decode the body using the declared charset, falling back to UTF-8."""
        content_type = self.headers.get("content-type", "")
        charset = "utf-8"

        for part in content_type.split(";")[1:]:
            key, separator, value = part.strip().partition("=")
            if separator and key.lower() == "charset":
                charset = value.strip("\"' ")
                break

        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


def _canonical_host(host: str) -> str:
    """Normalize an IP literal or DNS name for scope comparisons."""
    host = host.strip().rstrip(".").lower()
    if not host:
        raise TargetAuthorizationError("The URL must contain a hostname.")

    try:
        return ipaddress.ip_address(host).compressed
    except ValueError:
        try:
            return host.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise TargetAuthorizationError("Invalid hostname.") from exc


def _host_and_port(value: str) -> tuple[str, int | None]:
    """Parse a host allowlist entry; ports are optional."""
    value = value.strip()

    # URL parsing handles bracketed IPv6 and optional ports consistently.
    parsed = urlsplit("//" + value)
    if parsed.username or parsed.password or not parsed.hostname:
        raise ValueError(f"Invalid allowlist entry: {value!r}")
    if parsed.path or parsed.query or parsed.fragment:
        raise ValueError(f"Allowlist entries must contain only a host and port: {value!r}")

    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid port in allowlist entry: {value!r}") from exc

    return _canonical_host(parsed.hostname), port


class HttpClient:
    """Reusable HTTPX client with scope, SSRF, redirect and size controls.

    Args:
        target: Required initial HTTP or HTTPS URL.
        allowed_hosts: Optional additional host allowlist. Entries may be
            ``example.com`` or ``example.com:8443``. When omitted, only the
            target's original scheme, host and port are authorized.
        allow_private_targets: Explicit opt-in for private, loopback, link-local
            and other non-global IPs. For safety, the host must also appear in
            ``allowed_hosts``. Use only for a controlled laboratory.
        connect_timeout: Connection establishment timeout in seconds.
        read_timeout: Per-read timeout in seconds.
        write_timeout: Request write timeout in seconds.
        pool_timeout: Connection pool acquisition timeout in seconds.
        max_response_bytes: Maximum decoded response body size.
        max_redirects: Maximum redirects followed manually.
        requests_per_second: Maximum average request rate; use a positive value.
        verify_tls: TLS certificate validation; enabled by default.
        headers: Custom request headers. The User-Agent is set by this client.
    """

    def __init__(
        self,
        *,
        target: str,
        allowed_hosts: list[str] | tuple[str, ...] | None = None,
        allow_private_targets: bool = False,
        connect_timeout: float = 5.0,
        read_timeout: float = 10.0,
        write_timeout: float = 10.0,
        pool_timeout: float = 5.0,
        max_response_bytes: int = 2_000_000,
        max_redirects: int = 3,
        requests_per_second: float = 2.0,
        verify_tls: bool = True,
        headers: Mapping[str, str] | None = None,
    ) -> None:
        if not target:
            raise ValueError("An explicit target URL is required.")
        if min(connect_timeout, read_timeout, write_timeout, pool_timeout) <= 0:
            raise ValueError("Timeouts must be greater than zero.")
        if max_response_bytes < 1:
            raise ValueError("max_response_bytes must be at least 1.")
        if max_redirects < 0:
            raise ValueError("max_redirects cannot be negative.")
        if requests_per_second <= 0:
            raise RateLimitConfigurationError(
                "requests_per_second must be greater than zero."
            )
        if not verify_tls:
            # Keep TLS verification mandatory in this client implementation.
            raise ValueError("TLS verification cannot be disabled.")

        self._target = self._validate_url(target)
        self._target_parts = urlsplit(self._target)
        self._target_host = _canonical_host(self._target_parts.hostname or "")
        self._target_port = self._effective_port(self._target_parts)
        self._target_scheme = self._target_parts.scheme.lower()

        self._allow_private_targets = allow_private_targets
        self._allowlist: set[tuple[str, int | None]] = set()

        if allowed_hosts:
            self._allowlist = {_host_and_port(entry) for entry in allowed_hosts}

        self._max_response_bytes = max_response_bytes
        self._max_redirects = max_redirects
        self._interval = 1.0 / requests_per_second
        self._rate_lock = threading.Lock()
        self._last_request_at = 0.0
        self._closed = False

        request_headers = dict(headers or {})
        # Always identify the tool consistently. Never log these headers.
        request_headers["User-Agent"] = USER_AGENT

        timeout = httpx.Timeout(
            connect=connect_timeout,
            read=read_timeout,
            write=write_timeout,
            pool=pool_timeout,
        )
        self._client = httpx.Client(
            timeout=timeout,
            verify=True,
            follow_redirects=False,
            trust_env=False,
            headers=request_headers,
        )

    @staticmethod
    def _validate_url(url: str) -> str:
        """Validate URL syntax and allow only HTTP and HTTPS."""
        if not isinstance(url, str) or not url.strip():
            raise TargetAuthorizationError("An explicit URL is required.")

        try:
            parsed = urlsplit(url.strip())
            # Accessing .port validates malformed port values.
            _ = parsed.port
        except (ValueError, TypeError) as exc:
            raise TargetAuthorizationError("Malformed target URL.") from exc

        if parsed.scheme.lower() not in {"http", "https"}:
            raise TargetAuthorizationError("Only HTTP and HTTPS URLs are supported.")
        if not parsed.hostname:
            raise TargetAuthorizationError("The URL must contain a hostname.")
        if parsed.username is not None or parsed.password is not None:
            raise TargetAuthorizationError("Credentials in URLs are not allowed.")
        if parsed.fragment:
            # Fragments are not sent to the server; reject to avoid ambiguity.
            raise TargetAuthorizationError("URL fragments are not allowed.")

        return parsed.geturl()

    @staticmethod
    def _effective_port(parsed) -> int:
        port = parsed.port
        if port is not None:
            return port
        return 443 if parsed.scheme.lower() == "https" else 80

    def _is_host_authorized(self, host: str, port: int) -> bool:
        if not self._allowlist:
            return (
                host == self._target_host
                and port == self._target_port
            )

        return any(
            host == allowed_host and (allowed_port is None or port == allowed_port)
            for allowed_host, allowed_port in self._allowlist
        )

    def _validate_destination(self, url: str) -> str:
        """Validate URL scope and current DNS answers before each request."""
        normalized = self._validate_url(url)
        parsed = urlsplit(normalized)
        host = _canonical_host(parsed.hostname or "")
        port = self._effective_port(parsed)

        if not self._is_host_authorized(host, port):
            raise TargetAuthorizationError(
                "Destination is outside the configured host allowlist."
            )

        try:
            literal_ip = ipaddress.ip_address(host)
            addresses = {literal_ip}
        except ValueError:
            try:
                records = socket.getaddrinfo(
                    host,
                    port,
                    type=socket.SOCK_STREAM,
                )
            except socket.gaierror as exc:
                raise DNSResolutionError("Destination DNS resolution failed.") from exc
            except OSError as exc:
                raise DNSResolutionError("Destination DNS lookup failed.") from exc

            addresses = set()
            for record in records:
                sockaddr = record[4]
                try:
                    addresses.add(ipaddress.ip_address(sockaddr[0].split("%")[0]))
                except ValueError as exc:
                    raise DNSResolutionError(
                        "DNS returned an invalid IP address."
                    ) from exc

        if not addresses:
            raise DNSResolutionError("Destination has no usable IP addresses.")

        if not all(address.is_global for address in addresses):
            explicitly_allowlisted = any(
                allowed_host == host
                and (allowed_port is None or allowed_port == port)
                for allowed_host, allowed_port in self._allowlist
            )
            if not (
                self._allow_private_targets
                and explicitly_allowlisted
            ):
                raise TargetAuthorizationError(
                    "Destination resolves to a non-global IP. "
                    "Private targets require explicit lab authorization."
                )

        return normalized

    def _wait_for_rate_limit(self) -> None:
        """Serialize request starts to enforce the configured rate."""
        with self._rate_lock:
            now = time.monotonic()
            delay = self._interval - (now - self._last_request_at)
            if delay > 0:
                time.sleep(delay)
            self._last_request_at = time.monotonic()

    def request(
        self,
        method: str,
        url: str | None = None,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> HttpResult:
        """Send a bounded request to the target or an authorized URL.

        Redirects are handled manually so every destination is revalidated.
        Request bodies are intentionally not exposed by this initial client.
        """
        if self._closed:
            raise HttpClientError("HTTP client is closed.")

        candidate_url = urljoin(self._target, url) if url else self._target
        current_url = self._validate_destination(candidate_url)
        method = method.upper().strip()
        if not method or any(char.isspace() for char in method):
            raise ValueError("Invalid HTTP method.")

        start = time.monotonic()
        history: list[str] = []

        for redirect_number in range(self._max_redirects + 1):
            self._wait_for_rate_limit()

            try:
                with self._client.stream(
                    method,
                    current_url,
                    headers=dict(headers or {}),
                    params=params if redirect_number == 0 else None,
                ) as response:
                    status = response.status_code
                    response_headers = dict(response.headers)

                    if status in {301, 302, 303, 307, 308}:
                        location = response.headers.get("location")
                        if not location:
                            raise MalformedResponseError(
                                "Redirect response is missing Location."
                            )
                        if redirect_number >= self._max_redirects:
                            raise RedirectLimitError(
                                "Maximum redirect count exceeded."
                            )

                        next_url = urljoin(current_url, location)
                        next_url = self._validate_destination(next_url)
                        history.append(current_url)

                        # Browser-like redirect semantics for GET/HEAD only.
                        if status == 303 or (
                            status in {301, 302} and method not in {"GET", "HEAD"}
                        ):
                            method = "GET"
                        current_url = next_url
                        continue

                    body = bytearray()
                    for chunk in response.iter_bytes():
                        if len(body) + len(chunk) > self._max_response_bytes:
                            raise ResponseTooLargeError(
                                "Response exceeded max_response_bytes."
                            )
                        body.extend(chunk)

                    return HttpResult(
                        url=current_url,
                        status_code=status,
                        headers=response_headers,
                        body=bytes(body),
                        redirect_history=tuple(history),
                        elapsed_seconds=time.monotonic() - start,
                    )

            except httpx.TimeoutException as exc:
                raise RequestTimeoutError(
                    "HTTP request timed out."
                ) from exc
            except httpx.ConnectError as exc:
                cause_text = repr(exc.__cause__).lower()
                if "certificate" in cause_text or "ssl" in cause_text:
                    raise TLSValidationError(
                        "TLS validation or handshake failed."
                    ) from exc
                if "refused" in str(exc).lower() or "refused" in cause_text:
                    raise ConnectionFailure("Connection was refused.") from exc
                if "getaddrinfo" in cause_text or "name or service not known" in cause_text:
                    raise DNSResolutionError("DNS resolution failed.") from exc
                raise ConnectionFailure("Could not connect to destination.") from exc
            except httpx.TransportError as exc:
                # Includes protocol failures and malformed HTTP responses.
                if isinstance(exc, (httpx.RemoteProtocolError, httpx.DecodingError)):
                    raise MalformedResponseError(
                        "Server returned a malformed HTTP response."
                    ) from exc
                raise ConnectionFailure("HTTP transport failed.") from exc

        raise RedirectLimitError("Maximum redirect count exceeded.")

    def get(
        self,
        url: str | None = None,
        *,
        headers: Mapping[str, str] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> HttpResult:
        """Convenience method for GET requests."""
        return self.request("GET", url, headers=headers, params=params)

    def close(self) -> None:
        """Close the underlying HTTPX client and release its connections."""
        if not self._closed:
            self._client.close()
            self._closed = True

    def __enter__(self) -> "HttpClient":
        if self._closed:
            raise HttpClientError("HTTP client is closed.")
        return self

    def __exit__(self, exc_type, exc, traceback) -> None:
        self.close()
