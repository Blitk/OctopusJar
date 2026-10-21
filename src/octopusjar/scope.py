"""Explicit URL allowlist validation for OctopusJar."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from urllib.parse import urlsplit


class ScopeError(ValueError):
    """Raised when a URL is malformed or outside the configured allowlist."""


@dataclass(frozen=True, slots=True)
class Origin:
    """Normalized network origin: scheme, hostname, and effective port."""

    scheme: str
    hostname: str
    port: int


def _normalize_hostname(hostname: str) -> str:
    """Normalize IP literals or DNS names for exact allowlist comparison."""
    candidate = hostname.rstrip(".")
    if not candidate:
        raise ScopeError("URL must include a valid hostname.")

    try:
        return ipaddress.ip_address(candidate).compressed.lower()
    except ValueError:
        try:
            normalized = candidate.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise ScopeError("URL contains an invalid hostname.") from exc

        if len(normalized) > 253 or any(
            not label or len(label) > 63 for label in normalized.split(".")
        ):
            raise ScopeError("URL contains an invalid hostname.")
        return normalized


def parse_origin(url: str) -> Origin:
    """Parse a URL into a normalized origin, rejecting unsafe or malformed forms."""
    if not isinstance(url, str) or not url.strip():
        raise ScopeError("URL must be a non-empty string.")
    if url != url.strip() or any(ord(char) < 32 for char in url):
        raise ScopeError("URL contains surrounding whitespace or control characters.")

    try:
        parsed = urlsplit(url)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ScopeError("Only http and https URLs are supported.")
        if not parsed.netloc or parsed.hostname is None:
            raise ScopeError("URL must include a hostname.")
        if parsed.username is not None or parsed.password is not None:
            raise ScopeError("URLs containing embedded credentials are not allowed.")
        hostname = _normalize_hostname(parsed.hostname)
        port = parsed.port
    except ValueError as exc:
        if isinstance(exc, ScopeError):
            raise
        raise ScopeError("URL is malformed or contains an invalid port.") from exc

    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    if not 1 <= effective_port <= 65535:
        raise ScopeError("URL port must be between 1 and 65535.")
    return Origin(scheme=scheme, hostname=hostname, port=effective_port)


@dataclass(frozen=True, slots=True)
class Allowlist:
    """Allow only URLs whose normalized origin exactly matches an allowlist entry."""

    origins: frozenset[Origin]

    @classmethod
    def from_urls(cls, allowed_urls: list[str] | tuple[str, ...]) -> "Allowlist":
        """Build an allowlist from origin URLs; paths are rejected to avoid ambiguity."""
        if not allowed_urls:
            raise ScopeError("Allowlist must contain at least one origin.")

        origins: set[Origin] = set()
        for url in allowed_urls:
            origin = parse_origin(url)
            parsed = urlsplit(url)
            if parsed.path not in {"", "/"} or parsed.query or parsed.fragment:
                raise ScopeError(
                    f"Allowlist entry must be an origin without a path, query, or fragment: {url!r}"
                )
            origins.add(origin)
        return cls(origins=frozenset(origins))

    def permits(self, target_url: str) -> bool:
        """Return whether the target URL's exact normalized origin is allowed."""
        try:
            target = parse_origin(target_url)
        except ScopeError:
            return False
        return target in self.origins

    def require_permitted(self, target_url: str) -> None:
        """Raise ScopeError unless the target URL is within the allowlist."""
        try:
            target = parse_origin(target_url)
        except ScopeError:
            raise
        if target not in self.origins:
            raise ScopeError(
                f"Target origin {target.scheme}://{target.hostname}:{target.port} "
                "is not present in the allowlist."
            )
