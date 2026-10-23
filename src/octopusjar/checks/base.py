
"""Shared interfaces and result models for OctopusJar checks."""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from enum import StrEnum
from typing import Protocol
from urllib.parse import urlsplit, urlunsplit


class Severity(StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Confidence(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(frozen=True, slots=True)
class Finding:
    rule_id: str
    name: str
    description: str
    severity: Severity
    evidence: str
    endpoint: str
    recommendation: str
    reference: str | None
    confidence: Confidence
    limitations: str

    def to_dict(self) -> dict:
        """Return a JSON-compatible representation."""
        result = asdict(self)
        result["severity"] = self.severity.value
        result["confidence"] = self.confidence.value
        return result


class HttpResponse(Protocol):
    url: str
    status_code: int
    headers: dict[str, str]
    body: bytes

    @property
    def text(self) -> str: ...


class HttpClient(Protocol):
    def request(
        self,
        method: str,
        url: str | None = None,
        *,
        headers: dict[str, str] | None = None,
        params: dict[str, str] | None = None,
    ) -> HttpResponse: ...


class Check(Protocol):
    """Common interface for independent security rules."""

    rule_id: str
    name: str

    def run(self, client: HttpClient, endpoint: str) -> list[Finding]:
        """Run the check and return structured findings."""
        ...


SECRET_KEY = re.compile(
    r"(authorization|cookie|set-cookie|token|secret|password|api[-_]?key)",
    re.IGNORECASE,
)

SECRET_VALUE = re.compile(
    r"\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]+"
    r"|(token|secret|password|api[_-]?key)=([^&\s]+)",
    re.IGNORECASE,
)



def sanitize_text(value: str, limit: int = 240) -> str:
    """Remove common credentials and bound evidence length."""
    value = SECRET_VALUE.sub("[REDACTED]", value)
    value = re.sub(r"[\r\n\t]+", " ", value)
    return value[:limit]


def safe_endpoint(url: str) -> str:
    """Remove userinfo, query strings and fragments from an endpoint."""
    try:
        parsed = urlsplit(url)
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        port = f":{parsed.port}" if parsed.port else ""
        return urlunsplit(
            (parsed.scheme, host + port, parsed.path or "/", "", "")
        )
    except ValueError:
        return "[invalid endpoint]"


def header_value(headers: dict[str, str], name: str) -> str | None:
    """Case-insensitive lookup that also tolerates ordinary dicts."""
    target = name.casefold()
    for key, value in headers.items():
        if key.casefold() == target:
            return value
    return None


def finding(
    *,
    rule_id: str,
    name: str,
    description: str,
    severity: Severity,
    evidence: str,
    endpoint: str,
    recommendation: str,
    reference: str | None,
    confidence: Confidence,
    limitations: str,
) -> Finding:
    """Build a finding while sanitizing evidence and endpoint values."""
    return Finding(
        rule_id=rule_id,
        name=name,
        description=description,
        severity=severity,
        evidence=sanitize_text(evidence),
        endpoint=safe_endpoint(endpoint),
        recommendation=recommendation,
        reference=reference,
        confidence=confidence,
        limitations=limitations,
    )
