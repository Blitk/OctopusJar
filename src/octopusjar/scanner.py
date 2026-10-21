
"""Orchestrate independent checks using one shared HTTP client."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from octopusjar.checks import DEFAULT_CHECKS
from octopusjar.checks.base import Check, Finding, HttpClient
from octopusjar.http_client import HttpClientError


@dataclass(slots=True)
class CheckError:
    """A sanitized record of a check that could not complete."""

    rule_id: str
    rule_name: str
    error_type: str
    message: str


@dataclass(slots=True)
class ScanReport:
    """Findings and execution errors produced by a scan."""

    target: str
    started_at: str
    finished_at: str | None = None
    findings: list[Finding] = field(default_factory=list)
    errors: list[CheckError] = field(default_factory=list)


class Scanner:
    """Run registered checks against explicit endpoints."""

    def __init__(
        self,
        client: HttpClient,
        *,
        checks: Iterable[Check] | None = None,
    ) -> None:
        self.client = client
        self.checks = tuple(
            check() for check in DEFAULT_CHECKS
        ) if checks is None else tuple(checks)

    def scan(self, target: str, endpoints: Iterable[str] | None = None) -> ScanReport:
        """Run all rules against each supplied endpoint.

        The caller must provide an explicit target. Endpoints should be
        authorized URLs accepted by the shared HTTP client's scope policy.
        """
        if not target or not target.strip():
            raise ValueError("An explicit scan target is required.")

        report = ScanReport(
            target=target,
            started_at=datetime.now(timezone.utc).isoformat(),
        )

        # A single endpoint by default. Do not crawl or discover routes implicitly.
        targets = tuple(endpoints) if endpoints is not None else (target,)
        if not targets:
            raise ValueError("At least one endpoint is required.")

        seen: set[tuple[str, str, str]] = set()

        for endpoint in targets:
            for check in self.checks:
                try:
                    results = check.run(self.client, endpoint)
                    for item in results:
                        key = (item.rule_id, item.endpoint, item.name)
                        if key not in seen:
                            seen.add(key)
                            report.findings.append(item)
                except HttpClientError as exc:
                    # Do not log request headers, response bodies or raw URLs.
                    report.errors.append(CheckError(
                        rule_id=check.rule_id,
                        rule_name=check.name,
                        error_type=type(exc).__name__,
                        message="HTTP operation failed; details intentionally omitted.",
                    ))
                except (ValueError, TypeError) as exc:
                    report.errors.append(CheckError(
                        rule_id=check.rule_id,
                        rule_name=check.name,
                        error_type=type(exc).__name__,
                        message="Invalid check input or response format.",
                    ))

        report.finished_at = datetime.now(timezone.utc).isoformat()
        return report
