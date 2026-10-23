
"""Run registered OctopusJar checks with one shared HTTP client."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Iterable

from octopusjar.checks import DEFAULT_CHECKS
from octopusjar.checks.base import Check, Finding, HttpClient, safe_endpoint
from octopusjar.http_client import HttpClientError


@dataclass(slots=True)
class CheckError:
    rule_id: str
    rule_name: str
    endpoint: str
    error_type: str
    message: str

    def to_dict(self) -> dict:
        return asdict(self)



@dataclass(slots=True)
class ScanReport:
    target: str
    started_at: str
    finished_at: str | None = None
    endpoints_scanned: list[str] = field(default_factory=list)
    checks_performed: int = 0
    findings: list[Finding] = field(default_factory=list)
    errors: list[CheckError] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "tool": "OctopusJar",
            "target": self.target,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "endpoints_scanned": self.endpoints_scanned,
            "checks_performed": self.checks_performed,
            "findings": [item.to_dict() for item in self.findings],
            "errors": [item.to_dict() for item in self.errors],
            "summary": {
                "endpoints": len(self.endpoints_scanned),
                "checks_performed": self.checks_performed,
                "findings": len(self.findings),
                "errors": len(self.errors),
            },
        }



class Scanner:
    """Orchestrate registered checks without owning HTTP transport."""

    def __init__(
        self,
        client: HttpClient,
        *,
        checks: Iterable[Check] | None = None,
    ) -> None:
        self.client = client
        self.checks = (
            tuple(check() for check in DEFAULT_CHECKS)
            if checks is None
            else tuple(checks)
        )

        rule_ids = [check.rule_id for check in self.checks]
        if len(rule_ids) != len(set(rule_ids)):
            raise ValueError("Duplicate rule IDs are not allowed.")

    def scan(
        self,
        target: str,
        endpoints: Iterable[str] | None = None,
    ) -> ScanReport:
        if not target or not target.strip():
            raise ValueError("An explicit scan target is required.")

        targets = tuple(endpoints) if endpoints is not None else (target,)
        if not targets:
            raise ValueError("At least one endpoint is required.")

        report = ScanReport(
            target=safe_endpoint(target),
            started_at=datetime.now(timezone.utc).isoformat(),
        )
        seen: set[tuple[str, str, str]] = set()

        try:
            
            for endpoint in targets:
                safe_url = safe_endpoint(endpoint)

                for check in self.checks:
                    report.checks_performed += 1
                    try:
                        results = check.run(self.client, endpoint)

                        for item in results:
                            key = (item.rule_id, item.endpoint, item.name)
                            if key not in seen:
                                seen.add(key)
                                report.findings.append(item)

                    except HttpClientError as exc:
                        report.errors.append(CheckError(
                            rule_id=check.rule_id,
                            rule_name=check.name,
                            endpoint=safe_url,
                            error_type=type(exc).__name__,
                            message=(
                                "HTTP operation failed; sensitive details "
                                "were omitted."
                            ),
                        ))
                    except Exception as exc:
                        # Keep one faulty check from suppressing the others.
                        # The exception text is deliberately not serialized.
                        report.errors.append(CheckError(
                            rule_id=check.rule_id,
                            rule_name=check.name,
                            endpoint=safe_url,
                            error_type=type(exc).__name__,
                            message="The check failed; details were omitted.",
                        ))

                # Record the endpoint even if some checks failed.
                report.endpoints_scanned.append(safe_url)
        finally:
            report.finished_at = datetime.now(timezone.utc).isoformat()

        return report
