
"""Identify potentially revealing headers and error responses."""

import re

from .base import (
    Check, Confidence, Finding, HttpClient, Severity, finding, header_value,
)

ERROR_SIGNATURES = (
    (re.compile(r"traceback \(most recent call last\)", re.I), "Python traceback"),
    (re.compile(r"\bat [\w.$]+\([^)]*:\d+\)", re.I), "Java-like stack trace"),
    (re.compile(r"exception in thread|java\.[\w.]+exception", re.I), "Java exception"),
    (re.compile(r"stack trace|stacktrace", re.I), "Stack trace marker"),
    (re.compile(r"warning: .* on line \d+", re.I), "Runtime warning with line number"),
)


class InformationDisclosureCheck:
    rule_id = "OJ-DISCLOSURE-001"
    name = "Information disclosure"

    def run(self, client: HttpClient, endpoint: str) -> list[Finding]:
        response = client.get(endpoint)
        results: list[Finding] = []

        for header in ("Server", "X-Powered-By", "X-AspNet-Version"):
            value = header_value(response.headers, header)
            if value:
                results.append(finding(
                    rule_id=self.rule_id,
                    name=f"Technology information in {header}",
                    description=(
                        "A response header reveals a server or framework "
                        "identifier that may help fingerprint the deployment."
                    ),
                    severity=Severity.INFO,
                    evidence=f"{header}: {value[:100]}",
                    endpoint=response.url,
                    recommendation=(
                        "Remove or minimize unnecessary version details if "
                        "compatible with operational and debugging requirements."
                    ),
                    reference="https://owasp.org/www-project-web-security-testing-guide/",
                    confidence=Confidence.HIGH,
                    limitations=(
                        "Technology identification is not itself proof of a "
                        "vulnerable version or exploitable weakness."
                    ),
                ))

        if response.status_code >= 400:
            # Only inspect a bounded prefix; do not include arbitrary body text
            # in findings because it may contain PII, tokens or user data.
            body = response.body[:16_384].decode("utf-8", errors="replace")
            for pattern, label in ERROR_SIGNATURES:
                if pattern.search(body):
                    results.append(finding(
                        rule_id=self.rule_id,
                        name="Potentially verbose error response",
                        description=(
                            "An error response contains a signature commonly "
                            "associated with internal runtime diagnostics."
                        ),
                        severity=Severity.MEDIUM,
                        evidence=(
                            f"HTTP {response.status_code}; signature detected: {label}; "
                            "response content intentionally omitted"
                        ),
                        endpoint=response.url,
                        recommendation=(
                            "Return a generic client-facing error and keep "
                            "stack traces and internal diagnostics in protected logs."
                        ),
                        reference="https://cheatsheetseries.owasp.org/cheatsheets/Error_Handling_Cheat_Sheet.html",
                        confidence=Confidence.MEDIUM,
                        limitations=(
                            "Signature matching can produce false positives. "
                            "The response was not interpreted as proof of source "
                            "code disclosure or sensitive-data exposure."
                        ),
                    ))
                    break

        return results
