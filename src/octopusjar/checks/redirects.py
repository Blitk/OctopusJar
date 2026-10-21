
"""Check redirect behavior and basic response inconsistencies."""

from urllib.parse import urlsplit

from .base import (
    Check, Confidence, Finding, HttpClient, Severity, finding, header_value,
)


class RedirectsCheck:
    rule_id = "OJ-REDIRECTS-001"
    name = "Redirect behavior"

    def run(self, client: HttpClient, endpoint: str) -> list[Finding]:
        response = client.get(endpoint)
        results: list[Finding] = []

        for previous in response.redirect_history:
            old = urlsplit(previous)
            new = urlsplit(response.url)

            if old.scheme == "https" and new.scheme == "http":
                results.append(finding(
                    rule_id=self.rule_id,
                    name="HTTPS to HTTP redirect",
                    description=(
                        "A redirect chain ended at an HTTP URL after starting "
                        "from HTTPS."
                    ),
                    severity=Severity.MEDIUM,
                    evidence="Redirect chain downgraded from HTTPS to HTTP",
                    endpoint=response.url,
                    recommendation=(
                        "Keep the entire redirect chain on HTTPS and configure "
                        "canonical HTTPS URLs at the application or proxy."
                    ),
                    reference="https://developer.mozilla.org/docs/Web/HTTP/Redirections",
                    confidence=Confidence.HIGH,
                    limitations=(
                        "The finding describes the observed chain only; it does "
                        "not establish whether credentials or sensitive data were sent."
                    ),
                ))
                break

            if (old.scheme, old.hostname, old.port) != (
                new.scheme, new.hostname, new.port
            ):
                results.append(finding(
                    rule_id=self.rule_id,
                    name="Cross-origin redirect",
                    description=(
                        "The redirect chain changed scheme, host or port."
                    ),
                    severity=Severity.INFO,
                    evidence="Redirect destination differs in origin",
                    endpoint=response.url,
                    recommendation=(
                        "Confirm that the cross-origin destination is an "
                        "expected part of the application's flow."
                    ),
                    reference="https://developer.mozilla.org/docs/Web/HTTP/Redirections",
                    confidence=Confidence.MEDIUM,
                    limitations=(
                        "Cross-origin redirects are common and are not inherently "
                        "vulnerable. Review the intended login and API flows."
                    ),
                ))
                break

        location = header_value(response.headers, "Location")
        if response.status_code not in {301, 302, 303, 307, 308} and location:
            results.append(finding(
                rule_id=self.rule_id,
                name="Location header on a non-redirect response",
                description=(
                    "The final response contains a Location header but does not "
                    "use a conventional redirect status."
                ),
                severity=Severity.INFO,
                evidence=(
                    f"HTTP {response.status_code}; Location header present; "
                    "value omitted"
                ),
                endpoint=response.url,
                recommendation=(
                    "Confirm whether this is intentional for the application "
                    "and whether clients interpret the header consistently."
                ),
                reference="https://developer.mozilla.org/docs/Web/HTTP/Headers/Location",
                confidence=Confidence.LOW,
                limitations=(
                    "Location can be meaningful outside redirects; its presence "
                    "alone does not prove incorrect behavior."
                ),
            ))

        return results
