
"""Observe advertised HTTP methods without attempting exploitation."""

from .base import (
    Check, Confidence, Finding, HttpClient, Severity, finding, header_value,
)


class HttpMethodsCheck:
    rule_id = "OJ-METHODS-001"
    name = "HTTP methods"

    def run(self, client: HttpClient, endpoint: str) -> list[Finding]:
        response = client.request("OPTIONS", endpoint)
        allow = header_value(response.headers, "Allow") or ""
        cors_methods = (
            header_value(response.headers, "Access-Control-Allow-Methods") or ""
        )
        advertised = {
            method.strip().upper()
            for method in (allow + "," + cors_methods).split(",")
            if method.strip()
        }

        results: list[Finding] = []
        if not advertised:
            return results

        unusual = sorted(advertised & {"TRACE", "CONNECT"})
        if unusual:
            results.append(finding(
                rule_id=self.rule_id,
                name="Potentially sensitive HTTP methods advertised",
                description=(
                    "The response advertises methods that merit configuration "
                    "review. Their presence does not establish that they are "
                    "accepted on the endpoint or exploitable."
                ),
                severity=Severity.LOW,
                evidence="Advertised methods: " + ", ".join(unusual),
                endpoint=response.url,
                recommendation=(
                    "Disable unnecessary methods at the application and proxy "
                    "layers, and verify actual behavior in an authorized test."
                ),
                reference="https://developer.mozilla.org/docs/Web/HTTP/Methods",
                confidence=Confidence.MEDIUM,
                limitations=(
                    "OPTIONS and CORS headers can describe different capabilities "
                    "from the methods actually accepted by the endpoint."
                ),
            ))

        results.append(finding(
            rule_id=self.rule_id,
            name="HTTP methods advertised",
            description=(
                "The server advertises one or more HTTP methods. This is an "
                "inventory observation, not a vulnerability by itself."
            ),
            severity=Severity.INFO,
            evidence="Methods: " + ", ".join(sorted(advertised)),
            endpoint=response.url,
            recommendation=(
                "Compare advertised methods with the API contract and verify "
                "authorization for every state-changing operation."
            ),
            reference="https://developer.mozilla.org/docs/Web/HTTP/Methods",
            confidence=Confidence.HIGH,
            limitations=(
                "An Allow or Access-Control-Allow-Methods header does not prove "
                "that a method is executable or improperly authorized."
            ),
        ))
        return results
