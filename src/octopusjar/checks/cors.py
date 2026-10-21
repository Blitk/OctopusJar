
"""Context-aware CORS configuration checks."""

from .base import (
    Check, Confidence, Finding, HttpClient, Severity, finding, header_value,
)

TEST_ORIGIN = "https://octopusjar.invalid"


class CorsCheck:
    rule_id = "OJ-CORS-001"
    name = "CORS policy"

    def run(self, client: HttpClient, endpoint: str) -> list[Finding]:
        normal = client.get(endpoint, headers={"Origin": TEST_ORIGIN})
        results: list[Finding] = []
        origin = header_value(normal.headers, "Access-Control-Allow-Origin")
        credentials = (
            header_value(normal.headers, "Access-Control-Allow-Credentials") or ""
        ).strip().lower()
        vary = (header_value(normal.headers, "Vary") or "").lower()

        if origin == "*" and credentials == "true":
            results.append(finding(
                rule_id=self.rule_id,
                name="Inconsistent permissive CORS headers",
                description=(
                    "The response combines wildcard origin with credential "
                    "permission. Browsers reject this combination for "
                    "credentialed cross-origin reads, so it is not proof "
                    "of a successful credentialed attack."
                ),
                severity=Severity.INFO,
                evidence="ACAO wildcard and ACAC true observed",
                endpoint=normal.url,
                recommendation=(
                    "Use an explicit trusted-origin allowlist and enable "
                    "credentials only when necessary."
                ),
                reference="https://developer.mozilla.org/docs/Web/HTTP/CORS",
                confidence=Confidence.HIGH,
                limitations=(
                    "Browsers do not accept ACAO '*' for credentialed requests; "
                    "this combination alone does not demonstrate data exposure."
                ),
            ))
        elif origin == "*":
            results.append(finding(
                rule_id=self.rule_id,
                name="Wildcard CORS origin",
                description=(
                    "The endpoint permits browser cross-origin access from "
                    "any origin for responses governed by this header."
                ),
                severity=Severity.LOW,
                evidence="Access-Control-Allow-Origin: *",
                endpoint=normal.url,
                recommendation=(
                    "Confirm the resource is intentionally public. Otherwise, "
                    "return only explicitly trusted origins."
                ),
                reference="https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny",
                confidence=Confidence.MEDIUM,
                limitations=(
                    "Wildcard CORS does not grant authentication or prove "
                    "sensitive data exposure; endpoint data sensitivity matters."
                ),
            ))
        elif origin == TEST_ORIGIN:
            severity = Severity.MEDIUM if credentials == "true" else Severity.LOW
            results.append(finding(
                rule_id=self.rule_id,
                name="Test origin accepted by CORS",
                description=(
                    "The response allowed the reserved test origin, which may "
                    "indicate reflection or an overly broad origin policy."
                ),
                severity=severity,
                evidence=(
                    "Test origin was returned in Access-Control-Allow-Origin; "
                    f"credentials={'true' if credentials == 'true' else 'not true'}"
                ),
                endpoint=normal.url,
                recommendation=(
                    "Inspect the origin allowlist and compare exact scheme, "
                    "host and port. Avoid substring or suffix-only matching."
                ),
                reference="https://developer.mozilla.org/docs/Web/HTTP/CORS",
                confidence=Confidence.MEDIUM,
                limitations=(
                    "One origin probe cannot establish the complete allowlist "
                    "or prove access to sensitive authenticated data."
                ),
            ))

        if origin and origin != "*" and origin != TEST_ORIGIN:
            if "origin" not in vary and origin != "":
                results.append(finding(
                    rule_id=self.rule_id,
                    name="CORS response may be incorrectly cached",
                    description=(
                        "A specific Access-Control-Allow-Origin was returned "
                        "without Vary: Origin."
                    ),
                    severity=Severity.LOW,
                    evidence="Specific ACAO observed; Vary does not include Origin",
                    endpoint=normal.url,
                    recommendation=(
                        "If the response varies by request Origin, include "
                        "Vary: Origin and verify intermediary cache behavior."
                    ),
                    reference="https://developer.mozilla.org/docs/Web/HTTP/Headers/Vary",
                    confidence=Confidence.LOW,
                    limitations=(
                        "This is only relevant when the server varies ACAO "
                        "between requests and the response is cacheable."
                    ),
                ))

        preflight = client.request(
            "OPTIONS",
            endpoint,
            headers={
                "Origin": TEST_ORIGIN,
                "Access-Control-Request-Method": "PUT",
                "Access-Control-Request-Headers": "authorization,content-type",
            },
        )
        allowed_methods = (
            header_value(preflight.headers, "Access-Control-Allow-Methods") or ""
        )
        allowed_headers = (
            header_value(preflight.headers, "Access-Control-Allow-Headers") or ""
        )
        preflight_origin = header_value(
            preflight.headers, "Access-Control-Allow-Origin"
        )

        if preflight_origin == TEST_ORIGIN and (
            "put" in allowed_methods.lower()
            or "*" in allowed_methods
        ):
            results.append(finding(
                rule_id=self.rule_id,
                name="Preflight accepts test origin and requested method",
                description=(
                    "The preflight response permits the test origin and "
                    "the requested PUT method."
                ),
                severity=Severity.INFO,
                evidence=(
                    "Preflight allowed test origin; "
                    f"methods={allowed_methods[:80]}; headers={allowed_headers[:80]}"
                ),
                endpoint=preflight.url,
                recommendation=(
                    "Confirm that this origin and method are intentionally "
                    "permitted. Separately enforce authorization on the actual API."
                ),
                reference="https://developer.mozilla.org/docs/Glossary/Preflight_request",
                confidence=Confidence.MEDIUM,
                limitations=(
                    "A successful preflight does not prove that the actual "
                    "request succeeds or bypasses server-side authorization."
                ),
            ))

        return results
