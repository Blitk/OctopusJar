
"""Checks for browser-relevant HTTP security headers."""

from .base import (
    Check, Confidence, Finding, HttpClient, Severity, finding, header_value,
)


class SecurityHeadersCheck:
    rule_id = "OJ-HEADERS-001"
    name = "Security headers"

    def run(self, client: HttpClient, endpoint: str) -> list[Finding]:
        response = client.get(endpoint)
        headers = response.headers
        content_type = (header_value(headers, "Content-Type") or "").lower()
        is_https = response.url.lower().startswith("https://")
        is_html = "text/html" in content_type
        results: list[Finding] = []

        def missing(header: str, severity: Severity, context: str) -> None:
            results.append(finding(
                rule_id=self.rule_id,
                name=f"Missing {header}",
                description=f"The response does not include {header}.",
                severity=severity,
                evidence=f"HTTP {response.status_code}; {header} absent",
                endpoint=response.url,
                recommendation=context,
                reference="https://owasp.org/www-project-secure-headers/",
                confidence=Confidence.MEDIUM,
                limitations=(
                    "Assessment is based on one response. Reverse proxies, "
                    "other routes and application-specific controls may differ."
                ),
            ))

        if is_https and not header_value(headers, "Strict-Transport-Security"):
            missing(
                "Strict-Transport-Security", Severity.LOW,
                "Configure HSTS after confirming all relevant subdomains "
                "and HTTPS deployment are ready.",
            )

        if not header_value(headers, "X-Content-Type-Options"):
            missing(
                "X-Content-Type-Options", Severity.LOW,
                "Consider sending X-Content-Type-Options: nosniff, especially "
                "for browser-served resources.",
            )

        if is_html:
            if not header_value(headers, "Content-Security-Policy"):
                missing(
                    "Content-Security-Policy", Severity.LOW,
                    "Evaluate a CSP appropriate to the application's scripts, "
                    "styles, frames and other browser resources.",
                )
            if not header_value(headers, "X-Frame-Options") and not (
                header_value(headers, "Content-Security-Policy")
                and "frame-ancestors" in (
                    header_value(headers, "Content-Security-Policy") or ""
                ).lower()
            ):
                missing(
                    "X-Frame-Options / CSP frame-ancestors", Severity.LOW,
                    "If this page must not be embedded, configure "
                    "frame-ancestors or X-Frame-Options.",
                )

        xcto = header_value(headers, "X-Content-Type-Options")
        if xcto and xcto.strip().lower() != "nosniff":
            results.append(finding(
                rule_id=self.rule_id,
                name="Potentially ineffective X-Content-Type-Options",
                description="The header is present but does not equal nosniff.",
                severity=Severity.LOW,
                evidence=f"X-Content-Type-Options: {xcto}",
                endpoint=response.url,
                recommendation="Use X-Content-Type-Options: nosniff if appropriate.",
                reference="https://developer.mozilla.org/docs/Web/HTTP/Headers/X-Content-Type-Options",
                confidence=Confidence.HIGH,
                limitations="This observation alone does not demonstrate exploitability.",
            ))

        return results
