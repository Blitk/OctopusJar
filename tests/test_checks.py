
from dataclasses import dataclass, field

from octopusjar.checks.base import Confidence, Severity
from octopusjar.checks.cors import CorsCheck
from octopusjar.checks.headers import SecurityHeadersCheck
from octopusjar.checks.information_disclosure import InformationDisclosureCheck
from octopusjar.checks.methods import HttpMethodsCheck
from octopusjar.checks.redirects import RedirectsCheck


@dataclass
class FakeResponse:
    url: str
    status_code: int = 200
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""

    @property
    def text(self):
        return self.body.decode("utf-8", errors="replace")


class FakeClient:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def request(self, method, url=None, *, headers=None, params=None):
        self.calls.append((method, url, headers))
        if not self.responses:
            raise AssertionError("Unexpected extra HTTP request")
        return self.responses.pop(0)

    def get(self, url=None, *, headers=None, params=None):
        return self.request("GET", url, headers=headers, params=params)


def test_headers_html_missing_csp_is_low_severity():
    client = FakeClient([FakeResponse(
        "https://api.example.test/page",
        headers={"Content-Type": "text/html"},
    )])

    findings = SecurityHeadersCheck().run(client, "https://api.example.test/page")

    csp = [item for item in findings if "Content-Security-Policy" in item.name]
    assert len(csp) == 1
    assert csp[0].severity == Severity.LOW
    assert csp[0].confidence == Confidence.MEDIUM


def test_headers_api_json_does_not_report_missing_csp():
    client = FakeClient([FakeResponse(
        "https://api.example.test/v1/items",
        headers={"Content-Type": "application/json"},
    )])

    findings = SecurityHeadersCheck().run(client, "https://api.example.test/v1/items")

    assert not any("Content-Security-Policy" in item.name for item in findings)


def test_cors_wildcard_is_observation_not_critical():
    client = FakeClient([
        FakeResponse(
            "https://api.example.test/data",
            headers={"Access-Control-Allow-Origin": "*"},
        ),
        FakeResponse("https://api.example.test/data", status_code=204),
    ])

    findings = CorsCheck().run(client, "https://api.example.test/data")

    wildcard = next(item for item in findings if item.name == "Wildcard CORS origin")
    assert wildcard.severity == Severity.LOW
    assert wildcard.severity != Severity.CRITICAL


def test_cors_reflected_test_origin_with_credentials_is_flagged():
    client = FakeClient([
        FakeResponse(
            "https://api.example.test/data",
            headers={
                "Access-Control-Allow-Origin": "https://octopusjar.invalid",
                "Access-Control-Allow-Credentials": "true",
            },
        ),
        FakeResponse("https://api.example.test/data", status_code=204),
    ])

    findings = CorsCheck().run(client, "https://api.example.test/data")

    assert any(
        item.severity == Severity.MEDIUM
        and "Test origin accepted" in item.name
        for item in findings
    )


def test_cors_without_allow_origin_is_not_flagged():
    client = FakeClient([
        FakeResponse("https://api.example.test/data"),
        FakeResponse("https://api.example.test/data", status_code=204),
    ])

    findings = CorsCheck().run(client, "https://api.example.test/data")

    assert not any("Wildcard CORS" in item.name for item in findings)
    assert not any("Test origin accepted" in item.name for item in findings)


def test_methods_only_produces_inventory_for_get_post():
    client = FakeClient([FakeResponse(
        "https://api.example.test/items",
        status_code=204,
        headers={"Allow": "GET, POST, OPTIONS"},
    )])

    findings = HttpMethodsCheck().run(client, "https://api.example.test/items")

    assert len(findings) == 1
    assert findings[0].severity == Severity.INFO
    assert "GET" in findings[0].evidence


def test_advertised_trace_is_not_called_exploitable():
    client = FakeClient([FakeResponse(
        "https://api.example.test/items",
        status_code=204,
        headers={"Allow": "GET, TRACE"},
    )])

    findings = HttpMethodsCheck().run(client, "https://api.example.test/items")

    assert any(item.severity == Severity.LOW for item in findings)
    assert all("exploit" not in item.name.lower() for item in findings)


def test_information_disclosure_detects_server_header():
    client = FakeClient([FakeResponse(
        "https://api.example.test/",
        headers={"Server": "ExampleServer/1.2"},
    )])

    findings = InformationDisclosureCheck().run(client, "https://api.example.test/")

    assert any("Server" in item.name for item in findings)
    assert all("1.2" in item.evidence for item in findings if "Server" in item.name)


def test_information_disclosure_detects_stack_trace_without_copying_body():
    secret_body = b"Traceback (most recent call last): token=supersecret"
    client = FakeClient([FakeResponse(
        "https://api.example.test/fail",
        status_code=500,
        body=secret_body,
    )])

    findings = InformationDisclosureCheck().run(client, "https://api.example.test/fail")

    disclosure = next(item for item in findings if "verbose error" in item.name.lower())
    assert "supersecret" not in disclosure.evidence
    assert "content intentionally omitted" in disclosure.evidence


def test_information_disclosure_does_not_flag_generic_error():
    client = FakeClient([FakeResponse(
        "https://api.example.test/fail",
        status_code=500,
        body=b'{"error":"Internal server error"}',
    )])

    findings = InformationDisclosureCheck().run(client, "https://api.example.test/fail")

    assert not any("verbose error" in item.name.lower() for item in findings)


def test_redirect_rule_flags_https_downgrade():
    # The fake client returns the final URL and redirect history as the real
    # HttpResult does. Use a tiny compatible object for that extra attribute.
    @dataclass
    class RedirectResponse(FakeResponse):
        redirect_history: tuple[str, ...] = ()

    client = FakeClient([RedirectResponse(
        "http://api.example.test/final",
        redirect_history=("https://api.example.test/start",),
    )])

    findings = RedirectsCheck().run(client, "https://api.example.test/start")

    assert any("HTTPS to HTTP" in item.name for item in findings)


def test_redirect_rule_treats_cross_origin_as_review_not_vulnerability():
    @dataclass
    class RedirectResponse(FakeResponse):
        redirect_history: tuple[str, ...] = ()

    client = FakeClient([RedirectResponse(
        "https://login.example.test/callback",
        redirect_history=("https://api.example.test/login",),
    )])

    findings = RedirectsCheck().run(client, "https://api.example.test/login")

    cross_origin = next(item for item in findings if item.name == "Cross-origin redirect")
    assert cross_origin.severity == Severity.INFO
