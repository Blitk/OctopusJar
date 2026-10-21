
"""Security and correctness tests for OctopusJar report generation."""

import json
from pathlib import Path

import pytest

from octopusjar.reporting import (
    ReportWriteError,
    normalize_report,
    render_html,
    render_json,
    write_report,
)


@pytest.fixture
def sample_report():
    """Synthetic findings modeled after a controlled local HTTP test server."""
    return {
        "target": "http://user:password@127.0.0.1:8000/?api_key=supersecret",
        "started_at": "2026-10-21T10:00:00+00:00",
        "finished_at": "2026-10-21T10:00:02+00:00",
        "endpoints_scanned": [
            "http://127.0.0.1:8000/",
            "http://127.0.0.1:8000/health",
        ],
        "checks_performed": 10,
        "findings": [
            {
                "rule_id": "information-disclosure.server-header",
                "name": "Server header disclosed",
                "description": "The response exposes a server identification header.",
                "severity": "LOW",
                "endpoint": "http://127.0.0.1:8000/?access_token=abc123",
                "evidence": {
                    "header": "Server",
                    "value": "LabServer/1.0",
                    "authorization": "Bearer abc.def.ghi",
                    "cookie": "sessionid=private-value",
                    "message": "token=secret-token-value",
                },
                "recommendation": "Remove or minimize unnecessary server-identification headers.",
                "confidence": "HIGH",
                "limitations": ["The header alone does not prove an exploitable vulnerability."],
            }
        ],
        "errors": [],
        "limitations": ["Controlled local HTTP server; not a production assessment."],
    }


def test_json_is_valid_and_contains_summary(sample_report):
    output = render_json(sample_report)
    parsed = json.loads(output)

    assert parsed["tool"] == "OctopusJar"
    assert parsed["version"]
    assert parsed["duration_seconds"] == 2.0
    assert parsed["checks_performed"] == 10
    assert parsed["findings_count"] == 1
    assert parsed["findings_by_severity"]["LOW"] == 1
    assert len(parsed["scope"]) == 2


def test_sensitive_values_are_redacted_in_json(sample_report):
    output = render_json(sample_report)

    assert "password" not in output
    assert "supersecret" not in output
    assert "abc123" not in output
    assert "abc.def.ghi" not in output
    assert "private-value" not in output
    assert "secret-token-value" not in output
    assert "[REDACTED]" in output


def test_html_escapes_injected_markup(sample_report):
    sample_report["findings"][0]["description"] = (
        '<img src=x onerror="alert(1)">'
    )
    sample_report["findings"][0]["evidence"]["payload"] = (
        "</pre><script>alert('xss')</script>"
    )

    output = render_html(sample_report)

    assert "<script>" not in output
    assert "<img src=x" not in output
    assert "&lt;img" in output
    assert "&lt;script&gt;" in output


def test_html_does_not_load_remote_resources(sample_report):
    output = render_html(sample_report).lower()

    assert "<script" not in output
    assert "<iframe" not in output
    assert "<link" not in output
    assert "https://fonts.googleapis.com" not in output
    assert "src=\"http" not in output
    assert "connect-src 'none'" in output


def test_url_credentials_and_sensitive_query_values_are_removed(sample_report):
    normalized = normalize_report(sample_report)

    assert "user:password@" not in normalized["target"]
    assert "supersecret" not in normalized["target"]
    assert "api_key=%5BREDACTED%5D" in normalized["target"]


def test_write_report_creates_json_file(sample_report, tmp_path: Path):
    destination = tmp_path / "reports" / "report.json"

    returned_path = write_report(sample_report, destination, "json")

    assert returned_path == destination
    assert json.loads(destination.read_text(encoding="utf-8"))["tool"] == "OctopusJar"


def test_existing_report_is_not_overwritten(sample_report, tmp_path: Path):
    destination = tmp_path / "report.json"
    destination.write_text("existing report", encoding="utf-8")

    with pytest.raises(ReportWriteError):
        write_report(sample_report, destination, "json")

    assert destination.read_text(encoding="utf-8") == "existing report"


def test_write_error_is_reported(sample_report, tmp_path: Path):
    # A regular file cannot be used as a parent directory.
    parent_file = tmp_path / "not-a-directory"
    parent_file.write_text("file", encoding="utf-8")
    destination = parent_file / "report.json"

    with pytest.raises(ReportWriteError):
        write_report(sample_report, destination, "json")


def test_unknown_format_is_rejected(sample_report, tmp_path: Path):
    with pytest.raises(ValueError, match="Formato inválido"):
        write_report(sample_report, tmp_path / "report.xml", "xml")


def test_html_contains_recommendation_and_errors(sample_report):
    sample_report["errors"] = [
        {"rule_id": "http.timeout", "message": "Request timed out"}
    ]

    output = render_html(sample_report)

    assert "Remove or minimize unnecessary server-identification headers." in output
    assert "Request timed out" in output
    assert "DEMONSTRAÇÃO" in output
