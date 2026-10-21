
"""Secure JSON and HTML reporting for OctopusJar.

Reports are generated from the same normalized data model. Dynamic HTML
content is escaped, sensitive values are redacted, and file writes refuse
to overwrite an existing destination.
"""

from __future__ import annotations

import html
import json
import os
import re
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from octopusjar import __version__


REDACTED = "[REDACTED]"

SENSITIVE_KEY_RE = re.compile(
    r"(?:authorization|proxy-authorization|cookie|set-cookie|"
    r"token|access[_-]?key|api[_-]?key|secret|password|passwd|"
    r"session|credential|client[_-]?secret)",
    re.IGNORECASE,
)

BEARER_RE = re.compile(
    r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+"
)
JWT_RE = re.compile(
    r"\beyJ[A-Za-z0-9_-]{5,}\."
    r"[A-Za-z0-9_-]{5,}\."
    r"[A-Za-z0-9_-]{5,}\b"
)
ASSIGNMENT_RE = re.compile(
    r"""(?ix)
    (["']?
    (?:access[_-]?token|refresh[_-]?token|api[_-]?key|
       client[_-]?secret|password|passwd|secret|authorization)
    ["']?\s*[:=]\s*)
    (["'])?[^,\s;"'}]+
    """
)
URL_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN")

HTML_TEMPLATE = """<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy"
      content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none';
               connect-src 'none'; script-src 'none'; base-uri 'none';
               form-action 'none'">
<title>OctopusJar — Relatório de demonstração de segurança</title>
<style>
:root { color-scheme: light dark; font-family: system-ui, sans-serif; }
body { max-width: 1050px; margin: 2rem auto; padding: 0 1rem; line-height: 1.5; }
header, section, article { border: 1px solid #8886; border-radius: .6rem;
  padding: 1rem; margin: 1rem 0; }
h1, h2, h3 { line-height: 1.25; }
.muted { opacity: .8; }
.badge { display: inline-block; border: 1px solid currentColor;
  border-radius: .3rem; padding: .1rem .4rem; font-size: .85rem; }
pre, code { white-space: pre-wrap; overflow-wrap: anywhere; }
dt { font-weight: 700; margin-top: .6rem; }
dd { margin-left: 0; overflow-wrap: anywhere; }
</style>
</head>
<body>
<header>
<h1>OctopusJar — Relatório de análise</h1>
<p><strong>DEMONSTRAÇÃO:</strong> relatório ilustrativo produzido para
um servidor HTTP de teste local. Não representa uma avaliação de um sistema real.</p>
<p class="muted">Versão: <span id="version-placeholder"></span></p>
</header>
<main id="report-content">
CONTENT_PLACEHOLDER
</main>
<footer class="muted">
<p>Relatório gerado pelo OctopusJar. Findings são sinais observados e
precisam ser interpretados no contexto do alvo autorizado.</p>
</footer>
</body>
</html>
"""


class ReportWriteError(OSError):
    """Raised when a report cannot be written safely."""


def _get(value: Any, key: str, default: Any = None) -> Any:
    """Read a field from a mapping or an object."""
    if isinstance(value, dict):
        return value.get(key, default)
    return getattr(value, key, default)


def _plain(value: Any) -> Any:
    """Convert supported model values into JSON-compatible primitives."""
    if hasattr(value, "to_dict") and callable(value.to_dict):
        return _plain(value.to_dict())

    if isinstance(value, dict):
        return {str(key): _plain(item) for key, item in value.items()}

    if isinstance(value, (list, tuple, set)):
        return [_plain(item) for item in value]

    if isinstance(value, datetime):
        return value.isoformat()

    if hasattr(value, "value") and isinstance(value.value, (str, int, float)):
        return value.value

    if value is None or isinstance(value, (str, int, float, bool)):
        return value

    return str(value)


def _redact_url(value: str) -> str:
    """Remove URL user information and redact sensitive query parameters."""
    try:
        parts = urlsplit(value)
        if parts.scheme.lower() not in {"http", "https"} or not parts.hostname:
            return value

        hostname = parts.hostname
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"

        try:
            port = parts.port
        except ValueError:
            port = None

        netloc = hostname
        if port is not None:
            netloc = f"{netloc}:{port}"

        query_items = []
        for key, item in parse_qsl(parts.query, keep_blank_values=True):
            if SENSITIVE_KEY_RE.search(key):
                item = REDACTED
            query_items.append((key, item))

        return urlunsplit(
            (
                parts.scheme,
                netloc,
                parts.path,
                urlencode(query_items),
                "",  # Fragments are unnecessary for server-side reproduction.
            )
        )
    except (ValueError, TypeError):
        return "[INVALID URL REDACTED]"


def sanitize_text(value: str) -> str:
    """Redact common credentials, token formats, and secrets embedded in text."""
    value = BEARER_RE.sub(r"\1 " + REDACTED, value)
    value = JWT_RE.sub(REDACTED, value)
    value = ASSIGNMENT_RE.sub(lambda match: match.group(1) + REDACTED, value)
    value = URL_RE.sub(lambda match: _redact_url(match.group(0)), value)
    return value


def sanitize_data(value: Any, key: str = "") -> Any:
    """Recursively sanitize data before it is serialized or rendered."""
    if SENSITIVE_KEY_RE.search(key):
        return REDACTED

    if isinstance(value, dict):
        sanitized = {}
        for child_key, child_value in value.items():
            name = str(child_key)
            if SENSITIVE_KEY_RE.search(name):
                sanitized[name] = REDACTED
            else:
                sanitized[name] = sanitize_data(child_value, name)
        return sanitized

    if isinstance(value, (list, tuple, set)):
        return [sanitize_data(item, key) for item in value]

    if isinstance(value, str):
        return sanitize_text(value)

    if isinstance(value, datetime):
        return value.isoformat()

    if value is None or isinstance(value, (int, float, bool)):
        return value

    if hasattr(value, "value"):
        return sanitize_data(value.value, key)

    return sanitize_text(str(value))


def _iso_datetime(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return sanitize_text(str(value))


def _duration_seconds(started_at: Any, finished_at: Any) -> float | None:
    """Calculate duration from datetime objects or ISO-8601 timestamps."""
    try:
        start = (
            started_at
            if isinstance(started_at, datetime)
            else datetime.fromisoformat(str(started_at))
        )
        finish = (
            finished_at
            if isinstance(finished_at, datetime)
            else datetime.fromisoformat(str(finished_at))
        )

        if start.tzinfo is None and finish.tzinfo is not None:
            start = start.replace(tzinfo=finish.tzinfo)
        elif start.tzinfo is not None and finish.tzinfo is None:
            finish = finish.replace(tzinfo=start.tzinfo)

        return round(max(0.0, (finish - start).total_seconds()), 3)
    except (TypeError, ValueError, OverflowError):
        return None


def normalize_report(report: Any) -> dict[str, Any]:
    """Build the canonical sanitized model shared by JSON and HTML output."""
    raw = _plain(report)

    if not isinstance(raw, dict):
        raise TypeError("O relatório deve ser um objeto ou um modelo com to_dict().")

    findings_raw = raw.get("findings") or []
    errors_raw = raw.get("errors") or []
    findings = [sanitize_data(_plain(item)) for item in findings_raw]
    errors = [sanitize_data(_plain(item)) for item in errors_raw]

    started_at = raw.get("started_at")
    finished_at = raw.get("finished_at")

    endpoints = raw.get("endpoints_scanned")
    if endpoints is None:
        endpoints = raw.get("scope") or []

    scope = sanitize_data(_plain(endpoints))
    if not isinstance(scope, list):
        scope = [scope]

    severity_counts = Counter()
    for item in findings:
        severity = str(item.get("severity", "UNKNOWN")).upper()
        severity_counts[severity if severity in SEVERITIES else "UNKNOWN"] += 1

    for severity in SEVERITIES:
        severity_counts.setdefault(severity, 0)

    checks_performed = raw.get("checks_performed")
    if checks_performed is not None:
        try:
            checks_performed = max(0, int(checks_performed))
        except (TypeError, ValueError):
            checks_performed = None

    target = sanitize_data(raw.get("target", "[target not recorded]"))

    return {
        "tool": "OctopusJar",
        "version": __version__,
        "generated_at": datetime.now().astimezone().isoformat(),
        "started_at": _iso_datetime(started_at),
        "finished_at": _iso_datetime(finished_at),
        "duration_seconds": _duration_seconds(started_at, finished_at),
        "target": target,
        "scope": scope,
        "checks_performed": checks_performed,
        "findings_count": len(findings),
        "findings_by_severity": dict(severity_counts),
        "findings": findings,
        "errors": errors,
        "limitations": sanitize_data(_plain(raw.get("limitations") or [])),
        "reproduction": {
            "method": "Non-destructive HTTP checks only",
            "request_body_recorded": False,
            "response_bodies_included": False,
            "redirects_and_request_limits": (
                "Use the original scan configuration; this report does not "
                "store secrets or guarantee a byte-for-byte replay."
            ),
        },
    }


def render_json(report: Any) -> str:
    """Render a sanitized report as UTF-8-compatible JSON text."""
    return json.dumps(
        normalize_report(report),
        ensure_ascii=False,
        indent=2,
        sort_keys=False,
    ) + "\n"


def _display(value: Any) -> str:
    """Create readable text without allowing HTML interpretation."""
    if isinstance(value, (dict, list)):
        value = json.dumps(value, ensure_ascii=False, indent=2)
    elif value is None:
        value = "Não informado"
    return html.escape(str(value), quote=True)


def render_html(report: Any) -> str:
    """Render the same normalized report as a self-contained HTML document."""
    data = normalize_report(report)

    summary_rows = [
        ("Versão", data["version"]),
        ("Início", data["started_at"]),
        ("Término", data["finished_at"]),
        ("Duração (segundos)", data["duration_seconds"]),
        ("Alvo autorizado", data["target"]),
        ("Verificações realizadas", data["checks_performed"]),
        ("Findings", data["findings_count"]),
    ]

    summary_html = "".join(
        f"<dt>{_display(label)}</dt><dd>{_display(value)}</dd>"
        for label, value in summary_rows
    )

    severity_html = "".join(
        f"<li>{_display(severity)}: {_display(count)}</li>"
        for severity, count in data["findings_by_severity"].items()
    )

    scope_html = "".join(f"<li>{_display(item)}</li>" for item in data["scope"])
    if not scope_html:
        scope_html = "<li>Escopo não registrado</li>"

    findings_html = []
    for index, finding in enumerate(data["findings"], start=1):
        findings_html.append(
            "<article>"
            f"<h3>{index}. {_display(finding.get('name', 'Finding'))}</h3>"
            f"<p><span class=\"badge\">{_display(finding.get('severity', 'UNKNOWN'))}"
            "</span> "
            f"<code>{_display(finding.get('rule_id', 'N/A'))}</code></p>"
            f"<p>{_display(finding.get('description', ''))}</p>"
            f"<dl><dt>Endpoint</dt><dd>{_display(finding.get('endpoint'))}</dd>"
            f"<dt>Evidências sanitizadas</dt><dd><pre>{_display(finding.get('evidence'))}</pre></dd>"
            f"<dt>Recomendação</dt><dd>{_display(finding.get('recommendation'))}</dd>"
            f"<dt>Confiança</dt><dd>{_display(finding.get('confidence'))}</dd>"
            f"<dt>Limitações</dt><dd>{_display(finding.get('limitations'))}</dd></dl>"
            "</article>"
        )

    if not findings_html:
        findings_html.append("<p>Nenhum finding foi registrado.</p>")

    errors_html = "".join(
        f"<li><pre>{_display(error)}</pre></li>" for error in data["errors"]
    ) or "<li>Nenhum erro registrado.</li>"

    limitations_html = "".join(
        f"<li>{_display(item)}</li>" for item in data["limitations"]
    ) or "<li>Nenhuma limitação adicional registrada.</li>"

    content = (
        f"<section><h2>Resumo</h2><dl>{summary_html}</dl></section>"
        f"<section><h2>Escopo analisado</h2><ul>{scope_html}</ul></section>"
        f"<section><h2>Findings por severidade</h2><ul>{severity_html}</ul></section>"
        f"<section><h2>Findings</h2>{''.join(findings_html)}</section>"
        f"<section><h2>Erros</h2><ul>{errors_html}</ul></section>"
        f"<section><h2>Limitações</h2><ul>{limitations_html}</ul></section>"
        f"<section><h2>Reprodução não destrutiva</h2>"
        f"<pre>{_display(data['reproduction'])}</pre></section>"
    )

    # The template is static; all report-derived values enter through escaped
    # content in `content`. No scripts, external stylesheets, or remote assets.
    return (
        HTML_TEMPLATE.replace(
            '<span id="version-placeholder"></span>',
            _display(data["version"]),
        ).replace("CONTENT_PLACEHOLDER", content)
    )


def write_report(
    report: Any,
    destination: str | Path,
    report_format: str,
) -> Path:
    """Write JSON or HTML without overwriting an existing file.

    Creates parent directories as needed. If a write fails after the new file
    has been created, attempts to remove the incomplete file.
    """
    output_path = Path(destination)
    fmt = report_format.lower()

    if fmt not in {"json", "html"}:
        raise ValueError("Formato inválido. Use 'json' ou 'html'.")

    content = render_json(report) if fmt == "json" else render_html(report)
    created = False

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("x", encoding="utf-8", newline="\n") as stream:
            created = True
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        if created:
            try:
                output_path.unlink(missing_ok=True)
            except OSError:
                pass
        raise ReportWriteError(
            f"Não foi possível gravar o relatório em {output_path}: {exc}"
        ) from exc

    return output_path
