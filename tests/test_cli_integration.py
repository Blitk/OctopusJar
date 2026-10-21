
"""Testes de integração da CLI do OctopusJar usando um servidor HTTP local."""

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from typer.testing import CliRunner

from octopusjar.cli import app


class LabHandler(BaseHTTPRequestHandler):
    """Servidor controlado para testes de integração."""

    server_version = "LabServer/1.0"
    sys_version = ""

    def do_GET(self):
        """Responde a GETs e fornece um endpoint de redirecionamento."""
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        body = json.dumps({"status": "ok"}).encode("utf-8")

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        """Anuncia os métodos disponíveis no laboratório."""
        self.send_response(204)
        self.send_header("Allow", "GET, OPTIONS")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format_string, *args):
        """Evita poluir a saída dos testes com logs HTTP."""
        return


@pytest.fixture
def lab_server():
    """Inicia e encerra um servidor HTTP local para cada teste."""
    server = ThreadingHTTPServer(("127.0.0.1", 0), LabHandler)
    server.daemon_threads = True

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()

    host, port = server.server_address
    base_url = f"http://{host}:{port}"

    try:
        yield base_url
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@pytest.fixture
def runner():
    """Cria o executor de comandos Typer."""
    return CliRunner()


def lab_args(base_url: str) -> list[str]:
    """Retorna argumentos comuns para executar a varredura no laboratório."""
    parsed = urlsplit(base_url)
    assert parsed.hostname is not None
    assert parsed.port is not None

    return [
        "scan",
        base_url,
        "--allow-host",
        f"{parsed.hostname}:{parsed.port}",
        "--allow-private-targets",
        "--rate-limit",
        "100",
        "--max-requests",
        "40",
    ]


def test_help_displays_scan_options(runner):
    """A ajuda deve documentar as opções principais."""
    result = runner.invoke(app, ["scan", "--help"])

    assert result.exit_code == 0, result.output
    assert "--timeout" in result.output
    assert "--max-requests" in result.output
    assert "--rate-limit" in result.output
    assert "--header" in result.output
    assert "--allow-host" in result.output
    assert "--output" in result.output
    assert "--format" in result.output
    assert "--verbose" in result.output


def test_json_output_file(runner, lab_server, tmp_path: Path):
    """A CLI deve gerar um relatório JSON válido em arquivo."""
    output_file = tmp_path / "report.json"
    args = lab_args(lab_server) + [
        "--format",
        "json",
        "--output",
        str(output_file),
    ]

    result = runner.invoke(app, args)

    # Código 1 significa que foram encontrados achados.
    assert result.exit_code in (0, 1), result.output
    assert output_file.exists()

    report = json.loads(output_file.read_text(encoding="utf-8"))
    assert report["tool"] == "OctopusJar"
    assert "findings" in report
    assert "summary" in report


def test_html_output_file(runner, lab_server, tmp_path: Path):
    """A CLI deve gerar um relatório HTML."""
    output_file = tmp_path / "report.html"
    args = lab_args(lab_server) + [
        "--format",
        "html",
        "--output",
        str(output_file),
    ]

    result = runner.invoke(app, args)

    assert result.exit_code in (0, 1), result.output
    assert output_file.exists()

    html = output_file.read_text(encoding="utf-8")
    assert "<html" in html.lower()
    assert "OctopusJar" in html


def test_json_output_to_stdout(runner, lab_server):
    """Sem arquivo de saída, o JSON deve ser escrito em stdout."""
    args = lab_args(lab_server) + ["--format", "json"]

    result = runner.invoke(app, args)

    assert result.exit_code in (0, 1), result.output
    report = json.loads(result.stdout)
    assert report["tool"] == "OctopusJar"
    assert isinstance(report["findings"], list)


def test_invalid_format_returns_configuration_error(runner, lab_server):
    """Um formato desconhecido deve ser rejeitado."""
    args = lab_args(lab_server) + ["--format", "xml"]

    result = runner.invoke(app, args)

    assert result.exit_code == 2


def test_request_limit_is_enforced(runner, lab_server):
    """A CLI deve reportar uma varredura incompleta ao atingir o limite."""
    args = lab_args(lab_server) + ["--max-requests", "1"]

    result = runner.invoke(app, args)

    # Código 3 indica erro operacional ou varredura incompleta.
    assert result.exit_code == 3, result.output


def test_private_target_requires_explicit_opt_in(runner, lab_server):
    """Um alvo privado não deve ser aceito sem autorização explícita."""
    args = [
        "scan",
        lab_server,
        "--allow-host",
        f"{urlsplit(lab_server).hostname}:{urlsplit(lab_server).port}",
        "--rate-limit",
        "100",
    ]

    result = runner.invoke(app, args)

    assert result.exit_code == 3, result.output
