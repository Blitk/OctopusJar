"""OctopusJar command-line interface."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Optional
from urllib.parse import urlsplit

import typer

from octopusjar.http_client import HttpClient, HttpClientError
from octopusjar.reporting import render_html, render_json
from octopusjar.reporting import ReportWriteError, write_report
from octopusjar.scanner import Scanner

app = typer.Typer(
    name="octopusjar",
    help=(
    "Scanner de segurança para APIs HTTP/REST autorizadas. "
    "Only scan systems you are authorized to assess."),
    no_args_is_help=True,
    add_completion=False,
)

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_CONFIG = 2
EXIT_OPERATIONAL = 3

HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
FORBIDDEN_HEADERS = {
    "host", "content-length", "connection", "transfer-encoding",
    "proxy-authorization", "user-agent",
}


def _fail(message: str, code: int = EXIT_CONFIG) -> None:
    typer.echo(f"Erro: {message}", err=True)
    raise typer.Exit(code=code)


def _parse_target(target: str):
    try:
        parsed = urlsplit(target)
        port = parsed.port
    except ValueError:
        _fail("URL inválida ou porta malformada.")

    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        _fail("O alvo precisa ser uma URL HTTP ou HTTPS absoluta.")
    if parsed.username is not None or parsed.password is not None:
        _fail("Não informe credenciais na URL do alvo.")
    if parsed.fragment:
        _fail("Fragmentos de URL não são aceitos como alvo.")

    host = parsed.hostname.lower().rstrip(".")
    if not host:
        _fail("Hostname inválido.")

    effective_port = port or (443 if parsed.scheme.lower() == "https" else 80)
    display_host = f"[{host}]" if ":" in host else host
    origin_allowlist_entry = f"{display_host}:{effective_port}"
    return parsed, origin_allowlist_entry


def _parse_allow_host(value: str) -> str:
    value = value.strip()
    if not value:
        _fail("--allow-host não pode ser vazio.")

    try:
        parsed = urlsplit("//" + value)
        _ = parsed.port
    except ValueError:
        _fail(f"Entrada --allow-host inválida: {value!r}")

    if (
        not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        _fail(
            f"Use somente host ou host:porta em --allow-host: {value!r}"
        )
    return value


def _parse_headers(values: Optional[list[str]]) -> dict[str, str]:
    result: dict[str, str] = {}

    for item in values or []:
        name, separator, value = item.partition(":")
        name = name.strip()
        value = value.strip()

        if not separator or not HEADER_NAME.fullmatch(name):
            _fail("Cabeçalho inválido. Use --header 'Nome: valor'.")
        if "\r" in value or "\n" in value:
            _fail("Quebras de linha em cabeçalhos não são permitidas.")
        if name.lower() in FORBIDDEN_HEADERS:
            _fail(
                f"O cabeçalho {name} não pode ser substituído pela CLI."
            )

        result[name] = value

    return result


@app.callback()
def main(
    version: bool = typer.Option(
        False, "--version", help="Exibe a versão e encerra."
    ),
) -> None:
    """Comandos de análise de APIs autorizadas."""
    if version:
        from octopusjar import __version__
        typer.echo(f"OctopusJar {__version__}")
        raise typer.Exit(code=EXIT_OK)


@app.command()
def scan(
    target: str = typer.Argument(
        ...,
        help="URL HTTP(S) explícita do alvo autorizado.",
    ),
    timeout: float = typer.Option(
        10.0, "--timeout",
        min=0.1, max=120.0,
        help="Timeout em segundos aplicado a conexão, leitura, escrita e pool.",
    ),
    max_requests: int = typer.Option(
        100, "--max-requests",
        min=1, max=10000,
        help="Máximo total de requisições HTTP, incluindo redirecionamentos.",
    ),
    rate_limit: float = typer.Option(
        2.0, "--rate-limit",
        min=0.1, max=100.0,
        help="Limite médio de requisições por segundo para o cliente compartilhado.",
    ),
    header: Optional[list[str]] = typer.Option(
        None, "--header",
        help="Cabeçalho adicional no formato 'Nome: valor'. Pode ser repetido.",
    ),
    allow_host: Optional[list[str]] = typer.Option(
        None, "--allow-host",
        help="Host adicional autorizado, opcionalmente com porta. Pode ser repetido.",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o",
        help="Caminho do relatório JSON ou HTML.",
    ),
    format_: str = typer.Option(
        "text", "--format",
        help="Formato de saída: text, json ou html.",
    ),
    verbose: bool = typer.Option(
        False, "--verbose", "-v",
        help="Exibe detalhes dos findings e erros operacionais.",
    ),
    allow_private_targets: bool = typer.Option(
        False, "--allow-private-targets",
        help="Permite IPs privados/locais apenas para laboratório autorizado.",
    ),
) -> None:
    """Executa as verificações de segurança registradas para um alvo."""
    if format_ not in {"text", "json", "html"}:
        _fail("--format aceita somente text, json ou html.")
    if output is not None and format_ == "text":
        _fail("--output requer --format json ou --format html.")
    if output is not None and output.exists() and output.is_dir():
        _fail("--output deve indicar um arquivo, não um diretório.")

    parsed, target_allow_entry = _parse_target(target)
    headers = _parse_headers(header)

    extra_hosts = [
        _parse_allow_host(value) for value in (allow_host or [])
    ]
    # The explicit target origin is always included. Additional hosts are
    # exact entries supplied by the operator; the HTTP client checks each
    # redirect against this combined allowlist.
    allowed_hosts = [target_allow_entry, *extra_hosts]

    structured_stdout = output is None and format_ in {"json", "html"}

    def progress(message: str) -> None:
        typer.echo(message, err=structured_stdout)

    progress(f"OctopusJar: preparando varredura de {parsed.hostname}")
    progress(f"Regras registradas: 5 | Limite de requisições: {max_requests}")

    try:
        with HttpClient(
            target=target,
            allowed_hosts=allowed_hosts,
            allow_private_targets=allow_private_targets,
            connect_timeout=timeout,
            read_timeout=timeout,
            write_timeout=timeout,
            pool_timeout=timeout,
            max_requests=max_requests,
            requests_per_second=rate_limit,
            max_redirects=3,
            max_response_bytes=2_000_000,
            verify_tls=True,
            headers=headers,
        ) as client:
            scanner = Scanner(client)
            report = scanner.scan(target)

    except (ValueError, HttpClientError) as exc:
        # Never print exception contents: transport errors can contain URLs.
        typer.echo(
            f"Falha operacional: {type(exc).__name__}. "
            "Nenhum detalhe sensível foi exibido.",
            err=True,
        )
        raise typer.Exit(code=EXIT_OPERATIONAL)

    # Gravar relatório se output foi configurado
    if output is not None:
        try:
            write_report(report, output, format_)
        except ReportWriteError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=EXIT_OPERATIONAL)
    # Ou renderizar para stdout se formato estruturado
    elif format_ in {"json", "html"}:
        if format_ == "json":
            rendered = render_json(report)
        else:
            rendered = render_html(report)
        typer.echo(rendered, nl=False)

    if not structured_stdout:
        typer.echo("")
        typer.echo("Varredura finalizada.")
        typer.echo(f"Endpoints processados: {len(report.endpoints_scanned)}")
        typer.echo(f"Findings: {len(report.findings)}")
        typer.echo(f"Erros operacionais: {len(report.errors)}")
        if output:
            typer.echo(f"Relatório salvo em: {output}")

        for item in report.findings:
            typer.echo(
                f"[{item.severity.value.upper()}] "
                f"{item.rule_id} — {item.name}"
            )
            if verbose:
                typer.echo(f"  Endpoint: {item.endpoint}")
                typer.echo(f"  Evidência: {item.evidence}")
                typer.echo(f"  Recomendação: {item.recommendation}")

        if verbose:
            for error in report.errors:
                typer.echo(
                    f"[ERRO] {error.rule_id} — {error.error_type}: "
                    f"{error.message}"
                )

    # An incomplete run is an operational failure, not a security finding.
    if report.errors:
        raise typer.Exit(code=EXIT_OPERATIONAL)
    if report.findings:
        raise typer.Exit(code=EXIT_FINDINGS)
    raise typer.Exit(code=EXIT_OK)


if __name__ == "__main__":
    app()
