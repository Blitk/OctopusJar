
#!/usr/bin/env python3
"""Executa os checks registrados do OctopusJar e gera um relatório JSON."""

from __future__ import annotations

import sys
from pathlib import Path

from octopusjar.checks import DEFAULT_CHECKS
from octopusjar.http_client import HttpClient, HttpClientError
from octopusjar.reporting import ReportWriteError, write_report
from octopusjar.scanner import Scanner


def executar_todos_os_checks() -> int:
    # Use apenas um alvo que você controla ou tem autorização para testar.
    alvo = "https://blitk.github.io"
    destino = Path("relatorio_completo_checks.json")

    # Confirma quais verificações estão registradas no projeto.
    print("Checks registrados:")
    for check_class in DEFAULT_CHECKS:
        print(f" - {check_class.__name__}")

    # O host explícito do alvo é permitido; redirecionamentos para outros
    # hosts não são autorizados automaticamente.
    with HttpClient(
        target=alvo,
        allowed_hosts=["blitk.github.io:443"],
        allow_private_targets=False,
        connect_timeout=10.0,
        read_timeout=10.0,
        write_timeout=10.0,
        pool_timeout=10.0,
        max_requests=40,
        requests_per_second=2.0,
        max_redirects=3,
        max_response_bytes=2_000_000,
        verify_tls=True,
    ) as cliente:
        scanner = Scanner(cliente)

        print(f"\nIniciando análise de: {alvo}\n")

        try:
            relatorio = scanner.scan(alvo)
        except (ValueError, HttpClientError) as exc:
            print(
                f"Falha na execução: {type(exc).__name__}. "
                "Detalhes omitidos.",
                file=sys.stderr,
            )
            return 3

    print("Checks concluídos.")
    print(f"Endpoints analisados: {len(relatorio.endpoints_scanned)}")
    print(f"Checks executados: {relatorio.checks_performed}")
    print(f"Findings: {len(relatorio.findings)}")
    print(f"Erros: {len(relatorio.errors)}")

    try:
        write_report(relatorio, destino, "json")
    except (ReportWriteError, ValueError) as exc:
        print(
            f"Não foi possível gravar o relatório: {type(exc).__name__}",
            file=sys.stderr,
        )
        return 3

    print(f"\nRelatório salvo em: {destino.resolve()}")

    # Código 3 sinaliza que algum check não foi concluído corretamente.
    if relatorio.errors:
        return 3

    # Código 1 indica que foram encontrados findings.
    if relatorio.findings:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(executar_todos_os_checks())
