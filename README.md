# OctopusJar


A cautious, open-source CLI foundation for security checks against REST APIs you are authorized to assess.

## Portuguese Summary / Resumo em Português

O **OctopusJar** é uma ferramenta de linha de comando (CLI) modular de código aberto, projetada com foco em cautela para realizar verificações de segurança em APIs REST nas quais você possui autorização explícita para avaliar.

---

## Current Scope & Features

This initial foundation implements strict URL scope validation against an explicit allowlist.

* **URL Scope Validation**: Restricts execution to allowed origins using normalized schemes, hostnames, and effective ports. Subdomains are not implicitly included.
* **Security Protections**: Rejects URL credentials, malformed URLs, unsupported schemes, and URLs lacking a hostname.
* **Network Boundaries**: Designed with safety guardrails against redirect-based scope escapes, DNS rebinding, and access to prohibited IP ranges.

---

## Technical Requirements & Dependencies

### Prerequisites
* **Python**: Version 3.12 or newer.
* **Package Manager**: `pip` (with `venv` support for isolation).

### Development Tooling
* `pytest`: Automated test suite runner.
* `ruff`: Fast Python linter and code style checker.

---
## Examples

```python

from __future__ import annotations

import sys
from pathlib import Path

from octopusjar.checks import DEFAULT_CHECKS
from octopusjar.http_client import HttpClient, HttpClientError
from octopusjar.reporting import ReportWriteError, write_report
from octopusjar.scanner import Scanner


def executar_todos_os_checks() -> int:
    # Use apenas um alvo que você controla ou tem autorização para testar.
    alvo = "SITE_ALVO"
    destino = Path("relatorio_completo_checks.json")

    print("Checks registrados:")
    for check_class in DEFAULT_CHECKS:
        print(f" - {check_class.__name__}")

    with HttpClient(
        target=alvo,
        allowed_hosts=["SITEALVO:443"],
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

    if relatorio.errors:
        return 3

    if relatorio.findings:
        return 1

    return 0


if __name__ == "__main__":
    raise SystemExit(executar_todos_os_checks())

```
Or CLI:

```bash
# Executa uma varredura básica em um alvo específico gerando um relatório em JSON
octopusjar scan https://exemplo.com --output demo-report.json

# Execução alternativa chamando o pacote diretamente pelo Python
python -m octopusjar.cli scan https://exemplo.com
```

---

## Installation for Development

Follow these commands to set up a clean development environment and execute tests and linters:

```bash
# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install the package in editable mode with development dependencies
python -m pip install -e '.[dev]'

# Run the test suite
pytest

# Run the code linter
ruff check .
