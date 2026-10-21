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
from octopusjar.scanner import Scanner
from octopusjar.scope import Scope
from octopusjar.reporting import Reporting

def executar_auditoria():
    # Define o alvo e inicializa o escopo de segurança
    alvo = "https://exemplo.com"
    escopo = Scope(allowed_targets=[alvo])

    # Inicializa o scanner passando o escopo configurado
    scanner = Scanner(scope=escopo)

    print(f"Iniciando varredura de segurança em: {alvo}")
    resultados = scanner.run()

    # Processa e exporta os resultados para o formato de relatório
    relatorio = Reporting(resultados)
    relatorio.save_to_json("demo-report.json")
    
    print("Varredura finalizada. Relatório salvo com sucesso!")

if __name__ == "__main__":
    executar_auditoria()
```
Or CLI:

```bash
# Executa uma varredura básica em um alvo específico gerando um relatório em JSON
octopusjar scan --target https://exemplo.com --output demo-report.json

# Execução alternativa chamando o pacote diretamente pelo Python
python -m octopusjar.cli scan --target https://exemplo.com
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
