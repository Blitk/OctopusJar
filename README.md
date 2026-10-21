##OctopusJar
A cautious, open-source CLI foundation for security checks against REST APIs you are authorized to assess.
Portuguese Summary / Resumo em Português
O OctopusJar é uma ferramenta de linha de comando (CLI) modular de código aberto, projetada com foco em cautela para realizar verificações de segurança em APIs REST nas quais você possui autorização explícita para avaliar.
Current Scope & Features
This initial foundation implements strict URL scope validation against an explicit allowlist.
 * URL Scope Validation: Restricts execution to allowed origins using normalized schemes, hostnames, and effective ports. Subdomains are not implicitly included.
 * Security Protections: Rejects URL credentials, malformed URLs, unsupported schemes, and URLs lacking a hostname.
 * Network Boundaries: Designed with safety guardrails against redirect-based scope escapes, DNS rebinding, and access to prohibited IP ranges.
Technical Requirements & Dependencies
Prerequisites
 * Python: Version 3.12 or newer.
 * Package Manager: pip (with venv support for isolation).
Development Tooling
 * pytest: Automated test suite runner.
 * ruff: Fast Python linter and code style checker.
Installation for Development
Follow these commands to set up a clean development environment and execute tests and linters:
# Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# Install the package in editable mode with development dependencies
python -m pip install -e '.[dev]'

# Run the test suite
pytest

# Run the code linter
ruff check .

Scope Policy & Architecture
Allowlist entries operate strictly on origins. Examples of valid entries include:
 * [https://api.example.test](https://api.example.test)
 * [http://127.0.0.1:8000](http://127.0.0.1:8000)
Core Policy Rules:
 * Explicit Match: A target is permitted only when its normalized scheme, hostname, and effective port match an explicit entry.
 * Subdomain Restriction: Subdomains are not implicitly included.
 * Strict Rejection: URL credentials, malformed URLs, unsupported schemes, and URLs without a hostname are automatically rejected.
 * Defense-in-Depth: The allowlist serves as a policy check rather than a complete network security boundary. Future expansions require validation on each redirect hop and resolved destination to mitigate DNS rebinding and internal network exposure.
Risks, Disclaimer & Responsible Use
Legal & Ethical Disclaimer
OctopusJar is designed exclusively for authorized security testing and research. Executing scans against targets without prior explicit written permission from the asset owner is illegal and violates terms of service.
Semantic Versioning & Roadmap
OctopusJar follows Semantic Versioning 2.0.0:
 * v0.1.0 (Current Foundation): Focuses on robust architecture setup, testing pipelines, code quality checks via Ruff, and explicit allowlist scope validation policies.
