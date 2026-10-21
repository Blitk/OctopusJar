
"""Safe JSON and HTML report rendering."""

from __future__ import annotations

import html
import json

from octopusjar.scanner import ScanReport


def render_json(report: ScanReport) -> str:
    return json.dumps(
        report.to_dict(),
        ensure_ascii=False,
        indent=2,
    ) + "\n"


def render_html(report: ScanReport) -> str:
    data = report.to_dict()
    esc = lambda value: html.escape(str(value), quote=True)

    finding_rows = []
    for item in report.findings:
        finding_rows.append(
            "<tr>"
            f"<td>{esc(item.severity.value)}</td>"
            f"<td>{esc(item.rule_id)}</td>"
            f"<td>{esc(item.name)}</td>"
            f"<td>{esc(item.endpoint)}</td>"
            f"<td>{esc(item.description)}</td>"
            f"<td>{esc(item.evidence)}</td>"
            f"<td>{esc(item.recommendation)}</td>"
            f"<td>{esc(item.confidence.value)}</td>"
            f"<td>{esc(item.limitations)}</td>"
            "</tr>"
        )

    error_rows = []
    for error in report.errors:
        error_rows.append(
            "<tr>"
            f"<td>{esc(error.rule_id)}</td>"
            f"<td>{esc(error.rule_name)}</td>"
            f"<td>{esc(error.endpoint)}</td>"
            f"<td>{esc(error.error_type)}</td>"
            f"<td>{esc(error.message)}</td>"
            "</tr>"
        )

    summary = data["summary"]
    return f"""<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>OctopusJar — Relatório</title>
<style>
body {{ font: 16px/1.5 system-ui, sans-serif; margin: 2rem auto;
       padding: 0 1rem; max-width: 1200px; color: #202124; }}
table {{ border-collapse: collapse; width: 100%; margin: 1rem 0 2rem; }}
th, td {{ border: 1px solid #ccc; text-align: left; padding: .6rem;
          overflow-wrap: anywhere; }}
th {{ background: #f1f3f4; }}
small {{ color: #555; }}
</style>
</head>
<body>
<h1>OctopusJar — Relatório de varredura</h1>
<p><strong>Alvo:</strong> {esc(data["target"])}</p>
<p><strong>Início:</strong> {esc(data["started_at"])}</p>
<p><strong>Fim:</strong> {esc(data["finished_at"] or "incompleto")}</p>
<ul>
<li>Endpoints processados: {summary["endpoints"]}</li>
<li>Findings: {summary["findings"]}</li>
<li>Erros operacionais: {summary["errors"]}</li>
</ul>
<h2>Findings</h2>
<table>
<thead><tr><th>Severidade</th><th>Regra</th><th>Nome</th><th>Endpoint</th>
<th>Descrição</th><th>Evidência</th><th>Recomendação</th>
<th>Confiança</th><th>Limitações</th></tr></thead>
<tbody>{''.join(finding_rows) or '<tr><td colspan="9">Nenhum finding.</td></tr>'}</tbody>
</table>
<h2>Erros operacionais</h2>
<table>
<thead><tr><th>Regra</th><th>Nome</th><th>Endpoint</th>
<th>Tipo</th><th>Detalhes</th></tr></thead>
<tbody>{''.join(error_rows) or '<tr><td colspan="5">Nenhum erro.</td></tr>'}</tbody>
</table>
<small>Relatório gerado pelo OctopusJar. Findings indicam observações e não
constituem, isoladamente, prova de exploração.</small>
</body>
</html>
"""
