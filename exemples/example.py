from octopusjar.http_client import HttpClient
from octopusjar.scanner import Scanner

target = "https://api.example.com/"

with HttpClient(
    target=target,
    allowed_hosts=["api.example.com"],
    requests_per_second=2,
    max_redirects=3,
) as client:
    scanner = Scanner(client)
    report = scanner.scan(target)

    print(f"Findings: {len(report.findings)}")
    print(f"Errors: {len(report.errors)}")

    for item in report.findings:
        print(
            item.severity.value,
            item.rule_id,
            item.name,
            item.endpoint,
        )
