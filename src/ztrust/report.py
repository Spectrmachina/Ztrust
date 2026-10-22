"""Output formats: rich console, JSON and SARIF 2.1.0 (GitHub code scanning)."""

from __future__ import annotations

import json
from typing import IO, Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from ztrust import PROJECT_URL, __version__
from ztrust.models import ScanResult, Severity

SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "bold yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}
SARIF_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "3.0",
    Severity.INFO: "0.0",
}


def render_console(result: ScanResult, console: Console | None = None) -> None:
    console = console or Console()
    counts = result.counts()
    summary = Text()
    for sev in reversed(list(Severity)):
        summary.append(f" {sev.value.upper()} {counts[sev.value]} ", style=SEVERITY_STYLE[sev])
        summary.append("  ")
    console.print(
        Panel(
            Text.assemble(
                ("ZTrust ", "bold #f7931a"),
                (f"v{__version__}  ", "dim"),
                (f"{result.root}\n", "bold"),
                (f"{len(result.dependencies)} dependencies · scanners: {', '.join(result.scanners)} · "
                 f"{result.duration_s:.2f}s\n", "dim"),
                summary,
            ),
            border_style="#f7931a",
        )
    )
    if result.findings:
        table = Table(show_lines=False, header_style="bold", expand=True)
        table.add_column("Severity", no_wrap=True)
        table.add_column("Rule", no_wrap=True)
        table.add_column("Finding")
        table.add_column("Location", overflow="fold")
        for f in result.findings:
            location = f"{f.file}:{f.line}" if f.line else f.file
            table.add_row(
                Text(f.severity.value.upper(), style=SEVERITY_STYLE[f.severity]),
                f.rule_id,
                Text.assemble((f.title, "bold"), "\n", (f.remediation, "dim")),
                location,
            )
        console.print(table)
    else:
        console.print("[bold green]✔ No supply-chain issues found.[/]")
    for warning in result.warnings:
        console.print(f"[yellow]⚠ {warning}[/]")
    if any(f.severity.rank >= Severity.HIGH.rank for f in result.findings):
        console.print(
            f"[dim]Found something serious in an open-source project? Report it privately and get paid in "
            f"shielded ZEC: {PROJECT_URL}#-bounties-powered-by-zcash[/]"
        )


def to_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2)


def to_sarif(result: ScanResult) -> dict[str, Any]:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for f in result.findings:
        rules.setdefault(
            f.rule_id,
            {
                "id": f.rule_id,
                "name": f.rule_id.replace("-", ""),
                "shortDescription": {"text": f.category.value + " issue"},
                "helpUri": f"{PROJECT_URL}/blob/main/docs/rules.md#{f.rule_id.lower()}",
                "defaultConfiguration": {"level": SARIF_LEVEL[f.severity]},
                "properties": {
                    "tags": ["security", "supply-chain", f.category.value],
                    "security-severity": SECURITY_SEVERITY[f.severity],
                },
            },
        )
        region = {"startLine": f.line} if f.line else {"startLine": 1}
        results.append(
            {
                "ruleId": f.rule_id,
                "level": SARIF_LEVEL[f.severity],
                "message": {"text": f"{f.title}. {f.description} Fix: {f.remediation}".strip()},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": f.file}, "region": region}}
                ],
                "partialFingerprints": {"ztrust/v1": f.fingerprint},
                "properties": {"severity": f.severity.value, "package": f.package, "references": f.references},
            }
        )
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ZTrust",
                        "version": __version__,
                        "informationUri": PROJECT_URL,
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def write_report(result: ScanResult, fmt: str, stream: IO[str]) -> None:
    if fmt == "json":
        stream.write(to_json(result) + "\n")
    elif fmt == "sarif":
        stream.write(json.dumps(to_sarif(result), indent=2) + "\n")
    else:
        render_console(result, Console(file=stream, force_terminal=False, width=140))
