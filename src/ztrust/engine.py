"""Scan orchestration and policy application."""

from __future__ import annotations

import time
from collections.abc import Iterable
from pathlib import Path

from ztrust.config import Config, load_config
from ztrust.manifests import collect_dependencies
from ztrust.models import Finding, ScanResult
from ztrust.scanners import ScanContext, Scanner, default_scanners


def _package_name(package: str) -> str:
    at = package.rfind("@")
    return (package[:at] if at > 0 else package).lower()


def apply_policy(findings: Iterable[Finding], config: Config) -> list[Finding]:
    result: dict[str, Finding] = {}
    for finding in findings:
        if config.rule_disabled(finding.rule_id):
            continue
        if finding.package and _package_name(finding.package) in config.allowlist_packages:
            continue
        override = config.severity_overrides.get(finding.rule_id)
        if override:
            finding.severity = override
        result.setdefault(finding.fingerprint, finding)
    return sorted(result.values(), key=lambda f: (-f.severity.rank, f.file, f.line or 0, f.rule_id))


def run_scan(
    root: str | Path,
    config: Config | None = None,
    offline: bool = False,
    only: set[str] | None = None,
    scanners: list[Scanner] | None = None,
) -> ScanResult:
    started = time.perf_counter()
    root_path = Path(root).resolve()
    if not root_path.is_dir():
        raise NotADirectoryError(f"{root_path} is not a directory")
    config = config or load_config(root_path)
    ctx = ScanContext(root=root_path, config=config, offline=offline)
    ctx.dependencies = collect_dependencies(ctx)

    findings: list[Finding] = []
    ran: list[str] = []
    for scanner in scanners if scanners is not None else default_scanners():
        if only and scanner.name not in only:
            continue
        try:
            findings.extend(scanner.scan(ctx))
            ran.append(scanner.name)
        except Exception as exc:  # a broken scanner must never hide the others' results
            ctx.warnings.append(f"{scanner.name} scanner failed: {exc}")

    return ScanResult(
        root=str(root_path),
        findings=apply_policy(findings, config),
        dependencies=ctx.dependencies,
        scanners=ran,
        warnings=ctx.warnings,
        duration_s=time.perf_counter() - started,
    )
