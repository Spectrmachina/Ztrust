"""Supply-chain integrity checks: pinning, hashes, sources and install-time code."""

from __future__ import annotations

import json
import re
from collections import defaultdict

from ztrust.models import Category, Dependency, Finding, Severity
from ztrust.scanners.base import ScanContext, Scanner

LIFECYCLE_SCRIPTS = ("preinstall", "install", "postinstall", "prepare", "prepublish")
DANGEROUS_SCRIPT = re.compile(
    r"(curl|wget|Invoke-WebRequest|iwr)\b.*\|\s*(sudo\s+)?(sh|bash|zsh|node|python3?)\b"
    r"|\beval\b|base64\s+(-d|--decode)|node\s+-e\b|python3?\s+-c\b",
    re.IGNORECASE,
)
PIPE_TO_SHELL = re.compile(r"\b(curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b")
PIPE_TO_SHELL_FILES = re.compile(r"(^Dockerfile.*|.*\.dockerfile|.*\.sh|Makefile|.*\.mk)$")
NON_REGISTRY = re.compile(r"^(git\+|git:|github:|https://codeload\.github\.com|https://github\.com/.+\.tar\.gz)")


def _names(deps: list[Dependency], limit: int = 10) -> str:
    names = sorted({d.name for d in deps})
    shown = ", ".join(f"`{n}`" for n in names[:limit])
    return shown + (f" and {len(names) - limit} more" if len(names) > limit else "")


class IntegrityScanner(Scanner):
    name = "integrity"
    description = "Lockfile integrity, pinning, untrusted sources and install scripts"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        findings += self._dependency_sources(ctx.dependencies)
        findings += self._python_pinning(ctx.dependencies)
        findings += self._npm_install_scripts(ctx.dependencies)
        findings += self._package_json_scripts(ctx)
        findings += self._pipe_to_shell(ctx)
        return findings

    @staticmethod
    def _dependency_sources(deps: list[Dependency]) -> list[Finding]:
        findings = []
        for dep in deps:
            resolved = dep.resolved or ""
            if resolved.startswith("http://"):
                findings.append(
                    Finding(
                        rule_id="ZT-INT-002",
                        title=f"`{dep.name}` is downloaded over plain HTTP",
                        severity=Severity.HIGH,
                        category=Category.INTEGRITY,
                        file=dep.manifest,
                        line=dep.line,
                        package=dep.purl_like,
                        description=f"Resolved URL `{resolved}` can be tampered with in transit.",
                        remediation="Use an HTTPS registry and regenerate the lockfile.",
                    )
                )
            elif NON_REGISTRY.match(resolved):
                findings.append(
                    Finding(
                        rule_id="ZT-INT-003",
                        title=f"`{dep.name}` is installed from a git/tarball source",
                        severity=Severity.MEDIUM,
                        category=Category.INTEGRITY,
                        file=dep.manifest,
                        line=dep.line,
                        package=dep.purl_like,
                        description=f"`{resolved}` bypasses registry provenance and may change under you.",
                        remediation="Prefer a published, versioned release; if you must use git, pin a full commit SHA.",
                    )
                )
            if (
                dep.ecosystem == "npm"
                and dep.manifest.endswith("package-lock.json")
                and resolved.startswith("https://")
                and not dep.integrity
            ):
                findings.append(
                    Finding(
                        rule_id="ZT-INT-001",
                        title=f"Lockfile entry for `{dep.name}` has no integrity hash",
                        severity=Severity.MEDIUM,
                        category=Category.INTEGRITY,
                        file=dep.manifest,
                        package=dep.purl_like,
                        description="Without an `integrity` field npm cannot detect a swapped tarball.",
                        remediation="Delete the entry and run `npm install` to regenerate a lockfile with SRI hashes.",
                    )
                )
        return findings

    @staticmethod
    def _python_pinning(deps: list[Dependency]) -> list[Finding]:
        findings = []
        by_manifest: dict[str, list[Dependency]] = defaultdict(list)
        for dep in deps:
            if dep.ecosystem == "PyPI" and dep.manifest.endswith((".txt", ".in")):
                by_manifest[dep.manifest].append(dep)
        for manifest, items in by_manifest.items():
            unpinned = [d for d in items if not d.pinned]
            if unpinned:
                findings.append(
                    Finding(
                        rule_id="ZT-INT-004",
                        title=f"{len(unpinned)} unpinned Python requirement(s)",
                        severity=Severity.LOW,
                        category=Category.INTEGRITY,
                        file=manifest,
                        description=f"Not pinned with `==`: {_names(unpinned)}. A compromised future release "
                        "would be installed automatically.",
                        remediation="Pin exact versions (e.g. with `pip-compile` or `uv pip compile`).",
                    )
                )
            if not any(d.hashed for d in items):
                findings.append(
                    Finding(
                        rule_id="ZT-INT-005",
                        title="Requirements are not hash-locked",
                        severity=Severity.INFO,
                        category=Category.INTEGRITY,
                        file=manifest,
                        description="pip cannot verify that downloaded artifacts match what you reviewed.",
                        remediation="Generate hashes with `pip-compile --generate-hashes` and install with "
                        "`pip install --require-hashes`.",
                        references=["https://pip.pypa.io/en/stable/topics/secure-installs/"],
                    )
                )
        return findings

    @staticmethod
    def _npm_install_scripts(deps: list[Dependency]) -> list[Finding]:
        findings = []
        by_manifest: dict[str, list[Dependency]] = defaultdict(list)
        for dep in deps:
            if dep.has_install_script:
                by_manifest[dep.manifest].append(dep)
        for manifest, items in by_manifest.items():
            findings.append(
                Finding(
                    rule_id="ZT-INT-006",
                    title=f"{len(items)} dependencies run code at install time",
                    severity=Severity.LOW,
                    category=Category.INTEGRITY,
                    file=manifest,
                    description=f"Packages with install scripts: {_names(items)}. Install hooks are the main "
                    "execution vector of npm worms.",
                    remediation="Install with `npm ci --ignore-scripts` in CI and allow scripts only where needed.",
                )
            )
        return findings

    @staticmethod
    def _package_json_scripts(ctx: ScanContext) -> list[Finding]:
        findings = []
        for path in ctx.files():
            if path.name != "package.json":
                continue
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                continue
            scripts = data.get("scripts") or {}
            for hook in LIFECYCLE_SCRIPTS:
                command = scripts.get(hook)
                if isinstance(command, str) and DANGEROUS_SCRIPT.search(command):
                    findings.append(
                        Finding(
                            rule_id="ZT-INT-007",
                            title=f"Dangerous `{hook}` lifecycle script",
                            severity=Severity.HIGH,
                            category=Category.INTEGRITY,
                            file=ctx.rel(path),
                            description=f"`{hook}` runs `{command[:160]}` on every install — downloading or "
                            "evaluating remote code is a classic supply-chain backdoor pattern.",
                            remediation="Remove remote code execution from lifecycle scripts; vendor and review "
                            "any required tooling.",
                        )
                    )
        return findings

    @staticmethod
    def _pipe_to_shell(ctx: ScanContext) -> list[Finding]:
        findings = []
        for path in ctx.files():
            if not PIPE_TO_SHELL_FILES.match(path.name):
                continue
            text = ctx.read_text(path)
            if not text:
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if "ztrust:ignore" not in line and PIPE_TO_SHELL.search(line):
                    findings.append(
                        Finding(
                            rule_id="ZT-INT-008",
                            title="Remote script piped directly into a shell",
                            severity=Severity.MEDIUM,
                            category=Category.INTEGRITY,
                            file=ctx.rel(path),
                            line=lineno,
                            description="`curl | sh` executes whatever the server returns, with no integrity check.",
                            remediation="Download to a file, verify a pinned checksum or signature, then execute.",
                        )
                    )
        return findings
