"""Leaked-credential detection: provider-specific patterns + entropy heuristics."""

from __future__ import annotations

import math
import re
from collections import Counter
from dataclasses import dataclass
from pathlib import Path

from ztrust.models import Category, Finding, Severity
from ztrust.scanners.base import ScanContext, Scanner

IGNORE_MARKER = "ztrust:ignore"

SKIP_FILENAMES = {
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "poetry.lock",
    "uv.lock",
    "Cargo.lock",
    "go.sum",
    "composer.lock",
    "Gemfile.lock",
}
SKIP_SUFFIXES = {".min.js", ".map", ".svg", ".lock"}


@dataclass(frozen=True)
class SecretRule:
    rule_id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    remediation: str = "Revoke the credential immediately, rotate it and purge it from git history."


def _rule(rule_id: str, name: str, regex: str, severity: Severity) -> SecretRule:
    return SecretRule(rule_id, name, re.compile(regex), severity)


RULES: list[SecretRule] = [
    _rule("ZT-SEC-001", "AWS access key ID", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", Severity.HIGH),
    _rule("ZT-SEC-002", "GitHub token", r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b", Severity.CRITICAL),
    _rule("ZT-SEC-003", "GitHub fine-grained PAT", r"\bgithub_pat_[A-Za-z0-9_]{82}\b", Severity.CRITICAL),
    _rule("ZT-SEC-004", "GitLab personal access token", r"\bglpat-[A-Za-z0-9_\-]{20}\b", Severity.CRITICAL),
    _rule("ZT-SEC-005", "npm access token", r"\bnpm_[A-Za-z0-9]{36}\b", Severity.CRITICAL),
    _rule("ZT-SEC-006", "PyPI API token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,}", Severity.CRITICAL),
    _rule("ZT-SEC-007", "Slack token", r"\bxox[abprs]-[A-Za-z0-9-]{10,}", Severity.HIGH),
    _rule("ZT-SEC-008", "Stripe live key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b", Severity.CRITICAL),
    _rule("ZT-SEC-009", "Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", Severity.HIGH),
    _rule(
        "ZT-SEC-010",
        "Private key block",
        r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----",
        Severity.CRITICAL,
    ),
    _rule(
        "ZT-SEC-011",
        "Zcash Sapling spending key",
        r"\bsecret-extended-key-(?:main|test)1[02-9ac-hj-np-z]{200,}\b",
        Severity.CRITICAL,
    ),
    _rule("ZT-SEC-012", "Anthropic API key", r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}", Severity.CRITICAL),
    _rule("ZT-SEC-013", "OpenAI API key", r"\bsk-(?:proj|svcacct)-[A-Za-z0-9_\-]{40,}", Severity.CRITICAL),
]

GENERIC_ASSIGNMENT = re.compile(
    r"(?i)(?:api[_-]?key|secret|token|passw(?:or)?d|credential|auth[_-]?key)[A-Za-z0-9_\-]*"
    r"\s*[:=]\s*[\"']([^\"'\s]{16,})[\"']"
)
PLACEHOLDER_HINTS = ("example", "changeme", "change-me", "xxxx", "your_", "your-", "dummy", "sample", "<", "${", "{{")
ENTROPY_THRESHOLD = 3.5


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def redact(secret: str) -> str:
    return f"{secret[:4]}…({len(secret)} chars)" if len(secret) > 8 else "****"


class SecretsScanner(Scanner):
    name = "secrets"
    description = "Hard-coded credentials, private keys and Zcash spending keys"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        allow = [re.compile(p) for p in ctx.config.secrets_allowlist]
        findings: list[Finding] = []
        for path in ctx.files():
            if self._skip(path):
                continue
            rel = ctx.rel(path)
            if path.name == ".env" or (path.name.startswith(".env.") and not path.name.endswith((".example", ".sample", ".template"))):
                findings.append(
                    Finding(
                        rule_id="ZT-SEC-020",
                        title="Environment file committed to the repository",
                        severity=Severity.MEDIUM,
                        category=Category.SECRET,
                        file=rel,
                        description=f"`{rel}` usually contains runtime secrets and should not be versioned.",
                        remediation="Add the file to .gitignore, commit a `.env.example` instead and rotate its values.",
                    )
                )
            text = ctx.read_text(path)
            if text is None:
                continue
            findings.extend(self._scan_text(text, rel, allow))
        return findings

    @staticmethod
    def _skip(path: Path) -> bool:
        return path.name in SKIP_FILENAMES or any(path.name.endswith(s) for s in SKIP_SUFFIXES)

    def _scan_text(self, text: str, rel: str, allow: list[re.Pattern[str]]) -> list[Finding]:
        findings: list[Finding] = []
        for lineno, line in enumerate(text.splitlines(), 1):
            if IGNORE_MARKER in line or len(line) > 4000:
                continue
            matched_specific = False
            for rule in RULES:
                for match in rule.pattern.finditer(line):
                    secret = match.group(0)
                    if any(a.search(secret) for a in allow):
                        continue
                    matched_specific = True
                    findings.append(
                        Finding(
                            rule_id=rule.rule_id,
                            title=f"{rule.name} detected",
                            severity=rule.severity,
                            category=Category.SECRET,
                            file=rel,
                            line=lineno,
                            description=f"Possible {rule.name} `{redact(secret)}` committed in source.",
                            remediation=rule.remediation,
                        )
                    )
            if matched_specific:
                continue
            for match in GENERIC_ASSIGNMENT.finditer(line):
                value = match.group(1)
                lowered = value.lower()
                if any(h in lowered for h in PLACEHOLDER_HINTS) or any(a.search(value) for a in allow):
                    continue
                if shannon_entropy(value) < ENTROPY_THRESHOLD:
                    continue
                findings.append(
                    Finding(
                        rule_id="ZT-SEC-030",
                        title="High-entropy secret assigned in code",
                        severity=Severity.MEDIUM,
                        category=Category.SECRET,
                        file=rel,
                        line=lineno,
                        description=f"Value `{redact(value)}` looks like a credential "
                        f"(entropy {shannon_entropy(value):.2f} bits/char).",
                        remediation="Load secrets from the environment or a secret manager. "
                        f"If this is a false positive, add `# {IGNORE_MARKER}` to the line.",
                    )
                )
        return findings
