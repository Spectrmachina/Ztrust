"""Core data model shared by scanners, reporters and the bounty service."""

from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self.value]

    @classmethod
    def parse(cls, value: str | Severity) -> Severity:
        if isinstance(value, Severity):
            return value
        normalized = str(value).strip().lower()
        aliases = {"moderate": "medium", "warning": "medium", "error": "high", "none": "info"}
        return cls(aliases.get(normalized, normalized))


_SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Category(str, Enum):
    VULNERABILITY = "vulnerability"
    MALWARE = "malware"
    SECRET = "secret"
    TYPOSQUAT = "typosquat"
    INTEGRITY = "integrity"
    CI_CD = "ci-cd"


@dataclass
class Dependency:
    """A single resolved (or declared) third-party package."""

    name: str
    version: str | None
    ecosystem: str  # OSV ecosystem name: npm, PyPI, Go, crates.io
    manifest: str  # path relative to the scan root
    line: int | None = None
    direct: bool = True
    resolved: str | None = None
    integrity: str | None = None
    has_install_script: bool = False
    pinned: bool = True
    hashed: bool = False

    @property
    def key(self) -> tuple[str, str, str]:
        return (self.ecosystem, self.name.lower(), self.version or "")

    @property
    def purl_like(self) -> str:
        return f"{self.name}@{self.version}" if self.version else self.name


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    category: Category
    file: str
    description: str
    line: int | None = None
    remediation: str = ""
    package: str | None = None
    references: list[str] = field(default_factory=list)

    @property
    def fingerprint(self) -> str:
        """Stable identifier used for de-duplication, SARIF and bounty claims."""
        raw = "|".join([self.rule_id, self.file, str(self.line or ""), self.package or "", self.title])
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        data["category"] = self.category.value
        data["fingerprint"] = self.fingerprint
        return data


@dataclass
class ScanResult:
    root: str
    findings: list[Finding]
    dependencies: list[Dependency]
    scanners: list[str]
    warnings: list[str]
    duration_s: float

    def counts(self) -> dict[str, int]:
        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def max_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: s.rank)

    def to_dict(self) -> dict[str, Any]:
        return {
            "root": self.root,
            "scanners": self.scanners,
            "duration_s": round(self.duration_s, 3),
            "summary": self.counts(),
            "dependencies": len(self.dependencies),
            "warnings": self.warnings,
            "findings": [f.to_dict() for f in self.findings],
        }
