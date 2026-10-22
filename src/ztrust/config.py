"""Loading of the optional ``.ztrust.yml`` policy file."""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from ztrust.models import Severity

DEFAULT_FILENAMES = (".ztrust.yml", ".ztrust.yaml")


@dataclass
class BountyConfig:
    program_id: str | None = None
    api_url: str | None = None
    funding_address: str | None = None


@dataclass
class Config:
    exclude: list[str] = field(default_factory=list)
    disable_rules: list[str] = field(default_factory=list)
    severity_overrides: dict[str, Severity] = field(default_factory=dict)
    allowlist_packages: set[str] = field(default_factory=set)
    secrets_allowlist: list[str] = field(default_factory=list)
    fail_on: Severity | None = None
    bounty: BountyConfig = field(default_factory=BountyConfig)

    def is_excluded(self, rel_path: str) -> bool:
        for pattern in self.exclude:
            base = pattern[:-3] if pattern.endswith("/**") else pattern.rstrip("/")
            if fnmatch.fnmatch(rel_path, pattern) or rel_path == base or rel_path.startswith(base + "/"):
                return True
        return False

    def rule_disabled(self, rule_id: str) -> bool:
        return any(fnmatch.fnmatch(rule_id, pattern) for pattern in self.disable_rules)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Config:
        bounty = data.get("bounty") or {}
        fail_on = data.get("fail_on")
        return cls(
            exclude=[str(p) for p in data.get("exclude") or []],
            disable_rules=[str(r) for r in data.get("disable_rules") or []],
            severity_overrides={
                str(k): Severity.parse(v) for k, v in (data.get("severity_overrides") or {}).items()
            },
            allowlist_packages={str(p).lower() for p in data.get("allowlist_packages") or []},
            secrets_allowlist=[str(r) for r in data.get("secrets_allowlist") or []],
            fail_on=Severity.parse(fail_on) if fail_on else None,
            bounty=BountyConfig(
                program_id=bounty.get("program_id"),
                api_url=bounty.get("api_url"),
                funding_address=bounty.get("funding_address"),
            ),
        )


def load_config(root: Path, explicit: Path | None = None) -> Config:
    candidates = [explicit] if explicit else [root / name for name in DEFAULT_FILENAMES]
    for path in candidates:
        if path and path.is_file():
            data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if not isinstance(data, dict):
                raise ValueError(f"{path}: top-level YAML value must be a mapping")
            return Config.from_dict(data)
    if explicit:
        raise FileNotFoundError(explicit)
    return Config()
