"""Scanner interface and shared scan context."""

from __future__ import annotations

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

from ztrust.config import Config
from ztrust.models import Dependency, Finding

SKIP_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "node_modules",
    ".venv",
    "venv",
    "env",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".tox",
    ".nox",
    "dist",
    "build",
    "target",
    ".next",
    ".idea",
    ".vscode",
}

MAX_TEXT_FILE_BYTES = 1_000_000


@dataclass
class ScanContext:
    root: Path
    config: Config
    offline: bool = False
    dependencies: list[Dependency] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    _files: list[Path] | None = None

    def rel(self, path: Path) -> str:
        return path.relative_to(self.root).as_posix()

    def files(self) -> list[Path]:
        if self._files is None:
            found: list[Path] = []
            for dirpath, dirnames, filenames in os.walk(self.root):
                current = Path(dirpath)
                dirnames[:] = sorted(
                    d for d in dirnames if d not in SKIP_DIRS and not self.config.is_excluded(self.rel(current / d))
                )
                for name in filenames:
                    path = current / name
                    if path.is_symlink():
                        continue
                    if not self.config.is_excluded(self.rel(path)):
                        found.append(path)
            self._files = sorted(found)
        return self._files

    @staticmethod
    def read_text(path: Path) -> str | None:
        """Read a text file, returning ``None`` for binaries and oversized files."""
        try:
            if path.stat().st_size > MAX_TEXT_FILE_BYTES:
                return None
            raw = path.read_bytes()
        except OSError:
            return None
        if b"\x00" in raw[:8192]:
            return None
        return raw.decode("utf-8", errors="replace")


class Scanner(ABC):
    name: str = "base"
    description: str = ""

    @abstractmethod
    def scan(self, ctx: ScanContext) -> list[Finding]:
        raise NotImplementedError
