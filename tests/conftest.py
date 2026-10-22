from __future__ import annotations

import os
from pathlib import Path

import pytest

from ztrust.bounty.zcash import bech32_encode, convertbits


def make_sapling_address(seed: int = 1, network: str = "main") -> str:
    """A checksum-valid Sapling address built from deterministic bytes (not a real wallet)."""
    payload = bytes((seed * 7 + i) % 256 for i in range(43))
    return bech32_encode("zs" if network == "main" else "ztestsapling", convertbits(payload, 8, 5), "bech32")


def make_unified_address(seed: int = 1, network: str = "main") -> str:
    payload = bytes((seed * 13 + i) % 256 for i in range(80))
    return bech32_encode("u" if network == "main" else "utest", convertbits(payload, 8, 5), "bech32m")


def write(root: Path, rel: str, content: str) -> Path:
    path = root / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("ZTRUST_"):
            monkeypatch.delenv(key, raising=False)
