"""Parsers that turn manifests and lockfiles into a flat dependency inventory.

Supported: requirements*.txt, poetry.lock, uv.lock, package-lock.json (v1-v3),
package.json (fallback when no lockfile), go.mod, Cargo.lock.
"""

from __future__ import annotations

import json
import re
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import TYPE_CHECKING

from ztrust.models import Dependency

if TYPE_CHECKING:  # avoid a circular import with ztrust.scanners
    from ztrust.scanners.base import ScanContext

REQ_LINE = re.compile(
    r"^\s*([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(\[[^\]]*\])?\s*"
    r"(?:(===|==|~=|!=|>=|<=|>|<)\s*([A-Za-z0-9*+!._\-]+))?"
)
EXACT_SEMVER = re.compile(r"^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?$")
REQUIREMENTS_NAME = re.compile(r"^requirements.*\.(txt|in)$|.*requirements\.txt$")


def normalize_pypi(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(path: Path, rel: str) -> list[Dependency]:
    deps: list[Dependency] = []
    logical: list[tuple[int, str]] = []
    buf, start = "", None
    for lineno, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
        if start is None:
            start = lineno
        stripped = line.rstrip()
        if stripped.endswith("\\"):
            buf += stripped[:-1] + " "
            continue
        logical.append((start, buf + line))
        buf, start = "", None
    if buf and start is not None:
        logical.append((start, buf))

    for lineno, raw in logical:
        hashed = "--hash" in raw
        text = raw.strip()
        if not text or text.startswith("#") or text.startswith("-"):
            continue
        text = re.split(r"\s+#", text, maxsplit=1)[0]
        text = text.split(" --", 1)[0].split(";", 1)[0].strip()
        if " @ " in text:  # PEP 508 direct reference: name @ url
            name, url = (part.strip() for part in text.split(" @ ", 1))
            deps.append(
                Dependency(
                    name=normalize_pypi(name.split("[")[0]),
                    version=None,
                    ecosystem="PyPI",
                    manifest=rel,
                    line=lineno,
                    resolved=url,
                    pinned=False,
                    hashed=hashed,
                )
            )
            continue
        if "://" in text or text.startswith((".", "/")):
            continue
        match = REQ_LINE.match(text)
        if not match:
            continue
        name, _extras, op, version = match.groups()
        pinned = op in ("==", "===") and version is not None and "*" not in version
        deps.append(
            Dependency(
                name=normalize_pypi(name),
                version=version if pinned else None,
                ecosystem="PyPI",
                manifest=rel,
                line=lineno,
                pinned=pinned,
                hashed=hashed,
            )
        )
    return deps


def parse_package_lock(path: Path, rel: str) -> list[Dependency]:
    data = json.loads(path.read_text(encoding="utf-8"))
    deps: list[Dependency] = []
    packages = data.get("packages")
    if isinstance(packages, dict):  # lockfileVersion 2 / 3
        for key, meta in packages.items():
            if not key or "node_modules/" not in key or meta.get("link"):
                continue
            name = meta.get("name") or key.rsplit("node_modules/", 1)[-1]
            deps.append(
                Dependency(
                    name=name,
                    version=meta.get("version"),
                    ecosystem="npm",
                    manifest=rel,
                    direct=key.count("node_modules/") == 1,
                    resolved=meta.get("resolved"),
                    integrity=meta.get("integrity"),
                    has_install_script=bool(meta.get("hasInstallScript")),
                    hashed=bool(meta.get("integrity")),
                )
            )
        return deps

    def walk(tree: dict | None, depth: int) -> None:  # lockfileVersion 1
        for name, meta in (tree or {}).items():
            deps.append(
                Dependency(
                    name=name,
                    version=meta.get("version"),
                    ecosystem="npm",
                    manifest=rel,
                    direct=depth == 0,
                    resolved=meta.get("resolved"),
                    integrity=meta.get("integrity"),
                    hashed=bool(meta.get("integrity")),
                )
            )
            walk(meta.get("dependencies"), depth + 1)

    walk(data.get("dependencies"), 0)
    return deps


def parse_package_json(path: Path, rel: str) -> list[Dependency]:
    if (path.parent / "package-lock.json").exists():
        return []  # the lockfile is the source of truth
    data = json.loads(path.read_text(encoding="utf-8"))
    deps: list[Dependency] = []
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        for name, spec in (data.get(section) or {}).items():
            spec = str(spec).strip()
            exact = spec.lstrip("=v") if EXACT_SEMVER.match(spec.lstrip("=v")) else None
            resolved = spec if re.match(r"^(git\+|git:|github:|https?:|file:)", spec) else None
            deps.append(
                Dependency(
                    name=name,
                    version=exact,
                    ecosystem="npm",
                    manifest=rel,
                    pinned=exact is not None,
                    resolved=resolved,
                )
            )
    return deps


def parse_go_mod(path: Path, rel: str) -> list[Dependency]:
    deps: list[Dependency] = []
    in_block = False
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        stripped = line.strip()
        if re.match(r"^require\s*\($", stripped):
            in_block = True
            continue
        if in_block and stripped == ")":
            in_block = False
            continue
        body = stripped.split("//", 1)[0].strip()
        if in_block:
            parts = body.split()
        elif body.startswith("require "):
            parts = body[len("require ") :].split()
        else:
            continue
        if len(parts) >= 2:
            deps.append(
                Dependency(
                    name=parts[0],
                    version=parts[1].lstrip("v").removesuffix("+incompatible"),
                    ecosystem="Go",
                    manifest=rel,
                    line=lineno,
                    direct="// indirect" not in line,
                )
            )
    return deps


def parse_cargo_lock(path: Path, rel: str) -> list[Dependency]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return [
        Dependency(
            name=pkg["name"],
            version=pkg.get("version"),
            ecosystem="crates.io",
            manifest=rel,
            resolved=pkg.get("source"),
            integrity=pkg.get("checksum"),
            hashed=bool(pkg.get("checksum")),
        )
        for pkg in data.get("package", [])
        if "source" in pkg
    ]


def parse_poetry_lock(path: Path, rel: str) -> list[Dependency]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    return [
        Dependency(
            name=normalize_pypi(pkg["name"]),
            version=pkg.get("version"),
            ecosystem="PyPI",
            manifest=rel,
            hashed=bool(pkg.get("files")),
        )
        for pkg in data.get("package", [])
    ]


def parse_uv_lock(path: Path, rel: str) -> list[Dependency]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    deps = []
    for pkg in data.get("package", []):
        source = pkg.get("source") or {}
        if "editable" in source or "virtual" in source or "directory" in source:
            continue
        deps.append(
            Dependency(
                name=normalize_pypi(pkg["name"]),
                version=pkg.get("version"),
                ecosystem="PyPI",
                manifest=rel,
                resolved=source.get("url") or source.get("git"),
                hashed=bool(pkg.get("sdist") or pkg.get("wheels")),
            )
        )
    return deps


PARSERS: dict[str, Callable[[Path, str], list[Dependency]]] = {
    "package-lock.json": parse_package_lock,
    "package.json": parse_package_json,
    "go.mod": parse_go_mod,
    "Cargo.lock": parse_cargo_lock,
    "poetry.lock": parse_poetry_lock,
    "uv.lock": parse_uv_lock,
}


def parser_for(path: Path) -> Callable[[Path, str], list[Dependency]] | None:
    if path.name in PARSERS:
        return PARSERS[path.name]
    if REQUIREMENTS_NAME.match(path.name) or (path.parent.name == "requirements" and path.suffix == ".txt"):
        return parse_requirements
    return None


def collect_dependencies(ctx: ScanContext) -> list[Dependency]:
    deps: list[Dependency] = []
    seen: set[tuple[tuple[str, str, str], str]] = set()
    for path in ctx.files():
        parser = parser_for(path)
        if parser is None:
            continue
        rel = ctx.rel(path)
        try:
            parsed = parser(path, rel)
        except (ValueError, KeyError, OSError, tomllib.TOMLDecodeError) as exc:
            ctx.warnings.append(f"could not parse {rel}: {exc}")
            continue
        for dep in parsed:
            marker = (dep.key, dep.manifest)
            if marker not in seen:
                seen.add(marker)
                deps.append(dep)
    return deps
