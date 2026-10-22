"""Typosquatting / look-alike package detection.

A dependency is suspicious when its name is *almost* the name of a very popular
package in the same ecosystem: one edit away (``reqeusts``), the same name with
separators removed (``crossenv`` vs ``cross-env``) or with look-alike digits
(``l0dash``). Real attacks of exactly this shape have shipped malware to npm and
PyPI many times.
"""

from __future__ import annotations

import re

from ztrust.manifests import normalize_pypi
from ztrust.models import Category, Finding, Severity
from ztrust.scanners.base import ScanContext, Scanner

POPULAR: dict[str, list[str]] = {
    "npm": [
        "react", "react-dom", "lodash", "express", "axios", "chalk", "commander", "debug", "moment",
        "request", "vue", "webpack", "typescript", "eslint", "prettier", "jest", "mocha", "uuid",
        "dotenv", "yargs", "minimist", "async", "bluebird", "underscore", "jquery", "colors", "color",
        "semver", "glob", "rimraf", "mkdirp", "fs-extra", "body-parser", "cors", "jsonwebtoken",
        "bcrypt", "mongoose", "socket.io", "next", "nuxt", "vite", "rollup", "esbuild", "tslib",
        "rxjs", "classnames", "prop-types", "redux", "react-redux", "styled-components", "node-fetch",
        "cross-env", "nodemon", "ws", "cheerio", "puppeteer", "sharp", "dayjs", "date-fns", "zod",
        "inquirer", "ora", "electron", "event-stream", "ua-parser-js", "coffee-script", "babel-cli",
        "angular", "svelte", "tailwindcss", "postcss", "autoprefixer", "nanoid", "qs", "mime",
    ],
    "PyPI": [
        "requests", "urllib3", "numpy", "pandas", "django", "flask", "fastapi", "boto3", "botocore",
        "setuptools", "pip", "wheel", "python-dateutil", "pyyaml", "cryptography", "certifi", "idna",
        "charset-normalizer", "attrs", "pydantic", "jinja2", "click", "pytest", "sqlalchemy", "scipy",
        "matplotlib", "pillow", "tensorflow", "torch", "scikit-learn", "beautifulsoup4", "selenium",
        "colorama", "tqdm", "rich", "httpx", "aiohttp", "psycopg2", "pymongo", "redis", "celery",
        "gunicorn", "uvicorn", "openai", "anthropic", "transformers", "lxml", "paramiko", "docutils",
        "packaging", "typing-extensions", "protobuf", "grpcio", "virtualenv", "black", "ruff", "mypy",
        "toml", "tomli", "markupsafe", "werkzeug", "itsdangerous", "jmespath", "s3transfer", "pyjwt",
        "websocket-client", "pycparser", "cffi", "openpyxl", "pyopenssl", "keras",
    ],
    "crates.io": [
        "serde", "tokio", "rand", "clap", "regex", "reqwest", "hyper", "anyhow", "thiserror", "log",
        "chrono", "syn", "quote", "futures", "serde_json", "lazy_static", "once_cell", "bytes",
        "tracing", "libc", "base64", "itertools", "uuid", "url",
    ],
}

HOMOGLYPHS = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "7": "t", "4": "a"})
MIN_LENGTH = 4


def damerau_levenshtein(a: str, b: str) -> int:
    """Optimal-string-alignment distance (adjacent transpositions cost 1)."""
    if a == b:
        return 0
    if abs(len(a) - len(b)) > 2:
        return 3
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[len(a)][len(b)]


def _strip_separators(name: str) -> str:
    return re.sub(r"[-_.]", "", name)


def find_lookalike(name: str, ecosystem: str) -> tuple[str, str] | None:
    """Return ``(popular_name, reason)`` if *name* imitates a popular package."""
    popular = POPULAR.get(ecosystem)
    if not popular or name.startswith("@") or len(name) < MIN_LENGTH:
        return None
    candidate = normalize_pypi(name) if ecosystem == "PyPI" else name.lower()
    names = [normalize_pypi(p) if ecosystem == "PyPI" else p for p in popular]
    if candidate in names:
        return None
    for target in names:
        if len(target) < MIN_LENGTH:
            continue
        if _strip_separators(candidate) == _strip_separators(target):
            return target, "same name with different separators"
        if candidate.translate(HOMOGLYPHS) == target:
            return target, "look-alike characters"
        if damerau_levenshtein(candidate, target) == 1:
            return target, "one character away"
    return None


class TyposquatScanner(Scanner):
    name = "typosquat"
    description = "Dependencies whose names imitate popular packages"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()
        for dep in ctx.dependencies:
            marker = (dep.ecosystem, dep.name.lower())
            if marker in seen or dep.name.lower() in ctx.config.allowlist_packages:
                continue
            seen.add(marker)
            hit = find_lookalike(dep.name, dep.ecosystem)
            if not hit:
                continue
            target, reason = hit
            findings.append(
                Finding(
                    rule_id="ZT-TYPO-001",
                    title=f"Possible typosquat: `{dep.name}` imitates `{target}`",
                    severity=Severity.HIGH,
                    category=Category.TYPOSQUAT,
                    file=dep.manifest,
                    line=dep.line,
                    package=dep.purl_like,
                    description=f"`{dep.name}` ({dep.ecosystem}) differs from the popular package "
                    f"`{target}` only by {reason}. Typosquatted packages are a common malware vector.",
                    remediation=f"Verify you meant `{dep.name}`. If not, replace it with `{target}` and audit "
                    "any machine that installed it. If it is intentional, add it to `allowlist_packages`.",
                    references=["https://owasp.org/www-project-top-10-ci-cd-security-risks/"],
                )
            )
        return findings
