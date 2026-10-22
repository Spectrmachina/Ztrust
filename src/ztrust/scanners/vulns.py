"""Known-vulnerability and known-malware lookup via the OSV.dev API.

OSV aggregates GitHub Security Advisories, PyPA, RustSec, Go vulndb and the
OpenSSF malicious-packages feed (``MAL-`` identifiers).
API docs: https://google.github.io/osv.dev/api/
"""

from __future__ import annotations

import json
import math
import urllib.error
import urllib.request
from typing import Any

from ztrust import __version__
from ztrust.manifests import normalize_pypi
from ztrust.models import Category, Dependency, Finding, Severity
from ztrust.scanners.base import ScanContext, Scanner

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{id}"
BATCH_SIZE = 500
MAX_DETAIL_LOOKUPS = 300

# --------------------------------------------------------------------------- CVSS v3.x

_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
_AC = {"L": 0.77, "H": 0.44}
_UI = {"N": 0.85, "R": 0.62}
_CIA = {"H": 0.56, "L": 0.22, "N": 0.0}


def _roundup(value: float) -> float:
    as_int = round(value * 100_000)
    if as_int % 10_000 == 0:
        return as_int / 100_000.0
    return (math.floor(as_int / 10_000) + 1) / 10.0


def cvss3_base_score(vector: str) -> float | None:
    """Compute the CVSS v3.0/v3.1 base score from a vector string."""
    try:
        metrics = dict(part.split(":", 1) for part in vector.split("/")[1:])
        changed = metrics["S"] == "C"
        pr = {"N": 0.85, "L": 0.68 if changed else 0.62, "H": 0.5 if changed else 0.27}[metrics["PR"]]
        iss = 1 - (1 - _CIA[metrics["C"]]) * (1 - _CIA[metrics["I"]]) * (1 - _CIA[metrics["A"]])
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15 if changed else 6.42 * iss
        exploitability = 8.22 * _AV[metrics["AV"]] * _AC[metrics["AC"]] * pr * _UI[metrics["UI"]]
    except (KeyError, ValueError):
        return None
    if impact <= 0:
        return 0.0
    total = 1.08 * (impact + exploitability) if changed else impact + exploitability
    return _roundup(min(total, 10.0))


def severity_from_score(score: float) -> Severity:
    if score >= 9.0:
        return Severity.CRITICAL
    if score >= 7.0:
        return Severity.HIGH
    if score >= 4.0:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def vuln_severity(vuln: dict[str, Any]) -> Severity:
    if str(vuln.get("id", "")).startswith("MAL-"):
        return Severity.CRITICAL
    label = (vuln.get("database_specific") or {}).get("severity")
    if isinstance(label, str):
        try:
            return Severity.parse(label)
        except ValueError:
            pass
    for entry in vuln.get("severity") or []:
        if str(entry.get("type", "")).startswith("CVSS_V3"):
            score = cvss3_base_score(str(entry.get("score", "")))
            if score is not None:
                return severity_from_score(score)
    return Severity.MEDIUM


# --------------------------------------------------------------------------- client


class OSVClient:
    def __init__(self, timeout: float = 30.0) -> None:
        self.timeout = timeout
        self._cache: dict[str, dict[str, Any]] = {}

    def _request(self, url: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(
            url,
            data=data,
            method="POST" if data else "GET",
            headers={"Content-Type": "application/json", "User-Agent": f"ztrust/{__version__}"},
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            return json.load(resp)

    def query_batch(self, deps: list[Dependency]) -> list[list[str]]:
        ids: list[list[str]] = []
        for start in range(0, len(deps), BATCH_SIZE):
            chunk = deps[start : start + BATCH_SIZE]
            payload = {
                "queries": [
                    {"package": {"name": d.name, "ecosystem": d.ecosystem}, "version": d.version} for d in chunk
                ]
            }
            results = self._request(OSV_BATCH_URL, payload).get("results", [])
            for result in results:
                ids.append([v["id"] for v in result.get("vulns") or []])
        return ids

    def get_vuln(self, vuln_id: str) -> dict[str, Any]:
        if vuln_id not in self._cache:
            self._cache[vuln_id] = self._request(OSV_VULN_URL.format(id=vuln_id))
        return self._cache[vuln_id]


# --------------------------------------------------------------------------- scanner


def _fixed_versions(vuln: dict[str, Any], dep: Dependency) -> list[str]:
    def norm(name: str) -> str:
        return normalize_pypi(name) if dep.ecosystem == "PyPI" else name.lower()

    fixed: set[str] = set()
    for affected in vuln.get("affected") or []:
        if norm((affected.get("package") or {}).get("name", "")) != norm(dep.name):
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if "fixed" in event:
                    fixed.add(str(event["fixed"]))
    return sorted(fixed)


class OSVScanner(Scanner):
    name = "vulns"
    description = "Known vulnerabilities and malicious packages (OSV.dev)"

    def __init__(self, client: OSVClient | None = None) -> None:
        self.client = client or OSVClient()

    def scan(self, ctx: ScanContext) -> list[Finding]:
        if ctx.offline:
            ctx.warnings.append("offline mode: OSV vulnerability lookup skipped")
            return []
        unique: dict[tuple[str, str, str], Dependency] = {}
        for dep in ctx.dependencies:
            if dep.version:
                unique.setdefault(dep.key, dep)
        queryable = list(unique.values())
        if not queryable:
            return []
        try:
            id_lists = self.client.query_batch(queryable)
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            ctx.warnings.append(f"OSV lookup failed ({exc}); vulnerability results are incomplete")
            return []

        findings: list[Finding] = []
        lookups = 0
        for dep, vuln_ids in zip(queryable, id_lists, strict=False):
            for vuln_id in vuln_ids:
                vuln: dict[str, Any] = {"id": vuln_id}
                if lookups < MAX_DETAIL_LOOKUPS:
                    lookups += 1
                    try:
                        vuln = self.client.get_vuln(vuln_id)
                    except (urllib.error.URLError, TimeoutError, OSError, ValueError):
                        pass
                findings.append(self._to_finding(dep, vuln))
        return findings

    @staticmethod
    def _to_finding(dep: Dependency, vuln: dict[str, Any]) -> Finding:
        vuln_id = vuln["id"]
        malicious = vuln_id.startswith("MAL-")
        summary = vuln.get("summary") or (vuln.get("details") or "").strip().split("\n", 1)[0][:160]
        aliases = [a for a in vuln.get("aliases") or [] if a.startswith(("CVE-", "GHSA-"))]
        fixed = _fixed_versions(vuln, dep)
        if malicious:
            remediation = (
                f"Remove `{dep.name}` immediately, treat every machine that installed it as compromised "
                "and rotate all credentials it could reach."
            )
        elif fixed:
            remediation = f"Upgrade `{dep.name}` to {' / '.join(fixed[-3:])} or later."
        else:
            remediation = "No fixed version is published yet; consider an alternative package or mitigation."
        references = [f"https://osv.dev/vulnerability/{vuln_id}"]
        references += [r["url"] for r in (vuln.get("references") or [])[:3] if r.get("url")]
        return Finding(
            rule_id="ZT-MAL-001" if malicious else "ZT-VULN-001",
            title=f"{vuln_id}: {summary or ('Malicious package' if malicious else 'Known vulnerability')}",
            severity=vuln_severity(vuln),
            category=Category.MALWARE if malicious else Category.VULNERABILITY,
            file=dep.manifest,
            line=dep.line,
            package=dep.purl_like,
            description=f"`{dep.purl_like}` ({dep.ecosystem}) is affected by {vuln_id}"
            + (f" ({', '.join(aliases)})" if aliases else "")
            + ".",
            remediation=remediation,
            references=references,
        )
