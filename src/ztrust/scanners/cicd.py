"""GitHub Actions hardening checks.

Covers the patterns behind real incidents such as the tj-actions/changed-files
compromise (mutable tags) and "pwn request" attacks via ``pull_request_target``.
"""

from __future__ import annotations

import re
from typing import Any

import yaml

from ztrust.models import Category, Finding, Severity
from ztrust.scanners.base import ScanContext, Scanner

USES_LINE = re.compile(r"""^\s*-?\s*uses:\s*['"]?([^'"\s#]+)""")
FULL_SHA = re.compile(r"@[0-9a-f]{40}$")
FIRST_PARTY = ("actions/", "github/")
UNTRUSTED_EXPR = re.compile(
    r"\$\{\{\s*("
    r"github\.event\.(issue\.(title|body)|pull_request\.(title|body|head\.ref|head\.label)|comment\.body"
    r"|review\.body|review_comment\.body|pages\.[^}]*\.page_name|commits\.[^}]*\.message"
    r"|head_commit\.(message|author\.(email|name))|workflow_run\.head_branch)"
    r"|github\.head_ref"
    r")[^}]*\}\}"
)
HARDENING_DOCS = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions"


def _line_of(lines: list[str], needle: str) -> int | None:
    for i, line in enumerate(lines, 1):
        if needle in line:
            return i
    return None


def _triggers(data: dict[str, Any]) -> set[str]:
    on = data.get("on", data.get(True))  # YAML 1.1 parses a bare `on` key as boolean True
    if isinstance(on, str):
        return {on}
    if isinstance(on, list):
        return {str(t) for t in on}
    if isinstance(on, dict):
        return {str(t) for t in on}
    return set()


class WorkflowScanner(Scanner):
    name = "ci"
    description = "GitHub Actions: unpinned actions, pwn requests, script injection, token scope"

    def scan(self, ctx: ScanContext) -> list[Finding]:
        findings: list[Finding] = []
        for path in ctx.files():
            rel = ctx.rel(path)
            is_workflow = rel.startswith(".github/workflows/") and path.suffix in (".yml", ".yaml")
            is_action = path.name in ("action.yml", "action.yaml")
            if not (is_workflow or is_action):
                continue
            text = ctx.read_text(path)
            if not text:
                continue
            lines = text.splitlines()
            findings += self._unpinned(rel, lines)
            if is_workflow:
                try:
                    data = yaml.safe_load(text)
                except yaml.YAMLError as exc:
                    ctx.warnings.append(f"could not parse {rel}: {exc}")
                    continue
                if isinstance(data, dict):
                    findings += self._workflow_logic(rel, lines, data)
        return findings

    @staticmethod
    def _unpinned(rel: str, lines: list[str]) -> list[Finding]:
        findings = []
        for lineno, line in enumerate(lines, 1):
            match = USES_LINE.match(line)
            if not match or "ztrust:ignore" in line:
                continue
            ref = match.group(1)
            if ref.startswith("./") or (ref.startswith("docker://") and "@sha256:" in ref) or FULL_SHA.search(ref):
                continue
            first_party = ref.startswith(FIRST_PARTY)
            findings.append(
                Finding(
                    rule_id="ZT-CI-001",
                    title=f"Action `{ref}` is not pinned to a commit SHA",
                    severity=Severity.LOW if first_party else Severity.MEDIUM,
                    category=Category.CI_CD,
                    file=rel,
                    line=lineno,
                    package=ref,
                    description="Tags and branches are mutable: whoever controls the action repository can "
                    "silently change the code that runs with your secrets.",
                    remediation="Pin to a full 40-character commit SHA and keep the tag as a comment, e.g. "
                    "`uses: owner/action@<sha> # v4.1.0`. Dependabot can keep SHAs up to date.",
                    references=[HARDENING_DOCS],
                )
            )
        return findings

    @staticmethod
    def _workflow_logic(rel: str, lines: list[str], data: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        triggers = _triggers(data)
        jobs = data.get("jobs") or {}
        if not isinstance(jobs, dict):
            return findings

        if "permissions" not in data and not all(
            isinstance(job, dict) and "permissions" in job for job in jobs.values()
        ):
            findings.append(
                Finding(
                    rule_id="ZT-CI-004",
                    title="Workflow does not restrict GITHUB_TOKEN permissions",
                    severity=Severity.LOW,
                    category=Category.CI_CD,
                    file=rel,
                    description="Without an explicit `permissions:` block the token may have write access "
                    "to the repository, depending on organisation defaults.",
                    remediation="Add `permissions: contents: read` at the top level and grant more per job.",
                    references=[HARDENING_DOCS],
                )
            )

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            for step in job.get("steps") or []:
                if not isinstance(step, dict):
                    continue
                uses = str(step.get("uses", ""))
                ref = str((step.get("with") or {}).get("ref", ""))
                if (
                    "pull_request_target" in triggers
                    and uses.startswith("actions/checkout")
                    and ("pull_request.head" in ref or "head_ref" in ref)
                ):
                    findings.append(
                        Finding(
                            rule_id="ZT-CI-002",
                            title=f"Pwn request: job `{job_name}` checks out untrusted PR code",
                            severity=Severity.CRITICAL,
                            category=Category.CI_CD,
                            file=rel,
                            line=_line_of(lines, ref) if ref else None,
                            description="`pull_request_target` runs with repository secrets and a write token; "
                            "checking out the PR head lets any fork author execute code in that context.",
                            remediation="Use `pull_request` for untrusted code, or split into an unprivileged "
                            "build workflow and a privileged `workflow_run` that never executes PR code.",
                            references=["https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"],
                        )
                    )
                run = step.get("run")
                if isinstance(run, str):
                    for match in UNTRUSTED_EXPR.finditer(run):
                        expr = match.group(0)
                        findings.append(
                            Finding(
                                rule_id="ZT-CI-003",
                                title="Script injection via untrusted GitHub context",
                                severity=Severity.HIGH,
                                category=Category.CI_CD,
                                file=rel,
                                line=_line_of(lines, expr),
                                description=f"`{expr}` is attacker-controlled and is interpolated straight into "
                                f"a shell script in job `{job_name}`.",
                                remediation="Pass the value through an environment variable "
                                '(`env: TITLE: ${{ github.event.issue.title }}`) and reference "$TITLE".',
                                references=[HARDENING_DOCS],
                            )
                        )
        return findings
