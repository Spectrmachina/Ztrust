# Detection rules

Every finding has a stable rule id, a severity and a concrete remediation.
Disable or re-rate rules in `.ztrust.yml` (`disable_rules`, `severity_overrides`), or
silence a single line with a `ztrust:ignore` comment.

## Secrets — `secrets` scanner

| Rule | Detects | Severity |
|---|---|---|
| <a id="zt-sec-001"></a>`ZT-SEC-001` | AWS access key ID (`AKIA…`/`ASIA…`) | high |
| <a id="zt-sec-002"></a>`ZT-SEC-002` | GitHub classic / OAuth / app tokens (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_`) | critical |
| <a id="zt-sec-003"></a>`ZT-SEC-003` | GitHub fine-grained PAT (`github_pat_`) | critical |
| <a id="zt-sec-004"></a>`ZT-SEC-004` | GitLab PAT (`glpat-`) | critical |
| <a id="zt-sec-005"></a>`ZT-SEC-005` | npm access token (`npm_`) | critical |
| <a id="zt-sec-006"></a>`ZT-SEC-006` | PyPI API token | critical |
| <a id="zt-sec-007"></a>`ZT-SEC-007` | Slack token (`xox?-`) | high |
| <a id="zt-sec-008"></a>`ZT-SEC-008` | Stripe live secret / restricted key | critical |
| <a id="zt-sec-009"></a>`ZT-SEC-009` | Google API key (`AIza…`) | high |
| <a id="zt-sec-010"></a>`ZT-SEC-010` | PEM / OpenSSH / PGP private key block | critical |
| <a id="zt-sec-011"></a>`ZT-SEC-011` | **Zcash Sapling extended spending key** — someone can drain the wallet | critical |
| <a id="zt-sec-012"></a>`ZT-SEC-012` | Anthropic API key | critical |
| <a id="zt-sec-013"></a>`ZT-SEC-013` | OpenAI project / service-account key | critical |
| <a id="zt-sec-020"></a>`ZT-SEC-020` | `.env` file committed | medium |
| <a id="zt-sec-030"></a>`ZT-SEC-030` | High-entropy value assigned to a `key`/`secret`/`token`/`password` variable | medium |

Matched values are **redacted** in every output format.

## Typosquatting — `typosquat` scanner

| Rule | Detects | Severity |
|---|---|---|
| <a id="zt-typo-001"></a>`ZT-TYPO-001` | Dependency name one edit away from a popular package, identical after removing `-_.`, or equal after replacing look-alike digits (`0→o`, `1→l`, …) | high |

Covers npm, PyPI and crates.io. Scoped npm packages (`@org/x`) are skipped because scopes are owned.

## Integrity — `integrity` scanner

| Rule | Detects | Severity |
|---|---|---|
| <a id="zt-int-001"></a>`ZT-INT-001` | `package-lock.json` entry without an `integrity` hash | medium |
| <a id="zt-int-002"></a>`ZT-INT-002` | Dependency resolved over plain `http://` | high |
| <a id="zt-int-003"></a>`ZT-INT-003` | Dependency installed from git / GitHub tarball instead of a registry | medium |
| <a id="zt-int-004"></a>`ZT-INT-004` | Unpinned Python requirements | low |
| <a id="zt-int-005"></a>`ZT-INT-005` | Requirements without `--hash` | info |
| <a id="zt-int-006"></a>`ZT-INT-006` | npm dependencies that run install scripts | low |
| <a id="zt-int-007"></a>`ZT-INT-007` | Own `preinstall`/`install`/`postinstall`/`prepare` script downloads or evals code | high |
| <a id="zt-int-008"></a>`ZT-INT-008` | `curl … \| sh` in Dockerfiles, shell scripts, Makefiles | medium |

## CI/CD — `ci` scanner (GitHub Actions)

| Rule | Detects | Severity |
|---|---|---|
| <a id="zt-ci-001"></a>`ZT-CI-001` | `uses:` not pinned to a 40-char commit SHA (low for `actions/*`, `github/*`) | medium / low |
| <a id="zt-ci-002"></a>`ZT-CI-002` | `pull_request_target` + checkout of the PR head ("pwn request") | critical |
| <a id="zt-ci-003"></a>`ZT-CI-003` | Attacker-controlled `${{ github.event.* }}` interpolated into `run:` | high |
| <a id="zt-ci-004"></a>`ZT-CI-004` | No `permissions:` block for `GITHUB_TOKEN` | low |

## Vulnerabilities & malware — `vulns` scanner (OSV.dev)

| Rule | Detects | Severity |
|---|---|---|
| <a id="zt-vuln-001"></a>`ZT-VULN-001` | Known vulnerability (GHSA, PyPA, RustSec, Go vulndb …) | from advisory / CVSS v3 |
| <a id="zt-mal-001"></a>`ZT-MAL-001` | Package listed in the OpenSSF malicious-packages feed (`MAL-…`) | critical |

Severity comes from the advisory's `database_specific.severity` when present,
otherwise from the CVSS v3 base score computed locally. Requires network access;
use `--offline` to skip.
