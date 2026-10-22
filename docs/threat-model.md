# Threat model

## Supply-chain attacks ZTrust addresses

| # | Attack | Real-world example | ZTrust coverage |
|---|---|---|---|
| T1 | Malicious package published to a registry | event-stream / flatmap-stream (2018); npm worm campaigns (2025) | `ZT-MAL-001` via OSV malicious-packages feed |
| T2 | Typosquatting / look-alike names | `crossenv` vs `cross-env` (npm, 2017) | `ZT-TYPO-001` |
| T3 | Known-vulnerable dependency | log4shell, CVE-2021-44228 | `ZT-VULN-001` |
| T4 | Compromised maintainer / backdoored release | xz-utils, CVE-2024-3094 | Partly detectable; **this is what bounties are for** |
| T5 | Mutable CI dependencies | tj-actions/changed-files, CVE-2025-30066 | `ZT-CI-001` |
| T6 | Pwn request / script injection in CI | Numerous GitHub Security Lab advisories | `ZT-CI-002`, `ZT-CI-003` |
| T7 | Leaked publish / cloud credentials | Codecov bash uploader (2021) | `ZT-SEC-*` |
| T8 | Tampered artifacts in transit / non-registry sources | Dependency confusion (2021) | `ZT-INT-001…003` |
| T9 | Install-time code execution | Most npm malware | `ZT-INT-006`, `ZT-INT-007` |
| T10 | `curl \| sh` installers | — | `ZT-INT-008` |

Not covered by static scanning (yet): build provenance verification (SLSA / Sigstore),
binary diffing of releases vs source, maintainer account takeover signals. See the
[roadmap](roadmap.md).

## Bounty platform

| Threat | Mitigation |
|---|---|
| Triager or rival steals a report and submits it first | Commit-reveal; earliest commitment wins at reveal time |
| Brute-forcing a short report from its hash | 256-bit random salt |
| Program promises rewards it cannot pay | Budget reservation on accept; optional public viewing key on the pool |
| Researcher deanonymised through payments | Shielded-only payout addresses, `FullPrivacy` policy, no e-mail/KYC fields |
| Admin token brute force / timing | `hmac.compare_digest`; token required, server refuses admin calls if unset |
| Hot-wallet compromise | Separate wallet host, limited balance, RPC on private network |
| Wrong-network payouts | Address network checked against `ZTRUST_ZCASH_NETWORK` |
| Malicious content in reports (XSS, injection) | Reports stored as opaque text, size-limited, never rendered as HTML by the API |
| SQL injection | Parameterised queries; update columns whitelisted |

## Trust assumptions

- The maintainer operating a program is honest about triage. Commit-reveal limits theft, but
  cannot force a payout; reputation (public leaderboard) and the viewing key make bad faith visible.
- OSV.dev data is accurate. ZTrust adds no independent advisory database.
- The Zcash wallet and node are run by the program operator and are not compromised.
