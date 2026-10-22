# Security Policy

ZTrust is a security tool, so we hold ourselves to the standard we check others against.

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository (Security → Report a vulnerability).

We aim to acknowledge reports within **72 hours** and to ship a fix or mitigation
within **30 days** for high/critical issues.

## Eating our own dog food

Once a public ZTrust bounty instance is running, ZTrust itself will be listed as a
program: you will be able to commit to a report, reveal it privately and be paid in
shielded ZEC exactly as described in [docs/bounty-protocol.md](docs/bounty-protocol.md).

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | ✅ |

## Scope

In scope: the `ztrust` CLI, the bounty API, the GitHub Action, payout logic,
commitment verification, Zcash address/URI handling.

Out of scope: findings that require a compromised maintainer machine, denial of
service against a self-hosted instance without authentication bypass, issues in
third-party dependencies without a ZTrust-specific impact.
