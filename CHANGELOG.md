# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [SemVer](https://semver.org/).

## [0.1.0] — 2026-10-22

### Added
- `ztrust scan` with five scanners: secrets, typosquat, integrity, GitHub Actions, OSV vulnerabilities & malware.
- Manifest support: requirements.txt, poetry.lock, uv.lock, package-lock.json (v1–v3), package.json, go.mod, Cargo.lock.
- Console, JSON and SARIF 2.1.0 output; GitHub code scanning integration via `action.yml`.
- Pure-Python Zcash toolkit: Bech32/Bech32m and Base58Check validation, ZIP-321 payment URIs.
- Bounty API (FastAPI + SQLite): programs, commit-reveal submissions, duplicate resolution, triage, shielded payouts.
- Payout backends: `mock` and `rpc` (zcashd-compatible JSON-RPC / Zallet).
