<div align="center">

<img src="docs/assets/logo.png" alt="ZTrust" width="560">

### Zero-trust software supply-chain security — with shielded Zcash bounties for the people who defend open source

[![CI](https://github.com/Lostreaksmb/ztrust/actions/workflows/ci.yml/badge.svg)](https://github.com/Lostreaksmb/ztrust/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-f7931a.svg)](LICENSE)
[![SARIF](https://img.shields.io/badge/output-SARIF%202.1.0-black)](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
[![OSV](https://img.shields.io/badge/data-OSV.dev-4285F4)](https://osv.dev)
[![Zcash](https://img.shields.io/badge/payouts-shielded%20ZEC-F4B728?logo=zcash&logoColor=black)](https://z.cash)

[**Quick start**](#-quick-start) · [**How it works**](#-how-it-works) · [**Bounties**](#-bounties-powered-by-zcash) · [**Rules**](docs/rules.md) · [**API**](docs/api.md)

</div>

---

## 💡 The idea

Modern software is mostly other people's code. A single poisoned package, a mutable GitHub Action
tag or a leaked publish token is enough to compromise thousands of downstream projects —
**xz-utils**, **tj-actions/changed-files**, **event-stream** and a steady stream of npm/PyPI malware
have all shown it.

**ZTrust does two things:**

| | |
|---|---|
| 🛡️ **Detects** | A fast, dependency-light scanner for vulnerable and **malicious** dependencies, typosquats, leaked secrets, unsafe lockfiles and dangerous CI workflows. Runs locally, in CI, and reports straight into GitHub's Security tab. |
| 💰 **Pays defenders** | Scanners only find *known* problems. Backdoors are found by **people**. ZTrust lets maintainers fund bounty pools and pay independent researchers in **shielded Zcash** — private, borderless, without KYC — using a commit-reveal protocol that makes findings impossible to steal. |

> **Zero trust** applies to code *and* to money: every dependency is suspect until verified, and
> every payment is verifiable without exposing the people behind it.

---

## 🧭 How it works

```mermaid
flowchart LR
    subgraph Detect["🛡️ Detect"]
        direction TB
        A["📦 Manifests & lockfiles"] --> SCAN
        B["⚙️ GitHub workflows"] --> SCAN
        C["📝 Source & Dockerfiles"] --> SCAN
        SCAN{{"ztrust scan"}} --> OSV[("OSV.dev")]
        SCAN --> OUT["Console · JSON · SARIF"]
        OUT --> GH["GitHub Security tab"]
    end

    subgraph Reward["💰 Reward"]
        direction TB
        R(["🕵️ Researcher"]) -- "1 · commit hash" --> API["ZTrust Bounty API"]
        R -- "2 · reveal report" --> API
        M(["🧑‍💻 Maintainer"]) -- "3 · triage" --> API
        API -- "4 · z_sendmany" --> Z[("🔒 Zcash shielded pool")]
        Z -- "private payout + memo" --> R
    end

    GH -. "what scanners can't see" .-> R
```

More diagrams: [architecture](docs/architecture.md) · [bounty protocol](docs/bounty-protocol.md) · [Zcash integration](docs/zcash-integration.md)

---

## ✨ Features

| Scanner | What it catches | Example rule |
|---|---|---|
| 🔑 **secrets** | GitHub/GitLab/npm/PyPI/AWS/Stripe/Slack/Google/OpenAI/Anthropic tokens, private keys, **Zcash spending keys**, committed `.env`, high-entropy credentials | `ZT-SEC-002` |
| 🎭 **typosquat** | `reqeusts`, `crossenv`, `l0dash` — look-alikes of popular npm / PyPI / crates.io packages | `ZT-TYPO-001` |
| 🔗 **integrity** | Missing lockfile hashes, `http://` and git sources, unpinned requirements, install scripts, `curl \| sh` | `ZT-INT-007` |
| ⚙️ **ci** | Unpinned actions, `pull_request_target` pwn requests, `${{ github.event.* }}` script injection, broad token permissions | `ZT-CI-002` |
| 🧬 **vulns** | Known CVEs/GHSAs and **known malware** (OpenSSF `MAL-` feed) via [OSV.dev](https://osv.dev), CVSS v3 scoring | `ZT-MAL-001` |

**Ecosystems:** `requirements*.txt` · `poetry.lock` · `uv.lock` · `package-lock.json` (v1–v3) · `package.json` · `go.mod` · `Cargo.lock`

**Outputs:** rich terminal report · JSON · **SARIF 2.1.0** (GitHub code scanning, with `security-severity`)

**Zcash toolkit (pure Python):** Bech32/Bech32m & Base58Check address validation, Unified Addresses ([ZIP-316](https://zips.z.cash/zip-0316)), payment URIs ([ZIP-321](https://zips.z.cash/zip-0321)), `z_sendmany` payouts via zcashd-compatible JSON-RPC / [Zallet](https://github.com/zcash/wallet).

---

## 🚀 Quick start

```bash
git clone https://github.com/Lostreaksmb/ztrust.git
cd ztrust
pip install -e .

ztrust scan examples/vulnerable-app      # an intentionally broken demo project
ztrust scan .                            # your project
```

```text
╭───────────────────────────────────────────────────────────────────────────╮
│ ZTrust v0.1.0  /home/me/ztrust/examples/vulnerable-app                    │
│ 7 dependencies · scanners: secrets, typosquat, integrity, ci, vulns · 1.84s│
│  CRITICAL 1   HIGH 9   MEDIUM 6   LOW 3   INFO 1                          │
╰───────────────────────────────────────────────────────────────────────────╯
 Severity  Rule         Finding                                              Location
 CRITICAL  ZT-CI-002    Pwn request: job `preview` checks out untrusted PR…  .github/workflows/pr.yml:10
 HIGH      ZT-TYPO-001  Possible typosquat: `crossenv` imitates `cross-env`  package.json
 HIGH      ZT-INT-007   Dangerous `postinstall` lifecycle script             package.json
 HIGH      ZT-SEC-001   AWS access key ID detected                           app/config.py:2
 HIGH      ZT-VULN-001  GHSA-…: Prototype Pollution in lodash                package.json
 …
```

### Useful commands

| Command | Purpose |
|---|---|
| `ztrust scan . --format sarif -o ztrust.sarif` | SARIF for code scanning |
| `ztrust scan . --format json --offline` | JSON, no network |
| `ztrust scan . --only secrets,ci --fail-on medium` | Subset of scanners, stricter gate |
| `ztrust deps .` | Print the dependency inventory |
| `ztrust commit report.md` | Create a bounty commitment for a private report |
| `ztrust pay-uri --address u1… --amount 1.5 --memo "thanks"` | ZIP-321 payment link |
| `ztrust check-address u1…` | Validate & classify a Zcash address |
| `ztrust serve` | Run the bounty API (`pip install -e ".[server]"`) |

**Exit codes:** `0` clean · `1` findings ≥ `--fail-on` (default `high`) · `2` usage error.

---

## ⚙️ GitHub Action

```yaml
# .github/workflows/ztrust.yml
name: ZTrust
on: [push, pull_request]

permissions:
  contents: read
  security-events: write   # upload SARIF to the Security tab

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: Lostreaksmb/ztrust@v0.1.0
        with:
          fail-on: high
```

Findings appear under **Security → Code scanning** with file/line annotations on pull requests.
The action passes its inputs through environment variables — it does not commit the
script-injection mistake it detects (`ZT-CI-003`).

> 💡 Pin the action to a commit SHA in production — ZTrust will remind you (`ZT-CI-001`).

---

## 💰 Bounties powered by Zcash

### Why

Static analysis catches *known* bad things. The xz-utils backdoor was found by a person who
noticed SSH logins were 500 ms slower. Today that kind of work is mostly unpaid. ZTrust creates
an economic incentive for it, built on three requirements that ordinary payment rails can't meet:

| Requirement | Solution |
|---|---|
| 🕶️ Researchers may need anonymity | Pseudonym + **shielded** Unified/Sapling address only. No e-mail, no KYC. |
| 🏁 Findings must not be stealable | **Commit-reveal**: a salted SHA-256 is timestamped before anyone sees the report. Earliest commitment wins duplicates. |
| 🔍 Funding must be trustworthy | Pools can publish a **viewing key** — anyone can audit the balance, nobody sees who got paid. |

### Flow

```mermaid
sequenceDiagram
    autonumber
    actor Mt as Maintainer
    participant API as ZTrust API
    participant W as Zcash wallet
    actor Rs as Researcher
    Mt->>API: create program (payout table, budget, funding UA)
    API-->>Mt: ZIP-321 funding link
    Mt->>W: fund the pool
    Rs->>API: commitment = SHA-256(salt:report) + payout UA
    Rs->>API: reveal(report, salt)
    API->>API: verify hash · earliest commitment wins
    Mt->>API: accept as "critical"
    Mt->>API: payout
    API->>W: z_sendmany (FullPrivacy, encrypted memo)
    W-->>Rs: 🔒 5 ZEC, shielded
```

```mermaid
stateDiagram-v2
    direction LR
    [*] --> committed
    committed --> revealed: hash ✔
    revealed --> accepted
    revealed --> rejected
    revealed --> duplicate: earlier commit exists
    accepted --> paid: shielded tx
    paid --> [*]
```

### Try it locally

```bash
pip install -e ".[server]"
export ZTRUST_ADMIN_TOKEN=dev ZTRUST_ZCASH_NETWORK=test   # mock payouts by default
ztrust serve                                             # → http://127.0.0.1:8080/docs

# in another terminal
FUNDING_UA=utest1... PAYOUT_UA=utest1... ./examples/bounty-flow.sh
```

Or with Docker:

```bash
cp .env.example .env    # set ZTRUST_ADMIN_TOKEN
docker compose up --build
```

Switch to real payments with `ZTRUST_ZCASH_BACKEND=rpc` and a [Zallet](https://github.com/zcash/wallet)
wallet on a [Zebra](https://github.com/ZcashFoundation/zebra) node — see [docs/zcash-integration.md](docs/zcash-integration.md).

---

## 🔧 Configuration

Drop a `.ztrust.yml` in the repository root:

```yaml
exclude:
  - "vendor/**"
  - "tests/fixtures/**"

fail_on: high

disable_rules:
  - "ZT-INT-005"          # we don't use --require-hashes
  - "ZT-SEC-0*"           # globs work too

severity_overrides:
  ZT-CI-001: low

allowlist_packages:       # intentional look-alike names
  - colour

secrets_allowlist:        # regexes for known test values
  - "AKIAIOSFODNN7EXAMPLE"
```

Silence a single line with a `# ztrust:ignore` comment.

---

## 🗂️ Project structure

```text
ztrust/
├── action.yml                    # GitHub Action (composite)
├── Dockerfile · docker-compose.yml
├── src/ztrust/
│   ├── cli.py                    # ztrust scan | deps | commit | pay-uri | check-address | serve
│   ├── engine.py                 # orchestration + policy
│   ├── manifests.py              # 7 manifest / lockfile parsers
│   ├── report.py                 # console · JSON · SARIF
│   ├── scanners/                 # secrets · typosquat · integrity · cicd · vulns
│   ├── bounty/
│   │   ├── zcash.py              # Bech32m, Base58Check, ZIP-321, amounts
│   │   ├── protocol.py           # commit-reveal
│   │   ├── backends.py           # mock + JSON-RPC (zcashd / Zallet)
│   │   └── store.py              # SQLite
│   └── server/app.py             # FastAPI bounty API
├── tests/                        # pytest suite
├── examples/                     # vulnerable demo app + bounty walkthrough
└── docs/                         # architecture, protocol, Zcash, threat model, rules, API, roadmap
```

---

## 🛣️ Roadmap

- [x] Five scanners, SARIF, GitHub Action
- [x] Bounty API with commit-reveal and shielded payouts
- [ ] yarn / pnpm lockfiles, Maven, NuGet, RubyGems
- [ ] Sigstore / npm provenance & SLSA verification
- [ ] Release-tarball vs source diffing (xz-style backdoors)
- [ ] FROST multisig bounty pools, public multi-tenant hub

Full plan: [docs/roadmap.md](docs/roadmap.md)

---

## 🤝 Contributing & security

PRs welcome — start with [CONTRIBUTING.md](CONTRIBUTING.md). New detection rules are the most
valuable contribution. Found a vulnerability in ZTrust itself? Please follow [SECURITY.md](SECURITY.md).

## 📚 Learn more

| Topic | Link |
|---|---|
| OSV schema & API | <https://ossf.github.io/osv-schema/> · <https://google.github.io/osv.dev/api/> |
| OpenSSF malicious packages | <https://github.com/ossf/malicious-packages> |
| SLSA framework | <https://slsa.dev> |
| OpenSSF Scorecard | <https://github.com/ossf/scorecard> |
| GitHub Actions hardening | <https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions> |
| SARIF 2.1.0 | <https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html> |
| Zcash documentation | <https://zcash.readthedocs.io/> |
| ZIPs (316, 317, 321) | <https://zips.z.cash/> |

## 📄 License

[MIT](LICENSE) © 2026 ZTrust contributors

<div align="center">
<sub>Built for the people who read other people's code so the rest of us don't have to. 🧡</sub>
</div>
