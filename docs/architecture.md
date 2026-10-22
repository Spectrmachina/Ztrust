# Architecture

ZTrust has two halves that share one data model:

1. **Detection** — a stateless CLI / GitHub Action that turns a repository into a list of
   `Finding`s.
2. **Incentives** — a small API that lets maintainers fund bounties and lets independent
   researchers get paid in shielded ZEC for findings the scanner *cannot* make on its own.

```mermaid
flowchart TB
    subgraph Repo["📁 Your repository"]
        M["Manifests & lockfiles<br/>requirements · poetry · uv · npm · go · cargo"]
        W[".github/workflows/*.yml"]
        S["Source, Dockerfiles, scripts"]
    end

    subgraph CLI["🛡️ ztrust scan"]
        P["manifests.py<br/>dependency inventory"]
        SC1["secrets"]
        SC2["typosquat"]
        SC3["integrity"]
        SC4["ci"]
        SC5["vulns"]
        POL["engine.py<br/>policy · dedupe · sort"]
        R["report.py<br/>console · JSON · SARIF"]
    end

    OSV[("OSV.dev<br/>GHSA · PyPA · RustSec<br/>MAL- feed")]
    GH["GitHub code scanning<br/>Security tab"]

    M --> P --> SC2 & SC3 & SC5
    S --> SC1 & SC3
    W --> SC4
    SC5 <-->|querybatch| OSV
    SC1 & SC2 & SC3 & SC4 & SC5 --> POL --> R --> GH

    subgraph API["💰 ztrust serve (FastAPI + SQLite)"]
        PR["Programs"]
        F["Findings<br/>commit → reveal → triage"]
        PAY["Payout backend<br/>mock | rpc"]
    end

    Researcher(["🕵️ Researcher<br/>pseudonym + shielded address"]) -->|commitment| F
    Maintainer(["🧑‍💻 Maintainer"]) -->|create · triage| PR & F
    F --> PAY -->|z_sendmany| Wallet[("Zallet / zcashd<br/>JSON-RPC")] --> Chain[("Zcash<br/>shielded pool")]
```

## Scan pipeline

```mermaid
sequenceDiagram
    autonumber
    participant U as ztrust scan
    participant C as config.py
    participant M as manifests.py
    participant S as scanners/*
    participant O as OSV.dev
    participant E as engine.py
    participant R as report.py
    U->>C: load .ztrust.yml
    U->>M: walk files (skip node_modules, .git, excludes)
    M-->>U: [Dependency]
    loop each scanner
        U->>S: scan(ctx)
        S-->>O: POST /v1/querybatch (vulns only)
        O-->>S: vuln ids → GET /v1/vulns/{id}
        S-->>U: [Finding]
    end
    U->>E: apply_policy (disable · override · allowlist · dedupe)
    E->>R: sorted findings
    R-->>U: console / JSON / SARIF + exit code
```

A failing scanner never hides the others: its exception becomes a warning in the report.
Network failures in the OSV scanner degrade to a warning as well, so the CLI is safe to
run in air-gapped CI with `--offline`.

## Module map

| Module | Responsibility |
|---|---|
| `models.py` | `Severity`, `Category`, `Dependency`, `Finding`, `ScanResult` |
| `config.py` | `.ztrust.yml` loading, exclude globs, rule toggles |
| `manifests.py` | Parsers for 7 manifest / lockfile formats |
| `scanners/base.py` | `Scanner` ABC, `ScanContext` (file walk, safe text reads) |
| `scanners/secrets.py` | 13 provider patterns + entropy heuristic, redaction |
| `scanners/typosquat.py` | Damerau-Levenshtein, separator and homoglyph checks |
| `scanners/integrity.py` | Pinning, hashes, sources, install scripts, `curl \| sh` |
| `scanners/cicd.py` | GitHub Actions hardening |
| `scanners/vulns.py` | OSV client, CVSS v3 calculator |
| `engine.py` | Orchestration and policy |
| `report.py` | Rich console, JSON, SARIF 2.1.0 |
| `bounty/zcash.py` | Amounts, Bech32/Bech32m, Base58Check, ZIP-321 |
| `bounty/protocol.py` | Commit-reveal |
| `bounty/store.py` | SQLite persistence |
| `bounty/backends.py` | Mock and JSON-RPC payout backends |
| `server/app.py` | REST API |
| `cli.py` | `scan`, `deps`, `commit`, `pay-uri`, `check-address`, `serve` |

## Design principles

- **Zero trust in inputs.** Manifests, workflow files and research reports are attacker-controlled.
  Parsing uses `yaml.safe_load`, `json`, `tomllib`; nothing is executed.
- **Few dependencies.** The scanner needs only `rich` and `PyYAML`; Zcash primitives are pure Python.
  A supply-chain tool with a huge supply chain would be ironic.
- **Every finding is actionable.** A rule without a remediation is not merged.
- **Privacy by default for people, transparency for money.** Researchers are pseudonymous and paid
  through shielded transactions; program funding can be made auditable with a viewing key.
