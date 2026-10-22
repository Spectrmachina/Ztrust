# Roadmap

```mermaid
timeline
    title ZTrust roadmap
    v0.1 — Foundation : CLI with 5 scanners : SARIF + GitHub Action : Bounty API with commit-reveal : Zcash ZIP-321 + JSON-RPC payouts
    v0.2 — Coverage : yarn.lock / pnpm-lock : Maven, NuGet, RubyGems : GitLab CI & CircleCI rules : Container image SBOM input
    v0.3 — Provenance : Sigstore / npm provenance verification : SLSA level detection : Release-vs-source tarball diff (xz-style)
    v0.4 — Network : Public multi-tenant bounty hub : Program pages with live viewing-key audit : Researcher reputation via signed pseudonyms
    v1.0 — Ecosystem : Zcash shielded multi-sig pools (FROST) : Matching funds from foundations : Automatic bounties for MAL- discoveries
```

## Ideas under discussion

- **Auto-bounties**: when a researcher's report leads to a new `MAL-` OSV entry affecting a
  participating program, pay a pre-agreed reward automatically.
- **FROST multisig pools** so no single maintainer can spend the bounty pool alone.
- **Shielded donations** from users of a project directly into its security pool via a
  ZIP-321 link in the README badge.
- **Encrypted reports**: researchers encrypt the reveal to the maintainer's public key, so the
  server never sees plaintext.

Have an idea? Open an issue with the *New detection rule* or *feature* template.
