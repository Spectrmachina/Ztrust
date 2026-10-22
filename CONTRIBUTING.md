# Contributing to ZTrust

Thanks for helping make open source harder to poison! 🛡️

## Dev setup

```bash
git clone https://github.com/Lostreaksmb/ztrust.git
cd ztrust
python -m venv .venv && source .venv/bin/activate
pip install -e ".[server,dev]"
pytest
ruff check src tests
```

## Adding a detection rule

1. Pick the scanner in `src/ztrust/scanners/` (or create one by subclassing `Scanner`
   and registering it in `scanners/__init__.py::default_scanners`).
2. Use a new, stable rule id: `ZT-<AREA>-<NNN>` (`SEC`, `TYPO`, `INT`, `CI`, `VULN`, `MAL`).
3. Every finding must carry a concrete `remediation` — "what do I do now?".
4. Add a test in `tests/` with a minimal fixture. **Never commit real-looking secrets**:
   assemble them at runtime (`"ghp" + "_" + ...`) so push protection and ZTrust itself stay quiet.
5. Document the rule in [`docs/rules.md`](docs/rules.md).

## Commit style

[Conventional Commits](https://www.conventionalcommits.org/): `feat(ci): detect ...`,
`fix(secrets): ...`, `docs: ...`.

## Code of conduct

By participating you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
