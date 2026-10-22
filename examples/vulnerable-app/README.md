# 🧪 Intentionally vulnerable demo project

Every file here contains a supply-chain problem on purpose. **Do not install these
dependencies.** The AWS key is Amazon's documented example value, not a real credential.

```bash
ztrust scan examples/vulnerable-app
```

| File | Planted issue | Rule |
|---|---|---|
| `requirements.txt` | `python-dateutils` look-alike, old `requests`/`pyyaml`, unpinned `flask` | ZT-TYPO-001, ZT-VULN-001, ZT-INT-004 |
| `package.json` | `crossenv` typosquat, vulnerable `lodash`, `postinstall: curl … \| sh` | ZT-TYPO-001, ZT-VULN-001, ZT-INT-007 |
| `app/config.py` | hard-coded AWS key + generic secret | ZT-SEC-001, ZT-SEC-030 |
| `.github/workflows/pr.yml` | pwn request, script injection, unpinned action | ZT-CI-002, ZT-CI-003, ZT-CI-001 |
| `Dockerfile` | `curl \| sh` | ZT-INT-008 |
