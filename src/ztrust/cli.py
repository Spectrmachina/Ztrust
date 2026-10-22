"""Command-line interface: ``ztrust scan | deps | commit | pay-uri | check-address | serve``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.table import Table

from ztrust import __version__
from ztrust.bounty.protocol import compute_commitment, make_salt
from ztrust.bounty.zcash import build_payment_uri, classify_address, zec_to_zats
from ztrust.config import load_config
from ztrust.engine import run_scan
from ztrust.models import Severity
from ztrust.report import render_console, write_report
from ztrust.scanners import SCANNER_NAMES

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ztrust",
        description="Zero-trust supply-chain scanner with Zcash-powered security bounties.",
    )
    parser.add_argument("--version", action="version", version=f"ztrust {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan a project directory")
    scan.add_argument("path", nargs="?", default=".")
    scan.add_argument("-f", "--format", choices=["console", "json", "sarif"], default="console")
    scan.add_argument("-o", "--output", help="write the report to a file instead of stdout")
    scan.add_argument("--offline", action="store_true", help="skip network lookups (OSV)")
    scan.add_argument(
        "--fail-on",
        choices=[s.value for s in Severity] + ["none"],
        help="exit with code 1 when a finding of this severity or higher exists (default: high)",
    )
    scan.add_argument("--only", help=f"comma-separated subset of scanners: {','.join(SCANNER_NAMES)}")
    scan.add_argument("-c", "--config", help="path to a .ztrust.yml policy file")

    deps = sub.add_parser("deps", help="list the dependency inventory")
    deps.add_argument("path", nargs="?", default=".")

    commit = sub.add_parser("commit", help="create a bounty commitment for a private report")
    commit.add_argument("report", help="path to your report file (Markdown recommended)")
    commit.add_argument("--salt", help="reuse an existing salt (hex)")

    pay = sub.add_parser("pay-uri", help="build a ZIP-321 payment request URI")
    pay.add_argument("--address", required=True)
    pay.add_argument("--amount", help="amount in ZEC, e.g. 0.5")
    pay.add_argument("--memo")
    pay.add_argument("--message")

    check = sub.add_parser("check-address", help="validate and classify a Zcash address")
    check.add_argument("address")

    serve = sub.add_parser("serve", help="run the bounty API server")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8080)
    return parser


def cmd_scan(args: argparse.Namespace) -> int:
    root = Path(args.path)
    try:
        config = load_config(root.resolve(), Path(args.config) if args.config else None)
        only = {s.strip() for s in args.only.split(",")} if args.only else None
        if only and (unknown := only - set(SCANNER_NAMES)):
            print(f"unknown scanner(s): {', '.join(sorted(unknown))}", file=sys.stderr)
            return EXIT_USAGE
        result = run_scan(root, config=config, offline=args.offline, only=only)
    except (FileNotFoundError, NotADirectoryError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            write_report(result, args.format, fh)
        counts = result.counts()
        summary = ", ".join(f"{counts[s.value]} {s.value}" for s in reversed(list(Severity)))
        print(f"ZTrust: {len(result.findings)} finding(s) ({summary}) → {args.output}", file=sys.stderr)
    elif args.format == "console":
        render_console(result)
    else:
        write_report(result, args.format, sys.stdout)

    threshold = args.fail_on or (config.fail_on.value if config.fail_on else "high")
    if threshold == "none":
        return EXIT_OK
    worst = result.max_severity()
    return EXIT_FINDINGS if worst and worst.rank >= Severity.parse(threshold).rank else EXIT_OK


def cmd_deps(args: argparse.Namespace) -> int:
    result = run_scan(args.path, offline=True, scanners=[])
    table = Table(title=f"{len(result.dependencies)} dependencies", header_style="bold")
    for col in ("Ecosystem", "Package", "Version", "Direct", "Manifest"):
        table.add_column(col)
    for d in sorted(result.dependencies, key=lambda d: (d.ecosystem, d.name.lower())):
        table.add_row(d.ecosystem, d.name, d.version or "—", "yes" if d.direct else "", d.manifest)
    Console().print(table)
    return EXIT_OK


def cmd_commit(args: argparse.Namespace) -> int:
    report = Path(args.report).read_bytes()
    salt = args.salt or make_salt()
    commitment = compute_commitment(report, salt)
    print(json.dumps({"commitment": commitment, "salt": salt, "report_bytes": len(report)}, indent=2))
    print("Keep the salt secret until you reveal. Submit only the commitment now.", file=sys.stderr)
    return EXIT_OK


def cmd_pay_uri(args: argparse.Namespace) -> int:
    try:
        amount = zec_to_zats(args.amount) if args.amount else None
        print(build_payment_uri(args.address, amount_zats=amount, memo=args.memo, message=args.message))
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    return EXIT_OK


def cmd_check_address(args: argparse.Namespace) -> int:
    info = classify_address(args.address)
    print(json.dumps({"valid": info.valid, "kind": info.kind, "network": info.network, "shielded": info.shielded}))
    return EXIT_OK if info.valid else EXIT_FINDINGS


def cmd_serve(args: argparse.Namespace) -> int:
    try:
        import uvicorn
    except ImportError:
        print("The server needs extras: pip install 'ztrust[server]'", file=sys.stderr)
        return EXIT_USAGE
    uvicorn.run("ztrust.server.app:app", host=args.host, port=args.port)
    return EXIT_OK


COMMANDS = {
    "scan": cmd_scan,
    "deps": cmd_deps,
    "commit": cmd_commit,
    "pay-uri": cmd_pay_uri,
    "check-address": cmd_check_address,
    "serve": cmd_serve,
}


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return COMMANDS[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
