"""Command-line entry point for release validation."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from cti_provenance.release import run_release_check


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cti-provenance")
    subcommands = parser.add_subparsers(dest="command", required=True)

    release = subcommands.add_parser(
        "release-check",
        help="validate the checked-in benchmark, review record, results, and docs",
    )
    release.add_argument("--root", type=Path, default=None)

    legacy_alias = subcommands.add_parser(
        "portfolio-release-check",
        help="alias for release-check",
    )
    legacy_alias.add_argument("--root", type=Path, default=None)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command in {"release-check", "portfolio-release-check"}:
        root = args.root or Path.cwd()
        result = run_release_check(root)
        print(result.render())
        return 0 if result.passed else 1
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
