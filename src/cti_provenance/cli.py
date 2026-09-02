"""Command-line entry point for offline experiment work."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from cti_provenance.evaluation import canonical_json, recompute_v1, validate_benchmark
from cti_provenance.experiment import freeze_offline_artifacts, validate_frozen_v2


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cti-provenance")
    subcommands = parser.add_subparsers(dest="command", required=True)
    for name in ("validate", "recompute-v1", "freeze-v2"):
        command = subcommands.add_parser(name)
        command.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args(argv)
    if args.command == "validate":
        result = {
            "benchmark": validate_benchmark(args.root),
            "v1_metrics": recompute_v1(args.root),
            "v2_offline": validate_frozen_v2(args.root),
        }
        print(canonical_json(result), end="")
        return 0
    if args.command == "recompute-v1":
        print(canonical_json(recompute_v1(args.root)), end="")
        return 0
    if args.command == "freeze-v2":
        print(canonical_json(freeze_offline_artifacts(args.root)), end="")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
