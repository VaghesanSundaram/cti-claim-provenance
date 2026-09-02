"""Command-line entry point for offline experiment work."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from cti_provenance import schema_experiment
from cti_provenance.evaluation import (
    canonical_json,
    recompute_v1,
    validate_benchmark,
)
from cti_provenance.experiment import freeze_offline_artifacts, validate_frozen_v2
from cti_provenance.published import recompute_v2, validate_v1_outputs


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cti-provenance")
    subcommands = parser.add_subparsers(dest="command", required=True)
    for name in (
        "validate",
        "recompute-v1",
        "recompute-v2",
        "freeze-v2",
        "freeze-schema-v1.1",
        "validate-schema-v1.1",
    ):
        command = subcommands.add_parser(name)
        command.add_argument("--root", type=Path, default=Path.cwd())
    run_command = subcommands.add_parser("run-schema-v1.1")
    run_command.add_argument("--root", type=Path, default=Path.cwd())
    run_command.add_argument("--ledger", type=Path, required=True)
    run_command.add_argument("--raw-dir", type=Path, required=True)
    run_command.add_argument("--max-cells", type=int)
    report_command = subcommands.add_parser("report-schema-v1.1")
    report_command.add_argument("--root", type=Path, default=Path.cwd())
    report_command.add_argument("--ledger", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.command == "validate":
        result = {
            "benchmark": validate_benchmark(args.root),
            "v1_metrics": recompute_v1(args.root),
            "v1_outputs": validate_v1_outputs(args.root),
            "v2_offline": validate_frozen_v2(args.root),
            "v2_metrics": recompute_v2(args.root),
        }
        print(canonical_json(result), end="")
        return 0
    if args.command == "recompute-v1":
        print(canonical_json(recompute_v1(args.root)), end="")
        return 0
    if args.command == "recompute-v2":
        print(canonical_json(recompute_v2(args.root)), end="")
        return 0
    if args.command == "freeze-v2":
        print(canonical_json(freeze_offline_artifacts(args.root)), end="")
        return 0
    if args.command == "freeze-schema-v1.1":
        print(canonical_json(schema_experiment.freeze(args.root)), end="")
        return 0
    if args.command == "validate-schema-v1.1":
        print(canonical_json(schema_experiment.validate_frozen(args.root)), end="")
        return 0
    if args.command == "run-schema-v1.1":
        schema_experiment.run(args.root, args.ledger, args.raw_dir, args.max_cells)
        return 0
    if args.command == "report-schema-v1.1":
        result = schema_experiment.publish_results(args.root, args.ledger)
        print(canonical_json(result), end="")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
