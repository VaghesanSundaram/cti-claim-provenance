"""Focused command-line entry point for the active portfolio pilot."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from cti_provenance.claims.diverse_portfolio_v4 import (
    DiverseCorpusV4,
    PacketIndexV4,
    ReviewPacketV4,
)
from cti_provenance.claims.diverse_portfolio_v5 import (
    DiverseCorpusV5,
    PacketIndexV5,
    ReviewPacketV5,
)
from cti_provenance.claims.diverse_portfolio_v6 import (
    DiverseCorpusV6,
    PacketIndexV6,
    ReviewPacketV6,
)
from cti_provenance.claims.schema import ClaimAnswer
from cti_provenance.config import (
    load_portfolio_project_config_files,
    load_project_config_files,
    load_scale_project_config_files,
    load_yield_project_config_files,
)
from cti_provenance.dataset.cases import BenchmarkCase
from cti_provenance.experiments.ledger import RunRecord
from cti_provenance.experiments.portfolio_diverse_execution import (
    PortfolioProviderResult,
)
from cti_provenance.experiments.portfolio_diverse_provider import (
    PortfolioProviderPlan,
    PortfolioProviderResponse,
    PortfolioProviderSlot,
    portfolio_provider_response_schema,
)
from cti_provenance.experiments.provider_ledger import (
    AttemptReservation,
    AttemptTerminal,
    CostReconciliation,
    PlannedSlot,
    SafetyEvent,
)
from cti_provenance.experiments.provider_runner import (
    ProviderExperimentConfig,
    UserRunApproval,
    build_provider_schedule,
    load_provider_authorization_bundle,
    load_provider_experiment_config,
    provider_config_path,
)
from cti_provenance.grading.review_workflow import ReviewDecision, ReviewPacket
from cti_provenance.grading.schema import ClaimGrade
from cti_provenance.models.protocol import AuthorizationManifest
from cti_provenance.normalize.common import NormalizedDocument
from cti_provenance.snapshot.manifest import SnapshotManifest

SCHEMA_MODELS: dict[str, type[BaseModel]] = {
    "benchmark-case.schema.json": BenchmarkCase,
    "claim-answer.schema.json": ClaimAnswer,
    "claim-grade.schema.json": ClaimGrade,
    "review-decision.schema.json": ReviewDecision,
    "review-packet.schema.json": ReviewPacket,
    "review-packet-v2.schema.json": ReviewPacketV4,
    "authorization-manifest.schema.json": AuthorizationManifest,
    "normalized-document.schema.json": NormalizedDocument,
    "portfolio-diverse-packets-v4.schema.json": PacketIndexV4,
    "portfolio-diverse-v4.schema.json": DiverseCorpusV4,
    "review-packet-v3.schema.json": ReviewPacketV5,
    "portfolio-diverse-packets-v5.schema.json": PacketIndexV5,
    "portfolio-diverse-v5.schema.json": DiverseCorpusV5,
    "portfolio-diverse-packets-v6.schema.json": PacketIndexV6,
    "portfolio-diverse-v6.schema.json": DiverseCorpusV6,
    "review-packet-v4.schema.json": ReviewPacketV6,
    "portfolio-diverse-provider-plan-v1.schema.json": PortfolioProviderPlan,
    "portfolio-diverse-provider-response-v1.schema.json": PortfolioProviderResponse,
    "portfolio-diverse-provider-result-v1.schema.json": PortfolioProviderResult,
    "portfolio-diverse-provider-slot-v1.schema.json": PortfolioProviderSlot,
    "provider-attempt-reservation.schema.json": AttemptReservation,
    "provider-attempt-terminal.schema.json": AttemptTerminal,
    "provider-cost-reconciliation.schema.json": CostReconciliation,
    "provider-experiment-config.schema.json": ProviderExperimentConfig,
    "provider-planned-slot.schema.json": PlannedSlot,
    "provider-run-approval.schema.json": UserRunApproval,
    "provider-safety-event.schema.json": SafetyEvent,
    "run-record.schema.json": RunRecord,
    "snapshot-manifest.schema.json": SnapshotManifest,
}
SCHEMA_OVERRIDES = {
    "portfolio-diverse-provider-response-v1.schema.json": (
        portfolio_provider_response_schema
    )
}


def _discover_project_root(start: Path | None = None) -> Path | None:
    current = (Path.cwd() if start is None else start).resolve()
    markers = (
        Path("pyproject.toml"),
        Path("configs/sources.yaml"),
        Path("configs/authority-policy.yaml"),
        Path("schemas/claim-answer.schema.json"),
    )
    for candidate in (current, *current.parents):
        if all((candidate / marker).is_file() for marker in markers):
            return candidate
    return None


def _project_path(
    explicit: Path | None, relative: Path, option_name: str
) -> Path | None:
    if explicit is not None:
        return explicit
    root = _discover_project_root()
    if root is None:
        print(
            f"cannot discover a project checkout; pass {option_name}",
            file=sys.stderr,
        )
        return None
    return root / relative


def _render_schema(filename: str, model: type[BaseModel]) -> str:
    renderer = SCHEMA_OVERRIDES.get(filename)
    schema: dict[str, Any] = (
        renderer()
        if renderer is not None
        else model.model_json_schema(mode="serialization")
    )
    return json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8", newline="\n")
    temporary.replace(path)


def _write_versioned_outputs(
    outputs: Sequence[tuple[Path, str, str]],
) -> None:
    """Create immutable versioned outputs without leaving a partial set."""

    for path, rendered, label in outputs:
        if path.exists() and path.read_text(encoding="utf-8") != rendered:
            raise ValueError(
                f"existing {label} differs; create a new versioned ID/path"
            )
    for path, rendered, _label in outputs:
        if not path.exists():
            _atomic_write_text(path, rendered)


def export_schemas(output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    for filename in sorted(SCHEMA_MODELS):
        (output_dir / filename).write_text(
            _render_schema(filename, SCHEMA_MODELS[filename]),
            encoding="utf-8",
            newline="\n",
        )


def check_schemas(output_dir: Path) -> list[str]:
    drifted: list[str] = []
    for filename in sorted(SCHEMA_MODELS):
        path = output_dir / filename
        expected = _render_schema(filename, SCHEMA_MODELS[filename])
        try:
            actual = path.read_text(encoding="utf-8")
            json.loads(actual)
        except (FileNotFoundError, json.JSONDecodeError):
            drifted.append(filename)
            continue
        if actual != expected:
            drifted.append(filename)
    return drifted


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cti-provenance")
    commands = parser.add_subparsers(dest="command", required=True)

    schema = commands.add_parser("schema", help="manage exported JSON Schemas")
    schema_commands = schema.add_subparsers(dest="schema_command", required=True)
    for command in ("export", "check"):
        subparser = schema_commands.add_parser(command)
        subparser.add_argument("--output-dir", type=Path, default=None)

    config = commands.add_parser("config", help="validate checked-in configuration")
    config_commands = config.add_subparsers(dest="config_command", required=True)
    config_check = config_commands.add_parser("check")
    config_check.add_argument("--sources", type=Path, default=None)
    config_check.add_argument("--authority-policy", type=Path, default=None)
    provider_check = config_commands.add_parser(
        "provider-check",
        help="validate optional frozen provider configuration without credentials",
    )
    provider_check.add_argument("--root", type=Path, default=None)
    provider_check.add_argument("--config-version", choices=("v1", "v2"), default="v2")

    for command, help_text in (
        (
            "portfolio-demo",
            "validate the tracked 24/16/48 provider-free portfolio result",
        ),
        (
            "portfolio-rebuild",
            "verify the source-cache-to-v2 rebuild with no network fallback",
        ),
        (
            "portfolio-release-check",
            "run public-candidate checks without publishing or choosing a license",
        ),
    ):
        portfolio = commands.add_parser(command, help=help_text)
        portfolio.add_argument("--root", type=Path, default=None)

    review = commands.add_parser(
        "review", help="validate the append-only single-reviewer log"
    )
    review_commands = review.add_subparsers(dest="review_command", required=True)
    review_validate = review_commands.add_parser("validate")
    review_validate.add_argument("--packet", type=Path, required=True)
    review_validate.add_argument("--decisions", type=Path, required=True)
    review_validate.add_argument("--summary", type=Path, required=True)
    return parser


def _root_from_args(args: argparse.Namespace) -> Path | None:
    root = args.root.resolve() if args.root is not None else _discover_project_root()
    if root is None:
        print("cannot discover a project checkout; pass --root", file=sys.stderr)
    return root


def _run_schema(args: argparse.Namespace) -> int:
    output_dir = _project_path(args.output_dir, Path("schemas"), "--output-dir")
    if output_dir is None:
        return 2
    if args.schema_command == "export":
        export_schemas(output_dir)
        return 0
    drifted = check_schemas(output_dir)
    if drifted:
        print("schema drift detected: " + ", ".join(drifted), file=sys.stderr)
        return 1
    return 0


def _run_config(args: argparse.Namespace) -> int:
    if args.config_command == "provider-check":
        root = _root_from_args(args)
        if root is None:
            return 2
        try:
            provider_config = load_provider_experiment_config(
                root / provider_config_path(args.config_version)
            )
            authorization = load_provider_authorization_bundle(root, provider_config)
            schedule = build_provider_schedule(provider_config)
        except (OSError, ValueError) as exc:
            print(
                f"provider configuration validation failed ({type(exc).__name__})",
                file=sys.stderr,
            )
            return 1
        print(
            "provider configuration valid "
            f"(slots={len(schedule)}, config={provider_config.sha256()}, "
            f"authorization={authorization.bundle_sha256})"
        )
        return 0

    sources = _project_path(args.sources, Path("configs/sources.yaml"), "--sources")
    authority = _project_path(
        args.authority_policy,
        Path("configs/authority-policy.yaml"),
        "--authority-policy",
    )
    if sources is None or authority is None:
        return 2
    try:
        load_project_config_files(sources, authority)
        config_dir = sources.parent
        loaders = (
            (
                load_portfolio_project_config_files,
                "sources-portfolio-proof-v1.yaml",
                "authority-policy-portfolio-proof-v1.yaml",
            ),
            (
                load_yield_project_config_files,
                "sources-portfolio-yield-v1.yaml",
                "authority-policy-portfolio-yield-v1.yaml",
            ),
            (
                load_scale_project_config_files,
                "sources-portfolio-scale-v1.yaml",
                "authority-policy-portfolio-scale-v1.yaml",
            ),
        )
        for loader, source_name, authority_name in loaders:
            source_path = config_dir / source_name
            authority_path = config_dir / authority_name
            if source_path.is_file() or authority_path.is_file():
                loader(source_path, authority_path)
    except (OSError, ValueError) as exc:
        print(
            f"configuration validation failed ({type(exc).__name__})",
            file=sys.stderr,
        )
        return 1
    return 0


def _run_portfolio(args: argparse.Namespace) -> int:
    from cti_provenance.release import (
        DEMO_REPORT_PATH,
        RELEASE_REPORT_PATH,
        render_portfolio_demo,
        render_portfolio_release_readiness,
        run_portfolio_demo,
        run_portfolio_release_readiness,
        verify_portfolio_full_rebuild,
    )

    root = _root_from_args(args)
    if root is None:
        return 2
    try:
        if args.command == "portfolio-demo":
            summary = run_portfolio_demo(root)
            expected = render_portfolio_demo(summary)
            if (
                root.joinpath(*DEMO_REPORT_PATH.parts).read_text(encoding="utf-8")
                != expected
            ):
                raise ValueError("tracked portfolio demo summary is stale")
            print(
                "portfolio demo passed "
                f"({summary.inventory_family_count} inventory families; "
                f"{summary.public_family_count} public; "
                f"{summary.matched_case_count} matched cases)"
            )
            return 0
        if args.command == "portfolio-rebuild":
            rebuilt = verify_portfolio_full_rebuild(root)
            print(
                "portfolio full rebuild passed "
                f"({rebuilt.public_case_count} public; "
                f"{rebuilt.matched_case_count} matched cases)"
            )
            return 0
        readiness = run_portfolio_release_readiness(root)
        expected = render_portfolio_release_readiness(readiness)
        if (
            root.joinpath(*RELEASE_REPORT_PATH.parts).read_text(encoding="utf-8")
            != expected
        ):
            raise ValueError("tracked portfolio release summary is stale")
        print(f"portfolio release check: {readiness.status}")
        return 0 if readiness.status == "ready_for_user_decisions" else 1
    except (OSError, ValueError) as exc:
        print(
            f"{args.command} failed ({type(exc).__name__}): {exc}",
            file=sys.stderr,
        )
        return 1


def _run_review(args: argparse.Namespace) -> int:
    from cti_provenance.grading.diverse_review import validate_diverse_review_log
    from cti_provenance.grading.review_workflow import (
        load_jsonl_records,
        render_review_summary,
        validate_review_log,
    )

    try:
        packet_text = args.packet.read_text(encoding="utf-8")
        packet_version = json.loads(packet_text).get("schema_version")
        decisions = load_jsonl_records(args.decisions, ReviewDecision)
        if packet_version in {
            "review-packet-v2",
            "review-packet-v3",
            "review-packet-v4",
        }:
            packet_v2: ReviewPacketV4 = (
                ReviewPacketV6.model_validate_json(packet_text)
                if packet_version == "review-packet-v4"
                else (
                    ReviewPacketV5.model_validate_json(packet_text)
                    if packet_version == "review-packet-v3"
                    else ReviewPacketV4.model_validate_json(packet_text)
                )
            )
            active_count, unresolved = validate_diverse_review_log(packet_v2, decisions)
            _atomic_write_text(
                args.summary,
                "# Human review status\n\n"
                f"- Packet: `{packet_v2.packet_id}` (`{packet_v2.packet_sha256}`)\n"
                "- Review mode: `single_reviewer`\n"
                f"- Items: {len(packet_v2.items)}\n"
                f"- Active decisions: {active_count}\n"
                f"- Unresolved: {', '.join(unresolved) if unresolved else 'none'}\n",
            )
            print(
                f"review log valid ({active_count} active decisions, "
                f"{len(unresolved)} unresolved items)"
            )
            return 0
        packet = ReviewPacket.model_validate_json(packet_text)
        summary = validate_review_log(
            packet, decisions, [], review_mode="single_reviewer"
        )
        _atomic_write_text(args.summary, render_review_summary(summary))
    except (OSError, ValueError) as exc:
        print(f"review validation failed ({type(exc).__name__})", file=sys.stderr)
        return 1
    print(
        f"review log valid ({summary.active_decision_count} active decisions, "
        f"{len(summary.unresolved_item_ids)} unresolved items)"
    )
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    if args.command == "schema":
        return _run_schema(args)
    if args.command == "config":
        return _run_config(args)
    if args.command.startswith("portfolio-"):
        return _run_portfolio(args)
    if args.command == "review":
        return _run_review(args)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
