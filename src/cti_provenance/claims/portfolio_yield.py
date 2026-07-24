"""Fail-closed loader for the portfolio yield-gate family batch."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC
from pathlib import Path, PurePosixPath

from cti_provenance.claims.portfolio_proof import (
    PortfolioProofError,
    PortfolioProofReview,
    _load_jsonl,
    _safe_bytes,
    _time,
    load_portfolio_proof_corpus,
)
from cti_provenance.config import (
    AuthorityPolicyConfig,
    load_yield_project_config_files,
)
from cti_provenance.dataset import BenchmarkCase
from cti_provenance.normalize import (
    FamilySpec,
    NormalizedDocument,
    load_portfolio_family_config,
    load_portfolio_lineage_config,
    normalize_portfolio_source,
    validate_portfolio_dependency_splits,
)
from cti_provenance.normalize.spans import resolve_span
from cti_provenance.snapshot import (
    PublisherVersionEvidence,
    SnapshotManifest,
    SnapshotState,
    select_admissible_by_entity,
)

MANIFEST_PATH = PurePosixPath("data/manifests/portfolio-yield-corpus-v1.json")
FAMILY_SPEC_PATH = PurePosixPath("configs/portfolio-yield-families-v1.yaml")
SOURCE_POLICY_PATH = PurePosixPath("configs/sources-portfolio-yield-v1.yaml")
AUTHORITY_POLICY_PATH = PurePosixPath(
    "configs/authority-policy-portfolio-yield-v1.yaml"
)
CASE_PATHS = (
    PurePosixPath("data/benchmark/dev/portfolio-yield-dev-cases.jsonl"),
    PurePosixPath("data/benchmark/validation/portfolio-yield-validation-cases.jsonl"),
)
REVIEWS_PATH = PurePosixPath("annotations/portfolio-yield-review.jsonl")
LINEAGE_PATH = PurePosixPath("configs/portfolio-family-lineage-v1.yaml")
CAPTURE_LEDGER_PATH = PurePosixPath("data/manifests/portfolio-capture-ledger-v1.json")


def load_portfolio_yield_authority_policy(root: Path) -> AuthorityPolicyConfig:
    """Validate the closed yield source and authority catalogs together."""

    resolved = root.resolve(strict=True)
    try:
        _, authority = load_yield_project_config_files(
            resolved.joinpath(*SOURCE_POLICY_PATH.parts),
            resolved.joinpath(*AUTHORITY_POLICY_PATH.parts),
        )
    except (OSError, ValueError) as exc:
        raise PortfolioProofError("portfolio yield policy is invalid") from exc
    return authority


def _supporting_artifacts(
    root: Path,
    artifacts: list[dict[str, object]],
    ledger_successes: dict[str, dict[str, object]],
) -> dict[str, bytes]:
    bodies: dict[str, bytes] = {}
    for artifact in artifacts:
        try:
            artifact_id = str(artifact["id"])
            ledger_source_id = str(artifact["ledger_source_id"])
            body = _safe_bytes(root, PurePosixPath(str(artifact["path"])))
            if (
                len(body) != artifact["byte_length"]
                or hashlib.sha256(body).hexdigest() != artifact["sha256"]
            ):
                raise PortfolioProofError("yield supporting artifact hash mismatch")
            ledger = ledger_successes[ledger_source_id]
            expected_ledger = {
                "url": artifact["url"],
                "raw_blob_path": artifact["path"],
                "sha256": artifact["sha256"],
                "byte_length": artifact["byte_length"],
            }
            if any(
                ledger.get(field) != value for field, value in expected_ledger.items()
            ):
                raise PortfolioProofError(
                    "yield supporting artifact is not capture-ledger bound"
                )
        except (KeyError, TypeError, ValueError) as exc:
            raise PortfolioProofError("yield supporting artifact is invalid") from exc
        if artifact_id in bodies:
            raise PortfolioProofError("yield supporting artifact ID is duplicated")
        bodies[artifact_id] = body
    expected = {
        "django-fix-commit",
        "django-license",
        "django-pre-commit",
        "nodejs-commit-list",
        "nodejs-license",
        "nvd-change-history",
        "nvd-terms",
    }
    if set(bodies) != expected:
        raise PortfolioProofError("yield supporting artifact coverage is incomplete")
    return bodies


def _load_capture_ledger(root: Path) -> dict[str, dict[str, object]]:
    try:
        ledger = json.loads(_safe_bytes(root, CAPTURE_LEDGER_PATH))
        attempts = list(ledger["attempts"])
    except (KeyError, TypeError, json.JSONDecodeError) as exc:
        raise PortfolioProofError("portfolio capture ledger is invalid") from exc
    successes = [record for record in attempts if record.get("outcome") == "success"]
    if ledger.get("successful_captures") != len(successes) or ledger.get(
        "total_attempts"
    ) != len(attempts):
        raise PortfolioProofError("portfolio capture ledger counters are invalid")
    by_source = {str(record["source_id"]): record for record in successes}
    if len(by_source) != len(successes):
        raise PortfolioProofError("portfolio capture success IDs are duplicated")
    return by_source


def _validate_node_metadata(bodies: dict[str, bytes]) -> None:
    history = json.loads(bodies["nodejs-commit-list"])
    commits = {item["sha"]: item for item in history}
    expected = {
        "862c078202461b5f76583e95251d5948272f446b": "2025-05-08T18:09:17Z",
        "479f73b43344550422306212bad848605e94c9b7": "2025-05-14T21:31:44Z",
    }
    if any(
        commits.get(commit, {}).get("commit", {}).get("committer", {}).get("date")
        != timestamp
        for commit, timestamp in expected.items()
    ):
        raise PortfolioProofError("Node.js publisher version metadata is not exact")
    if b"MIT License" not in bodies["nodejs-license"]:
        raise PortfolioProofError("Node.js license evidence is missing")


def _validate_nvd_history(bodies: dict[str, bytes]) -> None:
    payload = json.loads(bodies["nvd-change-history"])
    changes = {
        item["change"]["created"]: item["change"]
        for item in payload.get("cveChanges", [])
        if item.get("change", {}).get("cveId") == "CVE-2024-3400"
    }
    old = changes.get("2024-04-23T19:57:25.223")
    new = changes.get("2024-05-29T16:00:24.110")
    target = "cpe:2.3:o:paloaltonetworks:pan-os:10.2.2:h5:*:*:*:*:*:*"
    if old is None or new is None:
        raise PortfolioProofError("NVD change-history events are missing")
    old_values = "\n".join(str(item) for item in old.get("details", []))
    new_values = "\n".join(str(item) for item in new.get("details", []))
    if target in old_values or target not in new_values:
        raise PortfolioProofError("NVD CPE semantic delta is not exact")
    terms = bodies["nvd-terms"].lower()
    if b"national vulnerability database" not in terms:
        raise PortfolioProofError("NVD terms evidence is missing")


def _validate_django_metadata(bodies: dict[str, bytes]) -> None:
    pre = json.loads(bodies["django-pre-commit"])
    fixed = json.loads(bodies["django-fix-commit"])
    if (
        pre.get("sha") != "428d06ccef09e70bcef9869c5a9404863b2fc7d8"
        or pre.get("commit", {}).get("committer", {}).get("date")
        != "2024-02-06T12:22:47Z"
        or fixed.get("sha") != "3394fc6132436eca89e997083bae9985fb7e761e"
        or fixed.get("commit", {}).get("committer", {}).get("date")
        != "2024-03-04T07:22:40Z"
        or "CVE-2024-27351" not in fixed.get("commit", {}).get("message", "")
    ):
        raise PortfolioProofError("Django publisher version metadata is not exact")
    if (
        b"Redistribution and use in source and binary forms"
        not in bodies["django-license"]
    ):
        raise PortfolioProofError("Django license evidence is missing")


def load_portfolio_yield_corpus(
    root: Path,
) -> tuple[list[SnapshotState], list[NormalizedDocument], list[FamilySpec]]:
    """Load six source states and prove three additional family deltas."""

    try:
        envelope = json.loads(_safe_bytes(root, MANIFEST_PATH))
        config = load_portfolio_family_config(
            root.resolve(strict=True).joinpath(*FAMILY_SPEC_PATH.parts)
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise PortfolioProofError("portfolio yield manifest/spec is invalid") from exc
    if (
        envelope.get("version") != "portfolio-yield-corpus-v1"
        or envelope.get("family_spec") != FAMILY_SPEC_PATH.as_posix()
        or envelope.get("source_policy") != SOURCE_POLICY_PATH.as_posix()
        or envelope.get("authority_policy") != AUTHORITY_POLICY_PATH.as_posix()
        or envelope.get("temporal_boundary")
        != (
            "publisher-declared version evidence only; not independently "
            "observed historical availability"
        )
        or len(config.families) != 4
        or len(envelope.get("snapshots", [])) != 6
    ):
        raise PortfolioProofError("portfolio yield manifest identity is invalid")

    ledger_successes = _load_capture_ledger(root)
    support = _supporting_artifacts(
        root, list(envelope.get("supporting_artifacts", [])), ledger_successes
    )
    _validate_node_metadata(support)
    _validate_nvd_history(support)
    _validate_django_metadata(support)

    proof_states, _, proof_specs = load_portfolio_proof_corpus(root)
    lineage = load_portfolio_lineage_config(
        root.resolve(strict=True).joinpath(*LINEAGE_PATH.parts)
    )
    expected_ids = {
        "cve-2024-3094",
        "ivanti-ed-24-01",
        "netscaler-cve-2023-4966",
        *(spec.family_id for spec in proof_specs),
        *(spec.family_id for spec in config.families),
    }
    if not expected_ids <= {record.family_id for record in lineage.families}:
        raise PortfolioProofError("portfolio lineage registry coverage is invalid")
    lineage_by_id = {record.family_id: record for record in lineage.families}
    for spec in [*proof_specs, *config.families]:
        lineage_record = lineage_by_id[spec.family_id]
        for field in type(lineage_record).model_fields:
            if field != "family_id" and getattr(lineage_record, field) != getattr(
                spec, field
            ):
                raise PortfolioProofError(
                    f"portfolio lineage registry mismatch for {spec.family_id}"
                )
    validate_portfolio_dependency_splits(lineage.families)
    proof_by_snapshot = {
        state.manifest.snapshot_id: state
        for state in proof_states
        if state.manifest.snapshot_id in set(envelope["reused_snapshot_ids"])
    }
    if set(proof_by_snapshot) != set(envelope["reused_snapshot_ids"]):
        raise PortfolioProofError("reused CISA snapshot binding is incomplete")

    spec_by_snapshot = {
        snapshot_id: spec
        for spec in config.families
        for snapshot_id in spec.source_state_ids
    }
    states = list(proof_by_snapshot.values())
    documents: list[NormalizedDocument] = []
    for snapshot_id, state in proof_by_snapshot.items():
        spec = spec_by_snapshot[snapshot_id]
        raw = _safe_bytes(root, PurePosixPath(state.manifest.raw_blob_path))
        documents.append(normalize_portfolio_source(state.manifest, raw, spec))

    for payload in envelope["snapshots"]:
        record = dict(payload)
        publisher = record.pop("publisher_version_evidence")
        for field in (
            "retrieved_at_utc",
            "effective_date_if_known",
            "available_by_utc",
        ):
            record[field] = _time(record[field])
        try:
            manifest = SnapshotManifest.model_validate(record)
            spec = spec_by_snapshot[manifest.snapshot_id]
            raw = _safe_bytes(root, PurePosixPath(manifest.raw_blob_path))
            document = normalize_portfolio_source(manifest, raw, spec)
            state = SnapshotState(
                manifest=manifest,
                publisher_version_evidence=PublisherVersionEvidence(
                    version_identifier=publisher["version_identifier"],
                    publisher_declared_time_utc=_time(
                        publisher["publisher_declared_time_utc"]
                    ),
                    independently_addressable=publisher["independently_addressable"],
                ),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise PortfolioProofError(
                "portfolio yield snapshot failed validation"
            ) from exc
        for span in document.spans:
            resolve_span(span, document.normalized_text)
        states.append(state)
        documents.append(document)

    by_snapshot = {document.snapshot_id: document for document in documents}
    for spec in config.families:
        actual = [
            by_snapshot[snapshot_id].fields["claim_value"]
            for snapshot_id in spec.source_state_ids
        ]
        if actual != spec.expected_values or actual[0] == actual[1]:
            raise PortfolioProofError(
                f"semantic delta unavailable for {spec.family_id}"
            )
    return states, documents, config.families


def load_portfolio_yield_cases(
    root: Path,
    *,
    states: list[SnapshotState],
    documents: list[NormalizedDocument],
    specs: list[FamilySpec],
) -> list[BenchmarkCase]:
    """Validate one audited question for each yield-gate family."""

    cases = [
        case for path in CASE_PATHS for case in _load_jsonl(root, path, BenchmarkCase)
    ]
    reviews = _load_jsonl(root, REVIEWS_PATH, PortfolioProofReview)
    authority = load_portfolio_yield_authority_policy(root)
    spec_by_template = {spec.template_family_id: spec for spec in specs}
    if (
        len(cases) != 4
        or {case.entity_family_id for case in cases}
        != {spec.family_id for spec in specs}
        or len({case.case_id for case in cases}) != 4
    ):
        raise PortfolioProofError("portfolio yield question coverage is invalid")
    review_by_id = {review.case_id: review for review in reviews}
    if len(reviews) != 4 or set(review_by_id) != {case.case_id for case in cases}:
        raise PortfolioProofError("portfolio yield review coverage is invalid")
    evidence_documents = {
        f"{document.document_id}:{span.span_id}": document
        for document in documents
        for span in document.spans
    }
    policy_ids = {policy.policy_id for policy in authority.policies}
    for case in cases:
        spec = spec_by_template.get(case.template_family_id)
        if (
            spec is None
            or case.split
            != (
                "holdout"
                if spec.prospective_split == "holdout_candidate"
                else spec.prospective_split
            )
            or case.temporal_truth_mode != "upstream_versioned"
            or case.should_abstain
            or len(case.expected_claims) != 1
            or len(case.allowed_snapshot_ids) != 1
            or case.expected_claims[0].predicate != spec.claim.predicate
        ):
            raise PortfolioProofError("portfolio yield case shape is invalid")
        selected = {
            manifest.snapshot_id
            for manifest in select_admissible_by_entity(states, case.as_of).values()
        }
        if not set(case.allowed_snapshot_ids) <= selected:
            raise PortfolioProofError("portfolio yield case crosses its cutoff")
        evidence_ids = sorted(case.expected_claims[0].evidence_ids)
        if not set(evidence_ids) <= set(evidence_documents):
            raise PortfolioProofError("portfolio yield evidence is unresolved")
        if {
            evidence_documents[evidence_id].snapshot_id for evidence_id in evidence_ids
        } != set(case.allowed_snapshot_ids):
            raise PortfolioProofError("portfolio yield evidence snapshot is invalid")
        if not set(case.required_authority_policy_ids) <= policy_ids:
            raise PortfolioProofError("portfolio yield authority policy is unresolved")
        review = review_by_id[case.case_id]
        if (
            review.reviewed_at_utc.tzinfo is None
            or review.reviewed_at_utc.utcoffset()
            != UTC.utcoffset(review.reviewed_at_utc)
            or review.evidence_ids != evidence_ids
        ):
            raise PortfolioProofError("portfolio yield manager audit is invalid")
    return cases
