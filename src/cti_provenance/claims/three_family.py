"""Fail-closed loading for the smallest three-family real-source corpus."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict

from cti_provenance.config import AuthorityPolicyConfig, load_authority_policy_config
from cti_provenance.dataset import BenchmarkCase
from cti_provenance.normalize import NormalizedDocument, normalize_versioned_source
from cti_provenance.normalize.spans import resolve_span
from cti_provenance.snapshot import (
    PublisherVersionEvidence,
    SnapshotManifest,
    SnapshotState,
    select_admissible_by_entity,
)

MANIFEST_PATH = PurePosixPath("data/manifests/three-family-corpus-v1.json")
CASES_PATH = PurePosixPath("data/benchmark/dev/three-family-cases.jsonl")
REVIEWS_PATH = PurePosixPath("annotations/three-family-review.jsonl")
AUTHORITY_POLICY_PATH = PurePosixPath("configs/authority-policy-three-family-v1.yaml")


class ThreeFamilyError(ValueError):
    """The local three-family corpus or reviewed gold is incomplete."""


class ThreeFamilyReview(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    case_id: str
    reviewer_role: Literal["manager"]
    reviewed_at_utc: datetime
    question_status: Literal["pass"]
    claim_status: Literal["pass"]
    evidence_status: Literal["pass"]
    evidence_ids: list[str]
    temporal_boundary: Literal["publisher_declared_version_evidence_only"]


def _safe_bytes(root: Path, relative: PurePosixPath) -> bytes:
    root = root.resolve(strict=True)
    candidate = root.joinpath(*relative.parts)
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        current = candidate
        while current != root:
            is_junction = getattr(current, "is_junction", None)
            if current.is_symlink() or (callable(is_junction) and is_junction()):
                raise ThreeFamilyError("three-family input traverses a link")
            current = current.parent
        return resolved.read_bytes()
    except (OSError, ValueError) as exc:
        raise ThreeFamilyError("three-family local input is unavailable") from exc


def _load_jsonl[ModelT: BaseModel](
    root: Path, relative: PurePosixPath, model: type[ModelT]
) -> list[ModelT]:
    records: list[ModelT] = []
    for line_number, line in enumerate(_safe_bytes(root, relative).splitlines(), 1):
        if not line.strip():
            continue
        try:
            records.append(model.model_validate_json(line))
        except ValueError as exc:
            raise ThreeFamilyError(
                f"invalid three-family record on line {line_number}"
            ) from exc
    return records


def load_three_family_authority_policy(root: Path) -> AuthorityPolicyConfig:
    """Load the distinct immutable authority catalog for this slice."""

    path = root.resolve(strict=True).joinpath(*AUTHORITY_POLICY_PATH.parts)
    try:
        config = load_authority_policy_config(path)
    except (OSError, ValueError) as exc:
        raise ThreeFamilyError("three-family authority policy is invalid") from exc
    if config.version != "authority-policy-three-family-v1":
        raise ThreeFamilyError("three-family authority policy identity is invalid")
    return config


def _validate_evidence_snapshot_boundary(
    case: BenchmarkCase,
    *,
    evidence_documents: dict[str, NormalizedDocument],
    selected_snapshot_ids: set[str],
) -> None:
    expected = sorted(case.expected_claims[0].evidence_ids)
    if not set(expected) <= set(evidence_documents):
        raise ThreeFamilyError("three-family evidence binding is unresolved")
    evidence_snapshot_ids = {
        evidence_documents[evidence_id].snapshot_id for evidence_id in expected
    }
    allowed_snapshot_ids = set(case.allowed_snapshot_ids)
    if not evidence_snapshot_ids <= allowed_snapshot_ids & selected_snapshot_ids:
        raise ThreeFamilyError(
            "three-family evidence is outside the case snapshot boundary"
        )


def load_three_family_corpus(
    root: Path,
) -> tuple[list[SnapshotState], list[NormalizedDocument]]:
    """Hash-check and normalize exactly six frozen local source versions."""
    try:
        envelope = json.loads(_safe_bytes(root, MANIFEST_PATH))
    except json.JSONDecodeError as exc:
        raise ThreeFamilyError("three-family manifest is invalid JSON") from exc
    if (
        envelope.get("version") != "three-family-corpus-v1"
        or envelope.get("temporal_boundary")
        != (
            "publisher-declared version evidence only; not independently "
            "observed historical availability"
        )
        or len(envelope.get("snapshots", [])) != 6
    ):
        raise ThreeFamilyError("three-family manifest identity is invalid")

    states: list[SnapshotState] = []
    documents: list[NormalizedDocument] = []
    for record in envelope["snapshots"]:
        record = dict(record)
        evidence_payload = record.pop("publisher_version_evidence")
        try:
            for field in (
                "retrieved_at_utc",
                "effective_date_if_known",
                "available_by_utc",
            ):
                if record[field] is not None:
                    record[field] = datetime.fromisoformat(
                        record[field].replace("Z", "+00:00")
                    ).astimezone(UTC)
            manifest = SnapshotManifest.model_validate(record)
            declared = datetime.fromisoformat(
                evidence_payload["publisher_declared_time_utc"].replace("Z", "+00:00")
            ).astimezone(UTC)
            evidence = PublisherVersionEvidence(
                version_identifier=evidence_payload["version_identifier"],
                publisher_declared_time_utc=declared,
                independently_addressable=evidence_payload["independently_addressable"],
            )
            raw = _safe_bytes(root, PurePosixPath(manifest.raw_blob_path))
            document = normalize_versioned_source(manifest, raw)
        except (KeyError, TypeError, ValueError) as exc:
            raise ThreeFamilyError("three-family snapshot failed validation") from exc
        states.append(
            SnapshotState(manifest=manifest, publisher_version_evidence=evidence)
        )
        documents.append(document)

    by_source: dict[str, list[NormalizedDocument]] = {}
    for document in documents:
        by_source.setdefault(document.source_name, []).append(document)
        for span in document.spans:
            resolve_span(span, document.normalized_text)
    if {key: len(value) for key, value in by_source.items()} != {
        "cisa_directive": 2,
        "cve_program": 2,
        "netscaler_advisory": 2,
    }:
        raise ThreeFamilyError("three-family source counts are invalid")

    minimum = datetime.min.replace(tzinfo=UTC)
    cve = sorted(by_source["cve_program"], key=lambda item: item.modified_at or minimum)
    if not (
        cve[0].fields["affected_versions"] == []
        and cve[0].fields["default_status"] == "affected"
        and cve[1].fields["affected_versions"] == ["5.6.0", "5.6.1"]
        and cve[1].fields["default_status"] == "unaffected"
    ):
        raise ThreeFamilyError("CVE-2024-3094 semantic delta is unavailable")
    cisa = sorted(
        by_source["cisa_directive"], key=lambda item: item.modified_at or minimum
    )
    if not (
        cisa[0].fields["required_disconnect_action"]
        and cisa[1].fields["required_february_8_update"]
    ):
        raise ThreeFamilyError("Ivanti semantic delta is unavailable")
    netscaler = sorted(
        by_source["netscaler_advisory"], key=lambda item: item.modified_at or minimum
    )
    if not (
        netscaler[0].fields["ssl_vpn_source_ip_pattern"] is None
        and netscaler[1].fields["ssl_vpn_source_ip_pattern"]
    ):
        raise ThreeFamilyError("NetScaler semantic delta is unavailable")
    return states, documents


def load_three_family_cases(
    root: Path,
    *,
    states: list[SnapshotState],
    documents: list[NormalizedDocument],
) -> list[BenchmarkCase]:
    """Validate exactly one reviewed question per source family."""
    cases = _load_jsonl(root, CASES_PATH, BenchmarkCase)
    reviews = _load_jsonl(root, REVIEWS_PATH, ThreeFamilyReview)
    authority = load_three_family_authority_policy(root)
    if len(cases) != 3 or len({case.case_id for case in cases}) != 3:
        raise ThreeFamilyError("three-family slice requires exactly three questions")
    if {case.entity_family_id for case in cases} != {
        "cve-2024-3094",
        "ivanti-ed-24-01",
        "netscaler-cve-2023-4966",
    }:
        raise ThreeFamilyError("three-family question coverage is invalid")
    review_by_id = {review.case_id: review for review in reviews}
    if (
        len(reviews) != 3
        or len(review_by_id) != 3
        or set(review_by_id) != {case.case_id for case in cases}
    ):
        raise ThreeFamilyError("each three-family question requires one review")

    evidence_documents = {
        f"{document.document_id}:{span.span_id}": document
        for document in documents
        for span in document.spans
    }
    policy_ids = {policy.policy_id for policy in authority.policies}
    state_ids = {state.manifest.snapshot_id for state in states}
    for case in cases:
        if (
            case.split != "dev"
            or case.temporal_truth_mode != "upstream_versioned"
            or case.should_abstain
            or len(case.expected_claims) != 1
            or len(case.allowed_snapshot_ids) != 1
        ):
            raise ThreeFamilyError("three-family case shape is invalid")
        selected = {
            manifest.snapshot_id
            for manifest in select_admissible_by_entity(states, case.as_of).values()
        }
        if not set(case.allowed_snapshot_ids) <= selected & state_ids:
            raise ThreeFamilyError("three-family case admits a post-cutoff snapshot")
        expected = sorted(case.expected_claims[0].evidence_ids)
        _validate_evidence_snapshot_boundary(
            case,
            evidence_documents=evidence_documents,
            selected_snapshot_ids=selected,
        )
        if not set(case.required_authority_policy_ids) <= policy_ids:
            raise ThreeFamilyError("three-family case authority policy is unresolved")
        review = review_by_id[case.case_id]
        if (
            review.reviewed_at_utc.tzinfo is None
            or review.reviewed_at_utc.utcoffset()
            != UTC.utcoffset(review.reviewed_at_utc)
            or review.evidence_ids != expected
        ):
            raise ThreeFamilyError("three-family review does not match gold")
    return cases
