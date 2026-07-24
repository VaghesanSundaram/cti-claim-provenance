"""Fail-closed loader for the first portfolio proof-family batch."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict

from cti_provenance.config import (
    AuthorityPolicyConfig,
    load_portfolio_project_config_files,
)
from cti_provenance.dataset import BenchmarkCase
from cti_provenance.normalize import (
    FamilySpec,
    NormalizedDocument,
    load_portfolio_family_config,
    normalize_portfolio_source,
)
from cti_provenance.normalize.spans import resolve_span
from cti_provenance.snapshot import (
    AttackEvidence,
    CisaEvidence,
    PublisherVersionEvidence,
    SnapshotManifest,
    SnapshotState,
    select_admissible_by_entity,
)

MANIFEST_PATH = PurePosixPath("data/manifests/portfolio-proof-corpus-v1.json")
FAMILY_SPEC_PATH = PurePosixPath("configs/portfolio-proof-families-v1.yaml")
CASES_PATH = PurePosixPath("data/benchmark/dev/portfolio-proof-cases.jsonl")
REVIEWS_PATH = PurePosixPath("annotations/portfolio-proof-review.jsonl")
AUTHORITY_POLICY_PATH = PurePosixPath(
    "configs/authority-policy-portfolio-proof-v1.yaml"
)
SOURCE_POLICY_PATH = PurePosixPath("configs/sources-portfolio-proof-v1.yaml")


class PortfolioProofError(ValueError):
    """The local portfolio proof corpus is incomplete or inconsistent."""


class PortfolioProofReview(BaseModel):
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
                raise PortfolioProofError("portfolio proof input traverses a link")
            current = current.parent
        return resolved.read_bytes()
    except (OSError, ValueError) as exc:
        raise PortfolioProofError("portfolio proof local input is unavailable") from exc


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
            raise PortfolioProofError(
                f"invalid portfolio proof record on line {line_number}"
            ) from exc
    return records


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(UTC)


def load_portfolio_proof_authority_policy(root: Path) -> AuthorityPolicyConfig:
    resolved_root = root.resolve(strict=True)
    try:
        _, config = load_portfolio_project_config_files(
            resolved_root.joinpath(*SOURCE_POLICY_PATH.parts),
            resolved_root.joinpath(*AUTHORITY_POLICY_PATH.parts),
        )
    except (OSError, ValueError) as exc:
        raise PortfolioProofError(
            "portfolio proof authority policy is invalid"
        ) from exc
    if config.version != "authority-policy-portfolio-proof-v1":
        raise PortfolioProofError("portfolio proof authority identity is invalid")
    return config


def _validate_supporting_artifacts(
    root: Path, artifacts: list[dict[str, object]]
) -> dict[str, bytes]:
    bodies: dict[str, bytes] = {}
    for artifact in artifacts:
        try:
            artifact_id = str(artifact["id"])
            body = _safe_bytes(root, PurePosixPath(str(artifact["path"])))
            if (
                len(body) != artifact["byte_length"]
                or hashlib.sha256(body).hexdigest() != artifact["sha256"]
            ):
                raise PortfolioProofError("supporting artifact hash mismatch")
        except (KeyError, TypeError, ValueError) as exc:
            raise PortfolioProofError("supporting artifact is invalid") from exc
        if artifact_id in bodies:
            raise PortfolioProofError("supporting artifact identity is duplicated")
        bodies[artifact_id] = body

    required = {
        "apache-archive-index",
        "apache-license",
        "cisa-commit-old",
        "cisa-commit-new",
        "cisa-license",
        "attack-release-v15.1",
        "attack-release-v16.0",
        "attack-tag-v15.1",
        "attack-tag-v16.0",
        "attack-license",
    }
    if set(bodies) != required:
        raise PortfolioProofError("supporting artifact coverage is incomplete")
    if (
        b"CHANGES_2.4.50" not in bodies["apache-archive-index"]
        or b"CHANGES_2.4.51" not in bodies["apache-archive-index"]
    ):
        raise PortfolioProofError("Apache archive version metadata is missing")
    if b"Apache License" not in bodies["apache-license"]:
        raise PortfolioProofError("Apache license evidence is missing")
    if b"CC0 1.0 Universal" not in bodies["cisa-license"]:
        raise PortfolioProofError("CISA KEV CC0 evidence is missing")
    if b"MITRE's copyright designation" not in bodies["attack-license"]:
        raise PortfolioProofError("ATT&CK license designation is missing")
    return bodies


def _validate_cisa_metadata(bodies: dict[str, bytes]) -> None:
    old = json.loads(bodies["cisa-commit-old"])
    new = json.loads(bodies["cisa-commit-new"])
    if (
        old.get("sha") != "87ba74fc7c502adcf482fc7b06e65ce9ea4d9ef2"
        or new.get("sha") != "bc9dbb256ec16f37b646b564770af99b0a96cbe1"
        or old["commit"]["committer"]["date"] != "2026-07-16T19:11:42Z"
        or new["commit"]["committer"]["date"] != "2026-07-21T15:43:32Z"
        or [item["sha"] for item in new["parents"]]
        != ["87ba74fc7c502adcf482fc7b06e65ce9ea4d9ef2"]
    ):
        raise PortfolioProofError("CISA KEV commit lineage is not exact")


def _validate_attack_metadata(bodies: dict[str, bytes]) -> None:
    expected = {
        "15.1": (
            "23b23819d2b074f76d75815f6e3b9c6228113ab6",
            "2024-05-02T14:41:53Z",
        ),
        "16.0": (
            "baa85d58a6eda286bca799fd8a237af1a6a0721e",
            "2024-10-31T13:20:14Z",
        ),
    }
    for version, (commit, published) in expected.items():
        release = json.loads(bodies[f"attack-release-v{version}"])
        tag = json.loads(bodies[f"attack-tag-v{version}"])
        if (
            release.get("tag_name") != f"v{version}"
            or release.get("published_at") != published
            or release.get("draft") is not False
            or release.get("prerelease") is not False
            or tag.get("tag") != f"v{version}"
            or tag.get("object", {}).get("sha") != commit
        ):
            raise PortfolioProofError("ATT&CK release metadata is not exact")


def load_portfolio_proof_corpus(
    root: Path,
) -> tuple[list[SnapshotState], list[NormalizedDocument], list[FamilySpec]]:
    """Hash-check, normalize, and prove exactly three semantic deltas."""

    try:
        envelope = json.loads(_safe_bytes(root, MANIFEST_PATH))
        config = load_portfolio_family_config(
            root.resolve(strict=True).joinpath(*FAMILY_SPEC_PATH.parts)
        )
    except (json.JSONDecodeError, OSError, ValueError) as exc:
        raise PortfolioProofError("portfolio proof manifest/spec is invalid") from exc
    if (
        envelope.get("version") != "portfolio-proof-corpus-v1"
        or envelope.get("family_spec") != FAMILY_SPEC_PATH.as_posix()
        or envelope.get("source_policy") != SOURCE_POLICY_PATH.as_posix()
        or envelope.get("authority_policy") != AUTHORITY_POLICY_PATH.as_posix()
        or envelope.get("temporal_boundary")
        != (
            "publisher-declared version evidence only; not independently "
            "observed historical availability"
        )
        or len(envelope.get("snapshots", [])) != 6
        or len(config.families) != 3
    ):
        raise PortfolioProofError("portfolio proof manifest identity is invalid")

    bodies = _validate_supporting_artifacts(
        root, list(envelope.get("supporting_artifacts", []))
    )
    _validate_cisa_metadata(bodies)
    _validate_attack_metadata(bodies)
    spec_by_snapshot = {
        snapshot_id: spec
        for spec in config.families
        for snapshot_id in spec.source_state_ids
    }
    states: list[SnapshotState] = []
    documents: list[NormalizedDocument] = []
    for payload in envelope["snapshots"]:
        record = dict(payload)
        publisher_payload = record.pop("publisher_version_evidence", None)
        cisa_payload = record.pop("cisa_evidence", None)
        attack_payload = record.pop("attack_evidence", None)
        try:
            for field in (
                "retrieved_at_utc",
                "effective_date_if_known",
                "available_by_utc",
            ):
                if record[field] is not None:
                    record[field] = _time(record[field])
            manifest = SnapshotManifest.model_validate(record)
            spec = spec_by_snapshot[manifest.snapshot_id]
            raw = _safe_bytes(root, PurePosixPath(manifest.raw_blob_path))
            document = normalize_portfolio_source(manifest, raw, spec)
            if publisher_payload is not None:
                state = SnapshotState(
                    manifest=manifest,
                    publisher_version_evidence=PublisherVersionEvidence(
                        version_identifier=publisher_payload["version_identifier"],
                        publisher_declared_time_utc=_time(
                            publisher_payload["publisher_declared_time_utc"]
                        ),
                        independently_addressable=publisher_payload[
                            "independently_addressable"
                        ],
                    ),
                )
            elif cisa_payload is not None:
                ancestors = frozenset(cisa_payload.pop("ancestor_snapshot_ids"))
                state = SnapshotState(
                    manifest=manifest,
                    cisa_ancestor_snapshot_ids=ancestors,
                    cisa_evidence=CisaEvidence(
                        **{
                            **cisa_payload,
                            "official_commit_time_utc": _time(
                                cisa_payload["official_commit_time_utc"]
                            ),
                        }
                    ),
                )
            elif attack_payload is not None:
                state = SnapshotState(
                    manifest=manifest,
                    attack_evidence=AttackEvidence(
                        **{
                            **attack_payload,
                            "publisher_release_time_utc": _time(
                                attack_payload["publisher_release_time_utc"]
                            ),
                        }
                    ),
                )
            else:
                raise PortfolioProofError("snapshot evidence shape is missing")
        except (KeyError, TypeError, ValueError) as exc:
            raise PortfolioProofError(
                "portfolio proof snapshot failed validation"
            ) from exc
        for span in document.spans:
            resolve_span(span, document.normalized_text)
        states.append(state)
        documents.append(document)

    by_snapshot = {document.snapshot_id: document for document in documents}
    for spec in config.families:
        actual = [
            by_snapshot[snapshot].fields["claim_value"]
            for snapshot in spec.source_state_ids
        ]
        if actual != spec.expected_values or actual[0] == actual[1]:
            raise PortfolioProofError(
                f"semantic delta unavailable for {spec.family_id}"
            )
    return states, documents, config.families


def load_portfolio_proof_cases(
    root: Path,
    *,
    states: list[SnapshotState],
    documents: list[NormalizedDocument],
    specs: list[FamilySpec],
) -> list[BenchmarkCase]:
    """Validate one manager-audited development question per proof family."""

    cases = _load_jsonl(root, CASES_PATH, BenchmarkCase)
    reviews = _load_jsonl(root, REVIEWS_PATH, PortfolioProofReview)
    authority = load_portfolio_proof_authority_policy(root)
    spec_by_template = {spec.template_family_id: spec for spec in specs}
    if (
        len(cases) != 3
        or len({case.case_id for case in cases}) != 3
        or {case.entity_family_id for case in cases}
        != {spec.family_id for spec in specs}
    ):
        raise PortfolioProofError("portfolio proof question coverage is invalid")
    review_by_id = {review.case_id: review for review in reviews}
    if len(reviews) != 3 or set(review_by_id) != {case.case_id for case in cases}:
        raise PortfolioProofError("portfolio proof review coverage is invalid")
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
            or spec.prospective_split != "dev"
            or case.split != spec.prospective_split
            or case.temporal_truth_mode != "upstream_versioned"
            or case.should_abstain
            or len(case.expected_claims) != 1
            or len(case.allowed_snapshot_ids) != 1
            or case.expected_claims[0].predicate != spec.claim.predicate
        ):
            raise PortfolioProofError("portfolio proof case shape is invalid")
        selected = {
            manifest.snapshot_id
            for manifest in select_admissible_by_entity(states, case.as_of).values()
        }
        if not set(case.allowed_snapshot_ids) <= selected:
            raise PortfolioProofError("portfolio proof case admits a post-cutoff state")
        evidence_ids = sorted(case.expected_claims[0].evidence_ids)
        if not set(evidence_ids) <= set(evidence_documents):
            raise PortfolioProofError("portfolio proof evidence binding is unresolved")
        evidence_snapshots = {
            evidence_documents[evidence_id].snapshot_id for evidence_id in evidence_ids
        }
        if not evidence_snapshots <= set(case.allowed_snapshot_ids) & selected:
            raise PortfolioProofError(
                "portfolio proof evidence crosses cutoff boundary"
            )
        if not set(case.required_authority_policy_ids) <= policy_ids:
            raise PortfolioProofError("portfolio proof authority policy is unresolved")
        review = review_by_id[case.case_id]
        if (
            review.reviewed_at_utc.tzinfo is None
            or review.reviewed_at_utc.utcoffset()
            != UTC.utcoffset(review.reviewed_at_utc)
            or review.evidence_ids != evidence_ids
        ):
            raise PortfolioProofError(
                "portfolio proof manager review does not match gold"
            )
    return cases
