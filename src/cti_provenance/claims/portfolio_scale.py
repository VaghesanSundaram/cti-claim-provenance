"""Fail-closed loader for the first portfolio scale-family batch."""

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
)
from cti_provenance.claims.portfolio_yield import (
    LINEAGE_PATH,
    _load_capture_ledger,
    load_portfolio_yield_corpus,
)
from cti_provenance.config import (
    AuthorityPolicyConfig,
    load_scale_project_config_files,
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

MANIFEST_PATH = PurePosixPath("data/manifests/portfolio-scale-corpus-v1.json")
FAMILY_SPEC_PATH = PurePosixPath("configs/portfolio-scale-families-v1.yaml")
SOURCE_POLICY_PATH = PurePosixPath("configs/sources-portfolio-scale-v1.yaml")
AUTHORITY_POLICY_PATH = PurePosixPath(
    "configs/authority-policy-portfolio-scale-v1.yaml"
)
CASE_PATHS = (
    PurePosixPath("data/benchmark/dev/portfolio-scale-dev-cases.jsonl"),
    PurePosixPath("data/benchmark/validation/portfolio-scale-validation-cases.jsonl"),
)
REVIEWS_PATH = PurePosixPath("annotations/portfolio-scale-review.jsonl")
BASE_MANIFEST_PATH = PurePosixPath("data/manifests/portfolio-yield-corpus-v1.json")

_NEW_FAMILY_IDS = frozenset(
    {
        "rust-cve-2024-24576",
        "python-cve-2023-24329",
        "jenkins-2017-12-14-security-release",
        "nvd-cve-2024-21762-cpe-history",
        "nvd-cve-2023-20115-cpe-history",
    }
)

_SUPPORT_IDS = frozenset(
    {
        "nvd-cve-2024-21762-history",
        "nvd-cve-2023-20115-history",
        "rust-blog-commit",
        "rust-tag-ref-1.77.1",
        "rust-tag-ref-1.77.2",
        "rust-tag-object-1.77.2",
        "rust-license-apache",
        "rust-license-mit",
        "python-tag-ref-v3.11.3",
        "python-tag-ref-v3.11.4",
        "python-tag-object-v3.11.4",
        "python-license",
        "jenkins-advisory-commit",
        "jenkins-tag-ref-2.94",
        "jenkins-tag-ref-2.95",
        "jenkins-tag-object-2.95",
        "jenkins-license",
    }
)


def load_portfolio_scale_authority_policy(root: Path) -> AuthorityPolicyConfig:
    """Validate the closed scale source and authority catalogs together."""

    resolved = root.resolve(strict=True)
    try:
        _, authority = load_scale_project_config_files(
            resolved.joinpath(*SOURCE_POLICY_PATH.parts),
            resolved.joinpath(*AUTHORITY_POLICY_PATH.parts),
        )
    except (OSError, ValueError) as exc:
        raise PortfolioProofError("portfolio scale policy is invalid") from exc
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
                raise PortfolioProofError("scale supporting artifact hash mismatch")
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
                    "scale supporting artifact is not capture-ledger bound"
                )
        except (KeyError, TypeError, ValueError) as exc:
            raise PortfolioProofError("scale supporting artifact is invalid") from exc
        if artifact_id in bodies:
            raise PortfolioProofError("scale supporting artifact ID is duplicated")
        bodies[artifact_id] = body
    if set(bodies) != _SUPPORT_IDS:
        raise PortfolioProofError("scale supporting artifact coverage is incomplete")
    return bodies


def _validate_primary_ledger_binding(
    snapshot: dict[str, object],
    ledger_successes: dict[str, dict[str, object]],
) -> None:
    expected = {
        "url": snapshot.get("source_url"),
        "raw_blob_path": snapshot.get("raw_blob_path"),
        "sha256": snapshot.get("sha256"),
        "byte_length": snapshot.get("byte_length"),
    }
    matches = [
        record
        for record in ledger_successes.values()
        if all(record.get(field) == value for field, value in expected.items())
    ]
    if len(matches) != 1:
        raise PortfolioProofError("scale primary snapshot is not ledger-bound")


def _json(body: bytes, label: str) -> object:
    try:
        return json.loads(body)
    except json.JSONDecodeError as exc:
        raise PortfolioProofError(f"{label} metadata is not JSON") from exc


def _nested(value: object, *keys: str) -> object:
    current = value
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


def _validate_nvd_history(
    body: bytes, *, cve_id: str, created: str, target: str
) -> None:
    payload = _json(body, cve_id)
    if not isinstance(payload, dict):
        raise PortfolioProofError("NVD history payload has an unexpected shape")
    changes = [
        item.get("change", {})
        for item in payload.get("cveChanges", [])
        if isinstance(item, dict)
        and isinstance(item.get("change"), dict)
        and item["change"].get("cveId") == cve_id
        and item["change"].get("created") == created
    ]
    if len(changes) != 1:
        raise PortfolioProofError(f"{cve_id} history event is not exact")
    details = changes[0].get("details", [])
    old_values = "\n".join(
        str(item.get("oldValue", "")) for item in details if isinstance(item, dict)
    )
    new_values = "\n".join(
        str(item.get("newValue", "")) for item in details if isinstance(item, dict)
    )
    if target in old_values or target not in new_values:
        raise PortfolioProofError(f"{cve_id} semantic delta is not exact")


def _validate_tag_pair(
    bodies: dict[str, bytes],
    *,
    prefix: str,
    pre_ref: str,
    post_ref: str,
    post_object: str,
    pre_tag_sha: str,
    post_tag_sha: str,
    post_commit_sha: str,
    post_date: str,
) -> None:
    pre = _json(bodies[pre_ref], pre_ref)
    post = _json(bodies[post_ref], post_ref)
    tagged = _json(bodies[post_object], post_object)
    if not all(isinstance(item, dict) for item in (pre, post, tagged)):
        raise PortfolioProofError(f"{prefix} tag metadata has an unexpected shape")
    if (
        _nested(pre, "object", "sha") != pre_tag_sha
        or _nested(post, "object", "sha") != post_tag_sha
        or _nested(tagged, "sha") != post_tag_sha
        or _nested(tagged, "object", "sha") != post_commit_sha
        or _nested(tagged, "tagger", "date") != post_date
    ):
        raise PortfolioProofError(f"{prefix} tag lineage is not exact")


def _validate_vendor_metadata(bodies: dict[str, bytes]) -> None:
    rust_commit = _json(bodies["rust-blog-commit"], "Rust advisory commit")
    jenkins_commit = _json(bodies["jenkins-advisory-commit"], "Jenkins advisory commit")
    if not isinstance(rust_commit, dict) or not isinstance(jenkins_commit, dict):
        raise PortfolioProofError("vendor commit metadata has an unexpected shape")
    if (
        rust_commit.get("sha") != "a0752f126db394e987981037441819e1ae0a6fc8"
        or rust_commit.get("commit", {}).get("committer", {}).get("date")
        != "2024-04-08T23:04:25Z"
        or jenkins_commit.get("sha") != "05ee8af3157c23f7d9d7bd45ccf8587c73285fd4"
        or jenkins_commit.get("commit", {}).get("committer", {}).get("date")
        != "2017-12-13T16:00:14Z"
    ):
        raise PortfolioProofError("vendor advisory commit metadata is not exact")
    _validate_tag_pair(
        bodies,
        prefix="Rust",
        pre_ref="rust-tag-ref-1.77.1",
        post_ref="rust-tag-ref-1.77.2",
        post_object="rust-tag-object-1.77.2",
        pre_tag_sha="42b49de7b7c3bfd4fc990691342af520ce142013",
        post_tag_sha="8b02fd2ae7f1b730f5df5210fc93a9bbb803a1af",
        post_commit_sha="25ef9e3d85d934b27d9dada2f9dd52b1dc63bb04",
        post_date="2024-04-09T21:39:36Z",
    )
    _validate_tag_pair(
        bodies,
        prefix="CPython",
        pre_ref="python-tag-ref-v3.11.3",
        post_ref="python-tag-ref-v3.11.4",
        post_object="python-tag-object-v3.11.4",
        pre_tag_sha="edb4401c7fce1b076fc8c99577bf590092923317",
        post_tag_sha="c92d5e040a326a72a5339af0ba5d2d17aef25bfe",
        post_commit_sha="d2340ef25721b6a72d45d4508c672c4be38c67d3",
        post_date="2023-06-06T22:00:29Z",
    )
    _validate_tag_pair(
        bodies,
        prefix="Jenkins",
        pre_ref="jenkins-tag-ref-2.94",
        post_ref="jenkins-tag-ref-2.95",
        post_object="jenkins-tag-object-2.95",
        pre_tag_sha="816e2f0760f7b013b12bc515b2adf0dc7ae8e436",
        post_tag_sha="b212538e269609e8c71216d64effe6b9b4903057",
        post_commit_sha="0f029f39e6edaa18a26f9244c1db42e801e90c92",
        post_date="2017-12-14T01:58:00Z",
    )
    if (
        b"Apache License" not in bodies["rust-license-apache"]
        or b"Permission is hereby granted, free of charge"
        not in bodies["rust-license-mit"]
        or b"PYTHON SOFTWARE FOUNDATION LICENSE VERSION 2"
        not in bodies["python-license"]
        or b"creativecommons.org/licenses/by-sa/4.0/" not in bodies["jenkins-license"]
    ):
        raise PortfolioProofError("scale license evidence is missing")


def load_portfolio_scale_corpus(
    root: Path,
) -> tuple[list[SnapshotState], list[NormalizedDocument], list[FamilySpec]]:
    """Load the validated yield base and five additional scale families."""

    try:
        envelope = json.loads(_safe_bytes(root, MANIFEST_PATH))
        config = load_portfolio_family_config(
            root.resolve(strict=True).joinpath(*FAMILY_SPEC_PATH.parts)
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise PortfolioProofError("portfolio scale manifest/spec is invalid") from exc
    if (
        envelope.get("version") != "portfolio-scale-corpus-v1"
        or envelope.get("base_manifest") != BASE_MANIFEST_PATH.as_posix()
        or envelope.get("family_spec") != FAMILY_SPEC_PATH.as_posix()
        or envelope.get("source_policy") != SOURCE_POLICY_PATH.as_posix()
        or envelope.get("authority_policy") != AUTHORITY_POLICY_PATH.as_posix()
        or envelope.get("temporal_boundary")
        != (
            "publisher-declared version evidence only; not independently "
            "observed historical availability"
        )
        or len(config.families) != 9
        or len(envelope.get("snapshots", [])) != 10
    ):
        raise PortfolioProofError("portfolio scale manifest identity is invalid")

    base_states, base_documents, base_specs = load_portfolio_yield_corpus(root)
    config_by_id = {spec.family_id: spec for spec in config.families}
    if set(config_by_id) - {spec.family_id for spec in base_specs} != _NEW_FAMILY_IDS:
        raise PortfolioProofError("portfolio scale family coverage is invalid")
    for base_spec in base_specs:
        if config_by_id.get(base_spec.family_id) != base_spec:
            raise PortfolioProofError("portfolio scale base-family identity changed")
    new_specs = [spec for spec in config.families if spec.family_id in _NEW_FAMILY_IDS]

    ledger_successes = _load_capture_ledger(root)
    support = _supporting_artifacts(
        root, list(envelope.get("supporting_artifacts", [])), ledger_successes
    )
    _validate_vendor_metadata(support)
    _validate_nvd_history(
        support["nvd-cve-2024-21762-history"],
        cve_id="CVE-2024-21762",
        created="2024-11-29T15:23:32.183",
        target=(
            "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:* versions from "
            "(including) 6.0.0 up to (excluding) 6.0.18"
        ),
    )
    _validate_nvd_history(
        support["nvd-cve-2023-20115-history"],
        cve_id="CVE-2023-20115",
        created="2023-10-03T13:50:23.637",
        target="cpe:2.3:h:cisco:nexus_3636c-r:-:*:*:*:*:*:*:*",
    )

    lineage = load_portfolio_lineage_config(
        root.resolve(strict=True).joinpath(*LINEAGE_PATH.parts)
    )
    expected_ids = {
        "cve-2024-3094",
        "ivanti-ed-24-01",
        "netscaler-cve-2023-4966",
        *(spec.family_id for spec in config.families),
        "apache-httpd-cve-2021-41773-42013",
        "cisa-kev-cve-2026-0257",
        "mitre-attack-t1027-011",
    }
    if not expected_ids <= {record.family_id for record in lineage.families}:
        raise PortfolioProofError("portfolio scale lineage coverage is invalid")
    lineage_by_id = {record.family_id: record for record in lineage.families}
    for spec in config.families:
        record = lineage_by_id[spec.family_id]
        for field in type(record).model_fields:
            if field != "family_id" and getattr(record, field) != getattr(spec, field):
                raise PortfolioProofError(
                    f"portfolio scale lineage mismatch for {spec.family_id}"
                )
    validate_portfolio_dependency_splits(lineage.families)

    spec_by_snapshot = {
        snapshot_id: spec for spec in new_specs for snapshot_id in spec.source_state_ids
    }
    states = list(base_states)
    documents = list(base_documents)
    for payload in envelope["snapshots"]:
        snapshot_record = dict(payload)
        _validate_primary_ledger_binding(snapshot_record, ledger_successes)
        publisher = snapshot_record.pop("publisher_version_evidence")
        for field in (
            "retrieved_at_utc",
            "effective_date_if_known",
            "available_by_utc",
        ):
            snapshot_record[field] = _time(snapshot_record[field])
        try:
            manifest = SnapshotManifest.model_validate(snapshot_record)
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
                "portfolio scale snapshot failed validation"
            ) from exc
        for span in document.spans:
            resolve_span(span, document.normalized_text)
        states.append(state)
        documents.append(document)

    by_snapshot = {document.snapshot_id: document for document in documents}
    for spec in new_specs:
        actual = [
            by_snapshot[snapshot_id].fields["claim_value"]
            for snapshot_id in spec.source_state_ids
        ]
        if actual != spec.expected_values or actual[0] == actual[1]:
            raise PortfolioProofError(
                f"semantic delta unavailable for {spec.family_id}"
            )
    return states, documents, new_specs


def load_portfolio_scale_cases(
    root: Path,
    *,
    states: list[SnapshotState],
    documents: list[NormalizedDocument],
    specs: list[FamilySpec],
) -> list[BenchmarkCase]:
    """Validate one audited question for each new scale family."""

    cases = [
        case for path in CASE_PATHS for case in _load_jsonl(root, path, BenchmarkCase)
    ]
    reviews = _load_jsonl(root, REVIEWS_PATH, PortfolioProofReview)
    authority = load_portfolio_scale_authority_policy(root)
    spec_by_template = {spec.template_family_id: spec for spec in specs}
    if (
        len(cases) != 5
        or {case.entity_family_id for case in cases}
        != {spec.family_id for spec in specs}
        or len({case.case_id for case in cases}) != 5
    ):
        raise PortfolioProofError("portfolio scale question coverage is invalid")
    review_by_id = {review.case_id: review for review in reviews}
    if len(reviews) != 5 or set(review_by_id) != {case.case_id for case in cases}:
        raise PortfolioProofError("portfolio scale review coverage is invalid")
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
            or case.split != spec.prospective_split
            or case.temporal_truth_mode != "upstream_versioned"
            or case.should_abstain
            or len(case.expected_claims) != 1
            or len(case.allowed_snapshot_ids) != 1
            or case.expected_claims[0].predicate != spec.claim.predicate
        ):
            raise PortfolioProofError("portfolio scale case shape is invalid")
        selected = {
            manifest.snapshot_id
            for manifest in select_admissible_by_entity(states, case.as_of).values()
        }
        if not set(case.allowed_snapshot_ids) <= selected:
            raise PortfolioProofError("portfolio scale case crosses its cutoff")
        evidence_ids = sorted(case.expected_claims[0].evidence_ids)
        if not set(evidence_ids) <= set(evidence_documents):
            raise PortfolioProofError("portfolio scale evidence is unresolved")
        if {
            evidence_documents[evidence_id].snapshot_id for evidence_id in evidence_ids
        } != set(case.allowed_snapshot_ids):
            raise PortfolioProofError("portfolio scale evidence snapshot is invalid")
        if not set(case.required_authority_policy_ids) <= policy_ids:
            raise PortfolioProofError("portfolio scale authority policy is unresolved")
        review = review_by_id[case.case_id]
        if (
            review.reviewed_at_utc.tzinfo is None
            or review.reviewed_at_utc.utcoffset()
            != UTC.utcoffset(review.reviewed_at_utc)
            or review.evidence_ids != evidence_ids
        ):
            raise PortfolioProofError("portfolio scale manager audit is invalid")
    return cases
