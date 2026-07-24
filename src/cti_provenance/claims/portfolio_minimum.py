"""Fail-closed loader for the 24-family minimum-completion checkpoint."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC
from pathlib import Path, PurePosixPath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from cti_provenance.claims.portfolio_proof import (
    PortfolioProofError,
    PortfolioProofReview,
    _load_jsonl,
    _safe_bytes,
    _time,
)
from cti_provenance.claims.portfolio_scale import load_portfolio_scale_corpus
from cti_provenance.claims.portfolio_yield import LINEAGE_PATH, _load_capture_ledger
from cti_provenance.config import (
    AuthorityPolicyConfig,
    load_minimum_project_config_files,
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

MANIFEST_PATH = PurePosixPath("data/manifests/portfolio-minimum-corpus-v1.json")
FAMILY_SPEC_PATH = PurePosixPath("configs/portfolio-minimum-families-v1.yaml")
SOURCE_POLICY_PATH = PurePosixPath("configs/sources-portfolio-minimum-v1.yaml")
AUTHORITY_POLICY_PATH = PurePosixPath(
    "configs/authority-policy-portfolio-minimum-v1.yaml"
)
CASE_PATH = PurePosixPath(
    "data/benchmark/validation/portfolio-minimum-validation-cases.jsonl"
)
REVIEWS_PATH = PurePosixPath("annotations/portfolio-minimum-review.jsonl")
CANDIDATE_PATH = PurePosixPath("data/manifests/portfolio-holdout-candidates-v1.json")
BASE_MANIFEST_PATH = PurePosixPath("data/manifests/portfolio-scale-corpus-v1.json")

_EXPECTED_CANDIDATE_SOURCES: dict[str, tuple[frozenset[str], frozenset[str]]] = {
    "curl-cve-2023-38545-release-8-4-0": (
        frozenset(
            {
                "curl-release-notes-8.3.0-repair",
                "curl-release-notes-8.4.0-repair",
            }
        ),
        frozenset(
            {
                "curl-tag-ref-8.3.0",
                "curl-tag-ref-8.4.0",
                "curl-tag-object-8.3.0",
                "curl-tag-object-8.4.0",
                "curl-cve-2023-38545-advisory-repair",
                "curl-license",
            }
        ),
    ),
    "kubernetes-cve-2023-5528-v1-28-4": (
        frozenset({"kubernetes-changelog-1.28.3", "kubernetes-changelog-1.28.4"}),
        frozenset(
            {
                "kubernetes-tag-ref-1.28.3",
                "kubernetes-tag-ref-1.28.4",
                "kubernetes-tag-object-1.28.3",
                "kubernetes-tag-object-1.28.4",
                "kubernetes-cve-2023-5528-advisory-repair",
                "kubernetes-license",
            }
        ),
    ),
    "git-security-release-v2-39-1": (
        frozenset({"git-release-2.39.0", "git-release-2.39.1"}),
        frozenset(
            {
                "git-tag-ref-2.39.0",
                "git-tag-ref-2.39.1",
                "git-tag-object-2.39.0",
                "git-tag-object-2.39.1",
                "git-license",
            }
        ),
    ),
    "tomcat-cve-2023-46589-9-0-83": (
        frozenset({"tomcat-changelog-9.0.82", "tomcat-changelog-9.0.83"}),
        frozenset(
            {
                "tomcat-tag-ref-9.0.82",
                "tomcat-tag-ref-9.0.83",
                "tomcat-cve-2023-46589-security-page-repair",
                "tomcat-license",
            }
        ),
    ),
    "cisa-icsa-25-212-01-guralp": (
        frozenset(
            {
                "cisa-icsa-25-212-01-initial",
                "cisa-icsa-25-212-01-update-a",
                "cisa-icsa-25-212-01-update-b",
            }
        ),
        frozenset({"cisa-intellectual-property-policy"}),
    ),
    "cisa-icsa-25-121-01-kunbus": (
        frozenset({"cisa-icsa-25-121-01-initial", "cisa-icsa-25-121-01-update-a"}),
        frozenset({"cisa-intellectual-property-policy"}),
    ),
    "cisa-icsa-25-135-19-ecovacs": (
        frozenset({"cisa-icsa-25-135-19-initial", "cisa-icsa-25-135-19-update-a"}),
        frozenset({"cisa-intellectual-property-policy"}),
    ),
    "nvd-cve-2024-6387-description-history": (
        frozenset(
            {
                "nvd-cve-2024-6387-event-initial",
                "nvd-cve-2024-6387-event-description-change",
            }
        ),
        frozenset({"nvd-cve-2024-6387-history-api"}),
    ),
}

_EXPECTED_CANDIDATE_STATE_ORDER: dict[str, tuple[str, ...]] = {
    "curl-cve-2023-38545-release-8-4-0": (
        "curl-release-notes-8.3.0-repair",
        "curl-release-notes-8.4.0-repair",
    ),
    "kubernetes-cve-2023-5528-v1-28-4": (
        "kubernetes-changelog-1.28.3",
        "kubernetes-changelog-1.28.4",
    ),
    "git-security-release-v2-39-1": (
        "git-release-2.39.0",
        "git-release-2.39.1",
    ),
    "tomcat-cve-2023-46589-9-0-83": (
        "tomcat-changelog-9.0.82",
        "tomcat-changelog-9.0.83",
    ),
    "cisa-icsa-25-212-01-guralp": (
        "cisa-icsa-25-212-01-initial",
        "cisa-icsa-25-212-01-update-a",
        "cisa-icsa-25-212-01-update-b",
    ),
    "cisa-icsa-25-121-01-kunbus": (
        "cisa-icsa-25-121-01-initial",
        "cisa-icsa-25-121-01-update-a",
    ),
    "cisa-icsa-25-135-19-ecovacs": (
        "cisa-icsa-25-135-19-initial",
        "cisa-icsa-25-135-19-update-a",
    ),
    "nvd-cve-2024-6387-description-history": (
        "nvd-cve-2024-6387-event-initial",
        "nvd-cve-2024-6387-event-description-change",
    ),
}

_NON_HOLDOUT_MANIFESTS = (
    PurePosixPath("data/manifests/portfolio-proof-corpus-v1.json"),
    PurePosixPath("data/manifests/portfolio-yield-corpus-v1.json"),
    PurePosixPath("data/manifests/portfolio-scale-corpus-v1.json"),
    MANIFEST_PATH,
)


class HoldoutIsolation(BaseModel):
    """Candidate-only boundary before the encrypted holdout protocol."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    questions_authored: Literal[False]
    gold_authored: Literal[False]
    prompt_exposure: Literal[False]
    retriever_exposure: Literal[False]
    grader_or_policy_tuning: Literal[False]
    encrypted_or_sealed: Literal[False]


class HoldoutCandidateFamily(BaseModel):
    """Non-gold source/provenance metadata for one candidate family."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    family_id: str = Field(min_length=1)
    dominant_stratum: Literal[
        "vendor_project",
        "public_coordination_exploitation",
        "structured_cti_vulnerability",
    ]
    prospective_split: Literal["holdout_candidate"]
    state_source_ids: list[str] = Field(min_length=2)
    support_source_ids: list[str]
    semantic_delta: str = Field(min_length=1)
    authority_boundary: str = Field(min_length=1)
    retention: str = Field(min_length=1)


class HoldoutCandidateManifest(BaseModel):
    """Strict metadata-only holdout-candidate envelope."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal["portfolio-holdout-candidates-v1"]
    status: Literal["accepted_candidate_metadata_only"]
    temporal_boundary: Literal[
        "publisher-declared version evidence only; not independently observed "
        "historical availability"
    ]
    isolation: HoldoutIsolation
    families: list[HoldoutCandidateFamily] = Field(min_length=8, max_length=8)


def load_holdout_candidate_metadata(root: Path) -> HoldoutCandidateManifest:
    """Bind eight isolated candidate families to captured exact-byte records."""

    try:
        manifest = HoldoutCandidateManifest.model_validate_json(
            _safe_bytes(root, CANDIDATE_PATH)
        )
        ledger = _load_capture_ledger(root)
        lineage = load_portfolio_lineage_config(
            root.resolve(strict=True).joinpath(*LINEAGE_PATH.parts)
        )
    except (OSError, ValueError) as exc:
        raise PortfolioProofError("holdout candidate metadata is invalid") from exc
    family_ids = [family.family_id for family in manifest.families]
    state_ids = [
        source_id
        for family in manifest.families
        for source_id in family.state_source_ids
    ]
    lineage_ids = {
        record.family_id
        for record in lineage.families
        if record.prospective_split == "holdout_candidate"
    }
    if (
        len(family_ids) != len(set(family_ids))
        or len(state_ids) != len(set(state_ids))
        or set(family_ids) != lineage_ids
    ):
        raise PortfolioProofError("holdout candidate identity coverage is invalid")
    for family in manifest.families:
        expected = _EXPECTED_CANDIDATE_SOURCES.get(family.family_id)
        actual = (
            frozenset(family.state_source_ids),
            frozenset(family.support_source_ids),
        )
        if (
            expected is None
            or actual != expected
            or tuple(family.state_source_ids)
            != _EXPECTED_CANDIDATE_STATE_ORDER.get(family.family_id)
            or len(family.support_source_ids) != len(set(family.support_source_ids))
        ):
            raise PortfolioProofError("holdout candidate source binding is invalid")
    referenced = {
        source_id
        for family in manifest.families
        for source_id in (*family.state_source_ids, *family.support_source_ids)
    }
    non_holdout_paths: set[str] = set()
    for path in _NON_HOLDOUT_MANIFESTS:
        try:
            envelope = json.loads(_safe_bytes(root, path))
            non_holdout_paths.update(
                str(item["raw_blob_path"]) for item in envelope.get("snapshots", [])
            )
            non_holdout_paths.update(
                str(item["path"]) for item in envelope.get("supporting_artifacts", [])
            )
        except (KeyError, TypeError, json.JSONDecodeError) as exc:
            raise PortfolioProofError(
                "non-holdout source inventory is invalid"
            ) from exc
    if any(
        str(ledger[source_id].get("raw_blob_path")) in non_holdout_paths
        for source_id in referenced
    ):
        raise PortfolioProofError("holdout candidate source crosses a split boundary")
    bodies: dict[str, bytes] = {}
    for source_id in referenced:
        try:
            record = ledger[source_id]
            raw = _safe_bytes(root, PurePosixPath(str(record["raw_blob_path"])))
        except (KeyError, TypeError, ValueError) as exc:
            raise PortfolioProofError(
                "holdout candidate source is not ledger-bound"
            ) from exc
        if (
            record.get("status") != 200
            or len(raw) != record.get("byte_length")
            or hashlib.sha256(raw).hexdigest() != record.get("sha256")
        ):
            raise PortfolioProofError(
                "holdout candidate source hash or status is invalid"
            )
        bodies[source_id] = raw
    _audit_candidate_semantics(bodies)
    return manifest


def _candidate_json(bodies: dict[str, bytes], source_id: str) -> dict[str, Any]:
    try:
        value = json.loads(bodies[source_id])
    except (KeyError, json.JSONDecodeError) as exc:
        raise PortfolioProofError("candidate structured source is invalid") from exc
    if not isinstance(value, dict):
        raise PortfolioProofError("candidate structured source has the wrong shape")
    return value


def _audit_candidate_semantics(bodies: dict[str, bytes]) -> None:
    """Recheck the exact non-gold deltas used only for family eligibility."""

    try:
        curl_pre = bodies["curl-release-notes-8.3.0-repair"].decode()
        curl_post = bodies["curl-release-notes-8.4.0-repair"].decode()
        curl_advisory = bodies["curl-cve-2023-38545-advisory-repair"].decode()
        kubernetes = bodies["kubernetes-cve-2023-5528-advisory-repair"].decode()
        git_pre = bodies["git-release-2.39.0"].decode()
        git_post = bodies["git-release-2.39.1"].decode()
        tomcat = bodies["tomcat-cve-2023-46589-security-page-repair"].decode()
    except (KeyError, UnicodeDecodeError) as exc:
        raise PortfolioProofError("candidate publisher text is invalid") from exc
    git_delta = "security fix that appears in v2.30.7"
    if not (
        "CVE-2023-38545.html" not in curl_pre
        and "CVE-2023-38545.html" in curl_post
        and "to and including" in curl_advisory
        and "8.4.0" in curl_advisory
        and "CVE-2023-5528" in kubernetes
        and "Fixed Versions" in kubernetes
        and "kubelet v1.28.4" in kubernetes
        and git_delta not in git_pre
        and git_delta in git_post
        and "Fixed_in_Apache_Tomcat_9.0.83" in tomcat
        and "CVE-2023-46589" in tomcat
        and "9.0.0-M1 to 9.0.82" in tomcat
    ):
        raise PortfolioProofError("candidate publisher semantic delta is missing")

    guralp = [
        _candidate_json(bodies, source_id)
        for source_id in (
            "cisa-icsa-25-212-01-initial",
            "cisa-icsa-25-212-01-update-a",
            "cisa-icsa-25-212-01-update-b",
        )
    ]
    try:
        guralp_known = [
            len(state["vulnerabilities"][0]["product_status"]["known_affected"])
            for state in guralp
        ]
        guralp_remediations = [
            state["vulnerabilities"][0]["remediations"] for state in guralp
        ]
        guralp_dates = [
            state["document"]["tracking"]["current_release_date"] for state in guralp
        ]
    except (KeyError, IndexError, TypeError) as exc:
        raise PortfolioProofError("Guralp CSAF delta has the wrong shape") from exc
    if (
        guralp_known != [1, 2, 2]
        or [len(items) for items in guralp_remediations] != [1, 1, 8]
        or guralp_dates
        != [
            "2025-07-31T06:00:00.000000Z",
            "2025-08-14T06:00:00.000000Z",
            "2026-01-13T07:00:00.000000Z",
        ]
        or not any(
            "experimental firmware" in str(item.get("details", ""))
            for item in guralp_remediations[-1]
        )
    ):
        raise PortfolioProofError("Guralp CSAF semantic delta is missing")

    kunbus = [
        _candidate_json(bodies, source_id)
        for source_id in (
            "cisa-icsa-25-121-01-initial",
            "cisa-icsa-25-121-01-update-a",
        )
    ]
    try:
        kunbus_remediations = [
            [
                item
                for vulnerability in state["vulnerabilities"]
                for item in vulnerability.get("remediations", [])
            ]
            for state in kunbus
        ]
    except (KeyError, TypeError) as exc:
        raise PortfolioProofError("KUNBUS CSAF delta has the wrong shape") from exc
    bookworm_pre = [
        item
        for item in kunbus_remediations[0]
        if "Revolution Pi OS Bookworm" in str(item.get("details", ""))
    ]
    bookworm_post = [
        item
        for item in kunbus_remediations[1]
        if "Revolution Pi OS Bookworm" in str(item.get("details", ""))
    ]
    if (
        [len(items) for items in kunbus_remediations] != [16, 17]
        or bookworm_pre
        or len(bookworm_post) != 1
        or bookworm_post[0].get("category") != "vendor_fix"
        or bookworm_post[0].get("product_ids") != ["CSAFPID-0001"]
    ):
        raise PortfolioProofError("KUNBUS CSAF semantic delta is missing")

    ecovacs_pre = _candidate_json(bodies, "cisa-icsa-25-135-19-initial")
    ecovacs_post = _candidate_json(bodies, "cisa-icsa-25-135-19-update-a")
    try:
        ecovacs_pre_remediations = [
            item
            for vulnerability in ecovacs_pre["vulnerabilities"]
            for item in vulnerability.get("remediations", [])
        ]
        ecovacs_post_remediations = [
            item
            for vulnerability in ecovacs_post["vulnerabilities"]
            for item in vulnerability.get("remediations", [])
        ]
    except (KeyError, TypeError) as exc:
        raise PortfolioProofError("ECOVACS CSAF delta has the wrong shape") from exc
    ecovacs_pre_updates = [
        item
        for item in ecovacs_pre_remediations
        if item.get("category") == "vendor_fix"
    ]
    ecovacs_post_updates = [
        item
        for item in ecovacs_post_remediations
        if str(item.get("details", "")).startswith(
            "ECOVACS has released software updates for all affected devices."
        )
    ]
    if not (
        len(ecovacs_pre_updates) == 3
        and all(len(item.get("product_ids", [])) == 2 for item in ecovacs_pre_updates)
        and len(ecovacs_post_updates) == 3
        and all(
            item.get("category") == "mitigation"
            and len(item.get("product_ids", [])) == 7
            for item in ecovacs_post_updates
        )
    ):
        raise PortfolioProofError("ECOVACS CSAF semantic delta is missing")

    nvd = _candidate_json(bodies, "nvd-cve-2024-6387-history-api")
    try:
        initial_changes = [
            item["change"]
            for item in nvd["cveChanges"]
            if item["change"]["created"] == "2024-07-01T13:15:06.467"
        ]
        initial_details = [
            detail
            for change in initial_changes
            for detail in change["details"]
            if detail.get("type") == "Description" and detail.get("action") == "Added"
        ]
        changes = [
            item["change"]
            for item in nvd["cveChanges"]
            if item["change"]["created"] == "2024-07-02T23:15:11.140"
        ]
        details = [
            detail
            for change in changes
            for detail in change["details"]
            if detail.get("type") == "Description" and detail.get("action") == "Changed"
        ]
    except (KeyError, TypeError) as exc:
        raise PortfolioProofError("NVD description delta has the wrong shape") from exc
    if (
        len(initial_changes) != 1
        or len(initial_details) != 1
        or not initial_details[0].get("newValue")
        or len(changes) != 1
        or len(details) != 1
        or not details[0].get("oldValue")
        or not details[0].get("newValue")
        or details[0]["oldValue"] == details[0]["newValue"]
    ):
        raise PortfolioProofError("NVD description semantic delta is missing")


def load_portfolio_minimum_authority_policy(root: Path) -> AuthorityPolicyConfig:
    """Validate the closed PostgreSQL source and authority catalogs."""

    resolved = root.resolve(strict=True)
    try:
        _, authority = load_minimum_project_config_files(
            resolved.joinpath(*SOURCE_POLICY_PATH.parts),
            resolved.joinpath(*AUTHORITY_POLICY_PATH.parts),
        )
    except (OSError, ValueError) as exc:
        raise PortfolioProofError("portfolio minimum policy is invalid") from exc
    return authority


def _ledger_bound(
    record: dict[str, object], ledger_successes: dict[str, dict[str, object]]
) -> None:
    expected = {
        "url": record.get("source_url"),
        "raw_blob_path": record.get("raw_blob_path"),
        "sha256": record.get("sha256"),
        "byte_length": record.get("byte_length"),
    }
    matches = [
        item
        for item in ledger_successes.values()
        if all(item.get(field) == value for field, value in expected.items())
    ]
    if len(matches) != 1:
        raise PortfolioProofError("minimum primary snapshot is not ledger-bound")


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
            expected = {
                "url": artifact["url"],
                "raw_blob_path": artifact["path"],
                "sha256": artifact["sha256"],
                "byte_length": artifact["byte_length"],
            }
            ledger = ledger_successes[ledger_source_id]
            if (
                len(body) != artifact["byte_length"]
                or hashlib.sha256(body).hexdigest() != artifact["sha256"]
                or any(ledger.get(field) != value for field, value in expected.items())
            ):
                raise PortfolioProofError(
                    "minimum supporting artifact is not hash/ledger-bound"
                )
        except (KeyError, TypeError, ValueError) as exc:
            raise PortfolioProofError("minimum supporting artifact is invalid") from exc
        if artifact_id in bodies:
            raise PortfolioProofError("minimum supporting artifact ID is duplicated")
        bodies[artifact_id] = body
    if set(bodies) != {
        "postgresql-tag-ref-15.4",
        "postgresql-tag-ref-15.5",
        "postgresql-license",
    }:
        raise PortfolioProofError("minimum supporting artifact coverage is incomplete")
    return bodies


def _validate_postgresql_support(bodies: dict[str, bytes]) -> None:
    try:
        pre = json.loads(bodies["postgresql-tag-ref-15.4"])
        post = json.loads(bodies["postgresql-tag-ref-15.5"])
    except json.JSONDecodeError as exc:
        raise PortfolioProofError("PostgreSQL tag metadata is not JSON") from exc
    if (
        pre.get("ref") != "refs/tags/REL_15_4"
        or pre.get("object", {}).get("type") != "commit"
        or pre.get("object", {}).get("sha")
        != "83ed1f71c88ae948a5b6ec6d2a4802cc54470102"
        or post.get("ref") != "refs/tags/REL_15_5"
        or post.get("object", {}).get("type") != "commit"
        or post.get("object", {}).get("sha")
        != "1e7f81e90741795d547c0290b4a82d84d518faac"
        or b"Permission to use, copy, modify, and distribute this software"
        not in bodies["postgresql-license"]
    ):
        raise PortfolioProofError("PostgreSQL tag or license evidence is not exact")


def load_portfolio_minimum_validation_corpus(
    root: Path,
) -> tuple[list[SnapshotState], list[NormalizedDocument], list[FamilySpec]]:
    """Load only the non-holdout first-scale and PostgreSQL validation corpus."""

    try:
        envelope = json.loads(_safe_bytes(root, MANIFEST_PATH))
        config = load_portfolio_family_config(
            root.resolve(strict=True).joinpath(*FAMILY_SPEC_PATH.parts)
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        raise PortfolioProofError("portfolio minimum manifest/spec is invalid") from exc
    if (
        envelope.get("version") != "portfolio-minimum-corpus-v1"
        or envelope.get("base_manifest") != BASE_MANIFEST_PATH.as_posix()
        or envelope.get("family_spec") != FAMILY_SPEC_PATH.as_posix()
        or envelope.get("source_policy") != SOURCE_POLICY_PATH.as_posix()
        or envelope.get("authority_policy") != AUTHORITY_POLICY_PATH.as_posix()
        or envelope.get("temporal_boundary")
        != (
            "publisher-declared version evidence only; not independently "
            "observed historical availability"
        )
        or len(config.families) != 1
        or len(envelope.get("snapshots", [])) != 2
    ):
        raise PortfolioProofError("portfolio minimum manifest identity is invalid")

    states, documents, _ = load_portfolio_scale_corpus(root)
    spec = config.families[0]
    if (
        spec.family_id != "postgresql-cve-2023-5868-release-15-5"
        or spec.prospective_split != "validation"
    ):
        raise PortfolioProofError("portfolio minimum family identity is invalid")

    ledger_successes = _load_capture_ledger(root)
    support = _supporting_artifacts(
        root, list(envelope.get("supporting_artifacts", [])), ledger_successes
    )
    _validate_postgresql_support(support)

    lineage = load_portfolio_lineage_config(
        root.resolve(strict=True).joinpath(*LINEAGE_PATH.parts)
    )
    lineage_by_id = {record.family_id: record for record in lineage.families}
    record = lineage_by_id.get(spec.family_id)
    if record is None:
        raise PortfolioProofError("PostgreSQL lineage is missing")
    for field in type(record).model_fields:
        if field != "family_id" and getattr(record, field) != getattr(spec, field):
            raise PortfolioProofError("PostgreSQL lineage does not match its spec")
    validate_portfolio_dependency_splits(lineage.families)

    for payload in envelope["snapshots"]:
        snapshot_record = dict(payload)
        _ledger_bound(snapshot_record, ledger_successes)
        publisher = snapshot_record.pop("publisher_version_evidence")
        for field in (
            "retrieved_at_utc",
            "effective_date_if_known",
            "available_by_utc",
        ):
            snapshot_record[field] = _time(snapshot_record[field])
        try:
            manifest = SnapshotManifest.model_validate(snapshot_record)
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
                "portfolio minimum snapshot failed validation"
            ) from exc
        for span in document.spans:
            resolve_span(span, document.normalized_text)
        states.append(state)
        documents.append(document)

    by_snapshot = {document.snapshot_id: document for document in documents}
    actual = [
        by_snapshot[snapshot_id].fields["claim_value"]
        for snapshot_id in spec.source_state_ids
    ]
    if actual != spec.expected_values or actual != [False, True]:
        raise PortfolioProofError("PostgreSQL semantic delta is unavailable")
    return states, documents, [spec]


def load_portfolio_minimum_corpus(
    root: Path,
) -> tuple[list[SnapshotState], list[NormalizedDocument], list[FamilySpec]]:
    """Load the validation corpus and separately audit candidate metadata."""

    corpus = load_portfolio_minimum_validation_corpus(root)
    load_holdout_candidate_metadata(root)
    return corpus


def load_portfolio_minimum_cases(
    root: Path,
    *,
    states: list[SnapshotState],
    documents: list[NormalizedDocument],
    specs: list[FamilySpec],
) -> list[BenchmarkCase]:
    """Validate the sole audited PostgreSQL validation question."""

    cases = _load_jsonl(root, CASE_PATH, BenchmarkCase)
    reviews = _load_jsonl(root, REVIEWS_PATH, PortfolioProofReview)
    authority = load_portfolio_minimum_authority_policy(root)
    if len(cases) != 1 or len(reviews) != 1 or len(specs) != 1:
        raise PortfolioProofError("portfolio minimum question coverage is invalid")
    case = cases[0]
    spec = specs[0]
    review = reviews[0]
    evidence_documents = {
        f"{document.document_id}:{span.span_id}": document
        for document in documents
        for span in document.spans
    }
    selected = {
        manifest.snapshot_id
        for manifest in select_admissible_by_entity(states, case.as_of).values()
    }
    evidence_ids = sorted(case.expected_claims[0].evidence_ids)
    if (
        case.entity_family_id != spec.family_id
        or case.template_family_id != spec.template_family_id
        or case.split != "validation"
        or case.temporal_truth_mode != "upstream_versioned"
        or case.should_abstain
        or len(case.expected_claims) != 1
        or case.expected_claims[0].predicate != spec.claim.predicate
        or case.allowed_snapshot_ids != [spec.source_state_ids[-1]]
        or not set(case.allowed_snapshot_ids) <= selected
        or not set(evidence_ids) <= set(evidence_documents)
        or {evidence_documents[evidence_id].snapshot_id for evidence_id in evidence_ids}
        != set(case.allowed_snapshot_ids)
        or set(case.required_authority_policy_ids)
        != {policy.policy_id for policy in authority.policies}
        or review.case_id != case.case_id
        or review.evidence_ids != evidence_ids
        or review.reviewed_at_utc.tzinfo is None
        or review.reviewed_at_utc.utcoffset() != UTC.utcoffset(review.reviewed_at_utc)
    ):
        raise PortfolioProofError("portfolio minimum case/review is invalid")
    return cases
