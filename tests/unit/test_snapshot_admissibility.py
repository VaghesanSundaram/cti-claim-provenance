from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from cti_provenance.snapshot.admissibility import (
    AdmissibilityError,
    AmbiguousSnapshotState,
    AttackEvidence,
    CisaEvidence,
    PublisherVersionEvidence,
    RedHatEvidence,
    SnapshotState,
    SyntheticEvidence,
    select_admissible_snapshot,
)
from cti_provenance.snapshot.manifest import SnapshotManifest

BASE_TIME = datetime(2026, 1, 1, tzinfo=UTC)


def _manifest(
    source_name: str, snapshot_id: str, **changes: object
) -> SnapshotManifest:
    source_class = {
        "nvd": "government",
        "cisa_kev": "government",
        "mitre_attack": "standards_body",
        "red_hat_rhsa": "vendor",
        "synthetic_control": "synthetic",
    }[source_name]
    basis = {
        "nvd": "observed_retrieval",
        "cisa_kev": "upstream_version",
        "mitre_attack": "upstream_version",
        "red_hat_rhsa": "publisher_timestamp_with_observation",
        "synthetic_control": "synthetic_fixture",
    }[source_name]
    source_url = {
        "nvd": "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "cisa_kev": "https://github.com/cisagov/kev-data",
        "mitre_attack": "https://github.com/mitre-attack/attack-stix-data",
        "red_hat_rhsa": "https://security.access.redhat.com/data/csaf/v2/advisories/",
        "synthetic_control": "urn:cti-provenance:test:synthetic",
    }[source_name]
    data: dict[str, object] = {
        "snapshot_id": snapshot_id,
        "source_name": source_name,
        "source_class": source_class,
        "source_url": source_url,
        "retrieved_at_utc": BASE_TIME,
        "http_status": 200,
        "http_etag": None,
        "http_last_modified": None,
        "effective_date_if_known": BASE_TIME,
        "effective_date_basis": "publisher_version",
        "available_by_utc": BASE_TIME,
        "available_by_basis": basis,
        "upstream_identifier": "entity-1",
        "upstream_version": "1.0",
        "media_type": "application/json",
        "byte_length": 10,
        "sha256": snapshot_id[0] * 64,
        "raw_blob_path": f"fixtures/{snapshot_id}.json",
        "fetcher_version": "fixture-v1",
        "normalization_version": "fixture-v1",
        "license_or_terms_note": "synthetic fixture only",
    }
    if source_name == "nvd":
        data["upstream_version"] = None
        data["effective_date_if_known"] = None
    if source_name == "cisa_kev":
        data["upstream_version"] = "c" * 40
    if source_name == "synthetic_control":
        data["upstream_version"] = "1"
    data.update(changes)
    return SnapshotManifest.model_validate(data)


def _state(manifest: SnapshotManifest, **changes: object) -> SnapshotState:
    common: dict[str, object] = {}
    if (
        manifest.source_name == "cisa_kev"
        and manifest.available_by_basis == "upstream_version"
    ):
        common["cisa_evidence"] = CisaEvidence(
            commit_sha="c" * 40,
            official_commit_time_utc=manifest.available_by_utc,
            mirror_relationship_verified=True,
            ancestry_verified=True,
        )
    elif manifest.source_name == "mitre_attack":
        common["attack_evidence"] = AttackEvidence(
            release_tag=f"v{manifest.upstream_version}",
            release_semantic_version=manifest.upstream_version or "",
            commit_sha="d" * 40,
            release_metadata_verified=True,
            publisher_release_time_utc=manifest.available_by_utc,
            bundle_sha256=manifest.sha256,
        )
    elif manifest.source_name == "red_hat_rhsa":
        common["red_hat_evidence"] = RedHatEvidence(
            final_status=True,
            tracking_id=manifest.upstream_identifier or "",
            revision_version=manifest.upstream_version or "",
            complete_revision_history=True,
            final_revision_date_utc=manifest.available_by_utc,
            current_release_date_utc=manifest.available_by_utc,
            published_sha256=manifest.sha256,
        )
    elif manifest.source_name == "synthetic_control":
        common["synthetic_evidence"] = SyntheticEvidence(
            generator_version="fixture-generator-v1",
            fixture_sequence=(
                int(manifest.upstream_version)
                if (manifest.upstream_version or "").isdigit()
                else 0
            ),
        )
    common.update(changes)
    return SnapshotState(manifest, **common)


def test_cutoff_is_inclusive_and_later_snapshot_is_excluded() -> None:
    early = _state(_manifest("nvd", "a-old"))
    later = _state(
        _manifest(
            "nvd",
            "b-new",
            retrieved_at_utc=BASE_TIME + timedelta(seconds=1),
            available_by_utc=BASE_TIME + timedelta(seconds=1),
        )
    )
    assert select_admissible_snapshot([early, later], BASE_TIME).snapshot_id == "a-old"
    assert (
        select_admissible_snapshot(
            [early, later], BASE_TIME - timedelta(microseconds=1)
        )
        is None
    )


def test_nvd_change_record_uses_publisher_version_evidence() -> None:
    declared = BASE_TIME - timedelta(days=1)
    manifest = _manifest(
        "nvd",
        "a-history",
        source_url=(
            "https://nvd.nist.gov/vuln/detail/CVE-2024-3400/change-record"
            "?changeRecordedOn=05%2F29%2F2024T12%3A00%3A24.110-0400"
        ),
        effective_date_if_known=declared,
        effective_date_basis="publisher_version",
        available_by_utc=declared,
        available_by_basis="publisher_declared_version",
        upstream_identifier="nvd-cve-2024-3400-change-history",
        upstream_version="2024-05-29T16:00:24.110Z",
    )
    state = _state(
        manifest,
        publisher_version_evidence=PublisherVersionEvidence(
            version_identifier="2024-05-29T16:00:24.110Z",
            publisher_declared_time_utc=declared,
            independently_addressable=True,
        ),
    )
    assert select_admissible_snapshot([state], declared) == manifest


def test_equal_time_distinct_nvd_states_fail_closed() -> None:
    with pytest.raises(AmbiguousSnapshotState):
        select_admissible_snapshot(
            [
                _state(_manifest("nvd", "a-one")),
                _state(_manifest("nvd", "b-two")),
            ],
            BASE_TIME,
        )


def test_equal_time_equivalent_duplicates_have_stable_representative() -> None:
    common = {"sha256": "f" * 64, "raw_blob_path": "data/raw/same.json"}
    first = _state(_manifest("nvd", "a-duplicate", **common))
    second = _state(_manifest("nvd", "b-duplicate", **common))
    assert (
        select_admissible_snapshot([second, first], BASE_TIME).snapshot_id
        == "a-duplicate"
    )
    assert (
        select_admissible_snapshot([first, second], BASE_TIME).snapshot_id
        == "a-duplicate"
    )


def test_equal_bytes_with_conflicting_provenance_fail_closed() -> None:
    first = _state(_manifest("nvd", "a-duplicate", sha256="f" * 64))
    second = _state(_manifest("nvd", "b-duplicate", sha256="f" * 64))
    with pytest.raises(AmbiguousSnapshotState, match="conflicting provenance"):
        select_admissible_snapshot([first, second], BASE_TIME)


def test_cisa_selects_only_validated_descendant_at_equal_time() -> None:
    parent = _state(_manifest("cisa_kev", "a-parent"))
    child = _state(
        _manifest("cisa_kev", "b-child", sha256="b" * 64),
        cisa_ancestor_snapshot_ids=frozenset({"a-parent"}),
    )
    assert (
        select_admissible_snapshot([parent, child], BASE_TIME).snapshot_id == "b-child"
    )


@pytest.mark.parametrize("source", ["mitre_attack", "red_hat_rhsa"])
def test_versioned_sources_choose_validated_highest_equal_time_version(
    source: str,
) -> None:
    old = _state(_manifest(source, "a-old", upstream_version="1.2"))
    new = _state(_manifest(source, "b-new", upstream_version="1.10", sha256="b" * 64))
    assert select_admissible_snapshot([old, new], BASE_TIME).snapshot_id == "b-new"


def test_invalid_basis_evidence_is_not_admissible() -> None:
    invalid = _state(
        _manifest("mitre_attack", "a-bad", available_by_basis="observed_retrieval")
    )
    with pytest.raises(AdmissibilityError, match="invalid mitre_attack"):
        select_admissible_snapshot([invalid], BASE_TIME)


def test_cisa_without_commit_provenance_must_use_observed_fallback() -> None:
    upstream_missing = _state(_manifest("cisa_kev", "a-missing"), cisa_evidence=None)
    with pytest.raises(AdmissibilityError, match="invalid cisa_kev"):
        select_admissible_snapshot([upstream_missing], BASE_TIME)

    observed = _state(
        _manifest(
            "cisa_kev",
            "b-observed",
            available_by_basis="observed_retrieval",
            upstream_version=None,
        )
    )
    assert select_admissible_snapshot([observed], BASE_TIME).snapshot_id == "b-observed"


def test_cisa_commit_sha_must_match_manifest_upstream_version() -> None:
    state = _state(
        _manifest("cisa_kev", "a-wrong-commit"),
        cisa_evidence=CisaEvidence(
            commit_sha="d" * 40,
            official_commit_time_utc=BASE_TIME,
            mirror_relationship_verified=True,
            ancestry_verified=True,
        ),
    )
    with pytest.raises(AdmissibilityError, match="invalid cisa_kev"):
        select_admissible_snapshot([state], BASE_TIME)


def test_cisa_observed_fallback_equal_time_distinct_bytes_fail_closed() -> None:
    first = _state(
        _manifest(
            "cisa_kev",
            "a-observed",
            available_by_basis="observed_retrieval",
            upstream_version=None,
        )
    )
    second = _state(
        _manifest(
            "cisa_kev",
            "b-observed",
            available_by_basis="observed_retrieval",
            upstream_version=None,
            sha256="b" * 64,
        )
    )
    with pytest.raises(AmbiguousSnapshotState):
        select_admissible_snapshot([first, second], BASE_TIME)


@pytest.mark.parametrize("source", ["mitre_attack", "red_hat_rhsa"])
def test_versioned_sources_reject_missing_required_evidence(source: str) -> None:
    state = _state(_manifest(source, "a-missing"))
    if source == "mitre_attack":
        state = _state(state.manifest, attack_evidence=None)
    else:
        state = _state(state.manifest, red_hat_evidence=None)
    with pytest.raises(AdmissibilityError, match=f"invalid {source}"):
        select_admissible_snapshot([state], BASE_TIME)


@pytest.mark.parametrize("source", ["mitre_attack", "red_hat_rhsa"])
def test_versioned_sources_reject_effective_date_or_basis_mismatch(source: str) -> None:
    state = _state(
        _manifest(
            source,
            "a-date-mismatch",
            effective_date_if_known=BASE_TIME + timedelta(seconds=1),
        )
    )
    with pytest.raises(AdmissibilityError, match=f"invalid {source}"):
        select_admissible_snapshot([state], BASE_TIME)


def test_attack_release_tag_must_match_its_semantic_release_version() -> None:
    manifest = _manifest("mitre_attack", "a-tag")
    state = _state(
        manifest,
        attack_evidence=AttackEvidence(
            release_tag="v2.0",
            release_semantic_version="1.0",
            commit_sha="d" * 40,
            release_metadata_verified=True,
            publisher_release_time_utc=BASE_TIME,
            bundle_sha256=manifest.sha256,
        ),
    )
    with pytest.raises(AdmissibilityError, match="invalid mitre_attack"):
        select_admissible_snapshot([state], BASE_TIME)


def test_foreign_evidence_shape_is_rejected() -> None:
    state = _state(
        _manifest("nvd", "a-foreign"),
        attack_evidence=AttackEvidence(
            release_tag="v1.0",
            release_semantic_version="1.0",
            commit_sha="d" * 40,
            release_metadata_verified=True,
            publisher_release_time_utc=BASE_TIME,
            bundle_sha256="a" * 64,
        ),
    )
    with pytest.raises(AdmissibilityError, match="invalid nvd"):
        select_admissible_snapshot([state], BASE_TIME)


def test_source_ordering_evidence_types_are_strict() -> None:
    with pytest.raises(ValidationError):
        CisaEvidence(
            commit_sha="c" * 40,
            official_commit_time_utc=BASE_TIME,
            mirror_relationship_verified="false",  # type: ignore[arg-type]
            ancestry_verified=True,
        )
    with pytest.raises(ValidationError):
        SyntheticEvidence(
            generator_version="fixture-generator-v1",
            fixture_sequence="1",  # type: ignore[arg-type]
        )


def test_red_hat_rejects_date_or_checksum_inconsistency() -> None:
    manifest = _manifest("red_hat_rhsa", "a-rhsa")
    state = _state(
        manifest,
        red_hat_evidence=RedHatEvidence(
            final_status=True,
            tracking_id="entity-1",
            revision_version="1.0",
            complete_revision_history=True,
            final_revision_date_utc=BASE_TIME,
            current_release_date_utc=BASE_TIME,
            published_sha256="f" * 64,
        ),
    )
    with pytest.raises(AdmissibilityError, match="invalid red_hat_rhsa"):
        select_admissible_snapshot([state], BASE_TIME)


def test_synthetic_requires_integer_sequence_and_monotonic_progression() -> None:
    invalid = _state(
        _manifest("synthetic_control", "a-invalid", upstream_version="1.0"),
        synthetic_evidence=SyntheticEvidence("fixture-generator-v1", 1),
    )
    with pytest.raises(AdmissibilityError, match="invalid synthetic_control"):
        select_admissible_snapshot([invalid], BASE_TIME)

    newer_time = BASE_TIME + timedelta(seconds=1)
    sequence_one = _state(_manifest("synthetic_control", "a-one", upstream_version="1"))
    sequence_zero = _state(
        _manifest(
            "synthetic_control",
            "b-zero",
            upstream_version="0",
            sha256="b" * 64,
            retrieved_at_utc=newer_time,
            available_by_utc=newer_time,
        )
    )
    with pytest.raises(AdmissibilityError, match="sequence must increase"):
        select_admissible_snapshot([sequence_one, sequence_zero], newer_time)


def test_synthetic_identical_bytes_at_different_times_are_not_collapsed() -> None:
    later_time = BASE_TIME + timedelta(seconds=1)
    first = _state(
        _manifest("synthetic_control", "a-one", upstream_version="1", sha256="f" * 64)
    )
    later = _state(
        _manifest(
            "synthetic_control",
            "b-one",
            upstream_version="1",
            sha256="f" * 64,
            retrieved_at_utc=later_time,
            available_by_utc=later_time,
        )
    )
    with pytest.raises(AdmissibilityError, match="sequence must increase"):
        select_admissible_snapshot([first, later], later_time)


@pytest.mark.parametrize("same_time_sequences", [(2, 1), (1, 2)])
def test_synthetic_sequence_check_is_not_input_order_dependent(
    same_time_sequences: tuple[int, int],
) -> None:
    states = [
        _state(
            _manifest(
                "synthetic_control",
                f"a-{sequence}",
                upstream_version=str(sequence),
                sha256=chr(97 + index) * 64,
            )
        )
        for index, sequence in enumerate(same_time_sequences)
    ]
    later_time = BASE_TIME + timedelta(seconds=1)
    states.append(
        _state(
            _manifest(
                "synthetic_control",
                "c-later",
                upstream_version="2",
                sha256="c" * 64,
                retrieved_at_utc=later_time,
                available_by_utc=later_time,
            )
        )
    )
    with pytest.raises(AdmissibilityError, match="sequence must increase"):
        select_admissible_snapshot(states, later_time)
