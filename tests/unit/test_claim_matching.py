from __future__ import annotations

import pytest
from pydantic import ValidationError

from cti_provenance.claims.schema import (
    AtomicClaim,
    ClaimObject,
    ClaimQualifiers,
    ClaimSubject,
    GoldAtomicClaim,
    PredicateName,
)
from cti_provenance.grading.schema import match_claims


def _claim(
    claim_id: str,
    value: bool | str | list[str],
    datatype: str,
    *,
    gold: bool = False,
    predicate: PredicateName = "kev.is_member",
) -> AtomicClaim:
    model = GoldAtomicClaim if gold else AtomicClaim
    return model.model_validate(
        {
            "claim_id": claim_id,
            "subject": ClaimSubject(type="cve", id="CVE-SYNTHETIC-0001"),
            "predicate": predicate,
            "object": ClaimObject.model_validate(
                {"value": value, "datatype": datatype}
            ),
            "qualifiers": ClaimQualifiers(
                authority="cisa_kev",
                cvss_version=None,
                product=None,
                ecosystem=None,
            ),
            "evidence_ids": ["doc-1:span-1"] if gold else [],
            "confidence": 0.5,
        }
    )


def test_first_exact_match_wins_and_duplicate_is_false_positive() -> None:
    expected = [_claim("expected", True, "boolean", gold=True)]
    generated = [
        _claim("generated-b", True, "boolean"),
        _claim("generated-a", True, "boolean"),
    ]
    result = match_claims(expected, generated)
    assert result.matches[0].generated_claim_id == "generated-a"
    assert result.matches[0].exact is True
    assert result.unmatched_generated_claim_ids == ["generated-b"]
    assert result.unmatched_expected_claim_ids == []


def test_exact_value_beats_earlier_mismatch_for_same_key() -> None:
    expected = [_claim("expected", True, "boolean", gold=True)]
    generated = [
        _claim("generated-a", False, "boolean"),
        _claim("generated-b", True, "boolean"),
    ]
    result = match_claims(expected, generated)
    assert result.matches[0].generated_claim_id == "generated-b"
    assert result.matches[0].exact is True
    assert result.unmatched_generated_claim_ids == ["generated-a"]


def test_first_claim_is_paired_only_for_mismatch_diagnostics() -> None:
    expected = [_claim("expected", True, "boolean", gold=True)]
    generated = [
        _claim("generated-b", False, "boolean"),
        _claim("generated-a", False, "boolean"),
    ]
    result = match_claims(expected, generated)
    assert result.matches[0].generated_claim_id == "generated-a"
    assert result.matches[0].exact is False
    assert result.unmatched_generated_claim_ids == ["generated-b"]


def test_typed_set_values_match_independent_of_order() -> None:
    expected = [
        _claim(
            "expected",
            ["1.0.1", "1.0.2"],
            "version_set",
            gold=True,
            predicate="vendor.fixed_versions",
        )
    ]
    generated = [
        _claim(
            "generated",
            ["1.0.2", "1.0.1"],
            "version_set",
            predicate="vendor.fixed_versions",
        )
    ]
    assert match_claims(expected, generated).matches[0].exact is True


def test_wrong_key_is_unmatched_and_no_fuzzy_matching_occurs() -> None:
    expected = [_claim("expected", True, "boolean", gold=True)]
    generated = [_claim("generated", True, "boolean", predicate="kev.date_added")]
    result = match_claims(expected, generated)
    assert result.matches == []
    assert result.unmatched_expected_claim_ids == ["expected"]
    assert result.unmatched_generated_claim_ids == ["generated"]


def test_duplicate_generated_ids_and_expected_keys_are_rejected() -> None:
    generated = [_claim("duplicate", True, "boolean")] * 2
    with pytest.raises(ValueError, match="generated claim_id"):
        match_claims([], generated)

    expected = [
        _claim("expected-a", True, "boolean", gold=True),
        _claim("expected-b", False, "boolean", gold=True),
    ]
    with pytest.raises(ValueError, match="matching key"):
        match_claims(expected, [])


def test_claim_object_rejects_duplicate_set_members() -> None:
    with pytest.raises(ValidationError):
        ClaimObject(value=["CVE-1", "CVE-1"], datatype="identifier_set")
