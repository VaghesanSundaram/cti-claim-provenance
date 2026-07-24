from __future__ import annotations

from pathlib import Path

import pytest

import cti_provenance.claims.ground_truth as ground_truth
from cti_provenance.claims import (
    FixtureBuildError,
    GroundTruthError,
    load_phase2_cases,
    load_phase2_plumbing_corpus,
    normalize_plumbing_fixture,
)

ROOT = Path(__file__).resolve().parents[2]


def test_phase2_plumbing_corpus_is_hash_bound_and_explicitly_labeled() -> None:
    states, documents = load_phase2_plumbing_corpus(ROOT)
    assert len(states) == len(documents) == 4
    assert {document.fields["scope_label"] for document in documents} == {
        "log4shell-plumbing-only"
    }
    red_hat = next(
        document
        for document in documents
        if document.fields["represented_source_name"] == "red_hat_rhsa"
    )
    assert red_hat.fields["timing_basis"] == "publisher-declared-version-evidence"
    assert all(document.spans for document in documents)


def test_phase2_fixture_normalizer_rejects_changed_bytes() -> None:
    states, _documents = load_phase2_plumbing_corpus(ROOT)
    state = next(
        state
        for state in states
        if state.manifest.snapshot_id == "phase2-fixture-nvd-v1"
    )
    raw = (ROOT / state.manifest.raw_blob_path).read_bytes()
    with pytest.raises(FixtureBuildError, match="bind"):
        normalize_plumbing_fixture(raw + b" ", state.manifest)


def test_phase2_case_set_binds_all_evidence_and_one_attack_pair() -> None:
    states, documents = load_phase2_plumbing_corpus(ROOT)
    cases = load_phase2_cases(ROOT, states=states, documents=documents)
    assert len(cases) == 12
    assert (
        len({claim.predicate for case in cases for claim in case.expected_claims}) >= 3
    )
    clean = next(case for case in cases if case.case_id == "p2-cvss-clean")
    attack = next(case for case in cases if case.case_id == "p2-cvss-contradiction")
    assert clean.question == attack.question
    assert clean.attack.family == "none"
    assert attack.attack.family == "contradiction"


@pytest.mark.parametrize(
    ("case_id", "wrong_code"),
    [
        ("p2-red-hat-fixed", "plumbing_only"),
        ("p2-cvss-contradiction", "plumbing_only"),
    ],
)
def test_phase2_review_labels_are_semantically_enforced(
    monkeypatch: pytest.MonkeyPatch,
    case_id: str,
    wrong_code: str,
) -> None:
    states, documents = load_phase2_plumbing_corpus(ROOT)
    reviews = ground_truth._load_reviews(ROOT / ground_truth.PHASE2_REVIEWS_PATH)
    mutated = [
        review.model_copy(update={"notes_code": wrong_code})
        if review.case_id == case_id
        else review
        for review in reviews
    ]
    monkeypatch.setattr(ground_truth, "_load_reviews", lambda _path: mutated)

    with pytest.raises(GroundTruthError, match="review is inconsistent"):
        load_phase2_cases(ROOT, states=states, documents=documents)
