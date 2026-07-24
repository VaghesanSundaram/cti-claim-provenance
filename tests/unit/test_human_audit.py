from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from cti_provenance.grading.human_audit import (
    ArtifactBinding,
    CalibrationItem,
    CalibrationJudgment,
    CalibrationManifest,
    HumanAuditError,
    audit_human_calibration,
)

EXPECTED = {
    "expected_candidate_manifest_sha256": "a" * 64,
    "expected_source_bundle_sha256": "b" * 64,
    "expected_grade_schema_sha256": "c" * 64,
}


def _write(root: Path, name: str, body: bytes) -> ArtifactBinding:
    path = root / name
    path.write_bytes(body)
    return ArtifactBinding(
        path=name,
        sha256=hashlib.sha256(body).hexdigest(),
        byte_length=len(body),
    )


def _canonical_item_hash(records: list[dict[str, object]]) -> str:
    body = "\n".join(
        json.dumps(item, sort_keys=True, separators=(",", ":"))
        for item in sorted(records, key=lambda item: str(item["item_id"]))
    )
    return hashlib.sha256(body.encode()).hexdigest()


def _context_sha256(record: dict[str, object]) -> str:
    body = json.dumps(record, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(body.encode()).hexdigest()


def _manifest(root: Path, count: int = 50) -> CalibrationManifest:
    protocol = json.dumps(
        {
            "protocol_version": "human-calibration-v1",
            "judgments_per_item": 2,
            "reviewers_blind_to_conditions": True,
            "adjudicator_blind_to_conditions": True,
            "agreement_method": "cohen_kappa_v1",
            "label_set": [
                "supported",
                "partial",
                "unsupported",
                "not_applicable",
            ],
        },
        separators=(",", ":"),
    ).encode()
    items: list[dict[str, object]] = []
    contexts: list[dict[str, object]] = []
    grades: list[dict[str, object]] = []
    for index in range(count):
        evidence_text = f"Synthetic test evidence {index}."
        context = {
            "item_id": f"item-{index}",
            "case_id": f"synthetic-case-{index}",
            "evidence_id": f"synthetic-evidence-{index}",
            "predicate": "cve.published_at",
            "source_name": "synthetic_control",
            "question": f"Synthetic test question {index}?",
            "evidence_text": evidence_text,
            "evidence_text_sha256": hashlib.sha256(evidence_text.encode()).hexdigest(),
        }
        contexts.append(context)
        items.append(
            {
                "item_id": context["item_id"],
                "case_id": context["case_id"],
                "claim_grade_id": f"synthetic-grade-{index}",
                "evidence_id": context["evidence_id"],
                "predicate": context["predicate"],
                "split": "dev" if index % 2 else "validation",
                "source_name": context["source_name"],
                "context_sha256": _context_sha256(context),
            }
        )
        grades.append(
            {
                "claim_grade_id": f"synthetic-grade-{index}",
                "run_id": "synthetic-test-run",
                "case_id": context["case_id"],
                "generated_claim_id": f"generated-{index}",
                "expected_claim_id": f"expected-{index}",
                "predicate": context["predicate"],
                "value_match": "exact",
                "evidence_assessments": [
                    {
                        "evidence_id": context["evidence_id"],
                        "resolution": "resolved",
                        "entailment": "supported",
                        "temporality": "admissible",
                        "authority": "accepted",
                        "span_hash_match": True,
                    }
                ],
                "contradiction": "none",
                "claim_support": "supported",
                "abstention_outcome": "not_applicable",
                "generated_confidence": 1.0,
                "deterministic_grader_version": "synthetic-grader-v1",
                "authority_policy_version": "synthetic-authority-v1",
                "normalization_version": "synthetic-normalization-v1",
                "human_judgment_id": None,
                "notes_code": None,
            }
        )
    judgments: list[bytes] = []
    adjudications: list[bytes] = []
    for index in range(count):
        first = "supported" if index % 3 else "partial"
        second = first if index % 5 else "unsupported"
        for reviewer, label in (("reviewer-a", first), ("reviewer-b", second)):
            judgments.append(
                json.dumps(
                    {
                        "judgment_id": f"j-{index}-{reviewer}",
                        "item_id": f"item-{index}",
                        "reviewer_id": reviewer,
                        "judged_at_utc": "2026-07-19T00:00:00Z",
                        "label": label,
                    },
                    separators=(",", ":"),
                ).encode()
            )
        if first != second:
            adjudications.append(
                json.dumps(
                    {
                        "adjudication_id": f"a-{index}",
                        "item_id": f"item-{index}",
                        "judgment_ids": [
                            f"j-{index}-reviewer-a",
                            f"j-{index}-reviewer-b",
                        ],
                        "adjudicator_id": "adjudicator",
                        "adjudicated_at_utc": "2026-07-19T01:00:00Z",
                        "final_label": first,
                        "rationale_code": "evidence_support_resolution",
                    },
                    separators=(",", ":"),
                ).encode()
            )
    items_body = b"\n".join(
        json.dumps(item, separators=(",", ":")).encode() for item in items
    )
    grade_records_body = b"\n".join(
        json.dumps(grade, separators=(",", ":")).encode() for grade in grades
    )
    contexts_body = b"\n".join(
        json.dumps(context, separators=(",", ":")).encode() for context in contexts
    )
    return CalibrationManifest(
        manifest_version="human-calibration-manifest-v1",
        protocol_spec=_write(root, "protocol.json", protocol),
        protocol_document=_write(
            root,
            "protocol.md",
            b"# Synthetic test protocol\n\nNo real reviewer evidence.\n",
        ),
        grade_records=_write(
            root,
            "grades.jsonl",
            grade_records_body,
        ),
        reviewer_contexts=_write(root, "contexts.jsonl", contexts_body),
        items=_write(root, "items.jsonl", items_body),
        judgments=_write(root, "judgments.jsonl", b"\n".join(judgments)),
        adjudications=_write(
            root,
            "adjudications.jsonl",
            b"\n".join(adjudications) or b"\n",
        ),
        candidate_manifest_sha256="a" * 64,
        source_bundle_sha256="b" * 64,
        grade_schema_sha256="c" * 64,
        deterministic_grader_version="synthetic-grader-v1",
        authority_policy_version="synthetic-authority-v1",
        normalization_versions=("synthetic-normalization-v1",),
        item_universe_sha256=_canonical_item_hash(items),
    )


def _audit(root: Path, manifest: CalibrationManifest):
    evidence_spans = {
        record["evidence_id"]: record["evidence_text_sha256"]
        for record in (
            json.loads(line)
            for line in (root / "contexts.jsonl").read_text().splitlines()
            if line
        )
    }
    return audit_human_calibration(
        root,
        manifest,
        expected_evidence_text_sha256_by_id=evidence_spans,
        **EXPECTED,
    )


def test_audit_derives_bound_agreement_for_complete_synthetic_fixture(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path)
    audit = _audit(tmp_path, manifest)

    assert audit.structural_gate_complete is True
    assert audit.item_count == 50
    assert audit.judgment_count == 100
    assert audit.disagreement_count == audit.adjudication_count == 10
    assert audit.raw_agreement_numerator == 40
    assert audit.raw_agreement_denominator == 50
    assert str(audit.raw_agreement) == "0.8"
    assert audit.cohens_kappa is not None
    assert audit.acceptance_threshold_status == "not_declared"
    assert audit.findings == ()

    unbound = audit_human_calibration(tmp_path, manifest, **EXPECTED)
    assert unbound.structural_gate_complete is False
    assert unbound.evidence_span_binding_status == "unbound"
    assert [finding.code for finding in unbound.findings] == [
        "evidence_span_provenance_unbound"
    ]
    with pytest.raises(HumanAuditError, match="candidate evidence span"):
        audit_human_calibration(
            tmp_path,
            manifest,
            expected_evidence_text_sha256_by_id={
                f"synthetic-evidence-{index}": "0" * 64 for index in range(50)
            },
            **EXPECTED,
        )


def test_audit_marks_small_or_degenerate_cohort_incomplete(tmp_path: Path) -> None:
    small = _audit(tmp_path, _manifest(tmp_path, count=2))
    assert small.structural_gate_complete is False
    assert [finding.code for finding in small.findings] == ["insufficient_cohort"]

    manifest = _manifest(tmp_path)
    lines = (tmp_path / "judgments.jsonl").read_text().splitlines()
    all_supported = [
        json.dumps({**json.loads(line), "label": "supported"}, separators=(",", ":"))
        for line in lines
    ]
    manifest = manifest.model_copy(
        update={
            "judgments": _write(
                tmp_path,
                "judgments.jsonl",
                "\n".join(all_supported).encode(),
            ),
            "adjudications": _write(tmp_path, "adjudications.jsonl", b"\n"),
        }
    )
    degenerate = _audit(tmp_path, manifest)
    assert degenerate.cohens_kappa is None
    assert [finding.code for finding in degenerate.findings] == ["kappa_undefined"]


def test_audit_accepts_a_bound_multi_source_normalization_bundle(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path, count=2)
    grades = [
        json.loads(line)
        for line in (tmp_path / "grades.jsonl").read_text().splitlines()
    ]
    grades[1]["normalization_version"] = "synthetic-normalization-v2"
    changed = manifest.model_copy(
        update={
            "grade_records": _write(
                tmp_path,
                "grades.jsonl",
                "\n".join(json.dumps(grade) for grade in grades).encode(),
            ),
            "normalization_versions": (
                "synthetic-normalization-v1",
                "synthetic-normalization-v2",
            ),
        }
    )
    audit = _audit(tmp_path, changed)
    assert audit.normalization_versions == (
        "synthetic-normalization-v1",
        "synthetic-normalization-v2",
    )


def test_audit_rejects_unbound_upstream_or_item_universe(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, count=2)
    with pytest.raises(HumanAuditError, match="upstream hash"):
        audit_human_calibration(
            tmp_path,
            manifest,
            **{**EXPECTED, "expected_candidate_manifest_sha256": "f" * 64},
        )
    with pytest.raises(HumanAuditError, match="item universe"):
        _audit(
            tmp_path,
            manifest.model_copy(update={"item_universe_sha256": "e" * 64}),
        )


def test_audit_rejects_missing_or_non_independent_review(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, count=2)
    lines = (tmp_path / "judgments.jsonl").read_text().splitlines()
    with pytest.raises(HumanAuditError, match="both independent reviewers"):
        one_missing = _write(
            tmp_path,
            "judgments.jsonl",
            "\n".join(lines[:-1]).encode(),
        )
        _audit(tmp_path, manifest.model_copy(update={"judgments": one_missing}))

    records = [json.loads(line) for line in lines]
    records[1]["reviewer_id"] = "reviewer-a"
    duplicate = _write(
        tmp_path,
        "judgments.jsonl",
        "\n".join(json.dumps(record) for record in records).encode(),
    )
    with pytest.raises(HumanAuditError, match="only once"):
        _audit(tmp_path, manifest.model_copy(update={"judgments": duplicate}))


def test_audit_rejects_incomplete_or_non_independent_adjudication(
    tmp_path: Path,
) -> None:
    manifest = _manifest(tmp_path, count=2)
    original_adjudications = (tmp_path / "adjudications.jsonl").read_text()
    with pytest.raises(HumanAuditError, match="every disagreement"):
        _audit(
            tmp_path,
            manifest.model_copy(
                update={
                    "adjudications": _write(
                        tmp_path,
                        "adjudications.jsonl",
                        b"\n",
                    )
                }
            ),
        )

    records = [json.loads(line) for line in original_adjudications.splitlines() if line]
    records[0]["adjudicator_id"] = "reviewer-a"
    binding = _write(
        tmp_path,
        "adjudications.jsonl",
        "\n".join(json.dumps(record) for record in records).encode(),
    )
    with pytest.raises(HumanAuditError, match="independent"):
        _audit(tmp_path, manifest.model_copy(update={"adjudications": binding}))

    records[0]["adjudicator_id"] = "adjudicator"
    records[0]["adjudicated_at_utc"] = "2026-07-19T00:00:00Z"
    chronological = _write(
        tmp_path,
        "adjudications.jsonl",
        "\n".join(json.dumps(record) for record in records).encode(),
    )
    with pytest.raises(HumanAuditError, match="follow both judgments"):
        _audit(
            tmp_path,
            manifest.model_copy(update={"adjudications": chronological}),
        )


def test_audit_rejects_condition_metadata_and_tampered_bytes(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, count=2)
    with pytest.raises(ValidationError, match="Extra inputs"):
        CalibrationItem.model_validate(
            {
                "item_id": "x",
                "case_id": "c",
                "claim_grade_id": "g",
                "evidence_id": "e",
                "predicate": "p",
                "split": "dev",
                "source_name": "s",
                "context_sha256": "0" * 64,
                "condition": "forbidden",
            }
        )
    with pytest.raises(ValidationError, match="UTC"):
        CalibrationJudgment.model_validate_json(
            json.dumps(
                {
                    "judgment_id": "j",
                    "item_id": "i",
                    "reviewer_id": "r",
                    "judged_at_utc": "2026-07-19T00:00:00+01:00",
                    "label": "supported",
                }
            )
        )

    (tmp_path / "items.jsonl").write_text("{}\n", encoding="utf-8")
    with pytest.raises(HumanAuditError, match="bytes do not match"):
        _audit(tmp_path, manifest)


def test_audit_rejects_condition_metadata_in_reviewer_context(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, count=2)
    records = [
        json.loads(line)
        for line in (tmp_path / "contexts.jsonl").read_text().splitlines()
    ]
    records[0]["condition"] = "forbidden"
    changed = manifest.model_copy(
        update={
            "reviewer_contexts": _write(
                tmp_path,
                "contexts.jsonl",
                "\n".join(json.dumps(record) for record in records).encode(),
            ),
        }
    )
    with pytest.raises(HumanAuditError, match="reviewer contexts JSONL"):
        _audit(tmp_path, changed)


def test_audit_rejects_linked_artifacts(tmp_path: Path) -> None:
    manifest = _manifest(tmp_path, count=2)
    link = tmp_path / "linked.json"
    try:
        link.symlink_to(tmp_path / "protocol.json")
    except OSError:
        pytest.skip("symlinks unavailable")
    manifest = manifest.model_copy(
        update={
            "protocol_spec": ArtifactBinding(
                path="linked.json",
                sha256=hashlib.sha256(
                    (tmp_path / "protocol.json").read_bytes()
                ).hexdigest(),
                byte_length=(tmp_path / "protocol.json").stat().st_size,
            )
        }
    )
    with pytest.raises(HumanAuditError, match="link or junction"):
        _audit(tmp_path, manifest)
