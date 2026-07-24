"""Fail-first contracts for the additive diverse portfolio V4 repair."""

# Frozen hashes and synthetic source fixtures are intentionally kept whole.
# ruff: noqa: E501

from __future__ import annotations

import hashlib
import json
from collections import Counter
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from cti_provenance.claims.diverse_portfolio import DiverseCorpusDraft
from cti_provenance.claims.diverse_portfolio_v4 import (
    CandidateComponent,
    DerivationRecord,
    DiverseCorpusV4,
    DiverseEvidence,
    PacketIndexV4,
    ReviewPacketV4,
    canonical_sha256,
    derive_curl_boundary,
    derive_cve_default_status,
    derive_ecovacs_version_table,
    derive_kev_field,
    derive_kubernetes_fixed_versions,
    derive_kunbus_remediation,
    derive_nvd_description_states,
    derive_nvd_primary_score,
    derive_tomcat_affected_fixed,
    grade_v4_outcome,
    load_diverse_corpus_v4,
    verify_absence,
    verify_derivation_record,
    verify_kev_membership_absence,
    verify_nvd_history_absence,
)
from cti_provenance.cli import main

ROOT = Path(__file__).resolve().parents[2]
V3 = ROOT / "data/benchmark/portfolio-diverse-draft-v3.json"
V4 = ROOT / "data/benchmark/portfolio-diverse-draft-v4.json"
REVIEW = ROOT / "annotations/packets/portfolio-diverse-review-v4.json"
INDEX = ROOT / "data/benchmark/portfolio-diverse-packets-v4.json"
LINEAGE = ROOT / "data/benchmark/portfolio-diverse-v3-to-v4.json"
V3_HASHES = {
    "data/benchmark/portfolio-diverse-draft-v3.json": "11e86a30c3458eca6b8eedf38d98015e1a9a5b2a8e76f5724230f1aba12f67ab",
    "annotations/packets/portfolio-diverse-review-v3.json": "7e3133b52c932237b5323a2dff9d01df690010ad0ce45629755ce4888773edab",
    "data/benchmark/portfolio-diverse-packets-v3.json": "c0e02d743fa50bcaa4a42b73efaa5211547d274aad1abadb257988ab0bb62c75",
}


def _corpus() -> DiverseCorpusV4:
    return load_diverse_corpus_v4(V4)


def _alias_map(case_id: str) -> dict[str, str]:
    index = PacketIndexV4.model_validate_json(INDEX.read_text(encoding="utf-8"))
    packet = next(item for item in index.packets if item.case_id == case_id)
    return {
        span.span_alias: span.evidence_id
        for document in index.evaluator_bindings[packet.packet_id]
        for span in document.evidence
    }


def _candidate_components(question: Any) -> list[CandidateComponent]:
    alias_map = _alias_map(question.case_id)
    aliases_by_evidence = {value: key for key, value in alias_map.items()}
    return [
        CandidateComponent(
            kind=item.kind,
            predicate=item.predicate,
            datatype=item.datatype,
            value=item.value,
            authority_scope=item.authority_scope,
            cited_span_aliases=[
                aliases_by_evidence[evidence_id]
                for evidence_id in item.required_evidence_ids
            ],
        )
        for item in question.expected_components
    ]


def _rehash_question(question: dict[str, Any]) -> None:
    body = {key: value for key, value in question.items() if key != "question_sha256"}
    question["question_sha256"] = canonical_sha256(body)


def _rehash_corpus(payload: dict[str, Any]) -> None:
    body = {key: value for key, value in payload.items() if key != "corpus_sha256"}
    payload["corpus_sha256"] = canonical_sha256(body)


def test_v3_artifact_bytes_are_immutable() -> None:
    for relative, expected in V3_HASHES.items():
        assert hashlib.sha256((ROOT / relative).read_bytes()).hexdigest() == expected


def test_v4_counts_lineage_and_review_contracts() -> None:
    corpus = _corpus()
    assert len(corpus.questions) == 64
    assert sum(item.review_status == "approved_v2" for item in corpus.questions) == 16
    assert sum(item.outcome_type == "abstain" for item in corpus.questions) == 8
    review = ReviewPacketV4.model_validate_json(REVIEW.read_text(encoding="utf-8"))
    index = PacketIndexV4.model_validate_json(INDEX.read_text(encoding="utf-8"))
    assert len(review.items) == 48
    assert len(index.packets) == 64
    lineage = json.loads(LINEAGE.read_text(encoding="utf-8"))
    v3 = DiverseCorpusDraft.model_validate_json(V3.read_text(encoding="utf-8"))
    v3_new_ids = {
        item.case_id for item in v3.questions if item.review_status != "approved_v2"
    }
    assert len(lineage["rows"]) == 49
    assert {row["v3_case_id"] for row in lineage["rows"]} == v3_new_ids
    assert len({row["v3_case_id"] for row in lineage["rows"]}) == 49
    assert lineage["v3_file_sha256"] == V3_HASHES[V3.relative_to(ROOT).as_posix()]
    assert lineage["v4_semantic_corpus_sha256"] == corpus.corpus_sha256

    v2_splits = {
        item["case_id"]: item["split"]
        for item in (
            json.loads(line)
            for line in (ROOT / "data/benchmark/portfolio-public-cases-v2.jsonl")
            .read_text(encoding="utf-8")
            .splitlines()
            if line
        )
        if "-control-v2" not in item["case_id"]
        and "-challenge-v2" not in item["case_id"]
    }
    for question in corpus.questions:
        if question.review_status == "approved_v2":
            assert question.split == v2_splits[question.retained_v2_case_id]


def test_no_dependency_family_snapshot_hash_or_semantic_pair_crosses_split() -> None:
    corpus = _corpus()
    identities: dict[str, dict[str, set[str]]] = {
        name: {}
        for name in ("dependency", "family", "snapshot", "hash", "semantic_pair")
    }
    for question in corpus.questions:
        for name, identity in (
            ("dependency", question.dependency_id),
            ("family", question.source_family_id),
            ("semantic_pair", question.semantic_pair_id),
        ):
            identities[name].setdefault(identity, set()).add(question.split)
        for source in question.source_states:
            identities["snapshot"].setdefault(source.source_id, set()).add(
                question.split
            )
            identities["hash"].setdefault(source.source_sha256, set()).add(
                question.split
            )
    assert all(
        len(splits) == 1
        for mapping in identities.values()
        for splits in mapping.values()
    )

    payload = corpus.model_dump(mode="json")
    dependency_counts = Counter(item["dependency_id"] for item in payload["questions"])
    dependency = next(key for key, count in dependency_counts.items() if count > 1)
    related = [
        item for item in payload["questions"] if item["dependency_id"] == dependency
    ]
    related[0]["split"] = "validation" if related[0]["split"] == "dev" else "dev"
    _rehash_question(related[0])
    _rehash_corpus(payload)
    with pytest.raises(ValidationError, match="crosses dev/validation"):
        DiverseCorpusV4.model_validate_json(json.dumps(payload))


def test_semantic_source_component_duplicate_is_rejected() -> None:
    corpus = _corpus()
    payload = corpus.model_dump(mode="json")
    original = next(
        item
        for item in payload["questions"]
        if item["review_status"] == "manager_audit_pending"
        and item["outcome_type"] != "abstain"
    )
    duplicate = json.loads(json.dumps(original))
    duplicate["case_id"] = f"{original['case_id']}-forged-duplicate"
    duplicate["question"] = f"Duplicate wording: {original['question']}"
    duplicate["semantic_pair_id"] = f"semantic:{duplicate['case_id']}"
    _rehash_question(duplicate)
    payload["questions"].append(duplicate)
    _rehash_corpus(payload)
    with pytest.raises(ValidationError, match="semantic source/component duplicate"):
        DiverseCorpusV4.model_validate_json(json.dumps(payload))

    payload = corpus.model_dump(mode="json")
    original = next(
        item for item in payload["questions"] if item["slice"] == "authority_divergence"
    )
    relabeled = json.loads(json.dumps(original))
    relabeled["case_id"] = f"{original['case_id']}-forged-synthesis"
    relabeled["question"] = f"Relabeled synthesis: {original['question']}"
    relabeled["slice"] = "multi_source_synthesis"
    relabeled["predicate"] = "source.multi_source_synthesis"
    relabeled["semantic_pair_id"] = f"semantic:{relabeled['case_id']}"
    for component in relabeled["expected_components"]:
        component["kind"] = "synthesis_fact"
        component["predicate"] = "source.multi_source_synthesis"
    _rehash_question(relabeled)
    payload["questions"].append(relabeled)
    _rehash_corpus(payload)
    with pytest.raises(ValidationError, match="semantic source/component duplicate"):
        DiverseCorpusV4.model_validate_json(json.dumps(payload))


def test_every_synthesis_component_needs_its_own_source_and_citations() -> None:
    for question in _corpus().questions:
        if question.slice != "multi_source_synthesis":
            continue
        evidence_source = {
            item.evidence_id: item.source_id for item in question.evidence
        }
        component_sources = [
            {
                evidence_source[evidence_id]
                for evidence_id in component.required_evidence_ids
            }
            for component in question.expected_components
        ]
        assert len(component_sources) >= 2
        assert len(set().union(*component_sources)) >= 2
        correct = _candidate_components(question)
        alias_map = _alias_map(question.case_id)
        assert grade_v4_outcome(
            question,
            components=correct,
            abstained=False,
            abstention_reason_code=None,
            span_alias_to_evidence_id=alias_map,
        )
        assert not grade_v4_outcome(
            question,
            components=correct[:-1],
            abstained=False,
            abstention_reason_code=None,
            span_alias_to_evidence_id=alias_map,
        )


def test_structured_grader_is_semantic_exact_and_rejects_extras() -> None:
    question = next(
        item
        for item in _corpus().questions
        if item.case_id == "portfolio-diverse-temporal-23"
    )
    correct = _candidate_components(question)
    alias_map = _alias_map(question.case_id)
    assert grade_v4_outcome(
        question,
        components=correct,
        abstained=False,
        abstention_reason_code=None,
        span_alias_to_evidence_id=alias_map,
    )
    other_alias = next(
        alias
        for alias, evidence_id in alias_map.items()
        if evidence_id not in question.expected_components[0].required_evidence_ids
    )
    wrong_source = correct[0].model_copy(update={"cited_span_aliases": [other_alias]})
    assert not grade_v4_outcome(
        question,
        components=[wrong_source, *correct[1:]],
        abstained=False,
        abstention_reason_code=None,
        span_alias_to_evidence_id=alias_map,
    )
    extra = correct[0].model_copy(update={"value": "plausible unsupported prose"})
    assert not grade_v4_outcome(
        question,
        components=[*correct, extra],
        abstained=False,
        abstention_reason_code=None,
        span_alias_to_evidence_id=alias_map,
    )


def test_abstention_requires_explicit_correct_reason_and_no_claim() -> None:
    question = next(
        item
        for item in _corpus().questions
        if item.case_id == "portfolio-diverse-abstain-03"
    )
    alias_map = _alias_map(question.case_id)
    assert grade_v4_outcome(
        question,
        components=[],
        abstained=True,
        abstention_reason_code="insufficient_product_version_specificity",
        span_alias_to_evidence_id=alias_map,
    )
    assert not grade_v4_outcome(
        question,
        components=[],
        abstained=True,
        abstention_reason_code="predicate_absent",
        span_alias_to_evidence_id=alias_map,
    )
    assert not grade_v4_outcome(
        question,
        components=[],
        abstained=False,
        abstention_reason_code=None,
        span_alias_to_evidence_id=alias_map,
    )


def test_candidate_view_has_only_opaque_aliases_and_neutral_titles() -> None:
    index = PacketIndexV4.model_validate_json(INDEX.read_text(encoding="utf-8"))
    for packet in index.packets:
        metadata = {
            "packet_id": packet.packet_id,
            "case_id": packet.case_id,
            "documents": [
                {
                    "document_alias": item.document_alias,
                    "neutral_title": item.neutral_title,
                    "publisher_identity": item.publisher_identity,
                    "source_class": item.source_class,
                    "state_label": item.state_label,
                    "available_by_utc": item.available_by_utc.isoformat(),
                    "temporal_basis": item.temporal_basis,
                }
                for item in packet.documents
            ],
        }
        serialized = json.dumps(metadata)
        assert "http://" not in serialized and "https://" not in serialized
        assert "data/raw/" not in serialized
        for number, document in enumerate(packet.documents, start=1):
            assert document.document_alias.startswith("doc-")
            assert document.neutral_title == f"Evidence document {number:02d}"
            assert document.state_label == f"State {number:02d}"
            for span in document.evidence:
                assert span.span_alias.startswith("span-")
        bindings = index.evaluator_bindings[packet.packet_id]
        assert {item.document_alias for item in bindings} == {
            item.document_alias for item in packet.documents
        }
        assert {
            span.span_alias
            for document in packet.documents
            for span in document.evidence
        } == {span.span_alias for document in bindings for span in document.evidence}


def test_component_datatypes_and_alias_bijection_fail_closed() -> None:
    with pytest.raises(ValidationError, match="datatype/value mismatch"):
        CandidateComponent(
            kind="answer_value",
            predicate="source.temporal_change",
            datatype="mapping",
            value="not-a-mapping",
            authority_scope="test",
            cited_span_aliases=["span-deadbeef0000"],
        )
    question = next(
        item
        for item in _corpus().questions
        if item.case_id == "portfolio-diverse-temporal-23"
    )
    aliases = _alias_map(question.case_id)
    correct = _candidate_components(question)
    assert not grade_v4_outcome(
        question,
        components=correct,
        abstained=False,
        abstention_reason_code=None,
        span_alias_to_evidence_id={next(iter(aliases)): next(iter(aliases.values()))},
    )

    index_payload = json.loads(INDEX.read_text(encoding="utf-8"))
    packet_id = next(
        packet["packet_id"]
        for packet in index_payload["packets"]
        if sum(
            len(document["evidence"])
            for document in index_payload["evaluator_bindings"][packet["packet_id"]]
        )
        >= 2
    )
    evaluator_spans = [
        span
        for document in index_payload["evaluator_bindings"][packet_id]
        for span in document["evidence"]
    ]
    evaluator_spans[1]["span_alias"] = evaluator_spans[0]["span_alias"]
    with pytest.raises(ValidationError, match="span alias"):
        PacketIndexV4.model_validate_json(json.dumps(index_payload))

    string_set_question = next(
        item
        for item in _corpus().questions
        if any(
            component.datatype == "string_set" for component in item.expected_components
        )
        and item.outcome_type != "abstain"
    )
    set_components = _candidate_components(string_set_question)
    set_index = next(
        index
        for index, component in enumerate(set_components)
        if component.datatype == "string_set"
    )
    value = set_components[set_index].value
    assert isinstance(value, list)
    set_components[set_index] = set_components[set_index].model_copy(
        update={"value": list(reversed(value))}
    )
    assert grade_v4_outcome(
        string_set_question,
        components=set_components,
        abstained=False,
        abstention_reason_code=None,
        span_alias_to_evidence_id=_alias_map(string_set_question.case_id),
    )


def test_answerable_question_rejects_post_cutoff_required_evidence() -> None:
    corpus = _corpus()
    payload = corpus.model_dump(mode="json")
    question = next(
        item
        for item in payload["questions"]
        if item["outcome_type"] != "abstain" and item["evidence"]
    )
    required = set(question["required_evidence_ids"])
    target = next(
        item for item in question["evidence"] if item["evidence_id"] in required
    )
    target["source_available_by_utc"] = "2099-01-01T00:00:00Z"
    _rehash_question(question)
    _rehash_corpus(payload)
    with pytest.raises(ValidationError, match="post-cutoff"):
        DiverseCorpusV4.model_validate_json(json.dumps(payload))


def test_derivation_recipes_reject_mutated_inputs_and_forged_output(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    assert "absent" in verify_absence(b"old state", needle="new-token", label="x")
    with pytest.raises(ValueError, match="absence invariant"):
        verify_absence(b"old state new-token", needle="new-token", label="x")

    nvd = b"<html><title>NVD - CVE-2024-3400</title><body>old CPE state</body></html>"
    assert "absent_from_nvd_history_text" in verify_nvd_history_absence(
        nvd, needle="10.2.2:h5", label="PAN-OS"
    )
    with pytest.raises(ValueError, match="NVD history absence invariant"):
        verify_nvd_history_absence(
            nvd.replace(b"old CPE state", b"10.2.2:h5"),
            needle="10.2.2:h5",
            label="PAN-OS",
        )

    kev = json.dumps(
        {"catalogVersion": "1", "vulnerabilities": [{"cveID": "CVE-OTHER"}]}
    ).encode()
    assert "absent_from_cisa_kev_membership" in verify_kev_membership_absence(
        kev, cve_id="CVE-2021-27137"
    )
    with pytest.raises(ValueError, match="CISA KEV absence invariant"):
        verify_kev_membership_absence(
            kev.replace(b"CVE-OTHER", b"CVE-2021-27137"),
            cve_id="CVE-2021-27137",
        )

    curl = b"Affected versions: libcurl 7.69.0 to and including 8.3.0 Not affected versions: libcurl &lt; 7.69.0 and >= 8.4.0"
    assert '"not_affected_before":"7.69.0"' in derive_curl_boundary(curl)
    with pytest.raises(ValueError, match="curl boundary"):
        derive_curl_boundary(curl.replace(b"8.4.0", b"8.5.0"))

    tomcat = b'<a id="Fixed_in_Apache_Tomcat_9.0.83"></a> CVE-2023-46589 Affects: 9.0.0-M1 to 9.0.82'
    assert "9.0.83" in derive_tomcat_affected_fixed(tomcat)
    with pytest.raises(ValueError, match="Tomcat range/fix"):
        derive_tomcat_affected_fixed(tomcat.replace(b"9.0.82", b"9.0.81"))

    table = b"""<tr><td>Affected Products</td><td>Patched Versions</td></tr>
<tr><td>X1S PRO</td><td>2.5.38</td></tr><tr><td>X1 PRO OMNI</td><td>2.5.38</td></tr>
<tr><td>X1 OMNI</td><td>2.4.45</td></tr><tr><td>X1 TURBO</td><td>2.4.45</td></tr>
<tr><td>T10 Series</td><td>1.11.0</td></tr><tr><td>T20 Series</td><td>1.25.0</td></tr>
<tr><td>T30 Series</td><td>1.100.0</td></tr>"""
    assert "T30 Series" in derive_ecovacs_version_table(table)
    with pytest.raises(ValueError, match="ECOVACS version-table"):
        derive_ecovacs_version_table(table.replace(b"1.100.0", b"1.99.0"))

    class _Page:
        def extract_text(self) -> str:
            return "Activate authentication. Restrict network access. Deactivate Node-RED if not needed."

    class _Reader:
        def __init__(self, _: object) -> None:
            self.pages = [_Page()]

    monkeypatch.setattr("pypdf.PdfReader", _Reader)
    assert "disable_node_red_if_unused" in derive_kunbus_remediation(b"fake")
    monkeypatch.setattr(_Page, "extract_text", lambda _: "Activate authentication")
    with pytest.raises(ValueError, match="KUNBUS PDF invariant"):
        derive_kunbus_remediation(b"fake")

    kubernetes = b"""<p>Fixed Versions</p><ul><li>kubelet v1.28.4</li><li>kubelet v1.27.8</li><li>kubelet v1.26.11</li><li>kubelet v1.25.16</li></ul>"""
    assert "kubelet v1.28.4" in derive_kubernetes_fixed_versions(kubernetes)
    with pytest.raises(ValueError, match="Kubernetes fixed-version"):
        derive_kubernetes_fixed_versions(
            kubernetes.replace(b"kubelet v1.28.4", b"kubelet v1.28.5")
        )

    nvd_score = json.dumps(
        {
            "vulnerabilities": [
                {
                    "cve": {
                        "metrics": {
                            "cvssMetricV31": [
                                {
                                    "source": "nvd@nist.gov",
                                    "cvssData": {
                                        "baseScore": 8.8,
                                        "vectorString": "CVSS:3.1/TEST",
                                    },
                                }
                            ]
                        }
                    }
                }
            ]
        }
    ).encode()
    assert '"base_score":8.8' in derive_nvd_primary_score(nvd_score)
    with pytest.raises(StopIteration):
        derive_nvd_primary_score(nvd_score.replace(b"nvd@nist.gov", b"cna@example.org"))

    kev_field = json.dumps(
        {"vulnerabilities": [{"cveID": "CVE-TEST", "requiredAction": "Apply updates."}]}
    ).encode()
    assert "Apply updates." in derive_kev_field(
        kev_field, cve_id="CVE-TEST", field="requiredAction"
    )
    with pytest.raises(KeyError):
        derive_kev_field(kev_field, cve_id="CVE-TEST", field="dueDate")

    cve_record = json.dumps(
        {"containers": {"cna": {"affected": [{"defaultStatus": "unaffected"}]}}}
    ).encode()
    assert derive_cve_default_status(cve_record) == "unaffected"
    with pytest.raises(KeyError):
        derive_cve_default_status(cve_record.replace(b"defaultStatus", b"status"))

    nvd_descriptions = json.dumps(
        {
            "cveChanges": [
                {
                    "change": {
                        "details": [
                            {
                                "type": "Description",
                                "action": "Added",
                                "newValue": "initial",
                            },
                            {
                                "type": "Description",
                                "action": "Changed",
                                "newValue": "changed",
                            },
                        ]
                    }
                }
            ]
        }
    ).encode()
    assert derive_nvd_description_states(nvd_descriptions) == ("initial", "changed")
    with pytest.raises(StopIteration):
        derive_nvd_description_states(
            nvd_descriptions.replace(b'"Changed"', b'"Added"')
        )

    corpus = _corpus()
    question = next(
        item
        for item in corpus.questions
        if any(
            record.recipe_id == "utf8-literal-absence"
            for record in item.derivation_records
        )
    )
    original_record = next(
        item
        for item in question.derivation_records
        if item.recipe_id == "utf8-literal-absence"
    )
    evidence = next(
        item
        for item in question.evidence
        if item.evidence_id == original_record.evidence_id
    )
    raw = b"old state"
    valid_text = verify_absence(raw, needle="new-token", label="x")
    record = DerivationRecord(
        record_id=original_record.record_id,
        evidence_id=evidence.evidence_id,
        recipe_id="utf8-literal-absence",
        recipe_version="v1",
        source_id=evidence.source_id,
        source_sha256=evidence.source_sha256,
        parameters={"needle": "new-token", "label": "x"},
        output_text=valid_text,
        output_sha256=hashlib.sha256(valid_text.encode()).hexdigest(),
    )
    forged_text = f"{valid_text} forged"
    forged = DerivationRecord(
        **{
            **record.model_dump(mode="python"),
            "output_text": forged_text,
            "output_sha256": hashlib.sha256(forged_text.encode()).hexdigest(),
        }
    )
    forged_evidence = DiverseEvidence.model_validate(
        {
            **evidence.model_dump(mode="python"),
            "exact_text": forged_text,
            "text_sha256": hashlib.sha256(forged_text.encode()).hexdigest(),
        }
    )
    with pytest.raises(ValueError, match="derivation output mismatch"):
        verify_derivation_record(forged_evidence, forged, raw)


def test_review_packet_hashes_bind_structured_labels_and_derivations() -> None:
    packet = ReviewPacketV4.model_validate_json(REVIEW.read_text(encoding="utf-8"))
    payload = packet.model_dump(mode="json")
    payload["items"][0]["expected_components"][0]["value"] = "forged"
    item = payload["items"][0]
    item_body = {key: value for key, value in item.items() if key != "item_sha256"}
    item["item_sha256"] = canonical_sha256(item_body)
    packet_body = {
        key: value for key, value in payload.items() if key != "packet_sha256"
    }
    payload["packet_sha256"] = canonical_sha256(packet_body)
    with pytest.raises(ValidationError, match="original-label hash mismatch"):
        ReviewPacketV4.model_validate_json(json.dumps(payload))


def test_review_cli_accepts_v4_packet_with_empty_append_only_log(
    tmp_path: Path,
) -> None:
    decisions = tmp_path / "decisions.jsonl"
    summary = tmp_path / "summary.md"
    decisions.write_text("", encoding="utf-8")
    assert (
        main(
            [
                "review",
                "validate",
                "--packet",
                str(REVIEW),
                "--decisions",
                str(decisions),
                "--summary",
                str(summary),
            ]
        )
        == 0
    )
    text = summary.read_text(encoding="utf-8")
    assert "- Items: 48" in text
    assert "- Active decisions: 0" in text
