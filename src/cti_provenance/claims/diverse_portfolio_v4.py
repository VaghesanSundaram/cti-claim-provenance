"""Additive V4 contracts for the manager-repaired diverse CTI corpus."""

from __future__ import annotations

import hashlib
import html
import io
import json
import re
from collections import Counter, defaultdict
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Literal, Self, cast

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    field_validator,
    model_validator,
)
from pydantic_core import to_jsonable_python

from cti_provenance.claims.diverse_portfolio import DiverseEvidence
from cti_provenance.claims.schema import PredicateName


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("timestamp must be UTC")
    return value.astimezone(UTC)


UtcDateTime = Annotated[datetime, AfterValidator(_utc)]
NonEmpty = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
QuestionSlice = Literal[
    "single_source_extraction",
    "temporal_comparison",
    "cutoff_or_insufficiency_abstention",
    "authority_divergence",
    "multi_source_synthesis",
]
ReasoningPredicate = (
    PredicateName
    | Literal[
        "source.temporal_change",
        "source.authority_divergence",
        "source.multi_source_synthesis",
    ]
)
ComponentKind = Literal[
    "answer_value",
    "old_value",
    "new_value",
    "delta_kind",
    "authority_fact",
    "synthesis_fact",
    "abstention_reason",
]
AbstentionReasonCode = Literal[
    "no_cutoff_eligible_state",
    "insufficient_product_version_specificity",
    "predicate_absent",
    "wrong_authority_for_predicate",
    "unresolved_authoritative_evidence",
]


def canonical_sha256(value: object) -> str:
    """Hash JSON-compatible values with the repository canonical encoding."""

    if isinstance(value, BaseModel):
        value = value.model_dump(mode="json")
    else:
        value = to_jsonable_python(value)
    return hashlib.sha256(
        json.dumps(
            value,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
    ).hexdigest()


def _validate_component_value(datatype: str, value: JsonValue) -> None:
    """Reject component values whose JSON shape disagrees with the contract."""

    valid = {
        "boolean": isinstance(value, bool),
        "string": isinstance(value, str),
        "decimal": isinstance(value, (int, float)) and not isinstance(value, bool),
        "string_set": (
            isinstance(value, list)
            and all(isinstance(item, str) for item in value)
            and len(value) == len(set(value))
        ),
        "mapping": isinstance(value, dict),
    }
    if not valid.get(datatype, False):
        raise ValueError(f"component datatype/value mismatch: {datatype}")


def _normalized_component_value(datatype: str, value: JsonValue) -> JsonValue:
    if datatype == "string_set":
        assert isinstance(value, list)
        return cast(JsonValue, sorted(item for item in value if isinstance(item, str)))
    return value


class ExpectedComponent(BaseModel):
    """One typed, independently gradable semantic answer component."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    component_id: NonEmpty
    kind: ComponentKind
    predicate: ReasoningPredicate
    datatype: Literal["boolean", "string", "decimal", "string_set", "mapping"]
    value: JsonValue
    authority_scope: NonEmpty
    required_evidence_ids: list[NonEmpty]

    @field_validator("required_evidence_ids")
    @classmethod
    def unique_evidence_ids(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("component evidence IDs must be unique")
        return values

    @model_validator(mode="after")
    def validate_datatype(self) -> Self:
        _validate_component_value(self.datatype, self.value)
        return self


class CandidateComponent(BaseModel):
    """One candidate-emitted structured component."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    kind: ComponentKind
    predicate: ReasoningPredicate
    datatype: Literal["boolean", "string", "decimal", "string_set", "mapping"]
    value: JsonValue
    authority_scope: NonEmpty
    cited_span_aliases: list[NonEmpty]

    @field_validator("cited_span_aliases")
    @classmethod
    def unique_citations(cls, values: list[str]) -> list[str]:
        if len(values) != len(set(values)):
            raise ValueError("component citations must be unique")
        return values

    @model_validator(mode="after")
    def validate_datatype(self) -> Self:
        _validate_component_value(self.datatype, self.value)
        return self


class SourceStateBinding(BaseModel):
    """Evaluator-side source identity used for split and provenance audits."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    source_id: NonEmpty
    source_sha256: Sha256
    lineage_id: NonEmpty


class DerivationRecord(BaseModel):
    """Executable derivation provenance for one non-literal evidence item."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    record_id: NonEmpty
    evidence_id: NonEmpty
    recipe_id: NonEmpty
    recipe_version: Literal["v1"]
    source_id: NonEmpty
    source_sha256: Sha256
    parameters: dict[NonEmpty, JsonValue]
    output_text: NonEmpty
    output_sha256: Sha256

    @model_validator(mode="after")
    def validate_output(self) -> Self:
        if hashlib.sha256(self.output_text.encode()).hexdigest() != self.output_sha256:
            raise ValueError("derivation output hash mismatch")
        return self


class DiverseQuestionV4(BaseModel):
    """One V4 semantic question with typed gold and complete source identity."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    case_id: NonEmpty
    predecessor_v3_case_id: NonEmpty
    slice: QuestionSlice
    source_family_id: NonEmpty
    dependency_id: NonEmpty
    semantic_pair_id: NonEmpty
    split: Literal["dev", "validation"]
    predicate: ReasoningPredicate
    answer_type: Literal["boolean", "string", "set", "qualified_statement"]
    outcome_type: Literal["positive", "negative", "no_change", "abstain"]
    cutoff_utc: UtcDateTime
    question: NonEmpty
    readable_reference_answer: str | bool | list[str] | None
    abstention_reason: str | None
    abstention_reason_code: AbstentionReasonCode | None
    expected_components: list[ExpectedComponent]
    evidence: list[DiverseEvidence]
    required_evidence_ids: list[NonEmpty]
    source_states: list[SourceStateBinding]
    derivation_records: list[DerivationRecord]
    authority_rationale: NonEmpty
    temporal_rationale: NonEmpty
    ambiguity_notes: NonEmpty
    leakage_audit: NonEmpty
    retained_v2_case_id: str | None = None
    retained_v2_case_sha256: Sha256 | None = None
    review_status: Literal["approved_v2", "manager_audit_pending"]
    question_sha256: Sha256

    @model_validator(mode="after")
    def validate_question(self) -> Self:
        evidence_ids = [item.evidence_id for item in self.evidence]
        if len(evidence_ids) != len(set(evidence_ids)):
            raise ValueError("evidence IDs must be unique")
        source_ids = [item.source_id for item in self.source_states]
        if len(source_ids) != len(set(source_ids)):
            raise ValueError("source snapshot IDs must be unique")
        source_hashes = {
            item.source_id: item.source_sha256 for item in self.source_states
        }
        if not {item.source_id for item in self.evidence}.issubset(source_ids):
            raise ValueError("evidence source missing from source_snapshot_ids")
        if any(
            source_hashes[item.source_id] != item.source_sha256
            for item in self.evidence
        ):
            raise ValueError("evidence source hash differs from source binding")
        derived_ids = {
            item.evidence_id
            for item in self.evidence
            if item.extraction_method == "deterministic_derivation"
        }
        record_ids = [item.record_id for item in self.derivation_records]
        record_evidence_ids = [item.evidence_id for item in self.derivation_records]
        if len(record_ids) != len(set(record_ids)):
            raise ValueError("derivation record IDs must be unique")
        if set(record_evidence_ids) != derived_ids or len(record_evidence_ids) != len(
            derived_ids
        ):
            raise ValueError("each deterministic evidence item needs one derivation")
        evidence_by_id = {item.evidence_id: item for item in self.evidence}
        for record in self.derivation_records:
            evidence = evidence_by_id[record.evidence_id]
            if (
                record.source_id != evidence.source_id
                or record.source_sha256 != evidence.source_sha256
                or record.output_text != evidence.exact_text
                or record.output_sha256 != evidence.text_sha256
            ):
                raise ValueError("derivation record does not bind its evidence")
        component_ids = [item.component_id for item in self.expected_components]
        if len(component_ids) != len(set(component_ids)):
            raise ValueError("component IDs must be unique")
        component_evidence = {
            evidence_id
            for component in self.expected_components
            for evidence_id in component.required_evidence_ids
        }
        if not component_evidence.issubset(evidence_ids):
            raise ValueError("component evidence is not present")
        if set(self.required_evidence_ids) != component_evidence:
            raise ValueError("question evidence must equal component evidence union")
        if self.outcome_type != "abstain" and any(
            evidence.evidence_id in component_evidence
            and evidence.source_available_by_utc > self.cutoff_utc
            for evidence in self.evidence
        ):
            raise ValueError("answerable component cites post-cutoff evidence")
        if self.outcome_type == "abstain":
            if (
                self.readable_reference_answer is not None
                or not self.abstention_reason
                or not self.abstention_reason_code
                or len(self.expected_components) != 1
                or self.expected_components[0].kind != "abstention_reason"
                or self.expected_components[0].value != self.abstention_reason_code
            ):
                raise ValueError("abstention requires one typed reason component")
        elif (
            self.readable_reference_answer is None
            or self.abstention_reason is not None
            or self.abstention_reason_code is not None
            or not self.expected_components
        ):
            raise ValueError("answerable questions require structured components")
        if self.slice == "temporal_comparison" and {
            "old_value",
            "new_value",
            "delta_kind",
        } - {item.kind for item in self.expected_components}:
            raise ValueError("temporal questions require old/new/delta components")
        if (
            self.slice == "authority_divergence"
            and sum(item.kind == "authority_fact" for item in self.expected_components)
            < 2
        ):
            raise ValueError("authority questions require at least two scoped facts")
        if self.slice == "multi_source_synthesis":
            synthesis = [
                item
                for item in self.expected_components
                if item.kind == "synthesis_fact"
            ]
            if len(synthesis) < 2:
                raise ValueError("synthesis requires at least two atomic facts")
            source_sets = [
                {
                    evidence.source_id
                    for evidence in self.evidence
                    if evidence.evidence_id in component.required_evidence_ids
                }
                for component in synthesis
            ]
            if len(set().union(*source_sets)) < 2 or any(
                not source_set for source_set in source_sets
            ):
                raise ValueError("synthesis components require multiple source states")
        body = self.model_dump(mode="json", exclude={"question_sha256"})
        if canonical_sha256(body) != self.question_sha256:
            raise ValueError("question hash mismatch")
        return self


def _semantic_signature(question: DiverseQuestionV4) -> str:
    evidence_sources = {
        item.evidence_id: (item.source_id, item.source_sha256)
        for item in question.evidence
    }
    return canonical_sha256(
        {
            "source_states": sorted(
                (item.source_id, item.source_sha256) for item in question.source_states
            ),
            "components": sorted(
                (
                    component.datatype,
                    canonical_sha256(
                        _normalized_component_value(component.datatype, component.value)
                    ),
                    sorted(
                        evidence_sources[evidence_id]
                        for evidence_id in component.required_evidence_ids
                    ),
                )
                for component in question.expected_components
            ),
        }
    )


class DiverseCorpusV4(BaseModel):
    """Manager-audit successor preserving V2 and V3 artifact identity."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["portfolio-diverse-draft-v4"]
    corpus_id: Literal["portfolio-diverse-v4-manager-audit-candidate"]
    predecessor_corpus_file_sha256: Sha256
    created_at_utc: UtcDateTime
    temporal_boundary: Literal[
        "publisher-declared version evidence is not independently observed history"
    ]
    questions: list[DiverseQuestionV4] = Field(min_length=64)
    corpus_sha256: Sha256

    @model_validator(mode="after")
    def validate_corpus(self) -> Self:
        ids = [question.case_id for question in self.questions]
        if len(ids) != len(set(ids)):
            raise ValueError("case IDs must be unique")
        if len({question.question for question in self.questions}) != len(ids):
            raise ValueError("question text must be unique")
        counts = Counter(question.slice for question in self.questions)
        slices: tuple[QuestionSlice, ...] = (
            "temporal_comparison",
            "cutoff_or_insufficiency_abstention",
            "authority_divergence",
            "multi_source_synthesis",
        )
        if counts["single_source_extraction"] != 16 or any(
            counts[slice_name] < 8 for slice_name in slices
        ):
            raise ValueError("V4 slice minimums are not satisfied")
        if sum(item.outcome_type == "abstain" for item in self.questions) != 8:
            raise ValueError("V4 requires exactly eight real abstentions")
        dependency_splits: dict[str, set[str]] = defaultdict(set)
        family_splits: dict[str, set[str]] = defaultdict(set)
        snapshot_splits: dict[str, set[str]] = defaultdict(set)
        source_hash_splits: dict[str, set[str]] = defaultdict(set)
        semantic_pair_splits: dict[str, set[str]] = defaultdict(set)
        for question in self.questions:
            dependency_splits[question.dependency_id].add(question.split)
            family_splits[question.source_family_id].add(question.split)
            semantic_pair_splits[question.semantic_pair_id].add(question.split)
            for source in question.source_states:
                snapshot_splits[source.source_id].add(question.split)
                source_hash_splits[source.source_sha256].add(question.split)
        split_maps = {
            "dependency family": dependency_splits,
            "source family": family_splits,
            "source snapshot": snapshot_splits,
            "source hash": source_hash_splits,
            "semantic pair": semantic_pair_splits,
        }
        for identity, split_map in split_maps.items():
            if any(len(splits) != 1 for splits in split_map.values()):
                raise ValueError(f"{identity} crosses dev/validation")
        new_questions = [
            item for item in self.questions if item.review_status != "approved_v2"
        ]
        signatures = [_semantic_signature(item) for item in new_questions]
        if len(signatures) != len(set(signatures)):
            raise ValueError("semantic source/component duplicate detected")
        body = self.model_dump(mode="json", exclude={"corpus_sha256"})
        if canonical_sha256(body) != self.corpus_sha256:
            raise ValueError("corpus hash mismatch")
        return self


def load_diverse_corpus_v4(path: Path) -> DiverseCorpusV4:
    """Load the strict V4 manager-audit candidate."""

    return DiverseCorpusV4.model_validate_json(path.read_text(encoding="utf-8"))


def grade_v4_outcome(
    question: DiverseQuestionV4,
    *,
    components: list[CandidateComponent],
    abstained: bool,
    abstention_reason_code: str | None,
    span_alias_to_evidence_id: dict[str, str],
    compare_authority_scope: bool = True,
) -> bool:
    """Grade typed semantic components plus their necessary citations."""

    evidence_ids = {item.evidence_id for item in question.evidence}
    if (
        len(span_alias_to_evidence_id) != len(set(span_alias_to_evidence_id.values()))
        or set(span_alias_to_evidence_id.values()) != evidence_ids
    ):
        return False

    if question.outcome_type == "abstain":
        return (
            abstained
            and abstention_reason_code == question.abstention_reason_code
            and not components
        )
    if abstained or abstention_reason_code is not None:
        return False
    expected = {
        (
            item.kind,
            item.predicate,
            item.datatype,
            item.authority_scope if compare_authority_scope else None,
            canonical_sha256(_normalized_component_value(item.datatype, item.value)),
            frozenset(item.required_evidence_ids),
        )
        for item in question.expected_components
    }
    try:
        actual = {
            (
                item.kind,
                item.predicate,
                item.datatype,
                item.authority_scope if compare_authority_scope else None,
                canonical_sha256(
                    _normalized_component_value(item.datatype, item.value)
                ),
                frozenset(
                    span_alias_to_evidence_id[alias]
                    for alias in item.cited_span_aliases
                ),
            )
            for item in components
        }
    except KeyError:
        return False
    return len(actual) == len(components) and actual == expected


def verify_absence(raw: bytes, *, needle: str, label: str) -> str:
    """Fail closed unless a named UTF-8 token is absent from exact source bytes."""

    text = raw.decode("utf-8", errors="strict")
    if needle in text:
        raise ValueError(f"absence invariant failed for {label}: {needle!r}")
    return json.dumps(
        {"assertion": "absent", "label": label, "needle": needle},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def verify_nvd_history_absence(raw: bytes, *, needle: str, label: str) -> str:
    """Parse NVD history HTML text and assert the target is absent."""

    decoded = raw.decode("utf-8", errors="strict")
    title = re.search(r"<title>\s*NVD - (CVE-[0-9-]+)\s*</title>", decoded)
    if not title:
        raise ValueError("NVD history document identity missing")
    visible = html.unescape(re.sub(r"<[^>]+>", " ", decoded))
    if needle in visible:
        raise ValueError(f"NVD history absence invariant failed for {label}")
    return json.dumps(
        {
            "assertion": "absent_from_nvd_history_text",
            "cve_id": title.group(1),
            "label": label,
            "needle": needle,
        },
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def verify_kev_membership_absence(raw: bytes, *, cve_id: str) -> str:
    """Parse a CISA KEV JSON catalog and assert one CVE is not a member."""

    payload = json.loads(raw)
    identifiers = {item["cveID"] for item in payload["vulnerabilities"]}
    if cve_id in identifiers:
        raise ValueError(f"CISA KEV absence invariant failed for {cve_id}")
    return json.dumps(
        {
            "assertion": "absent_from_cisa_kev_membership",
            "catalog_version": payload["catalogVersion"],
            "cve_id": cve_id,
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def derive_curl_boundary(raw: bytes) -> str:
    """Extract curl's affected and not-affected boundary from its advisory HTML."""

    text = html.unescape(re.sub(r"<[^>]+>", " ", raw.decode("utf-8")))
    text = " ".join(text.split())
    affected = re.search(
        r"Affected versions: libcurl (7\.69\.0) to and including (8\.3\.0)", text
    )
    unaffected = re.search(
        r"Not affected versions: libcurl < (7\.69\.0) and >= (8\.4\.0)", text
    )
    if not affected or not unaffected or affected.group(1) != unaffected.group(1):
        raise ValueError("curl boundary invariant failed")
    return json.dumps(
        {
            "affected_from": affected.group(1),
            "affected_through": affected.group(2),
            "not_affected_before": unaffected.group(1),
            "not_affected_from": unaffected.group(2),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def derive_tomcat_affected_fixed(raw: bytes) -> str:
    """Extract CVE-2023-46589 range/fix from its anchored Tomcat section."""

    text = raw.decode("utf-8")
    match = re.search(
        r'id="Fixed_in_Apache_Tomcat_(9\.0\.83)".*?CVE-2023-46589.*?'
        r"Affects:\s*(9\.0\.0-M1)\s+to\s+(9\.0\.82)",
        text,
        flags=re.DOTALL,
    )
    if not match:
        raise ValueError("Tomcat range/fix invariant failed")
    return json.dumps(
        {
            "affected_from": match.group(2),
            "affected_through": match.group(3),
            "fixed": match.group(1),
        },
        sort_keys=True,
        separators=(",", ":"),
    )


def derive_ecovacs_version_table(raw: bytes) -> str:
    """Extract the complete seven-row product/version table from ECOVACS HTML."""

    text = raw.decode("utf-8")
    rows = re.findall(
        r"<tr[^>]*>\s*<td[^>]*>([^<]+)</td>\s*<td[^>]*>([^<]+)</td>\s*</tr>",
        text,
        flags=re.IGNORECASE,
    )
    expected = [
        ["X1S PRO", "2.5.38"],
        ["X1 PRO OMNI", "2.5.38"],
        ["X1 OMNI", "2.4.45"],
        ["X1 TURBO", "2.4.45"],
        ["T10 Series", "1.11.0"],
        ["T20 Series", "1.25.0"],
        ["T30 Series", "1.100.0"],
    ]
    normalized = [[html.unescape(a).strip(), html.unescape(b).strip()] for a, b in rows]
    normalized = [
        row for row in normalized if row != ["Affected Products", "Patched Versions"]
    ]
    if normalized != expected:
        raise ValueError(f"ECOVACS version-table invariant failed: {normalized!r}")
    return json.dumps(expected, ensure_ascii=False, separators=(",", ":"))


def derive_kunbus_remediation(raw: bytes) -> str:
    """Extract three required remediation actions from the pinned KUNBUS PDF."""

    from pypdf import PdfReader

    text = "\n".join(
        page.extract_text() or "" for page in PdfReader(io.BytesIO(raw)).pages
    )
    normalized = " ".join(text.split()).casefold()
    checks = {
        "enable_node_red_authentication": "activate authentication",
        "restrict_network_access": "restrict network access",
        "disable_node_red_if_unused": "deactivate node-red if not needed",
    }
    for action, exact_phrase in checks.items():
        if exact_phrase not in normalized:
            raise ValueError(f"KUNBUS PDF invariant failed for {action}")
    return json.dumps(sorted(checks), separators=(",", ":"))


def derive_kubernetes_fixed_versions(raw: bytes) -> str:
    """Extract Kubernetes' predicate-bearing fixed-version list."""

    visible = " ".join(
        html.unescape(re.sub(r"<[^>]+>", " ", raw.decode("utf-8"))).split()
    )
    match = re.search(
        r"Fixed Versions\s+(kubelet v1\.28\.4)\s+(kubelet v1\.27\.8)\s+"
        r"(kubelet v1\.26\.11)\s+(kubelet v1\.25\.16)",
        visible,
    )
    if not match:
        raise ValueError("Kubernetes fixed-version invariant failed")
    return json.dumps(
        {"fixed_versions": list(match.groups())},
        sort_keys=True,
        separators=(",", ":"),
    )


def derive_nvd_primary_score(raw: bytes) -> str:
    """Extract NVD's own CVSS v3.1 score and vector."""

    payload = json.loads(raw)
    metrics = payload["vulnerabilities"][0]["cve"]["metrics"]["cvssMetricV31"]
    metric = next(item for item in metrics if item["source"] == "nvd@nist.gov")
    data = metric["cvssData"]
    return json.dumps(
        {"base_score": data["baseScore"], "vector": data["vectorString"]},
        sort_keys=True,
        separators=(",", ":"),
    )


def derive_kev_field(raw: bytes, *, cve_id: str, field: str) -> str:
    """Extract one named field from one CISA KEV entry."""

    payload = json.loads(raw)
    entry = next(item for item in payload["vulnerabilities"] if item["cveID"] == cve_id)
    return json.dumps(
        {"cve_id": cve_id, "field": field, "value": entry[field]},
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def derive_cve_default_status(raw: bytes) -> str:
    """Extract the CNA affected container's default status."""

    payload = json.loads(raw)
    return str(payload["containers"]["cna"]["affected"][0]["defaultStatus"])


def derive_nvd_description_states(raw: bytes) -> tuple[str, str]:
    """Extract the first added and first changed NVD description values."""

    payload = json.loads(raw)
    details = [
        detail
        for event in payload["cveChanges"]
        for detail in event["change"]["details"]
        if detail["type"] == "Description" and detail["action"] in {"Added", "Changed"}
    ]
    initial = next(item["newValue"] for item in details if item["action"] == "Added")
    changed = next(item["newValue"] for item in details if item["action"] == "Changed")
    return initial, changed


def verify_derivation_record(
    evidence: DiverseEvidence, record: DerivationRecord, raw: bytes
) -> None:
    """Re-execute one narrow recipe and reject asserted or forged output."""

    parameters = record.parameters
    if record.recipe_id == "utf8-literal-absence":
        output = verify_absence(
            raw,
            needle=str(parameters["needle"]),
            label=str(parameters["label"]),
        )
    elif record.recipe_id == "nvd-history-visible-text-absence":
        output = verify_nvd_history_absence(
            raw,
            needle=str(parameters["needle"]),
            label=str(parameters["label"]),
        )
    elif record.recipe_id == "cisa-kev-membership-absence":
        output = verify_kev_membership_absence(raw, cve_id=str(parameters["cve_id"]))
    elif record.recipe_id == "git-cve-range-absence":
        needles = parameters["needles"]
        if not isinstance(needles, list):
            raise ValueError("Git absence recipe needs a needle list")
        output = json.dumps(
            [
                json.loads(
                    verify_absence(raw, needle=str(needle), label=f"Git {needle}")
                )
                for needle in needles
            ],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    elif record.recipe_id == "guralp-production-release-absence":
        needles = parameters["needles"]
        if not isinstance(needles, list):
            raise ValueError("Güralp absence recipe needs a needle list")
        outputs = [
            json.loads(
                verify_absence(raw, needle=str(needle), label=f"Güralp {needle}")
            )
            for needle in needles
        ]
        output = json.dumps(
            outputs,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
    elif record.recipe_id == "curl-affected-boundary":
        output = derive_curl_boundary(raw)
    elif record.recipe_id == "ecovacs-version-table":
        output = derive_ecovacs_version_table(raw)
    elif record.recipe_id == "kunbus-pdf-remediation":
        output = derive_kunbus_remediation(raw)
    elif record.recipe_id == "kubernetes-fixed-versions":
        output = derive_kubernetes_fixed_versions(raw)
    elif record.recipe_id == "nvd-primary-cvss":
        output = derive_nvd_primary_score(raw)
    elif record.recipe_id == "cisa-kev-field":
        output = derive_kev_field(
            raw,
            cve_id=str(parameters["cve_id"]),
            field=str(parameters["field"]),
        )
    elif record.recipe_id == "cve-cna-default-status":
        output = derive_cve_default_status(raw)
    elif record.recipe_id == "nvd-description-history-values":
        output = derive_nvd_description_states(raw)[int(str(parameters["ordinal"]))]
    else:
        raise ValueError(f"unknown derivation recipe: {record.recipe_id}")
    if output != record.output_text or output != evidence.exact_text:
        raise ValueError(f"derivation output mismatch: {record.record_id}")


class CandidateEvidenceSpanV4(BaseModel):
    """Opaque candidate-visible span identifier and authentic evidence text."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    span_alias: Annotated[str, StringConstraints(pattern=r"^span-[0-9a-f]{12}$")]
    text: NonEmpty


class CandidateDocumentV4(BaseModel):
    """Neutral candidate-visible document with opaque identifiers."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    document_alias: Annotated[str, StringConstraints(pattern=r"^doc-[0-9a-f]{12}$")]
    neutral_title: Annotated[
        str, StringConstraints(pattern=r"^Evidence document [0-9]{2}$")
    ]
    state_label: Annotated[str, StringConstraints(pattern=r"^State [0-9]{2}$")]
    available_by_utc: UtcDateTime
    temporal_basis: Literal[
        "publisher_declared_version",
        "observed_retrieval",
        "publisher_timestamp_with_observation",
    ]
    publisher_identity: NonEmpty
    source_class: Literal["government", "standards_body", "vendor"]
    evidence: list[CandidateEvidenceSpanV4]

    @model_validator(mode="after")
    def validate_evidence_aliases(self) -> Self:
        aliases = [item.span_alias for item in self.evidence]
        if len(aliases) != len(set(aliases)):
            raise ValueError("candidate span aliases must be unique")
        return self


class EvaluatorEvidenceBindingV4(BaseModel):
    """Evaluator-only binding from a span alias to provenance evidence."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    span_alias: Annotated[str, StringConstraints(pattern=r"^span-[0-9a-f]{12}$")]
    evidence_id: NonEmpty
    locator: NonEmpty


class EvaluatorDocumentBindingV4(BaseModel):
    """Evaluator-only mapping from an opaque alias to full provenance."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    document_alias: Annotated[str, StringConstraints(pattern=r"^doc-[0-9a-f]{12}$")]
    source_id: NonEmpty
    source_sha256: Sha256
    title: NonEmpty
    url: NonEmpty
    local_reference: NonEmpty
    evidence: list[EvaluatorEvidenceBindingV4]


class CandidatePacketV4(BaseModel):
    """Candidate-visible clean packet separated from evaluator provenance."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    packet_id: NonEmpty
    case_id: NonEmpty
    question: NonEmpty
    cutoff_utc: UtcDateTime
    documents: list[CandidateDocumentV4]
    packet_sha256: Sha256

    @model_validator(mode="after")
    def validate_packet(self) -> Self:
        aliases = [item.document_alias for item in self.documents]
        if len(aliases) != len(set(aliases)):
            raise ValueError("candidate aliases must be unique")
        span_aliases = [
            span.span_alias for document in self.documents for span in document.evidence
        ]
        if len(span_aliases) != len(set(span_aliases)):
            raise ValueError("candidate packet span aliases must be unique")
        body = self.model_dump(mode="json", exclude={"packet_sha256"})
        if canonical_sha256(body) != self.packet_sha256:
            raise ValueError("candidate packet hash mismatch")
        return self


class PacketIndexV4(BaseModel):
    """Candidate packets plus evaluator-only alias/provenance bindings."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["portfolio-diverse-packets-v4"]
    corpus_sha256: Sha256
    packets: list[CandidatePacketV4]
    evaluator_bindings: dict[NonEmpty, list[EvaluatorDocumentBindingV4]]
    index_sha256: Sha256

    @model_validator(mode="after")
    def validate_index(self) -> Self:
        packet_ids = [item.packet_id for item in self.packets]
        if len(packet_ids) != len(set(packet_ids)):
            raise ValueError("packet IDs must be unique")
        if set(self.evaluator_bindings) != set(packet_ids):
            raise ValueError("each packet requires evaluator bindings")
        for packet in self.packets:
            candidate_aliases = {item.document_alias for item in packet.documents}
            evaluator_aliases = {
                item.document_alias
                for item in self.evaluator_bindings[packet.packet_id]
            }
            if candidate_aliases != evaluator_aliases:
                raise ValueError("candidate/evaluator alias mismatch")
            candidate_span_aliases = {
                span.span_alias
                for document in packet.documents
                for span in document.evidence
            }
            evaluator_span_alias_list = [
                span.span_alias
                for document in self.evaluator_bindings[packet.packet_id]
                for span in document.evidence
            ]
            evaluator_span_aliases = set(evaluator_span_alias_list)
            evaluator_evidence_ids = [
                span.evidence_id
                for document in self.evaluator_bindings[packet.packet_id]
                for span in document.evidence
            ]
            if candidate_span_aliases != evaluator_span_aliases:
                raise ValueError("candidate/evaluator span alias mismatch")
            if len(evaluator_span_alias_list) != len(evaluator_span_aliases):
                raise ValueError("evaluator span aliases must be one-to-one")
            if len(evaluator_evidence_ids) != len(set(evaluator_evidence_ids)):
                raise ValueError("evaluator evidence bindings must be one-to-one")
        body = self.model_dump(mode="json", exclude={"index_sha256"})
        if canonical_sha256(body) != self.index_sha256:
            raise ValueError("packet index hash mismatch")
        return self


class ReviewItemV4(BaseModel):
    """Reviewer-facing V4 label with structured gold and readable context."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    item_id: NonEmpty
    item_sha256: Sha256
    case_id: NonEmpty
    question_sha256: Sha256
    evidence_binding_sha256: Sha256
    original_label_sha256: Sha256
    question: NonEmpty
    cutoff_utc: UtcDateTime
    slice: QuestionSlice
    expected_components: list[ExpectedComponent]
    readable_reference_answer: str | bool | list[str] | None
    abstention_reason_code: AbstentionReasonCode | None
    abstention_rationale: str | None
    source_states: list[SourceStateBinding]
    evidence: list[DiverseEvidence]
    derivation_records: list[DerivationRecord]
    authority_rationale: NonEmpty
    temporal_rationale: NonEmpty
    ambiguity_notes: NonEmpty

    @model_validator(mode="after")
    def validate_item(self) -> Self:
        evidence_binding = {
            "question_sha256": self.question_sha256,
            "sources": [item.model_dump(mode="json") for item in self.source_states],
            "evidence": [
                {
                    "evidence_id": item.evidence_id,
                    "source_id": item.source_id,
                    "source_sha256": item.source_sha256,
                    "text_sha256": item.text_sha256,
                }
                for item in self.evidence
            ],
        }
        if canonical_sha256(evidence_binding) != self.evidence_binding_sha256:
            raise ValueError("review evidence binding mismatch")
        original_label = {
            "expected_components": [
                item.model_dump(mode="json") for item in self.expected_components
            ],
            "readable_reference_answer": self.readable_reference_answer,
            "abstention_reason_code": self.abstention_reason_code,
            "abstention_rationale": self.abstention_rationale,
        }
        if canonical_sha256(original_label) != self.original_label_sha256:
            raise ValueError("review original-label hash mismatch")
        body = self.model_dump(mode="json", exclude={"item_sha256"})
        if canonical_sha256(body) != self.item_sha256:
            raise ValueError("review item hash mismatch")
        return self


class ReviewPacketV4(BaseModel):
    """Manager-audit-only packet; it is not open for human review yet."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["review-packet-v2"]
    packet_id: Literal["portfolio-diverse-review-v4-manager-audit-candidate"]
    corpus_sha256: Sha256
    created_at_utc: UtcDateTime
    status: Literal["manager_audit_pending"]
    blinding_statement: Literal[
        "No model outputs, condition labels, pass/fail fields, or aggregates."
    ]
    items: list[ReviewItemV4] = Field(min_length=1)
    packet_sha256: Sha256

    @model_validator(mode="after")
    def validate_review_packet(self) -> Self:
        ids = [item.item_id for item in self.items]
        cases = [item.case_id for item in self.items]
        if len(ids) != len(set(ids)) or len(cases) != len(set(cases)):
            raise ValueError("review packet item and case IDs must be unique")
        body = self.model_dump(mode="json", exclude={"packet_sha256"})
        if canonical_sha256(body) != self.packet_sha256:
            raise ValueError("review packet hash mismatch")
        return self
