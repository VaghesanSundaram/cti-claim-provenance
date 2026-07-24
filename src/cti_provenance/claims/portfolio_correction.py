"""Explicit v2 successor overlay for one reviewed portfolio gold defect."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Annotated, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, StringConstraints

from cti_provenance.claims.portfolio_proof import (
    PortfolioProofError,
    _load_jsonl,
    _safe_bytes,
)
from cti_provenance.dataset import BenchmarkCase
from cti_provenance.grading.review_workflow import ReviewPacket
from cti_provenance.normalize import (
    FamilySpec,
    load_portfolio_family_config,
    load_portfolio_lineage_config,
)
from cti_provenance.snapshot import SnapshotState

OVERLAY_PATH = PurePosixPath("configs/portfolio-gold-correction-v2.yaml")
YIELD_SPEC_PATH = PurePosixPath("configs/portfolio-yield-families-v1.yaml")
SCALE_SPEC_PATH = PurePosixPath("configs/portfolio-scale-families-v1.yaml")
LINEAGE_PATH = PurePosixPath("configs/portfolio-family-lineage-v1.yaml")
YIELD_CASE_PATH = PurePosixPath("data/benchmark/dev/portfolio-yield-dev-cases.jsonl")
CHALLENGE_CASE_PATH = PurePosixPath(
    "data/benchmark/challenges/portfolio-challenge-cases-v1.jsonl"
)
REVIEW_PACKET_PATH = PurePosixPath(
    "annotations/packets/portfolio-dev-validation-review-v1.json"
)

_NON_EMPTY = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
_SHA256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class ReviewLogBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    path: _NON_EMPTY
    sha256: _SHA256


class SourceBinding(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    snapshot_id: Literal["cisa-kev-2026-07-21-f17a5ced05e7"]
    raw_snapshot_sha256: Literal[
        "f17a5ced05e70c4abbc893bed7ffd52c8dd53ed4fb112c95380f8de53c5ba597"
    ]
    raw_locator: Literal["/vulnerabilities/3"]
    cve_id: Literal["CVE-2021-27137"]
    vendor_project: Literal["DD-WRT"]
    product: Literal["DD-WRT"]


class SemanticCorrection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    family_id: Literal["cisa-kev-cve-2021-27137"]
    base_case_id: Literal["portfolio-yield-cisa-kev-cve-2021-27137"]
    predicate: Literal["kev.is_member"]
    qualifier: Literal["product"]
    old_value: Literal["Accellion FTA"]
    new_value: Literal["DD-WRT"]
    old_incident_campaign_lineage: Literal["cve-2021-27137-accellion-fta"]
    new_incident_campaign_lineage: Literal["cve-2021-27137-dd-wrt"]
    old_vendor_product_lineage: Literal["accellion-fta-cve-2021-27137"]
    new_vendor_product_lineage: Literal["dd-wrt-cve-2021-27137"]


class PortfolioGoldCorrection(BaseModel):
    """Closed correction contract; it cannot describe arbitrary mutations."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal["portfolio-gold-correction-v2"]
    correction_id: Literal["cisa-kev-cve-2021-27137-product-qualifier"]
    discovered_by_decision_id: Literal["66dae977-b2eb-4cdc-a305-cfc90630a7ef"]
    superseded_decision_id: Literal["a91b0891-d337-4bbe-a1ce-83fde45ee8e7"]
    review_log: ReviewLogBinding
    frozen_v1_artifacts: dict[_NON_EMPTY, _SHA256] = Field(min_length=6)
    source_binding: SourceBinding
    correction: SemanticCorrection
    boundary: Literal[
        "Additive successor overlay only. Frozen v1 configs, cases, packets, "
        "reports, manifests, and decision predecessors remain unchanged."
    ]


def _sha256(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def load_portfolio_gold_correction(root: Path) -> PortfolioGoldCorrection:
    """Load the one authorized overlay and verify every frozen v1 binding."""

    resolved = root.resolve(strict=True)
    try:
        payload = yaml.safe_load(_safe_bytes(resolved, OVERLAY_PATH))
        overlay = PortfolioGoldCorrection.model_validate(payload)
    except (OSError, ValueError, yaml.YAMLError) as exc:
        raise PortfolioProofError(
            "portfolio gold correction overlay is invalid"
        ) from exc
    for path, expected in overlay.frozen_v1_artifacts.items():
        body = _safe_bytes(resolved, PurePosixPath(path))
        if _sha256(body) != expected:
            raise PortfolioProofError(f"frozen v1 artifact changed: {path}")
    review_body = _safe_bytes(resolved, PurePosixPath(overlay.review_log.path))
    if _sha256(review_body) != overlay.review_log.sha256:
        raise PortfolioProofError("portfolio reviewer log hash is invalid")
    _audit_frozen_defect(resolved, overlay)
    return overlay


def _audit_frozen_defect(root: Path, overlay: PortfolioGoldCorrection) -> None:
    correction = overlay.correction
    yield_specs = load_portfolio_family_config(
        root.joinpath(*YIELD_SPEC_PATH.parts)
    ).families
    scale_specs = load_portfolio_family_config(
        root.joinpath(*SCALE_SPEC_PATH.parts)
    ).families
    lineage = load_portfolio_lineage_config(root.joinpath(*LINEAGE_PATH.parts)).families
    for values in (yield_specs, scale_specs):
        target = [item for item in values if item.family_id == correction.family_id]
        if len(target) != 1:
            raise PortfolioProofError("frozen family config lacks the reviewed defect")
        _assert_old_spec(target[0], correction)
    lineage_target = [
        item for item in lineage if item.family_id == correction.family_id
    ]
    if (
        len(lineage_target) != 1
        or lineage_target[0].incident_campaign_lineage
        != correction.old_incident_campaign_lineage
        or lineage_target[0].vendor_product_lineage
        != correction.old_vendor_product_lineage
    ):
        raise PortfolioProofError("frozen lineage no longer matches reviewed defect")
    yield_cases = _load_jsonl(root, YIELD_CASE_PATH, BenchmarkCase)
    target_cases = [
        case for case in yield_cases if case.case_id == correction.base_case_id
    ]
    if len(target_cases) != 1:
        raise PortfolioProofError("frozen yield case lacks the reviewed defect")
    _assert_old_case(target_cases[0], correction)
    challenge_cases = _load_jsonl(root, CHALLENGE_CASE_PATH, BenchmarkCase)
    challenge_targets = [
        case
        for case in challenge_cases
        if case.case_id.startswith(f"{correction.base_case_id}-")
    ]
    if len(challenge_targets) != 3:
        raise PortfolioProofError("frozen challenge gold coverage is invalid")
    for case in challenge_targets:
        _assert_old_case(case, correction)
    packet = ReviewPacket.model_validate_json(
        _safe_bytes(root, REVIEW_PACKET_PATH).decode("utf-8")
    )
    packet_targets = [
        item
        for item in packet.items
        if item.original_label.expected_claim is not None
        and item.original_label.expected_claim.subject.id == "CVE-2021-27137"
    ]
    if (
        len(packet_targets) != 1
        or packet_targets[0].original_label.expected_claim is None
        or packet_targets[0].original_label.expected_claim.qualifiers.product
        != correction.old_value
    ):
        raise PortfolioProofError("frozen review packet no longer records the defect")


def _assert_old_spec(spec: FamilySpec, correction: SemanticCorrection) -> None:
    if (
        spec.claim.predicate != correction.predicate
        or spec.claim.product != correction.old_value
        or spec.incident_campaign_lineage != correction.old_incident_campaign_lineage
        or spec.vendor_product_lineage != correction.old_vendor_product_lineage
    ):
        raise PortfolioProofError("frozen family spec no longer records the defect")


def _assert_old_case(case: BenchmarkCase, correction: SemanticCorrection) -> None:
    if (
        len(case.expected_claims) != 1
        or case.expected_claims[0].predicate != correction.predicate
        or case.expected_claims[0].qualifiers.product != correction.old_value
    ):
        raise PortfolioProofError("frozen benchmark case no longer records the defect")


def apply_correction_to_specs(
    specs: list[FamilySpec], overlay: PortfolioGoldCorrection
) -> list[FamilySpec]:
    """Return the additive successor spec list with exactly one correction."""

    correction = overlay.correction
    corrected: list[FamilySpec] = []
    matches = 0
    for spec in specs:
        if spec.family_id != correction.family_id:
            corrected.append(spec)
            continue
        matches += 1
        _assert_old_spec(spec, correction)
        corrected.append(
            spec.model_copy(
                update={
                    "incident_campaign_lineage": (
                        correction.new_incident_campaign_lineage
                    ),
                    "vendor_product_lineage": correction.new_vendor_product_lineage,
                    "claim": spec.claim.model_copy(
                        update={"product": correction.new_value}
                    ),
                }
            )
        )
    if matches != 1:
        raise PortfolioProofError("correction must update exactly one family spec")
    return corrected


def apply_correction_to_cases(
    cases: list[BenchmarkCase], overlay: PortfolioGoldCorrection
) -> list[BenchmarkCase]:
    """Return active cases with the one reviewed qualifier corrected."""

    correction = overlay.correction
    corrected: list[BenchmarkCase] = []
    matches = 0
    for case in cases:
        if case.case_id != correction.base_case_id:
            corrected.append(case)
            continue
        matches += 1
        _assert_old_case(case, correction)
        claim = case.expected_claims[0]
        corrected.append(
            case.model_copy(
                update={
                    "expected_claims": [
                        claim.model_copy(
                            update={
                                "qualifiers": claim.qualifiers.model_copy(
                                    update={"product": correction.new_value}
                                )
                            }
                        )
                    ]
                }
            )
        )
    if matches != 1:
        raise PortfolioProofError("correction must update exactly one base case")
    return corrected


def verify_corrected_source(
    root: Path,
    states: list[SnapshotState],
    overlay: PortfolioGoldCorrection,
) -> None:
    """Verify DD-WRT directly from the hash-bound frozen CISA record."""

    binding = overlay.source_binding
    matches = [
        state for state in states if state.manifest.snapshot_id == binding.snapshot_id
    ]
    if len(matches) != 1:
        raise PortfolioProofError("corrected source snapshot is unavailable")
    manifest = matches[0].manifest
    raw = _safe_bytes(root.resolve(strict=True), PurePosixPath(manifest.raw_blob_path))
    if (
        manifest.sha256 != binding.raw_snapshot_sha256
        or _sha256(raw) != manifest.sha256
    ):
        raise PortfolioProofError("corrected source snapshot hash is invalid")
    try:
        record = json.loads(raw)["vulnerabilities"][3]
    except (IndexError, KeyError, TypeError, json.JSONDecodeError) as exc:
        raise PortfolioProofError("corrected source locator is invalid") from exc
    if (
        record.get("cveID") != binding.cve_id
        or record.get("vendorProject") != binding.vendor_project
        or record.get("product") != binding.product
    ):
        raise PortfolioProofError("corrected source fields do not match DD-WRT")
