"""Fail-closed, category-preserving Red Hat CSAF normalization."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast

from pydantic import JsonValue

from cti_provenance.ingest.nvd import SELECTED_CVE
from cti_provenance.ingest.vendor import RHSA_ID, RHSA_URL, parse_red_hat_bytes
from cti_provenance.normalize.common import EvidenceSpan, NormalizedDocument
from cti_provenance.normalize.spans import (
    create_span,
    verify_raw_round_trip,
)
from cti_provenance.snapshot import SnapshotManifest

NORMALIZATION_VERSION = "phase2-red-hat-v1"


@dataclass(frozen=True)
class _Product:
    product_id: str
    name: str
    id_pointer: str
    name_pointer: str


def _time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _add_product(products: dict[str, _Product], candidate: Any, pointer: str) -> None:
    if not isinstance(candidate, dict):
        raise ValueError("CSAF product mapping must be an object")
    product_id = candidate.get("product_id")
    name = candidate.get("name")
    if (
        not isinstance(product_id, str)
        or not product_id.strip()
        or not isinstance(name, str)
        or not name.strip()
        or product_id in products
    ):
        raise ValueError("CSAF product mapping is missing, empty, or duplicate")
    products[product_id] = _Product(
        product_id=product_id,
        name=name,
        id_pointer=f"{pointer}/product_id",
        name_pointer=f"{pointer}/name",
    )


def _walk_branches(products: dict[str, _Product], branches: Any, pointer: str) -> None:
    if not isinstance(branches, list):
        raise ValueError("CSAF product-tree branches must be a list")
    for index, branch in enumerate(branches):
        branch_pointer = f"{pointer}/{index}"
        if not isinstance(branch, dict):
            raise ValueError("CSAF product-tree branch must be an object")
        if "product" in branch:
            _add_product(
                products,
                branch["product"],
                f"{branch_pointer}/product",
            )
        if "branches" in branch:
            _walk_branches(
                products,
                branch["branches"],
                f"{branch_pointer}/branches",
            )


def _product_map(payload: dict[str, Any]) -> dict[str, _Product]:
    tree = payload.get("product_tree")
    if not isinstance(tree, dict):
        raise ValueError("CSAF product tree is missing")
    products: dict[str, _Product] = {}
    if "branches" in tree:
        _walk_branches(products, tree["branches"], "/product_tree/branches")
    relationships = tree.get("relationships", [])
    if not isinstance(relationships, list):
        raise ValueError("CSAF product relationships must be a list")
    for index, relationship in enumerate(relationships):
        if not isinstance(relationship, dict):
            raise ValueError("CSAF product relationship must be an object")
        if "full_product_name" in relationship:
            _add_product(
                products,
                relationship["full_product_name"],
                f"/product_tree/relationships/{index}/full_product_name",
            )
    dependency_graph: dict[str, set[str]] = {}
    for relationship in relationships:
        product_reference = relationship.get("product_reference")
        relates_to = relationship.get("relates_to_product_reference")
        full_product = relationship.get("full_product_name")
        full_product_id = (
            full_product.get("product_id") if isinstance(full_product, dict) else None
        )
        if (
            not isinstance(product_reference, str)
            or product_reference not in products
            or not isinstance(relates_to, str)
            or relates_to not in products
            or not isinstance(full_product_id, str)
            or full_product_id not in products
            or full_product_id in {product_reference, relates_to}
        ):
            raise ValueError("CSAF product relationship has a dangling endpoint")
        dependency_graph[full_product_id] = {product_reference, relates_to}

    def visit(product_id: str, active: set[str], finished: set[str]) -> None:
        if product_id in active:
            raise ValueError("CSAF product relationships contain a cycle")
        if product_id in finished:
            return
        active.add(product_id)
        for dependency in dependency_graph.get(product_id, set()):
            visit(dependency, active, finished)
        active.remove(product_id)
        finished.add(product_id)

    finished: set[str] = set()
    for product_id in dependency_graph:
        visit(product_id, set(), finished)
    if not products:
        raise ValueError("CSAF product tree has no direct product mappings")
    return products


def _status_map(
    product_status: Any, products: dict[str, _Product]
) -> dict[str, list[_Product]]:
    if not isinstance(product_status, dict) or not product_status:
        raise ValueError("CSAF product status is missing")
    resolved: dict[str, list[_Product]] = {}
    for category, identifiers in product_status.items():
        if (
            not isinstance(category, str)
            or not category
            or not isinstance(identifiers, list)
            or not identifiers
            or not all(isinstance(identifier, str) for identifier in identifiers)
            or len(identifiers) != len(set(identifiers))
        ):
            raise ValueError("CSAF product-status category is invalid")
        if any(identifier not in products for identifier in identifiers):
            raise ValueError("CSAF product status references an unknown product")
        resolved[category] = [products[identifier] for identifier in identifiers]
    fixed = {product.product_id for product in resolved.get("fixed", [])}
    affected = {product.product_id for product in resolved.get("known_affected", [])}
    not_affected = {
        product.product_id for product in resolved.get("known_not_affected", [])
    }
    if not fixed:
        raise ValueError("CSAF product status has no explicit fixed products")
    if fixed & affected or fixed & not_affected or affected & not_affected:
        raise ValueError("CSAF product has contradictory status categories")
    return resolved


def _validate_remediations(remediations: Any, products: dict[str, _Product]) -> None:
    if remediations is None:
        return
    if not isinstance(remediations, list):
        raise ValueError("CSAF remediations must be a list")
    for remediation in remediations:
        if not isinstance(remediation, dict):
            raise ValueError("CSAF remediation must be an object")
        identifiers = remediation.get("product_ids", [])
        if (
            not isinstance(identifiers, list)
            or not all(isinstance(identifier, str) for identifier in identifiers)
            or any(identifier not in products for identifier in identifiers)
        ):
            raise ValueError("CSAF remediation references an unknown product")


def _add_value(
    chunks: list[str],
    specs: list[tuple[str, str, int, int, str]],
    *,
    label: str,
    value: str,
    span_id: str,
    field_path: str,
    raw_pointer: str,
) -> None:
    prefix = f"{label}: "
    start = sum(len(chunk) for chunk in chunks) + len(prefix)
    chunks.append(f"{prefix}{value}\n")
    specs.append((span_id, field_path, start, start + len(value), raw_pointer))


def normalize_red_hat(
    raw: bytes, checksum_raw: bytes, manifest: SnapshotManifest
) -> list[NormalizedDocument]:
    if (
        manifest.source_name != "red_hat_rhsa"
        or manifest.source_class != "vendor"
        or str(manifest.source_url) != RHSA_URL
        or manifest.normalization_version != NORMALIZATION_VERSION
        or manifest.upstream_identifier != RHSA_ID
        or manifest.byte_length != len(raw)
        or manifest.sha256 != hashlib.sha256(raw).hexdigest()
    ):
        raise ValueError("manifest is not the Phase 2 Red Hat capture")
    payload = parse_red_hat_bytes(raw, checksum_raw)
    document = payload["document"]
    tracking = document["tracking"]
    vulnerability_index = next(
        index
        for index, value in enumerate(payload["vulnerabilities"])
        if value.get("cve") == SELECTED_CVE
    )
    vulnerability = payload["vulnerabilities"][vulnerability_index]
    products = _product_map(payload)
    statuses = _status_map(vulnerability.get("product_status"), products)
    _validate_remediations(vulnerability.get("remediations"), products)

    chunks: list[str] = []
    specs: list[tuple[str, str, int, int, str]] = []
    _add_value(
        chunks,
        specs,
        label="Advisory",
        value=RHSA_ID,
        span_id="rhsa-advisory",
        field_path="/advisory_id",
        raw_pointer="/document/tracking/id",
    )
    _add_value(
        chunks,
        specs,
        label="CVE",
        value=SELECTED_CVE,
        span_id="rhsa-cve",
        field_path="/cve_id",
        raw_pointer=f"/vulnerabilities/{vulnerability_index}/cve",
    )
    _add_value(
        chunks,
        specs,
        label="Current release",
        value=tracking["current_release_date"],
        span_id="rhsa-release",
        field_path="/current_release_date",
        raw_pointer="/document/tracking/current_release_date",
    )
    status_fields: dict[str, list[dict[str, str]]] = {}
    for category in sorted(statuses):
        status_fields[category] = []
        identifiers = vulnerability["product_status"][category]
        for index, product in enumerate(statuses[category]):
            status_fields[category].append(
                {"product_id": product.product_id, "product": product.name}
            )
            safe_category = category.replace("_", "-")
            _add_value(
                chunks,
                specs,
                label=f"{category} product id",
                value=product.product_id,
                span_id=f"rhsa-{safe_category}-{index}-id",
                field_path=f"/product_status/{category}/{index}/product_id",
                raw_pointer=(
                    f"/vulnerabilities/{vulnerability_index}/product_status/"
                    f"{category}/{index}"
                ),
            )
            _add_value(
                chunks,
                specs,
                label=f"{category} product",
                value=product.name,
                span_id=f"rhsa-{safe_category}-{index}-name",
                field_path=f"/product_status/{category}/{index}/product",
                raw_pointer=product.name_pointer,
            )
            if identifiers[index] != product.product_id:
                raise ValueError("CSAF status ordering changed during normalization")
    text = "".join(chunks).rstrip("\n")
    spans: list[EvidenceSpan] = [
        create_span(
            span_id=span_id,
            field_path=field_path,
            normalized_text=text,
            start_char=start,
            end_char=end,
            raw_locator=raw_pointer,
            raw_locator_unavailable_reason=None,
            raw_snapshot_id=manifest.snapshot_id,
            raw_snapshot_sha256=manifest.sha256,
            normalization_version=NORMALIZATION_VERSION,
        )
        for span_id, field_path, start, end, raw_pointer in specs
    ]
    for span in spans:
        verify_raw_round_trip(span, normalized_text=text, raw=raw)
    return [
        NormalizedDocument(
            document_id="red-hat-rhsa-2021-5133",
            snapshot_id=manifest.snapshot_id,
            upstream_entity_id=RHSA_ID,
            title=(
                document.get("title")
                if isinstance(document.get("title"), str)
                else RHSA_ID
            ),
            canonical_url=RHSA_URL,
            published_at=None,
            modified_at=_time(tracking["current_release_date"]),
            source_name="red_hat_rhsa",
            source_class="vendor",
            normalization_version=NORMALIZATION_VERSION,
            normalized_text=text,
            normalized_text_sha256=hashlib.sha256(text.encode()).hexdigest(),
            fields={
                "advisory_id": RHSA_ID,
                "cve_id": SELECTED_CVE,
                "revision_version": str(tracking["version"]),
                "product_status_by_category": cast(JsonValue, status_fields),
                "known_affected_products": cast(
                    JsonValue, status_fields.get("known_affected", [])
                ),
                "fixed_products": cast(JsonValue, status_fields["fixed"]),
            },
            spans=spans,
        )
    ]
