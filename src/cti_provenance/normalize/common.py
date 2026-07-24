"""Normalized document and exact evidence-span contracts."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Annotated, Literal, Self

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    JsonValue,
    StringConstraints,
    field_validator,
    model_validator,
)


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("timestamp must use the UTC offset")
    return value.astimezone(UTC)


UtcDateTime = Annotated[datetime, AfterValidator(_utc_datetime)]
NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
_SOURCE_CLASSES = {
    "cisa_directive": "government",
    "cve_program": "standards_body",
    "nvd": "government",
    "cisa_kev": "government",
    "mitre_attack": "standards_body",
    "netscaler_advisory": "vendor",
    "red_hat_rhsa": "vendor",
    "synthetic_control": "synthetic",
    "vendor_advisory": "vendor",
}


class EvidenceSpan(BaseModel):
    """Addressable normalized span with a mapping back to immutable raw data."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    span_id: NonEmptyString
    field_path: NonEmptyString
    start_char: int = Field(ge=0)
    end_char: int = Field(ge=0)
    text_sha256: Sha256
    raw_locator: str | None
    raw_locator_unavailable_reason: str | None
    raw_snapshot_id: NonEmptyString
    raw_snapshot_sha256: Sha256
    normalization_version: NonEmptyString

    @model_validator(mode="after")
    def validate_span(self) -> Self:
        if self.end_char <= self.start_char:
            raise ValueError("end_char must be greater than start_char")
        if (self.raw_locator is None) == (self.raw_locator_unavailable_reason is None):
            raise ValueError(
                "provide exactly one of raw_locator or raw_locator_unavailable_reason"
            )
        return self


class NormalizedDocument(BaseModel):
    """Deterministic derivative of exactly one immutable source snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    document_id: NonEmptyString
    snapshot_id: NonEmptyString
    upstream_entity_id: NonEmptyString
    title: str | None
    canonical_url: HttpUrl | Annotated[str, StringConstraints(pattern=r"^urn:")]
    published_at: UtcDateTime | None
    modified_at: UtcDateTime | None
    source_name: Literal[
        "cisa_directive",
        "cve_program",
        "nvd",
        "cisa_kev",
        "mitre_attack",
        "netscaler_advisory",
        "red_hat_rhsa",
        "synthetic_control",
        "vendor_advisory",
    ]
    source_class: Literal["government", "standards_body", "vendor", "synthetic"]
    normalization_version: NonEmptyString
    normalized_text: str
    normalized_text_sha256: Sha256
    fields: dict[str, JsonValue]
    spans: list[EvidenceSpan]

    @field_validator("spans")
    @classmethod
    def unique_span_ids(cls, spans: list[EvidenceSpan]) -> list[EvidenceSpan]:
        ids = [span.span_id for span in spans]
        if len(ids) != len(set(ids)):
            raise ValueError("span_id values must be unique within a document")
        return spans

    @model_validator(mode="after")
    def validate_text_and_spans(self) -> Self:
        if self.source_class != _SOURCE_CLASSES[self.source_name]:
            raise ValueError("source_name requires its configured source_class")
        text_hash = hashlib.sha256(self.normalized_text.encode("utf-8")).hexdigest()
        if text_hash != self.normalized_text_sha256:
            raise ValueError("normalized_text_sha256 does not match normalized_text")
        for span in self.spans:
            if span.end_char > len(self.normalized_text):
                raise ValueError(
                    f"span {span.span_id!r} exceeds normalized_text bounds"
                )
            span_text = self.normalized_text[span.start_char : span.end_char]
            span_hash = hashlib.sha256(span_text.encode("utf-8")).hexdigest()
            if span_hash != span.text_sha256:
                raise ValueError(f"span {span.span_id!r} text hash does not match")
            if span.raw_snapshot_id != self.snapshot_id:
                raise ValueError(
                    f"span {span.span_id!r} raw_snapshot_id does not match snapshot_id"
                )
            if span.normalization_version != self.normalization_version:
                raise ValueError(
                    f"span {span.span_id!r} normalization_version does not match"
                )
        return self
