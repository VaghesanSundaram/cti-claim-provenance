"""Creation and resolution helpers for exact normalized-text evidence spans."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from cti_provenance.normalize.common import EvidenceSpan


class SpanResolutionError(ValueError):
    """A span no longer resolves to its claimed exact normalized text."""


def resolve_json_pointer(raw: bytes, pointer: str) -> Any:
    """Resolve one RFC 6901 pointer against the immutable JSON bytes."""
    try:
        value: Any = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise SpanResolutionError("raw evidence is not valid JSON") from exc
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise SpanResolutionError("raw locator is not an absolute JSON pointer")
    for encoded_token in pointer[1:].split("/"):
        index = 0
        while index < len(encoded_token):
            if encoded_token[index] == "~":
                if index + 1 >= len(encoded_token) or encoded_token[index + 1] not in {
                    "0",
                    "1",
                }:
                    raise SpanResolutionError(
                        "raw locator contains invalid JSON-pointer escape"
                    )
                index += 2
                continue
            index += 1
        token = encoded_token.replace("~1", "/").replace("~0", "~")
        if isinstance(value, dict):
            if token not in value:
                raise SpanResolutionError("raw locator does not resolve")
            value = value[token]
        elif isinstance(value, list):
            if (
                not token.isascii()
                or not token.isdecimal()
                or (len(token) > 1 and token.startswith("0"))
            ):
                raise SpanResolutionError("raw locator has an invalid array index")
            index = int(token)
            if index >= len(value):
                raise SpanResolutionError("raw locator array index is out of range")
            value = value[index]
        else:
            raise SpanResolutionError("raw locator traverses a scalar value")
    return value


def verify_raw_round_trip(
    span: EvidenceSpan, *, normalized_text: str, raw: bytes
) -> None:
    """Require the normalized span text to equal its addressed raw scalar."""
    if span.raw_locator is None:
        raise SpanResolutionError("span has no raw locator")
    raw_value = resolve_json_pointer(raw, span.raw_locator)
    if not isinstance(raw_value, (str, int, float)) or isinstance(raw_value, bool):
        raise SpanResolutionError("raw locator does not address a scalar value")
    if str(raw_value) != resolve_span(span, normalized_text):
        raise SpanResolutionError("normalized span does not round-trip to raw JSON")


def verify_raw_json_round_trip(
    span: EvidenceSpan, *, normalized_text: str, raw: bytes
) -> None:
    """Require a span to equal canonical JSON for its addressed object or array."""

    if span.raw_locator is None:
        raise SpanResolutionError("span has no raw locator")
    raw_value = resolve_json_pointer(raw, span.raw_locator)
    if not isinstance(raw_value, (dict, list)):
        raise SpanResolutionError("raw locator does not address an object or array")
    canonical = json.dumps(raw_value, sort_keys=True, separators=(",", ":"))
    if canonical != resolve_span(span, normalized_text):
        raise SpanResolutionError("normalized span does not round-trip to raw JSON")


def create_span(
    *,
    span_id: str,
    field_path: str,
    normalized_text: str,
    start_char: int,
    end_char: int,
    raw_locator: str | None,
    raw_locator_unavailable_reason: str | None,
    raw_snapshot_id: str,
    raw_snapshot_sha256: str,
    normalization_version: str,
) -> EvidenceSpan:
    """Create a hash-bound span from exact Python Unicode character offsets."""
    if start_char < 0 or end_char > len(normalized_text) or end_char <= start_char:
        raise SpanResolutionError("span offsets are outside normalized text")
    text = normalized_text[start_char:end_char]
    return EvidenceSpan(
        span_id=span_id,
        field_path=field_path,
        start_char=start_char,
        end_char=end_char,
        text_sha256=hashlib.sha256(text.encode("utf-8")).hexdigest(),
        raw_locator=raw_locator,
        raw_locator_unavailable_reason=raw_locator_unavailable_reason,
        raw_snapshot_id=raw_snapshot_id,
        raw_snapshot_sha256=raw_snapshot_sha256,
        normalization_version=normalization_version,
    )


def resolve_span(span: EvidenceSpan, normalized_text: str) -> str:
    """Resolve and verify a span; never silently accept offset drift."""
    if span.end_char > len(normalized_text):
        raise SpanResolutionError("span exceeds normalized text")
    text = normalized_text[span.start_char : span.end_char]
    actual_hash = hashlib.sha256(text.encode("utf-8")).hexdigest()
    if actual_hash != span.text_sha256:
        raise SpanResolutionError("span text hash does not match normalized text")
    return text
