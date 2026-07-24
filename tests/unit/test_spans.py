from __future__ import annotations

import pytest

from cti_provenance.normalize.spans import (
    SpanResolutionError,
    create_span,
    resolve_span,
)


def test_create_and_resolve_exact_unicode_character_span() -> None:
    text = "A normalized café record"
    start = text.index("café")
    span = create_span(
        span_id="span-1",
        field_path="/description",
        normalized_text=text,
        start_char=start,
        end_char=start + len("café"),
        raw_locator="/description",
        raw_locator_unavailable_reason=None,
        raw_snapshot_id="snapshot-1",
        raw_snapshot_sha256="a" * 64,
        normalization_version="normalize-v1",
    )
    assert resolve_span(span, text) == "café"
    with pytest.raises(SpanResolutionError, match="hash"):
        resolve_span(span, "A normalized cafe record")


def test_create_span_rejects_bad_offsets_and_locator_ambiguity() -> None:
    with pytest.raises(SpanResolutionError, match="offsets"):
        create_span(
            span_id="span-1",
            field_path="/x",
            normalized_text="abc",
            start_char=2,
            end_char=4,
            raw_locator="/x",
            raw_locator_unavailable_reason=None,
            raw_snapshot_id="snapshot-1",
            raw_snapshot_sha256="a" * 64,
            normalization_version="normalize-v1",
        )
    with pytest.raises(ValueError, match="exactly one"):
        create_span(
            span_id="span-1",
            field_path="/x",
            normalized_text="abc",
            start_char=0,
            end_char=1,
            raw_locator=None,
            raw_locator_unavailable_reason=None,
            raw_snapshot_id="snapshot-1",
            raw_snapshot_sha256="a" * 64,
            normalization_version="normalize-v1",
        )
