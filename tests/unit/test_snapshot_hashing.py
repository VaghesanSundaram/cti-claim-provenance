from __future__ import annotations

from io import BytesIO

import pytest

from cti_provenance.snapshot.hashing import sha256_chunks, sha256_stream


def test_hashing_helpers_are_streaming_and_count_exact_bytes() -> None:
    expected = "936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af"
    assert sha256_chunks([b"hello", b"world"]) == (expected, 10)
    assert sha256_stream(BytesIO(b"helloworld"), chunk_size=3) == (expected, 10)


def test_hashing_rejects_invalid_chunks_and_sizes() -> None:
    with pytest.raises(TypeError):
        sha256_chunks([b"valid", "not-bytes"])  # type: ignore[list-item]
    with pytest.raises(ValueError):
        sha256_stream(BytesIO(), chunk_size=0)
