"""Small streaming SHA-256 helpers for immutable snapshot bytes."""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from pathlib import Path
from typing import BinaryIO


def sha256_chunks(chunks: Iterable[bytes]) -> tuple[str, int]:
    """Return the lowercase SHA-256 and byte count for a byte stream."""
    digest = hashlib.sha256()
    size = 0
    for chunk in chunks:
        if not isinstance(chunk, bytes):
            raise TypeError("hash chunks must be bytes")
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def sha256_stream(stream: BinaryIO, chunk_size: int = 64 * 1024) -> tuple[str, int]:
    """Hash a binary stream without reading it all into memory."""
    if chunk_size <= 0:
        raise ValueError("chunk_size must be positive")

    def chunks() -> Iterable[bytes]:
        while chunk := stream.read(chunk_size):
            yield chunk

    return sha256_chunks(chunks())


def sha256_file(path: Path, chunk_size: int = 64 * 1024) -> tuple[str, int]:
    """Hash *path* as exact bytes."""
    with path.open("rb") as stream:
        return sha256_stream(stream, chunk_size)
