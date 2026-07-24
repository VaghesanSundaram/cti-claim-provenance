"""Content-addressed, append-only local storage for snapshot bytes."""

from __future__ import annotations

import os
import uuid
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from cti_provenance.snapshot.hashing import sha256_file
from cti_provenance.snapshot.manifest import safe_relative_posix_path


class ImmutableStoreError(RuntimeError):
    """Raised when a blob path is unsafe or would mutate immutable bytes."""


@dataclass(frozen=True)
class StoredBlob:
    """Verified immutable blob metadata."""

    relative_path: str
    sha256: str
    byte_length: int


def _safe_relative_path(relative_path: str) -> PurePosixPath:
    try:
        return safe_relative_posix_path(relative_path)
    except ValueError as exc:
        raise ImmutableStoreError(
            "blob path must be a safe relative POSIX path"
        ) from exc


def _is_link_or_junction(path: Path) -> bool:
    is_junction = getattr(path, "is_junction", None)
    return path.is_symlink() or (callable(is_junction) and is_junction())


def _reject_linked_existing_parents(path: Path) -> None:
    for candidate in (path, *path.parents):
        if candidate.exists() and _is_link_or_junction(candidate):
            raise ImmutableStoreError("store path traverses a symlink or junction")


def _reject_case_collision(parent: Path, child_name: str) -> None:
    if not parent.exists():
        return
    for child in parent.iterdir():
        if child.name.casefold() == child_name.casefold() and child.name != child_name:
            raise ImmutableStoreError("blob path has a case-colliding existing entry")


class ImmutableBlobStore:
    """Store bytes once; later writes must prove exact-byte identity."""

    def __init__(self, root: Path) -> None:
        _reject_linked_existing_parents(root.absolute())
        self.root = root.absolute()
        self.root.mkdir(parents=True, exist_ok=True)
        _reject_linked_existing_parents(self.root)

    def _target(self, relative_path: str) -> Path:
        relative = _safe_relative_path(relative_path)
        target = self.root
        for part in relative.parts:
            _reject_case_collision(target, part)
            target = target / part
        _reject_linked_existing_parents(target.parent)
        try:
            target.relative_to(self.root)
        except ValueError as exc:  # defensive against platform path behavior
            raise ImmutableStoreError("blob path escapes store root") from exc
        return target

    def put_bytes(
        self,
        relative_path: str,
        data: bytes,
        *,
        expected_sha256: str | None = None,
    ) -> StoredBlob:
        """Atomically create a blob, or verify an identical existing blob."""
        if not isinstance(data, bytes):
            raise TypeError("snapshot data must be bytes")
        target = self._target(relative_path)
        target.parent.mkdir(parents=True, exist_ok=True)
        _reject_linked_existing_parents(target.parent)
        _reject_case_collision(target.parent, target.name)
        if target.exists() and _is_link_or_junction(target):
            raise ImmutableStoreError("blob path traverses a symlink or junction")

        temporary = target.parent / f".{target.name}.{uuid.uuid4().hex}.tmp"
        try:
            with temporary.open("xb") as stream:
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
            sha256, byte_length = sha256_file(temporary)
            if expected_sha256 is not None and sha256 != expected_sha256:
                raise ImmutableStoreError(
                    "provided bytes do not match expected SHA-256"
                )
            try:
                os.link(temporary, target)
            except FileExistsError:
                existing_sha256, existing_length = sha256_file(target)
                if existing_sha256 != sha256 or existing_length != byte_length:
                    raise ImmutableStoreError(
                        "immutable blob path already has different bytes"
                    ) from None
            return StoredBlob(relative_path, sha256, byte_length)
        finally:
            temporary.unlink(missing_ok=True)
