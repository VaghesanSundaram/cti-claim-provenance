from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from cti_provenance.snapshot.store import ImmutableBlobStore, ImmutableStoreError


def test_store_creates_and_idempotently_verifies_exact_bytes(tmp_path: Path) -> None:
    store = ImmutableBlobStore(tmp_path / "store")
    payload = b"immutable bytes"
    expected = hashlib.sha256(payload).hexdigest()
    created = store.put_bytes("aa/blob.json", payload, expected_sha256=expected)
    repeated = store.put_bytes("aa/blob.json", payload, expected_sha256=expected)
    assert created == repeated
    assert (tmp_path / "store" / "aa" / "blob.json").read_bytes() == payload


def test_store_rejects_mutation_hash_mismatch_and_unsafe_path(tmp_path: Path) -> None:
    store = ImmutableBlobStore(tmp_path / "store")
    store.put_bytes("blob", b"first")
    with pytest.raises(ImmutableStoreError, match="different bytes"):
        store.put_bytes("blob", b"second")
    with pytest.raises(ImmutableStoreError, match="expected SHA-256"):
        store.put_bytes("other", b"bytes", expected_sha256="0" * 64)
    with pytest.raises(ImmutableStoreError, match="safe relative"):
        store.put_bytes("../outside", b"bytes")


@pytest.mark.parametrize(
    "unsafe_path",
    ["C:/escape", "folder//blob", "folder/./blob", "folder/aux", "folder/blob. "],
)
def test_store_rejects_windows_unsafe_path_forms(
    tmp_path: Path, unsafe_path: str
) -> None:
    with pytest.raises(ImmutableStoreError, match="safe relative"):
        ImmutableBlobStore(tmp_path / "store").put_bytes(unsafe_path, b"bytes")


def test_store_fails_closed_for_case_colliding_existing_entry(tmp_path: Path) -> None:
    store = ImmutableBlobStore(tmp_path / "store")
    store.put_bytes("Blob", b"first")
    with pytest.raises(ImmutableStoreError, match="case-colliding"):
        store.put_bytes("blob", b"first")
