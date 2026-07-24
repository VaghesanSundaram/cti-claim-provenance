"""Persist and replay the exact Phase 2 capture without generalizing transport."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    StringConstraints,
    ValidationError,
    model_validator,
)

from cti_provenance.ingest.base import (
    CaptureError,
    SourceStateEvidenceRecord,
    store_capture,
    store_evidence_artifact,
)
from cti_provenance.ingest.kev import (
    kev_evidence_record,
    kev_state,
    replay_kev_state,
)
from cti_provenance.ingest.nvd import (
    nvd_evidence_record,
    nvd_state,
    replay_nvd_state,
)
from cti_provenance.ingest.session import (
    Phase2CaptureBundle,
    Phase2CaptureSessionError,
    Phase2CaptureSessionEvidence,
    bind_phase2_capture_artifacts,
    render_capture_session_json,
    run_phase2_capture_session,
)
from cti_provenance.ingest.vendor import (
    red_hat_evidence_record,
    red_hat_state,
    replay_red_hat_state,
)
from cti_provenance.normalize import (
    NormalizedDocument,
    normalize_kev,
    normalize_nvd,
    normalize_red_hat,
)
from cti_provenance.snapshot import ImmutableBlobStore, SnapshotManifest, SnapshotState
from cti_provenance.snapshot.manifest import safe_relative_posix_path

PHASE2_SNAPSHOT_MANIFEST_PATH = "data/manifests/phase2-snapshots.jsonl"
PHASE2_SOURCE_EVIDENCE_PATH = "data/manifests/phase2-source-state-evidence.jsonl"
PHASE2_METADATA_ENVELOPE_PATH = "data/manifests/phase2-capture-metadata.json"
PHASE2_SESSION_DIRECTORY = "data/manifests/phase2-capture-sessions"
PHASE2_REAL_SLICE_SESSION_ID = "phase2-capture-b093c6c2e2bce1953d5f"
PHASE2_REAL_SLICE_SESSION_SHA256 = (
    "373f4c648ea05e074c1b2050aef200713a46b546d4c93f3fb4cf809e365cf224"
)
type Phase2SessionId = Annotated[
    str,
    StringConstraints(pattern=r"^phase2-capture-[0-9a-f]{20}$"),
]
type SupportingArtifactRole = Literal[
    "primary_body",
    "commit_lineage",
    "published_checksum",
]


@dataclass(frozen=True)
class Phase2Materialization:
    """Accepted local artifacts for one complete five-resource capture."""

    session_path: str
    states: tuple[SnapshotState, SnapshotState, SnapshotState]
    source_evidence: tuple[
        SourceStateEvidenceRecord,
        SourceStateEvidenceRecord,
        SourceStateEvidenceRecord,
    ]
    normalized_documents: tuple[
        NormalizedDocument,
        NormalizedDocument,
        NormalizedDocument,
    ]


class Phase2CaptureMetadataEnvelope(BaseModel):
    """Single immutable recovery source for both canonical metadata views."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal["phase2-capture-metadata-v1"]
    session_id: Phase2SessionId
    manifests: tuple[SnapshotManifest, SnapshotManifest, SnapshotManifest]
    source_evidence: tuple[
        SourceStateEvidenceRecord,
        SourceStateEvidenceRecord,
        SourceStateEvidenceRecord,
    ]

    @model_validator(mode="after")
    def validate_cross_binding(self) -> Self:
        source_order = ("nvd", "cisa_kev", "red_hat_rhsa")
        if tuple(manifest.source_name for manifest in self.manifests) != source_order:
            raise ValueError("capture metadata manifests have the wrong source order")
        if tuple(record.source_name for record in self.source_evidence) != source_order:
            raise ValueError("capture source evidence has the wrong source order")
        if tuple(manifest.snapshot_id for manifest in self.manifests) != tuple(
            record.snapshot_id for record in self.source_evidence
        ):
            raise ValueError("capture metadata snapshot identities do not cross-bind")
        return self


def _stable_json(model: BaseModel) -> bytes:
    return (
        json.dumps(
            model.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


def _stable_jsonl(models: tuple[BaseModel, ...]) -> bytes:
    return b"".join(_stable_json(model) for model in models)


def _validated_bundle(bundle: Phase2CaptureBundle) -> Phase2CaptureBundle:
    try:
        evidence = Phase2CaptureSessionEvidence.model_validate(
            bundle.evidence.model_dump(mode="python")
        )
    except ValidationError as exc:
        raise CaptureError("capture bundle failed final session revalidation") from exc
    return Phase2CaptureBundle(
        nvd_primary=bundle.nvd_primary,
        kev_catalog=bundle.kev_catalog,
        kev_lineage=bundle.kev_lineage,
        red_hat_primary=bundle.red_hat_primary,
        red_hat_checksum=bundle.red_hat_checksum,
        evidence=evidence,
    )


def _persist_session(
    store: ImmutableBlobStore,
    *,
    session_id: str,
    rendered: str,
) -> str:
    relative_path = f"{PHASE2_SESSION_DIRECTORY}/{session_id}.json"
    store.put_bytes(relative_path, rendered.encode())
    return relative_path


def _source_records(
    bundle: Phase2CaptureBundle,
) -> tuple[
    tuple[SnapshotState, SnapshotState, SnapshotState],
    tuple[
        SourceStateEvidenceRecord,
        SourceStateEvidenceRecord,
        SourceStateEvidenceRecord,
    ],
]:
    nvd_snapshot = nvd_state(bundle.nvd_primary)
    kev_snapshot = kev_state(bundle.kev_catalog, bundle.kev_lineage)
    red_hat_snapshot = red_hat_state(
        bundle.red_hat_primary,
        bundle.red_hat_checksum,
    )
    states = (nvd_snapshot, kev_snapshot, red_hat_snapshot)
    records = (
        nvd_evidence_record(bundle.nvd_primary, nvd_snapshot),
        kev_evidence_record(
            bundle.kev_catalog,
            bundle.kev_lineage,
            kev_snapshot,
        ),
        red_hat_evidence_record(
            bundle.red_hat_primary,
            bundle.red_hat_checksum,
            red_hat_snapshot,
        ),
    )
    bind_phase2_capture_artifacts(bundle.evidence, list(records))
    return states, records


def _artifact_path(
    record: SourceStateEvidenceRecord,
    role: SupportingArtifactRole,
) -> str:
    artifacts = [artifact for artifact in record.artifacts if artifact.role == role]
    if len(artifacts) != 1:
        raise CaptureError("source evidence artifact role is missing or duplicated")
    return artifacts[0].raw_blob_path


def _read_artifact(
    project_root: Path,
    record: SourceStateEvidenceRecord,
    role: SupportingArtifactRole,
) -> bytes:
    return _read_project_bytes(project_root, _artifact_path(record, role))


def _read_project_bytes(project_root: Path, relative_path: str) -> bytes:
    root = project_root.resolve(strict=True)
    try:
        relative = safe_relative_posix_path(relative_path)
        candidate = root.joinpath(*relative.parts)
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        if not resolved.is_file():
            raise CaptureError("stored source artifact is not a regular file")
        current = candidate
        while current != root:
            is_junction = getattr(current, "is_junction", None)
            if current.is_symlink() or (callable(is_junction) and is_junction()):
                raise CaptureError("stored source artifact traverses a link")
            current = current.parent
        return resolved.read_bytes()
    except CaptureError:
        raise
    except (OSError, ValueError) as exc:
        raise CaptureError("stored source artifact is unavailable for replay") from exc


def _store_bundle(
    store: ImmutableBlobStore,
    bundle: Phase2CaptureBundle,
    states: tuple[SnapshotState, SnapshotState, SnapshotState],
    records: tuple[
        SourceStateEvidenceRecord,
        SourceStateEvidenceRecord,
        SourceStateEvidenceRecord,
    ],
) -> None:
    primary_responses = (
        bundle.nvd_primary,
        bundle.kev_catalog,
        bundle.red_hat_primary,
    )
    for response, state, record in zip(
        primary_responses,
        states,
        records,
        strict=True,
    ):
        store_capture(
            response,
            store=store,
            raw_blob_path=state.manifest.raw_blob_path,
            manifest=state.manifest,
            state=state,
            source_evidence=record,
        )
    for response, record, role in (
        (bundle.kev_lineage, records[1], "commit_lineage"),
        (bundle.red_hat_checksum, records[2], "published_checksum"),
    ):
        artifacts = [artifact for artifact in record.artifacts if artifact.role == role]
        if len(artifacts) != 1:
            raise CaptureError("supporting source artifact is missing or duplicated")
        store_evidence_artifact(response, store=store, artifact=artifacts[0])


def _replay_and_normalize(
    project_root: Path,
    states: tuple[SnapshotState, SnapshotState, SnapshotState],
    records: tuple[
        SourceStateEvidenceRecord,
        SourceStateEvidenceRecord,
        SourceStateEvidenceRecord,
    ],
) -> tuple[NormalizedDocument, NormalizedDocument, NormalizedDocument]:
    replayed = _replay_states(project_root, records)
    if replayed != states:
        raise CaptureError("offline replay does not reproduce captured source state")
    return _normalize_replayed_documents(project_root, states, records)


def _replay_states(
    project_root: Path,
    records: tuple[
        SourceStateEvidenceRecord,
        SourceStateEvidenceRecord,
        SourceStateEvidenceRecord,
    ],
) -> tuple[SnapshotState, SnapshotState, SnapshotState]:
    nvd_raw = _read_artifact(project_root, records[0], "primary_body")
    kev_raw = _read_artifact(project_root, records[1], "primary_body")
    kev_lineage = _read_artifact(project_root, records[1], "commit_lineage")
    red_hat_raw = _read_artifact(project_root, records[2], "primary_body")
    red_hat_checksum = _read_artifact(
        project_root,
        records[2],
        "published_checksum",
    )
    return (
        replay_nvd_state(records[0], nvd_raw),
        replay_kev_state(
            records[1],
            primary_body=kev_raw,
            lineage_body=kev_lineage,
        ),
        replay_red_hat_state(
            records[2],
            primary_body=red_hat_raw,
            checksum_body=red_hat_checksum,
        ),
    )


def _normalize_replayed_documents(
    project_root: Path,
    states: tuple[SnapshotState, SnapshotState, SnapshotState],
    records: tuple[
        SourceStateEvidenceRecord,
        SourceStateEvidenceRecord,
        SourceStateEvidenceRecord,
    ],
) -> tuple[NormalizedDocument, NormalizedDocument, NormalizedDocument]:
    nvd_raw = _read_artifact(project_root, records[0], "primary_body")
    kev_raw = _read_artifact(project_root, records[1], "primary_body")
    red_hat_raw = _read_artifact(project_root, records[2], "primary_body")
    red_hat_checksum = _read_artifact(
        project_root,
        records[2],
        "published_checksum",
    )
    document_lists = (
        normalize_nvd(nvd_raw, states[0].manifest),
        normalize_kev(kev_raw, states[1].manifest),
        normalize_red_hat(
            red_hat_raw,
            red_hat_checksum,
            states[2].manifest,
        ),
    )
    if any(len(documents) != 1 for documents in document_lists):
        raise CaptureError("Phase 2 normalization must yield exactly three documents")
    return (
        document_lists[0][0],
        document_lists[1][0],
        document_lists[2][0],
    )


def load_phase2_materialized_corpus(
    project_root: Path,
) -> tuple[
    tuple[SnapshotState, SnapshotState, SnapshotState],
    tuple[NormalizedDocument, NormalizedDocument, NormalizedDocument],
]:
    """Replay one accepted capture without writing or transport fallback."""
    root = project_root.resolve(strict=True)
    try:
        envelope_bytes = _read_project_bytes(root, PHASE2_METADATA_ENVELOPE_PATH)
        envelope = Phase2CaptureMetadataEnvelope.model_validate_json(envelope_bytes)
        session_relative = safe_relative_posix_path(
            f"{PHASE2_SESSION_DIRECTORY}/{envelope.session_id}.json"
        )
        session_bytes = _read_project_bytes(root, session_relative.as_posix())
        session = Phase2CaptureSessionEvidence.model_validate_json(session_bytes)
    except (CaptureError, ValidationError, ValueError) as exc:
        raise CaptureError("real-slice capture metadata is unavailable") from exc
    if (
        envelope.session_id != PHASE2_REAL_SLICE_SESSION_ID
        or hashlib.sha256(session_bytes).hexdigest() != PHASE2_REAL_SLICE_SESSION_SHA256
        or session.status != "complete"
        or session.session_id != envelope.session_id
    ):
        raise CaptureError("real-slice metadata does not bind a complete session")
    bind_phase2_capture_artifacts(session, list(envelope.source_evidence))
    try:
        manifest_view = _read_project_bytes(root, PHASE2_SNAPSHOT_MANIFEST_PATH)
        evidence_view = _read_project_bytes(root, PHASE2_SOURCE_EVIDENCE_PATH)
    except CaptureError as exc:
        raise CaptureError("real-slice metadata view is unavailable") from exc
    if manifest_view != _stable_jsonl(envelope.manifests) or evidence_view != (
        _stable_jsonl(envelope.source_evidence)
    ):
        raise CaptureError("real-slice metadata views do not match the envelope")

    states = _replay_states(root, envelope.source_evidence)
    if tuple(state.manifest for state in states) != envelope.manifests:
        raise CaptureError("real-slice replay does not reproduce tracked manifests")
    documents = _normalize_replayed_documents(
        root,
        states,
        envelope.source_evidence,
    )
    for document in documents:
        relative_path = (
            f"data/normalized/phase2/{document.snapshot_id}/{document.document_id}.json"
        )
        try:
            persisted = _read_project_bytes(root, relative_path)
            parsed = NormalizedDocument.model_validate_json(persisted)
        except (CaptureError, ValidationError, ValueError) as exc:
            raise CaptureError("real-slice normalized document is unavailable") from exc
        if parsed != document or persisted != _stable_json(document):
            raise CaptureError("real-slice normalized document does not replay exactly")
    return states, documents


def _metadata_envelope(
    bundle: Phase2CaptureBundle,
    states: tuple[SnapshotState, SnapshotState, SnapshotState],
    records: tuple[
        SourceStateEvidenceRecord,
        SourceStateEvidenceRecord,
        SourceStateEvidenceRecord,
    ],
) -> Phase2CaptureMetadataEnvelope:
    return Phase2CaptureMetadataEnvelope(
        version="phase2-capture-metadata-v1",
        session_id=bundle.evidence.session_id,
        manifests=(
            states[0].manifest,
            states[1].manifest,
            states[2].manifest,
        ),
        source_evidence=records,
    )


def _write_metadata_views(
    store: ImmutableBlobStore,
    envelope: Phase2CaptureMetadataEnvelope,
) -> None:
    store.put_bytes(
        PHASE2_SNAPSHOT_MANIFEST_PATH,
        _stable_jsonl(envelope.manifests),
    )
    store.put_bytes(
        PHASE2_SOURCE_EVIDENCE_PATH,
        _stable_jsonl(envelope.source_evidence),
    )


def recover_phase2_metadata_views(project_root: Path) -> None:
    """Rebuild canonical JSONL views from the immutable metadata envelope."""
    root = project_root.resolve(strict=True)
    try:
        envelope = Phase2CaptureMetadataEnvelope.model_validate_json(
            (root / PHASE2_METADATA_ENVELOPE_PATH).read_bytes()
        )
        session_relative = safe_relative_posix_path(
            f"{PHASE2_SESSION_DIRECTORY}/{envelope.session_id}.json"
        )
        session = Phase2CaptureSessionEvidence.model_validate_json(
            root.joinpath(*session_relative.parts).read_bytes()
        )
    except (OSError, ValidationError, ValueError) as exc:
        raise CaptureError("capture metadata recovery source is unavailable") from exc
    if session.status != "complete" or session.session_id != envelope.session_id:
        raise CaptureError("capture metadata envelope does not bind a complete session")
    bind_phase2_capture_artifacts(session, list(envelope.source_evidence))
    _write_metadata_views(ImmutableBlobStore(root), envelope)


def materialize_phase2_capture(
    project_root: Path,
    bundle: Phase2CaptureBundle,
) -> Phase2Materialization:
    """Cross-bind, store, reread, replay, and normalize one exact capture."""
    root = project_root.resolve(strict=True)
    bundle = _validated_bundle(bundle)
    store = ImmutableBlobStore(root)
    session_path = _persist_session(
        store,
        session_id=bundle.evidence.session_id,
        rendered=render_capture_session_json(bundle.evidence),
    )
    states, records = _source_records(bundle)
    _store_bundle(store, bundle, states, records)
    documents = _replay_and_normalize(root, states, records)
    for document in documents:
        store.put_bytes(
            (
                f"data/normalized/phase2/{document.snapshot_id}/"
                f"{document.document_id}.json"
            ),
            _stable_json(document),
        )
    envelope = _metadata_envelope(bundle, states, records)
    store.put_bytes(
        PHASE2_METADATA_ENVELOPE_PATH,
        _stable_json(envelope),
    )
    _write_metadata_views(store, envelope)
    return Phase2Materialization(
        session_path=session_path,
        states=states,
        source_evidence=records,
        normalized_documents=documents,
    )


def capture_and_materialize_phase2(project_root: Path) -> Phase2Materialization:
    """Run the frozen session once and durably retain either terminal outcome."""
    root = project_root.resolve(strict=True)
    try:
        bundle = run_phase2_capture_session()
    except Phase2CaptureSessionError as exc:
        store = ImmutableBlobStore(root)
        _persist_session(
            store,
            session_id=exc.evidence.session_id,
            rendered=render_capture_session_json(exc.evidence),
        )
        raise
    return materialize_phase2_capture(root, bundle)
