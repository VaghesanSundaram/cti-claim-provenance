from __future__ import annotations

import json
import socket
from pathlib import Path

import pytest
from pydantic import ValidationError

from cti_provenance.claims import load_phase2_plumbing_corpus
from cti_provenance.models.protocol import (
    AuthorizationManifest,
    canonical_authorization_manifest_json,
    load_authorization_manifest,
)

ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = ROOT / "configs" / "experiments" / "phase2-plumbing-authorization.yaml"


def _valid_data() -> dict[str, object]:
    return load_authorization_manifest(MANIFEST_PATH).model_dump(mode="python")


def test_checked_in_manifest_is_exact_offline_phase2_scope() -> None:
    manifest = load_authorization_manifest(MANIFEST_PATH)
    assert manifest.authorization_id == "phase2-plumbing-offline-v1"
    assert manifest.target_ids == (
        "phase2-fixture-nvd-v1",
        "phase2-fixture-kev-v1",
        "phase2-fixture-red-hat-v1",
        "phase2-fixture-contradiction-v1",
    )
    assert manifest.provider_transport.allowed is False
    assert manifest.provider_transport.provider == "none"
    assert manifest.provider_transport.endpoint_class == "none"
    assert manifest.allowed_outcomes == ("identify_or_classify", "cite_evidence")
    assert manifest.approved_by == "project_protocol"
    assert manifest.protocol_version == "provider-safety-v1"


def test_checked_in_manifest_targets_bind_the_phase2_plumbing_corpus() -> None:
    states, _documents = load_phase2_plumbing_corpus(ROOT)
    assert set(load_authorization_manifest(MANIFEST_PATH).target_ids) == {
        state.manifest.snapshot_id for state in states
    }


def test_round_trip_canonical_serialization_and_hash_are_deterministic() -> None:
    manifest = load_authorization_manifest(MANIFEST_PATH)
    payload = canonical_authorization_manifest_json(manifest)
    assert AuthorizationManifest.model_validate_json(payload) == manifest
    reordered = AuthorizationManifest.model_validate(
        dict(reversed(list(manifest.model_dump(mode="python").items())))
    )
    assert reordered.canonical_json() == payload
    assert reordered.sha256() == manifest.sha256()


def test_collection_fields_are_deeply_immutable_and_hash_stable() -> None:
    manifest = load_authorization_manifest(MANIFEST_PATH)
    before = manifest.sha256()
    for values in (
        manifest.target_ids,
        manifest.allowed_outcomes,
        manifest.prohibited_outcomes,
    ):
        with pytest.raises(AttributeError):
            values.append("unexpected")  # type: ignore[attr-defined]
        with pytest.raises(AttributeError):
            values.pop()  # type: ignore[attr-defined]
        with pytest.raises(TypeError):
            values[0] = "unexpected"  # type: ignore[index]
    assert manifest.sha256() == before


def test_canonical_hash_binds_exact_manifest_array_order() -> None:
    manifest = load_authorization_manifest(MANIFEST_PATH)
    reordered = manifest.model_dump(mode="python")
    reordered["target_ids"] = tuple(reversed(manifest.target_ids))
    assert AuthorizationManifest.model_validate(reordered).sha256() != manifest.sha256()


def test_manifest_artifact_has_no_prompt_request_response_or_notes_surface() -> None:
    forbidden = {
        "prompt",
        "prompt_body",
        "target_content",
        "credential",
        "request_id",
        "response",
        "notes",
    }
    assert forbidden.isdisjoint(AuthorizationManifest.model_fields)
    assert forbidden.isdisjoint(
        load_authorization_manifest(MANIFEST_PATH).model_dump(mode="json")
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda data: data.update({"unexpected": True}),
        lambda data: data.pop("target_ids"),
        lambda data: data.update({"target_network_access": True}),
        lambda data: data.update({"external_or_live_target": True}),
        lambda data: data.update({"data_classification": "public"}),
        lambda data: data.update({"target_ids": ["fixture", "fixture"]}),
        lambda data: data.update(
            {"allowed_outcomes": ["cite_evidence", "cite_evidence"]}
        ),
        lambda data: data.update({"prohibited_outcomes": ["persistence"]}),
        lambda data: data.update({"target_network_access": "false"}),
    ],
)
def test_strict_scope_unknown_missing_and_duplicate_values_fail(
    mutation: object,
) -> None:
    data = _valid_data()
    mutation(data)  # type: ignore[operator]
    with pytest.raises(ValidationError):
        AuthorizationManifest.model_validate(data)


@pytest.mark.parametrize(
    "transport",
    [
        {"allowed": False, "provider": "openai", "endpoint_class": "none"},
        {
            "allowed": False,
            "provider": "none",
            "endpoint_class": "official_model_api",
        },
        {"allowed": True, "provider": "none", "endpoint_class": "none"},
        {"allowed": True, "provider": "openai", "endpoint_class": "none"},
    ],
)
def test_provider_transport_combinations_are_validated(
    transport: dict[str, object],
) -> None:
    data = _valid_data()
    data["provider_transport"] = transport
    with pytest.raises(ValidationError):
        AuthorizationManifest.model_validate(data)


def test_safe_yaml_loading_rejects_unsafe_tags(tmp_path: Path) -> None:
    path = tmp_path / "unsafe.yaml"
    path.write_text(
        "!!python/object/apply:os.system ['not executed']\n", encoding="utf-8"
    )
    with pytest.raises(ValueError, match="invalid YAML authorization manifest"):
        load_authorization_manifest(path)


def test_safe_yaml_loading_normalizes_unhashable_mapping_keys(tmp_path: Path) -> None:
    path = tmp_path / "unhashable-key.yaml"
    path.write_text("? [one, two]\n: value\n", encoding="utf-8")
    with pytest.raises(ValueError, match="invalid YAML authorization manifest"):
        load_authorization_manifest(path)


@pytest.mark.parametrize(
    "yaml_text",
    [
        "authorization_id: first\nauthorization_id: second\n",
        "provider_transport:\n  allowed: false\n  allowed: false\n",
    ],
)
def test_safe_yaml_loading_rejects_duplicate_keys(
    tmp_path: Path, yaml_text: str
) -> None:
    path = tmp_path / "duplicate.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    with pytest.raises(ValueError, match="invalid YAML authorization manifest"):
        load_authorization_manifest(path)


def test_manifest_validation_makes_zero_socket_attempts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def deny_socket(*args: object, **kwargs: object) -> socket.socket:
        raise AssertionError("manifest validation must not create a socket")

    monkeypatch.setattr(socket, "socket", deny_socket)
    assert (
        load_authorization_manifest(MANIFEST_PATH).provider_transport.allowed is False
    )


def test_exported_schema_encodes_offline_scope_constraints() -> None:
    schema = json.loads(
        (ROOT / "schemas" / "authorization-manifest.schema.json").read_text(
            encoding="utf-8"
        )
    )
    properties = schema["properties"]
    assert schema["additionalProperties"] is False
    assert set(schema["required"]) == set(AuthorizationManifest.model_fields)
    assert properties["target_network_access"]["const"] is False
    assert properties["external_or_live_target"]["const"] is False
    assert properties["target_ids"]["items"]["pattern"] == ".*\\S.*"
    assert properties["target_ids"]["uniqueItems"] is True
    assert properties["allowed_outcomes"]["uniqueItems"] is True
    prohibited = properties["prohibited_outcomes"]
    assert prohibited["minItems"] == prohibited["maxItems"] == 8
    assert prohibited["uniqueItems"] is True
    all_of = schema["allOf"]
    assert all_of[0]["if"]["properties"]["target_kind"]["const"] == (
        "synthetic_fixture"
    )
    assert all_of[0]["then"]["properties"]["data_classification"]["const"] == (
        "synthetic"
    )
    assert all_of[1]["if"]["properties"]["target_kind"]["const"] == (
        "frozen_public_document"
    )
    assert all_of[1]["then"]["properties"]["data_classification"]["const"] == ("public")
    transport_schema = schema["$defs"]["ProviderTransport"]
    transport_models = [
        schema["$defs"][reference["$ref"].rsplit("/", 1)[1]]
        for reference in transport_schema["anyOf"]
    ]
    disabled = next(
        model
        for model in transport_models
        if model["properties"]["allowed"]["const"] is False
    )
    enabled = next(
        model
        for model in transport_models
        if model["properties"]["allowed"]["const"] is True
    )
    assert disabled["properties"]["provider"]["const"] == "none"
    assert disabled["properties"]["endpoint_class"]["const"] == "none"
    assert enabled["properties"]["provider"]["enum"] == [
        "openai",
        "anthropic",
        "google",
    ]
    assert enabled["properties"]["endpoint_class"]["const"] == "official_model_api"
