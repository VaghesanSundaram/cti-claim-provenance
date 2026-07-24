"""Pure, strict authorization-manifest validation for offline safety checks."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Annotated, Literal, Self

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StrictStr,
    StringConstraints,
    field_validator,
    model_validator,
)

NonEmptyString = Annotated[
    StrictStr,
    StringConstraints(strip_whitespace=True, min_length=1, pattern=r".*\S.*"),
]
AllowedOutcome = Literal[
    "identify_or_classify",
    "cite_evidence",
    "recommend_remediation",
    "propose_local_regression_test",
    "evaluate_simulated_policy_behavior",
]
ProhibitedOutcome = Literal[
    "credential_collection",
    "persistence",
    "evasion_or_stealth",
    "malware_or_phishing",
    "data_exfiltration",
    "destructive_action",
    "denial_of_service",
    "live_target_scanning_or_exploitation",
]

_REQUIRED_PROHIBITED_OUTCOMES = frozenset(
    {
        "credential_collection",
        "persistence",
        "evasion_or_stealth",
        "malware_or_phishing",
        "data_exfiltration",
        "destructive_action",
        "denial_of_service",
        "live_target_scanning_or_exploitation",
    }
)


class NoProviderTransport(BaseModel):
    """Provider transport disabled; this class opens no connection."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    allowed: Literal[False]
    provider: Literal["none"]
    endpoint_class: Literal["none"]


class OfficialProviderTransport(BaseModel):
    """A named official API transport posture; this class opens no connection."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    allowed: Literal[True]
    provider: Literal["openai", "anthropic", "google"]
    endpoint_class: Literal["official_model_api"]


type ProviderTransport = NoProviderTransport | OfficialProviderTransport


class AuthorizationManifest(BaseModel):
    """Frozen protocol scope, never an authorization for provider egress."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        strict=True,
        json_schema_extra={
            "allOf": [
                {
                    "if": {
                        "properties": {"target_kind": {"const": "synthetic_fixture"}},
                        "required": ["target_kind"],
                    },
                    "then": {
                        "properties": {"data_classification": {"const": "synthetic"}},
                        "required": ["data_classification"],
                    },
                },
                {
                    "if": {
                        "properties": {
                            "target_kind": {"const": "frozen_public_document"}
                        },
                        "required": ["target_kind"],
                    },
                    "then": {
                        "properties": {"data_classification": {"const": "public"}},
                        "required": ["data_classification"],
                    },
                },
            ]
        },
    )

    authorization_id: NonEmptyString
    project: Literal["cross_tool_authz", "cti_provenance"]
    purpose: Literal["defensive_evaluation"]
    owner: Literal["local_project"]
    target_kind: Literal["synthetic_fixture", "frozen_public_document"]
    target_ids: tuple[NonEmptyString, ...] = Field(
        min_length=1, json_schema_extra={"uniqueItems": True}
    )
    target_network_access: Literal[False]
    provider_transport: ProviderTransport
    external_or_live_target: Literal[False]
    data_classification: Literal["synthetic", "public"]
    allowed_outcomes: tuple[AllowedOutcome, ...] = Field(
        min_length=1, json_schema_extra={"uniqueItems": True}
    )
    prohibited_outcomes: tuple[ProhibitedOutcome, ...] = Field(
        min_length=8, max_length=8, json_schema_extra={"uniqueItems": True}
    )
    approved_by: Literal["project_protocol"]
    protocol_version: Literal["provider-safety-v1"]

    @field_validator(
        "target_ids", "allowed_outcomes", "prohibited_outcomes", mode="before"
    )
    @classmethod
    def validate_array_input(cls, value: object) -> tuple[object, ...]:
        """Accept JSON/YAML arrays while freezing them before strict validation."""

        if isinstance(value, (list, tuple)):
            return tuple(value)
        raise ValueError("manifest collections must be arrays")

    @field_validator("target_ids", "allowed_outcomes", "prohibited_outcomes")
    @classmethod
    def validate_unique_non_empty_values(
        cls, values: tuple[str, ...]
    ) -> tuple[str, ...]:
        if not values:
            raise ValueError("manifest lists must not be empty")
        if len(values) != len(set(values)):
            raise ValueError("manifest list values must be unique")
        return values

    @model_validator(mode="after")
    def validate_protocol_scope(self) -> Self:
        expected_classification = {
            "synthetic_fixture": "synthetic",
            "frozen_public_document": "public",
        }[self.target_kind]
        if self.data_classification != expected_classification:
            raise ValueError("target_kind and data_classification must agree")
        if set(self.prohibited_outcomes) != _REQUIRED_PROHIBITED_OUTCOMES:
            raise ValueError("prohibited_outcomes must contain the complete frozen set")
        return self

    def canonical_json(self) -> str:
        """Return stable JSON suitable for an offline provenance hash."""

        return canonical_authorization_manifest_json(self)

    def sha256(self) -> str:
        """Return the stable canonical-manifest SHA-256 digest."""

        return hashlib.sha256(self.canonical_json().encode("utf-8")).hexdigest()


def canonical_authorization_manifest_json(manifest: AuthorizationManifest) -> str:
    """Serialize a manifest with its exact array order bound into the hash."""

    return json.dumps(
        manifest.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )


class _UniqueKeySafeLoader(yaml.SafeLoader):
    """Safe YAML loader that also rejects duplicate mapping keys recursively."""

    def construct_mapping(
        self, node: yaml.MappingNode, deep: bool = False
    ) -> dict[object, object]:
        mapping: dict[object, object] = {}
        for key_node, value_node in node.value:
            key = self.construct_object(key_node, deep=deep)
            try:
                duplicate = key in mapping
            except TypeError as exc:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    "found an unhashable mapping key",
                    key_node.start_mark,
                ) from exc
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    "while constructing a mapping",
                    node.start_mark,
                    f"found duplicate key {key!r}",
                    key_node.start_mark,
                )
            mapping[key] = self.construct_object(value_node, deep=deep)
        return mapping


def load_authorization_manifest(path: Path) -> AuthorizationManifest:
    """Safely load and validate an explicit local manifest without network access."""

    try:
        with path.open("r", encoding="utf-8") as stream:
            raw = yaml.load(stream, Loader=_UniqueKeySafeLoader)
    except yaml.YAMLError as exc:
        raise ValueError("invalid YAML authorization manifest") from exc
    return AuthorizationManifest.model_validate(raw)
