"""Deterministic temporal-v2 requests, schedule, and append-only runner."""

from __future__ import annotations

import hashlib
import json
import os
from collections import defaultdict, deque
from collections.abc import Callable
from importlib.metadata import version
from pathlib import Path

from cti_provenance.evaluation import (
    JSON,
    build_temporal_rubric,
    canonical_json,
    load_json,
    load_jsonl,
)

GOLD_KEYS = {
    "readable_reference_answer",
    "expected_components",
    "required_evidence_ids",
    "derivation_records",
    "authority_rationale",
    "ambiguity_notes",
    "evaluator_bindings",
    "source_id",
    "source_sha256",
    "evidence_id",
}


class RunStopped(RuntimeError):
    """The run cannot continue without violating a frozen stop rule."""


class RetryableProviderError(RuntimeError):
    """The provider failed before returning an accepted output."""


class UncertainProviderError(RuntimeError):
    """The provider outcome may be accepted or billable and must not retry."""


def compact(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=True)


def sha256(value: bytes | str) -> str:
    data = value.encode("utf-8") if isinstance(value, str) else value
    return hashlib.sha256(data).hexdigest()


def artifact_hash(path: Path) -> str:
    return sha256(path.read_bytes())


def _schema(method: str, oracle: bool = False) -> JSON:
    properties: JSON = {
        "final_answer": {"type": "string"},
        "citations": {"type": "array", "items": {"type": "string"}},
    }
    if method == "state_first" and not oracle:
        for name in ("old_state", "new_state", "change"):
            properties[name] = {"type": "string"}
        for name in (
            "old_state_citations",
            "new_state_citations",
            "change_citations",
        ):
            properties[name] = {"type": "array", "items": {"type": "string"}}
    if oracle:
        properties["change"] = {"type": "string"}
        properties["change_citations"] = {
            "type": "array",
            "items": {"type": "string"},
        }
    return {
        "type": "object",
        "properties": properties,
        "required": list(properties),
        "additionalProperties": False,
    }


def _packet_projection(packet: JSON) -> JSON:
    documents = []
    for document in packet["documents"]:
        documents.append(
            {
                key: document[key]
                for key in (
                    "document_alias",
                    "neutral_title",
                    "state_label",
                    "available_by_utc",
                    "temporal_basis",
                    "publisher_identity",
                    "source_class",
                    "evidence",
                )
            }
        )
    return {
        "packet_id": packet["packet_id"],
        "case_id": packet["case_id"],
        "question": packet["question"],
        "cutoff_utc": packet["cutoff_utc"],
        "documents": documents,
    }


def _state(question: JSON, kind: str) -> str:
    component = next(
        item for item in question["expected_components"] if item["kind"] == kind
    )
    value = component["value"]
    return value if isinstance(value, str) else compact(value)


def build_request(root: Path, cell: JSON, question: JSON, packet: JSON) -> JSON:
    design = load_json(root / "configs/experiments/temporal-v2.json")
    provider = design["provider_intent"]
    oracle = cell["kind"] == "oracle"
    method = (
        "state_first"
        if oracle
        else design["factorial"]["conditions"][cell["condition"]]["method"]
    )
    template_name = (
        f"temporal-v2-{'state-first' if method == 'state_first' else 'direct'}.txt"
    )
    template = (root / "prompts" / template_name).read_text(encoding="utf-8").strip()
    if oracle:
        shared = template.split("\n\nReturn one JSON object", 1)[0]
        template = (
            f"{shared}\n\nOracle diagnostic: the reviewed states are supplied. "
            "Return exactly change, change_citations, final_answer, and citations."
            f"\nOld state: {_state(question, 'old_value')}"
            f"\nNew state: {_state(question, 'new_value')}"
        )
    prompt = (
        f"{template}\n\nQuestion and evidence packet:\n"
        f"{canonical_json(_packet_projection(packet)).strip()}"
    )
    request: JSON = {
        "model": provider["model"],
        "input": prompt,
        "max_output_tokens": provider["max_output_tokens"],
        "reasoning": {"effort": provider["reasoning_effort"]},
        "service_tier": provider["service_tier"],
        "store": provider["store"],
        "background": provider["background"],
        "tools": provider["tools"],
        "tool_choice": provider["tool_choice"],
    }
    schema_enforced = oracle or bool(
        design["factorial"]["conditions"][cell["condition"]]["schema_enforced"]
    )
    if schema_enforced:
        request["text"] = {
            "format": {
                "type": "json_schema",
                "name": "cti_temporal_answer",
                "strict": True,
                "schema": _schema(method, oracle),
            }
        }
    _check_leakage(request, question, oracle)
    return request


def _check_leakage(request: JSON, question: JSON, oracle: bool) -> None:
    def walk(value: object) -> None:
        if isinstance(value, dict):
            if GOLD_KEYS & value.keys():
                raise RunStopped("request contains a gold-only key")
            for child in value.values():
                walk(child)
        elif isinstance(value, list):
            for child in value:
                walk(child)

    walk(request)
    serialized = compact(request)
    reference = str(question["readable_reference_answer"]).split(
        " Structured component coverage:", 1
    )[0]
    delta = _state(question, "delta_kind")
    if reference in serialized or delta in serialized:
        raise RunStopped("request contains the reviewed final answer or delta label")
    if not oracle and "Oracle diagnostic" in serialized:
        raise RunStopped("factorial request contains oracle state values")


def _case_order(questions: list[JSON]) -> list[JSON]:
    groups: dict[str, deque[JSON]] = defaultdict(deque)
    for question in sorted(questions, key=lambda item: item["case_id"]):
        groups[question["dependency_id"]].append(question)
    ordered: list[JSON] = []
    while any(groups.values()):
        for dependency in sorted(groups):
            if groups[dependency]:
                ordered.append(groups[dependency].popleft())
    return ordered


def build_schedule(root: Path) -> tuple[list[JSON], list[JSON]]:
    design = load_json(root / "configs/experiments/temporal-v2.json")
    corpus = load_json(root / design["source_artifacts"]["questions"])
    packets_file = load_json(root / design["source_artifacts"]["packets"])
    questions = [
        question
        for question in corpus["questions"]
        if question["slice"] == design["factorial"]["case_slice"]
    ]
    ordered_questions = _case_order(questions)
    question_by_id = {question["case_id"]: question for question in questions}
    packet_by_id = {packet["case_id"]: packet for packet in packets_file["packets"]}
    oracle_ids = design["oracle"]["case_ids"]
    condition_orders = design["schedule"]["condition_orders"]
    cells: list[JSON] = []
    requests: list[JSON] = []

    def add(question: JSON, condition: str, trial: int, kind: str) -> None:
        identity = compact(
            [design["experiment_version"], question["case_id"], condition, trial]
        )
        cell: JSON = {
            "ordinal": len(cells),
            "cell_id": sha256(identity),
            "case_id": question["case_id"],
            "dependency_id": question["dependency_id"],
            "split": question["split"],
            "condition": condition,
            "trial": trial,
            "kind": kind,
        }
        request = build_request(root, cell, question, packet_by_id[question["case_id"]])
        cell["request_sha256"] = sha256(compact(request))
        cells.append(cell)
        requests.append(request)

    for trial in range(1, design["factorial"]["trials"] + 1):
        oracle_index = 0
        for index, question in enumerate(ordered_questions):
            order = condition_orders[(index + trial - 1) % len(condition_orders)]
            for condition in order:
                add(question, condition, trial, "factorial")
            if (index + 1) % 3 == 0:
                add(question_by_id[oracle_ids[oracle_index]], "O", trial, "oracle")
                oracle_index += 1
    if len(cells) != design["schedule"]["total_cells"]:
        raise RunStopped("schedule cell count drifted")
    return cells, requests


def schedule_bytes(cells: list[JSON]) -> bytes:
    return "".join(f"{compact(cell)}\n" for cell in cells).encode()


def request_set_hash(requests: list[JSON]) -> str:
    return sha256("".join(f"{compact(request)}\n" for request in requests))


def freeze_offline_artifacts(root: Path) -> JSON:
    rubric_path = root / "configs/experiments/temporal-v2-rubric.json"
    rubric_path.write_text(
        canonical_json(build_temporal_rubric(root)), encoding="utf-8"
    )
    cells, requests = build_schedule(root)
    schedule_path = root / "data/experiments/temporal-v2-schedule.jsonl"
    schedule_path.write_bytes(schedule_bytes(cells))
    design = load_json(root / "configs/experiments/temporal-v2.json")
    corpus = load_json(root / design["source_artifacts"]["questions"])
    packet_file = load_json(root / design["source_artifacts"]["packets"])
    temporal_ids = {
        question["case_id"]
        for question in corpus["questions"]
        if question["slice"] == design["factorial"]["case_slice"]
    }
    egress_packets = [
        _packet_projection(packet)
        for packet in packet_file["packets"]
        if packet["case_id"] in temporal_ids
    ]
    egress_bytes = compact(egress_packets).encode()
    assertion_cases = sorted(
        packet["case_id"]
        for packet in egress_packets
        if "assertion" in compact(packet) and "absent" in compact(packet)
    )
    request_sizes = [len(compact(request).encode()) for request in requests]
    maximum_attempts = len(cells) * design["retry_policy"]["maximum_attempts_per_cell"]
    pricing = design["provider_intent"]["pricing"]
    input_reservation = max(request_sizes)
    retry_cost = (
        maximum_attempts * input_reservation * pricing["input_per_million_usd"]
        + maximum_attempts
        * design["provider_intent"]["max_output_tokens"]
        * pricing["output_per_million_usd"]
    ) / 1_000_000
    smoke_cases = set(design["schedule"]["smoke_case_ids"])
    smoke_ids = [
        cell["cell_id"]
        for cell in cells
        if cell["trial"] == design["schedule"]["smoke_trial"]
        and cell["case_id"] in smoke_cases
    ]
    tracked = {
        "descriptor": root / "configs/experiments/temporal-v2.json",
        "direct_prompt": root / "prompts/temporal-v2-direct.txt",
        "state_first_prompt": root / "prompts/temporal-v2-state-first.txt",
        "rubric": rubric_path,
        "grader": root / "src/cti_provenance/evaluation.py",
        "harness": root / "src/cti_provenance/experiment.py",
        "questions": root / design["source_artifacts"]["questions"],
        "packets": root / design["source_artifacts"]["packets"],
    }
    manifest: JSON = {
        "schema_version": "cti-temporal-offline-manifest-v2",
        "experiment_version": design["experiment_version"],
        "artifact_sha256": {
            name: artifact_hash(path) for name, path in tracked.items()
        },
        "schedule_sha256": sha256(schedule_bytes(cells)),
        "request_set_sha256": request_set_hash(requests),
        "request_count": len(requests),
        "request_utf8_bytes": sum(request_sizes),
        "maximum_request_utf8_bytes": input_reservation,
        "input_token_count_status": "not_sent_to_provider_before_approval",
        "input_token_reservation_per_attempt": input_reservation,
        "input_reservation_basis": "UTF-8 byte count is a conservative token ceiling",
        "unique_request_count": len({compact(request) for request in requests}),
        "smoke_cell_ids": smoke_ids,
        "provider_sdk": f"openai=={version('openai')}",
        "maximum_attempts": maximum_attempts,
        "base_cost_ceiling_usd": round(retry_cost / 2, 6),
        "retry_inclusive_cost_ceiling_usd": round(retry_cost, 6),
        "cost_cap_usd": design["cost_cap_usd"],
        "pricing_assumes_cached_input_tokens": 0,
        "egress_inventory": {
            "packet_count": len(egress_packets),
            "document_count": sum(
                len(packet["documents"]) for packet in egress_packets
            ),
            "span_count": sum(
                len(document["evidence"])
                for packet in egress_packets
                for document in packet["documents"]
            ),
            "utf8_bytes": len(egress_bytes),
            "sha256": sha256(egress_bytes),
            "supplied_absence_assertion_case_ids": assertion_cases,
        },
        "raw_output_directory": "${CTI_TEMPORAL_RAW_DIR}",
    }
    manifest_path = root / "configs/experiments/temporal-v2-manifest.json"
    manifest_path.write_text(canonical_json(manifest), encoding="utf-8")
    manifest["manifest_sha256"] = artifact_hash(manifest_path)
    return manifest


def validate_frozen_v2(root: Path) -> JSON:
    manifest_path = root / "configs/experiments/temporal-v2-manifest.json"
    manifest = load_json(manifest_path)
    cells, requests = build_schedule(root)
    frozen_cells = load_jsonl(root / "data/experiments/temporal-v2-schedule.jsonl")
    if schedule_bytes(cells) != schedule_bytes(frozen_cells):
        raise RunStopped("frozen schedule does not regenerate byte-identically")
    if sha256(schedule_bytes(cells)) != manifest["schedule_sha256"]:
        raise RunStopped("schedule hash does not match manifest")
    if request_set_hash(requests) != manifest["request_set_sha256"]:
        raise RunStopped("request-set hash does not match manifest")
    rubric = canonical_json(build_temporal_rubric(root))
    rubric_path = root / "configs/experiments/temporal-v2-rubric.json"
    if rubric_path.read_text(encoding="utf-8") != rubric:
        raise RunStopped("semantic rubric does not regenerate byte-identically")
    artifact_paths = {
        "descriptor": root / "configs/experiments/temporal-v2.json",
        "direct_prompt": root / "prompts/temporal-v2-direct.txt",
        "state_first_prompt": root / "prompts/temporal-v2-state-first.txt",
        "rubric": rubric_path,
        "grader": root / "src/cti_provenance/evaluation.py",
        "harness": root / "src/cti_provenance/experiment.py",
        "questions": root / "data/benchmark/questions.json",
        "packets": root / "data/benchmark/evidence-packets.json",
    }
    actual_hashes = {name: artifact_hash(path) for name, path in artifact_paths.items()}
    if actual_hashes != manifest["artifact_sha256"]:
        raise RunStopped("artifact hash does not match manifest")
    return {
        "cells": len(cells),
        "manifest_sha256": artifact_hash(manifest_path),
        "request_set_sha256": request_set_hash(requests),
        "schedule_sha256": sha256(schedule_bytes(cells)),
    }


def make_openai_provider(
    raw_directory: Path, repository_root: Path
) -> Callable[[JSON], JSON]:
    raw_directory = raw_directory.resolve()
    repository_root = repository_root.resolve()
    if not raw_directory.is_absolute() or raw_directory.is_relative_to(repository_root):
        raise RunStopped(
            "raw output directory must be absolute and outside the repository"
        )
    if any("onedrive" in part.casefold() for part in raw_directory.parts):
        raise RunStopped("raw output directory must be outside synchronized folders")

    def call(request: JSON) -> JSON:
        from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAI

        client = OpenAI(max_retries=0)
        try:
            response = client.responses.create(**request)
        except APIStatusError as error:
            if error.status_code == 429 or error.status_code >= 500:
                raise RetryableProviderError(
                    f"provider status {error.status_code}"
                ) from error
            raise RunStopped(
                f"provider rejected request with status {error.status_code}"
            ) from error
        except (APIConnectionError, APITimeoutError) as error:
            raise UncertainProviderError("connection outcome is uncertain") from error
        try:
            raw_directory.mkdir(parents=True, exist_ok=True)
            raw_path = raw_directory / f"{sha256(response.id)}.json"
            with raw_path.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(response.model_dump_json(indent=2))
                stream.flush()
                os.fsync(stream.fileno())
            usage = response.usage
            cached = usage.input_tokens_details.cached_tokens if usage else 0
            try:
                output = json.loads(response.output_text)
            except json.JSONDecodeError:
                output = response.output_text
            return {
                "model": response.model,
                "service_tier": response.service_tier,
                "status": response.status,
                "response_id_sha256": sha256(response.id),
                "output": output,
                "usage": {
                    "input_tokens": usage.input_tokens if usage else 0,
                    "cached_input_tokens": cached,
                    "output_tokens": usage.output_tokens if usage else 0,
                },
            }
        except Exception as error:
            raise UncertainProviderError(
                "accepted response could not be persisted"
            ) from error

    return call


def _append(path: Path, record: JSON) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(compact(record) + "\n")
        stream.flush()
        os.fsync(stream.fileno())


def run_schedule(
    cells: list[JSON],
    requests: list[JSON],
    provider: Callable[[JSON], JSON],
    ledger: Path,
    manifest_sha256: str,
    expected_model: str,
    maximum_attempts: int = 2,
    maximum_cells: int | None = None,
) -> None:
    history = load_jsonl(ledger) if ledger.exists() else []
    header = {"record_type": "run_header", "manifest_sha256": manifest_sha256}
    if history and history[0] != header:
        raise RunStopped("ledger manifest mismatch")
    if not history:
        _append(ledger, header)
    blocked = {
        "model_mismatch",
        "uncertain_outcome",
    }
    if any(record.get("status") in blocked for record in history):
        raise RunStopped("ledger contains a non-resumable outcome")
    started = {
        (record.get("cell_id"), record.get("attempt"))
        for record in history
        if record.get("status") == "attempt_started"
    }
    closed = {
        (record.get("cell_id"), record.get("attempt"))
        for record in history
        if record.get("status")
        in {"retryable_error", "uncertain_outcome", "model_mismatch", "completed"}
    }
    if started - closed:
        raise RunStopped("ledger contains an unclosed provider attempt")
    terminal = {
        record["cell_id"]
        for record in history
        if record.get("status") in {"completed", "provider_failure"}
    }
    attempts: dict[str, int] = defaultdict(int)
    for record in history:
        if "cell_id" in record:
            attempts[record["cell_id"]] = max(
                attempts[record["cell_id"]], int(record.get("attempt", 0))
            )
    processed = 0
    for cell, request in zip(cells, requests, strict=True):
        cell_id = cell["cell_id"]
        if cell_id in terminal:
            continue
        if maximum_cells is not None and processed >= maximum_cells:
            return
        if sha256(compact(request)) != cell["request_sha256"]:
            raise RunStopped("request hash drifted")
        while attempts[cell_id] < maximum_attempts:
            attempts[cell_id] += 1
            base: JSON = {
                "record_type": "attempt",
                "manifest_sha256": manifest_sha256,
                "cell_id": cell_id,
                "attempt": attempts[cell_id],
            }
            _append(ledger, {**base, "status": "attempt_started"})
            try:
                result = provider(request)
            except RetryableProviderError as error:
                base["status"] = "retryable_error"
                base["error"] = str(error)
                _append(ledger, base)
                continue
            except UncertainProviderError as error:
                base["status"] = "uncertain_outcome"
                base["error"] = str(error)
                _append(ledger, base)
                raise RunStopped("uncertain provider outcome") from error
            if result.get("model") != expected_model:
                base["status"] = "model_mismatch"
                _append(ledger, base)
                raise RunStopped("provider model mismatch")
            base.update({"status": "completed", "result": result})
            _append(ledger, base)
            break
        else:
            _append(
                ledger,
                {
                    "record_type": "outcome",
                    "manifest_sha256": manifest_sha256,
                    "cell_id": cell_id,
                    "status": "provider_failure",
                },
            )
        processed += 1
