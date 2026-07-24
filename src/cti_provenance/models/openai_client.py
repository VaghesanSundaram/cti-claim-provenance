"""Narrow, stdlib-only adapter for the OpenAI Responses endpoint.

This module deliberately owns no scheduling, persistence, or retry loop.  It
turns one prevalidated request into a redacted result; callers must persist
their own attempt state *before* invoking :meth:`OpenAIResponsesAdapter.send`.
"""

from __future__ import annotations

import hashlib
import json
import socket
from collections.abc import Mapping
from dataclasses import dataclass, field
from decimal import Decimal
from typing import Any, Literal, Protocol
from urllib.error import HTTPError, URLError
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pydantic import SecretStr

RESPONSES_ENDPOINT = "https://api.openai.com/v1/responses"
INPUT_RATE_PER_MILLION = Decimal("1.00")
CACHED_INPUT_RATE_PER_MILLION = Decimal("0.10")
OUTPUT_RATE_PER_MILLION = Decimal("6.00")
MAX_RESPONSE_BYTES = 2_000_000

ResultKind = Literal[
    "completed",
    "refusal",
    "incomplete",
    "api_error",
    "transport_error",
    "timeout",
    "invalid_response",
]
RetryClass = Literal[
    "not_retryable",
    "rate_limited",
    "transient_server",
    "transient_transport",
    "ambiguous_timeout",
]


def _non_empty(name: str, value: str) -> None:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} must be a non-empty string")


def _canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


@dataclass(frozen=True, slots=True)
class OpenAIMessage:
    """One textual developer or user message supplied to Responses."""

    role: Literal["developer", "user"]
    content: str

    def __post_init__(self) -> None:
        if self.role not in {"developer", "user"}:
            raise ValueError("role must be developer or user")
        _non_empty("content", self.content)

    def as_payload(self) -> dict[str, str]:
        return {"role": self.role, "content": self.content}


@dataclass(frozen=True, slots=True)
class OpenAIResponseRequest:
    """An immutable JSON-response request with optional schema enforcement."""

    model: str
    input: tuple[OpenAIMessage, ...]
    schema_name: str
    json_schema: Mapping[str, object]
    max_output_tokens: int
    schema_enforced: bool = True
    endpoint: str = RESPONSES_ENDPOINT

    def __post_init__(self) -> None:
        _non_empty("model", self.model)
        _non_empty("schema_name", self.schema_name)
        if not self.input:
            raise ValueError("input must contain at least one message")
        if not all(isinstance(message, OpenAIMessage) for message in self.input):
            raise ValueError("input must contain OpenAIMessage instances")
        if not isinstance(self.json_schema, Mapping) or not self.json_schema:
            raise ValueError("json_schema must be a non-empty mapping")
        if (
            not isinstance(self.max_output_tokens, int)
            or isinstance(self.max_output_tokens, bool)
            or self.max_output_tokens <= 0
        ):
            raise ValueError("max_output_tokens must be a positive integer")
        if self.endpoint != RESPONSES_ENDPOINT:
            raise ValueError("endpoint must be the exact official Responses endpoint")

    def payload(self) -> dict[str, object]:
        """Build the exact allowed request fields, excluding credentials."""

        response_format: dict[str, object] = (
            {
                "type": "json_schema",
                "name": self.schema_name,
                "schema": dict(self.json_schema),
                "strict": True,
            }
            if self.schema_enforced
            else {"type": "json_object"}
        )
        return {
            "model": self.model,
            "input": [message.as_payload() for message in self.input],
            "text": {"format": response_format},
            "reasoning": {"effort": "medium"},
            "max_output_tokens": self.max_output_tokens,
            "store": False,
            "tools": [],
            "tool_choice": "none",
            "service_tier": "default",
            "background": False,
        }

    def semantic_sha256(self) -> str:
        """Hash the full semantic payload; credentials are never part of it."""

        return hashlib.sha256(
            _canonical_json(self.payload()).encode("utf-8")
        ).hexdigest()


@dataclass(frozen=True, slots=True)
class OpenAIHttpRequest:
    """One in-memory HTTP request.  Its authorization value is never logged."""

    endpoint: str
    body: bytes = field(repr=False)
    authorization: str = field(repr=False)
    headers: Mapping[str, str] = field(repr=False)


@dataclass(frozen=True, slots=True)
class OpenAIHttpResponse:
    """Transport data retained only long enough to parse a redacted result."""

    status_code: int
    headers: Mapping[str, str]
    body: bytes = field(repr=False)


class OpenAITransport(Protocol):
    """Injectable boundary used by tests and by the stdlib implementation."""

    def __call__(
        self, request: OpenAIHttpRequest, *, timeout_seconds: float
    ) -> OpenAIHttpResponse: ...


@dataclass(frozen=True, slots=True)
class OpenAIResult:
    """Normalized outcome plus private-only exact response material.

    Callers must quarantine ``raw_response_body`` and selected headers outside
    version control and synchronization roots; both fields are excluded from
    representations.
    """

    kind: ResultKind
    semantic_request_sha256: str
    http_status: int | None
    provider_request_id_sha256: str | None
    model: str | None
    service_tier: str | None
    output_text: str | None = field(repr=False)
    refusal: str | None = field(repr=False)
    incomplete_reason: str | None
    input_tokens: int
    cached_input_tokens: int
    output_tokens: int
    reasoning_tokens: int
    error_code: str | None
    raw_response_body: bytes | None = field(repr=False)
    selected_response_headers: Mapping[str, str] = field(repr=False)

    def __post_init__(self) -> None:
        if self.cached_input_tokens > self.input_tokens:
            raise ValueError("cached_input_tokens cannot exceed input_tokens")
        if min(self.input_tokens, self.cached_input_tokens, self.output_tokens) < 0:
            raise ValueError("usage values cannot be negative")
        if not 0 <= self.reasoning_tokens <= self.output_tokens:
            raise ValueError("reasoning_tokens must be within output_tokens")

    @property
    def estimated_cost_usd(self) -> Decimal:
        return estimate_cost_usd(
            self.input_tokens, self.cached_input_tokens, self.output_tokens
        )

    @property
    def retry_class(self) -> RetryClass:
        return classify_retryability(self.kind, self.http_status, self.error_code)


def preflight(request: OpenAIResponseRequest, api_key: SecretStr | str) -> None:
    """Validate local invariants before any caller performs provider egress."""

    if request.endpoint != RESPONSES_ENDPOINT:
        raise ValueError("endpoint must be the exact official Responses endpoint")
    secret = api_key.get_secret_value() if isinstance(api_key, SecretStr) else api_key
    _non_empty("api_key", secret)
    # Verify serializability now so a request cannot fail after attempt reservation.
    _canonical_json(request.payload())


def estimate_cost_usd(
    input_tokens: int, cached_input_tokens: int, output_tokens: int
) -> Decimal:
    """Calculate documented standard-tier USD cost without rounding it away."""

    if min(input_tokens, cached_input_tokens, output_tokens) < 0:
        raise ValueError("token counts cannot be negative")
    if cached_input_tokens > input_tokens:
        raise ValueError("cached_input_tokens cannot exceed input_tokens")
    return (
        Decimal(input_tokens - cached_input_tokens) * INPUT_RATE_PER_MILLION
        + Decimal(cached_input_tokens) * CACHED_INPUT_RATE_PER_MILLION
        + Decimal(output_tokens) * OUTPUT_RATE_PER_MILLION
    ) / Decimal(1_000_000)


def classify_retryability(
    kind: ResultKind,
    http_status: int | None,
    error_code: str | None = None,
) -> RetryClass:
    """Classify only; this adapter never issues a second request itself."""

    if kind == "timeout":
        return "ambiguous_timeout"
    if kind == "transport_error":
        return "transient_transport"
    if (
        kind == "api_error"
        and http_status == 429
        and error_code not in {"insufficient_quota", "billing_hard_limit_reached"}
    ):
        return "rate_limited"
    if kind == "api_error" and http_status in {500, 503}:
        return "transient_server"
    return "not_retryable"


def _header(headers: Mapping[str, str], name: str) -> str | None:
    lower_name = name.lower()
    for key, value in headers.items():
        if key.lower() == lower_name:
            return value
    return None


def _request_id_hash(headers: Mapping[str, str]) -> str | None:
    request_id = _header(headers, "x-request-id")
    if not request_id:
        return None
    return hashlib.sha256(request_id.encode("utf-8")).hexdigest()


def _selected_response_headers(headers: Mapping[str, str]) -> dict[str, str]:
    allowed = {
        "content-type",
        "x-request-id",
        "x-ratelimit-limit-requests",
        "x-ratelimit-limit-tokens",
        "x-ratelimit-remaining-requests",
        "x-ratelimit-remaining-tokens",
        "x-ratelimit-reset-requests",
        "x-ratelimit-reset-tokens",
    }
    return {
        key.casefold(): value
        for key, value in headers.items()
        if key.casefold() in allowed
    }


def _usage(payload: Mapping[str, object]) -> tuple[int, int, int, int] | None:
    usage = payload.get("usage")
    if not isinstance(usage, Mapping):
        return None
    input_tokens = usage.get("input_tokens")
    output_tokens = usage.get("output_tokens")
    total_tokens = usage.get("total_tokens")
    details = usage.get("input_tokens_details")
    cached = details.get("cached_tokens") if isinstance(details, Mapping) else None
    output_details = usage.get("output_tokens_details")
    reasoning = (
        output_details.get("reasoning_tokens")
        if isinstance(output_details, Mapping)
        else None
    )
    values = (input_tokens, cached, output_tokens, reasoning, total_tokens)
    if not all(
        isinstance(value, int) and not isinstance(value, bool) and value >= 0
        for value in values
    ):
        return None
    assert isinstance(input_tokens, int)
    assert isinstance(cached, int)
    assert isinstance(output_tokens, int)
    assert isinstance(reasoning, int)
    assert isinstance(total_tokens, int)
    if (
        cached > input_tokens
        or reasoning > output_tokens
        or total_tokens != input_tokens + output_tokens
    ):
        return None
    return (input_tokens, cached, output_tokens, reasoning)


def _provider_request_id_hash(
    headers: Mapping[str, str],
    payload: Mapping[str, object],
) -> str | None:
    header_hash = _request_id_hash(headers)
    if header_hash is not None:
        return header_hash
    response_id = payload.get("id")
    if not isinstance(response_id, str) or not response_id:
        return None
    return hashlib.sha256(response_id.encode("utf-8")).hexdigest()


def _content_result(
    payload: Mapping[str, object], request_sha256: str, response: OpenAIHttpResponse
) -> OpenAIResult:
    usage = _usage(payload)
    if usage is None:
        input_tokens = cached_input_tokens = output_tokens = reasoning_tokens = 0
    else:
        input_tokens, cached_input_tokens, output_tokens, reasoning_tokens = usage
    model = payload.get("model") if isinstance(payload.get("model"), str) else None
    service_tier = (
        payload.get("service_tier")
        if isinstance(payload.get("service_tier"), str)
        else None
    )
    status = payload.get("status")
    common: dict[str, Any] = {
        "semantic_request_sha256": request_sha256,
        "http_status": response.status_code,
        "provider_request_id_sha256": _provider_request_id_hash(
            response.headers,
            payload,
        ),
        "model": model,
        "service_tier": service_tier,
        "input_tokens": input_tokens,
        "cached_input_tokens": cached_input_tokens,
        "output_tokens": output_tokens,
        "reasoning_tokens": reasoning_tokens,
        "error_code": "invalid_usage" if usage is None else None,
        "raw_response_body": response.body,
        "selected_response_headers": _selected_response_headers(response.headers),
    }
    if usage is None:
        return OpenAIResult(
            kind="invalid_response",
            output_text=None,
            refusal=None,
            incomplete_reason=None,
            **common,
        )
    if status == "incomplete":
        details = payload.get("incomplete_details")
        reason = details.get("reason") if isinstance(details, Mapping) else None
        return OpenAIResult(
            kind="incomplete",
            output_text=None,
            refusal=None,
            incomplete_reason=reason if isinstance(reason, str) else None,
            **common,
        )
    if status != "completed":
        return OpenAIResult(
            kind="invalid_response",
            output_text=None,
            refusal=None,
            incomplete_reason=None,
            **common,
        )
    output = payload.get("output")
    if not isinstance(output, list):
        return OpenAIResult(
            kind="invalid_response",
            output_text=None,
            refusal=None,
            incomplete_reason=None,
            **common,
        )
    parts: list[tuple[str, str]] = []
    for item in output:
        if not isinstance(item, Mapping) or item.get("type") != "message":
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for part in content:
            if not isinstance(part, Mapping):
                continue
            part_type = part.get("type")
            if part_type == "refusal" and isinstance(part.get("refusal"), str):
                parts.append(("refusal", part["refusal"]))
            if part_type == "output_text" and isinstance(part.get("text"), str):
                parts.append(("output_text", part["text"]))
    if len(parts) == 1 and parts[0][0] == "refusal":
        return OpenAIResult(
            kind="refusal",
            output_text=None,
            refusal=parts[0][1],
            incomplete_reason=None,
            **common,
        )
    if len(parts) == 1 and parts[0][0] == "output_text":
        return OpenAIResult(
            kind="completed",
            output_text=parts[0][1],
            refusal=None,
            incomplete_reason=None,
            **common,
        )
    return OpenAIResult(
        kind="invalid_response",
        output_text=None,
        refusal=None,
        incomplete_reason=None,
        **common,
    )


def _api_error_result(
    response: OpenAIHttpResponse, request_sha256: str
) -> OpenAIResult:
    error_code: str | None = None
    try:
        payload = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        payload = None
    if isinstance(payload, Mapping):
        error = payload.get("error")
        if isinstance(error, Mapping) and isinstance(error.get("code"), str):
            error_code = error["code"]
    return OpenAIResult(
        kind="api_error",
        semantic_request_sha256=request_sha256,
        http_status=response.status_code,
        provider_request_id_sha256=_request_id_hash(response.headers),
        model=None,
        service_tier=None,
        output_text=None,
        refusal=None,
        incomplete_reason=None,
        input_tokens=0,
        cached_input_tokens=0,
        output_tokens=0,
        reasoning_tokens=0,
        error_code=error_code,
        raw_response_body=response.body,
        selected_response_headers=_selected_response_headers(response.headers),
    )


def _stdlib_transport(
    request: OpenAIHttpRequest, *, timeout_seconds: float
) -> OpenAIHttpResponse:
    headers = dict(request.headers)
    headers["Authorization"] = request.authorization
    outbound = Request(
        request.endpoint, data=request.body, headers=headers, method="POST"
    )

    class _NoRedirect(HTTPRedirectHandler):
        def redirect_request(
            self,
            req: Request,
            fp: Any,
            code: int,
            msg: str,
            headers: Any,
            newurl: str,
        ) -> None:
            return None

    opener = build_opener(_NoRedirect())
    try:
        with opener.open(outbound, timeout=timeout_seconds) as inbound:
            body = inbound.read(MAX_RESPONSE_BYTES + 1)
            if len(body) > MAX_RESPONSE_BYTES:
                raise URLError("provider response exceeded byte ceiling")
            return OpenAIHttpResponse(
                inbound.status,
                dict(inbound.headers.items()),
                body,
            )
    except HTTPError as exc:
        body = exc.read(MAX_RESPONSE_BYTES + 1)
        if len(body) > MAX_RESPONSE_BYTES:
            raise URLError("provider error response exceeded byte ceiling") from exc
        return OpenAIHttpResponse(exc.code, dict(exc.headers.items()), body)


@dataclass(slots=True)
class OpenAIResponsesAdapter:
    """Adapter with an injectable transport and no import-time side effects."""

    transport: OpenAITransport = _stdlib_transport

    def send(
        self,
        request: OpenAIResponseRequest,
        api_key: SecretStr | str,
        *,
        timeout_seconds: float = 30.0,
    ) -> OpenAIResult:
        """Make one request; callers, not this method, decide whether to retry."""

        preflight(request, api_key)
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        secret = (
            api_key.get_secret_value() if isinstance(api_key, SecretStr) else api_key
        )
        assert isinstance(secret, str)  # narrow SecretStr|string for static analysis
        request_sha256 = request.semantic_sha256()
        outbound = OpenAIHttpRequest(
            endpoint=request.endpoint,
            body=_canonical_json(request.payload()).encode("utf-8"),
            authorization=f"Bearer {secret}",
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        try:
            response = self.transport(outbound, timeout_seconds=timeout_seconds)
        except TimeoutError:
            return OpenAIResult(
                kind="timeout",
                semantic_request_sha256=request_sha256,
                http_status=None,
                provider_request_id_sha256=None,
                model=None,
                service_tier=None,
                output_text=None,
                refusal=None,
                incomplete_reason=None,
                input_tokens=0,
                cached_input_tokens=0,
                output_tokens=0,
                reasoning_tokens=0,
                error_code=None,
                raw_response_body=None,
                selected_response_headers={},
            )
        except URLError as exc:
            safely_pre_send = isinstance(
                exc.reason,
                (socket.gaierror, ConnectionRefusedError),
            )
            return OpenAIResult(
                kind="transport_error" if safely_pre_send else "timeout",
                semantic_request_sha256=request_sha256,
                http_status=None,
                provider_request_id_sha256=None,
                model=None,
                service_tier=None,
                output_text=None,
                refusal=None,
                incomplete_reason=None,
                input_tokens=0,
                cached_input_tokens=0,
                output_tokens=0,
                reasoning_tokens=0,
                error_code=None,
                raw_response_body=None,
                selected_response_headers={},
            )
        if not 200 <= response.status_code < 300:
            return _api_error_result(response, request_sha256)
        try:
            parsed = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            parsed = None
        if not isinstance(parsed, Mapping):
            return OpenAIResult(
                kind="invalid_response",
                semantic_request_sha256=request_sha256,
                http_status=response.status_code,
                provider_request_id_sha256=_request_id_hash(response.headers),
                model=None,
                service_tier=None,
                output_text=None,
                refusal=None,
                incomplete_reason=None,
                input_tokens=0,
                cached_input_tokens=0,
                output_tokens=0,
                reasoning_tokens=0,
                error_code=None,
                raw_response_body=response.body,
                selected_response_headers=_selected_response_headers(response.headers),
            )
        return _content_result(parsed, request_sha256, response)
