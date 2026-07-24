from __future__ import annotations

import hashlib
import json
from decimal import Decimal
from urllib.error import URLError

import pytest
from pydantic import SecretStr

from cti_provenance.models.openai_client import (
    RESPONSES_ENDPOINT,
    OpenAIHttpRequest,
    OpenAIHttpResponse,
    OpenAIMessage,
    OpenAIResponseRequest,
    OpenAIResponsesAdapter,
    estimate_cost_usd,
    preflight,
)


def _request() -> OpenAIResponseRequest:
    return OpenAIResponseRequest(
        model="gpt-5.6-luna",
        input=(
            OpenAIMessage("developer", "Return JSON."),
            OpenAIMessage("user", "Case."),
        ),
        schema_name="claim_answer",
        json_schema={"type": "object", "additionalProperties": False},
        max_output_tokens=600,
    )


def _completed() -> bytes:
    return json.dumps(
        {
            "status": "completed",
            "service_tier": "default",
            "model": "gpt-5.6-luna-2026-07-01",
            "usage": {
                "input_tokens": 4000,
                "input_tokens_details": {"cached_tokens": 20},
                "output_tokens": 600,
                "output_tokens_details": {"reasoning_tokens": 100},
                "total_tokens": 4600,
            },
            "output": [
                {"type": "message", "content": [{"type": "output_text", "text": "{}"}]}
            ],
        }
    ).encode()


def _usage() -> dict[str, object]:
    return {
        "input_tokens": 4,
        "input_tokens_details": {"cached_tokens": 0},
        "output_tokens": 2,
        "output_tokens_details": {"reasoning_tokens": 1},
        "total_tokens": 6,
    }


def test_payload_is_exact_structured_and_semantically_hashed() -> None:
    request = _request()
    payload = request.payload()
    assert request.endpoint == RESPONSES_ENDPOINT
    assert payload["store"] is False
    assert payload["tools"] == []
    assert payload["tool_choice"] == "none"
    assert payload["background"] is False
    assert payload["reasoning"] == {"effort": "medium"}
    assert payload["text"] == {
        "format": {
            "type": "json_schema",
            "name": "claim_answer",
            "schema": {"type": "object", "additionalProperties": False},
            "strict": True,
        }
    }
    assert (
        request.semantic_sha256()
        == hashlib.sha256(
            json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            ).encode()
        ).hexdigest()
    )


def test_unenforced_condition_requests_json_without_schema_enforcement() -> None:
    request = OpenAIResponseRequest(
        model="gpt-5.6-luna",
        input=(OpenAIMessage("user", "Return the documented JSON contract."),),
        schema_name="claim_answer",
        json_schema={"type": "object", "additionalProperties": False},
        max_output_tokens=600,
        schema_enforced=False,
    )
    assert request.payload()["text"] == {"format": {"type": "json_object"}}


def test_preflight_rejects_empty_secret_and_noncanonical_endpoint() -> None:
    with pytest.raises(ValueError, match="api_key"):
        preflight(_request(), SecretStr(""))
    with pytest.raises(ValueError, match="exact official"):
        OpenAIResponseRequest(
            model="gpt-5.6-luna",
            input=(OpenAIMessage("user", "x"),),
            schema_name="answer",
            json_schema={"type": "object"},
            max_output_tokens=1,
            endpoint="https://example.test/v1/responses",
        )


def test_completed_response_is_redacted_and_costed() -> None:
    seen: list[OpenAIHttpRequest] = []

    def transport(
        request: OpenAIHttpRequest, *, timeout_seconds: float
    ) -> OpenAIHttpResponse:
        seen.append(request)
        assert timeout_seconds == 9
        return OpenAIHttpResponse(200, {"X-Request-Id": "req_secret"}, _completed())

    result = OpenAIResponsesAdapter(transport).send(
        _request(), SecretStr("key"), timeout_seconds=9
    )
    assert result.kind == "completed"
    assert result.output_text == "{}"
    assert result.service_tier == "default"
    assert result.reasoning_tokens == 100
    assert (
        result.provider_request_id_sha256 == hashlib.sha256(b"req_secret").hexdigest()
    )
    assert "req_secret" not in repr(result)
    assert "{}" not in repr(result)
    assert "key" not in repr(seen[0])
    assert result.raw_response_body == _completed()
    assert result.selected_response_headers == {"x-request-id": "req_secret"}
    assert result.estimated_cost_usd == Decimal("0.007582")
    assert result.retry_class == "not_retryable"


@pytest.mark.parametrize(
    ("body", "expected_kind", "retry_class"),
    [
        (
            json.dumps(
                {
                    "status": "incomplete",
                    "usage": _usage(),
                    "incomplete_details": {"reason": "max_output_tokens"},
                }
            ).encode(),
            "incomplete",
            "not_retryable",
        ),
        (
            json.dumps(
                {
                    "status": "completed",
                    "usage": _usage(),
                    "output": [
                        {
                            "type": "message",
                            "content": [{"type": "refusal", "refusal": "no"}],
                        }
                    ],
                }
            ).encode(),
            "refusal",
            "not_retryable",
        ),
        (b"not-json", "invalid_response", "not_retryable"),
    ],
)
def test_response_nonresults_remain_first_class(
    body: bytes, expected_kind: str, retry_class: str
) -> None:
    adapter = OpenAIResponsesAdapter(
        lambda _request, *, timeout_seconds: OpenAIHttpResponse(200, {}, body)
    )
    result = adapter.send(_request(), "key")
    assert result.kind == expected_kind
    assert result.retry_class == retry_class


@pytest.mark.parametrize(
    ("status", "expected"),
    [
        (429, "rate_limited"),
        (500, "transient_server"),
        (503, "transient_server"),
        (400, "not_retryable"),
    ],
)
def test_api_error_retryability_is_classified_without_retry(
    status: int, expected: str
) -> None:
    adapter = OpenAIResponsesAdapter(
        lambda _request, *, timeout_seconds: OpenAIHttpResponse(
            status, {}, b'{"error":{"code":"x"}}'
        )
    )
    result = adapter.send(_request(), "key")
    assert result.kind == "api_error"
    assert result.retry_class == expected
    assert result.error_code == "x"


def test_quota_429_is_not_retried_as_rate_limiting() -> None:
    adapter = OpenAIResponsesAdapter(
        lambda _request, *, timeout_seconds: OpenAIHttpResponse(
            429,
            {},
            b'{"error":{"code":"insufficient_quota"}}',
        )
    )
    result = adapter.send(_request(), "key")
    assert result.retry_class == "not_retryable"


def test_timeout_is_ambiguous_and_transport_error_is_distinct() -> None:
    timeout_adapter = OpenAIResponsesAdapter(
        lambda _request, *, timeout_seconds: (_ for _ in ()).throw(TimeoutError())
    )
    assert timeout_adapter.send(_request(), "key").retry_class == "ambiguous_timeout"
    transport_adapter = OpenAIResponsesAdapter(
        lambda _request, *, timeout_seconds: (_ for _ in ()).throw(
            URLError(ConnectionRefusedError())
        )
    )
    assert (
        transport_adapter.send(_request(), "key").retry_class == "transient_transport"
    )
    wrapped_timeout = OpenAIResponsesAdapter(
        lambda _request, *, timeout_seconds: (_ for _ in ()).throw(
            URLError(TimeoutError())
        )
    )
    assert wrapped_timeout.send(_request(), "key").retry_class == "ambiguous_timeout"


def test_multiple_output_or_refusal_parts_fail_closed() -> None:
    body = json.dumps(
        {
            "status": "completed",
            "usage": _usage(),
            "output": [
                {
                    "type": "message",
                    "content": [
                        {"type": "output_text", "text": "{}"},
                        {"type": "refusal", "refusal": "declined"},
                    ],
                }
            ],
        }
    ).encode()
    adapter = OpenAIResponsesAdapter(
        lambda _request, *, timeout_seconds: OpenAIHttpResponse(200, {}, body)
    )
    assert adapter.send(_request(), "key").kind == "invalid_response"


@pytest.mark.parametrize(
    "usage",
    [
        None,
        "not-an-object",
        {
            "input_tokens": 1,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": 1,
            "output_tokens_details": {"reasoning_tokens": 0},
        },
        {
            "input_tokens": True,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": 1,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 2,
        },
        {
            "input_tokens": -1,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": 1,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 0,
        },
        {
            "input_tokens": 1,
            "input_tokens_details": {"cached_tokens": 2},
            "output_tokens": 1,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 2,
        },
        {
            "input_tokens": 1,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": 1,
            "output_tokens_details": {"reasoning_tokens": 2},
            "total_tokens": 2,
        },
        {
            "input_tokens": 1,
            "input_tokens_details": {"cached_tokens": 0},
            "output_tokens": 1,
            "output_tokens_details": {"reasoning_tokens": 0},
            "total_tokens": 999_999,
        },
    ],
)
def test_completed_response_with_unverifiable_usage_fails_closed(
    usage: object,
) -> None:
    payload: dict[str, object] = {
        "status": "completed",
        "output": [
            {"type": "message", "content": [{"type": "output_text", "text": "{}"}]}
        ],
    }
    if usage is not None:
        payload["usage"] = usage
    body = json.dumps(payload).encode()
    adapter = OpenAIResponsesAdapter(
        lambda _request, *, timeout_seconds: OpenAIHttpResponse(200, {}, body)
    )

    result = adapter.send(_request(), "key")

    assert result.kind == "invalid_response"
    assert result.error_code == "invalid_usage"
    assert result.raw_response_body == body
    assert result.retry_class == "not_retryable"


def test_cost_calculation_rejects_impossible_usage() -> None:
    assert estimate_cost_usd(4_000, 20, 600) == Decimal("0.007582")
    with pytest.raises(ValueError, match="cannot exceed"):
        estimate_cost_usd(1, 2, 3)
