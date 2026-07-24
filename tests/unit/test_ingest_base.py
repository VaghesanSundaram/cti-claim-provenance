from __future__ import annotations

from datetime import UTC, datetime, timedelta
from email.message import Message
from typing import Any
from urllib.error import HTTPError, URLError

import pytest
from pydantic import ValidationError

from cti_provenance.ingest.base import (
    ArtifactEvidence,
    CapturedResponse,
    CaptureError,
    FetchSpec,
    artifact_evidence,
    fetch_https,
    replay_response,
)

NOW = datetime(2026, 7, 18, tzinfo=UTC)
SPEC = FetchSpec(
    url="https://example.test/resource?id=one",
    allowed_host="example.test",
    allowed_path="/resource",
    allowed_query=(("id", "one"),),
    max_bytes=8,
    retry_delay_seconds=2,
)


class _Response:
    def __init__(
        self,
        body: bytes,
        *,
        status: int = 200,
        url: str = SPEC.url,
        headers: dict[str, str] | None = None,
    ) -> None:
        self._body = body
        self._status = status
        self._url = url
        self.headers = Message()
        for key, value in (headers or {}).items():
            self.headers[key] = value

    def __enter__(self) -> _Response:
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def getcode(self) -> int:
        return self._status

    def geturl(self) -> str:
        return self._url

    def read(self, _size: int) -> bytes:
        return self._body


class _Opener:
    def __init__(self, outcomes: list[Any]) -> None:
        self.outcomes = outcomes
        self.calls = 0

    def open(self, _request: object, *, timeout: float) -> _Response:
        assert timeout == SPEC.timeout_seconds
        outcome = self.outcomes[self.calls]
        self.calls += 1
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


def _clock(count: int = 6) -> Any:
    values = iter(
        NOW + timedelta(seconds=index) for index in (0, 1, 3, 4, 6, 7)[:count]
    )
    return lambda: next(values)


def _http_error(status: int, headers: dict[str, str] | None = None) -> HTTPError:
    message = Message()
    for key, value in (headers or {}).items():
        message[key] = value
    return HTTPError(SPEC.url, status, "test", message, None)


def test_capture_rejects_unsafe_url_status_body_and_metadata() -> None:
    with pytest.raises(CaptureError, match="credential"):
        CapturedResponse("https://user:pass@example.test/x", 200, b"x", {}, NOW)
    with pytest.raises(CaptureError, match="credential"):
        CapturedResponse("https://example.test/x?token=x", 200, b"x", {}, NOW)
    with pytest.raises(CaptureError, match="HTTP 200"):
        CapturedResponse("https://example.test/x", 302, b"x", {}, NOW)
    with pytest.raises(CaptureError, match="non-empty"):
        CapturedResponse("https://example.test/x", 200, b"", {}, NOW)
    with pytest.raises(CaptureError, match="forbidden"):
        CapturedResponse(
            "https://example.test/x",
            200,
            b"x",
            {"Set-Cookie": "x"},
            NOW,
        )


@pytest.mark.parametrize(
    "url",
    [
        "https://example.test:443/resource?id=one",
        "https://example.test/resource?id=two",
        "https://example.test/resource?id=one&id=one",
        "https://example.test/resource?id=one&extra=x",
        "https://example.test/resource?id=one#fragment",
        "https://example.test/resource?id=one&token=x",
    ],
)
def test_fetch_rejects_any_url_outside_exact_allowlist(url: str) -> None:
    with pytest.raises(CaptureError, match="exact source allowlist"):
        fetch_https(
            FetchSpec(
                url=url,
                allowed_host="example.test",
                allowed_path="/resource",
                allowed_query=(("id", "one"),),
            ),
            opener_factory=lambda: _Opener([]),
        )


def test_fetch_retries_transport_once_and_records_redacted_attempts() -> None:
    opener = _Opener([URLError("temporary"), _Response(b"ok")])
    delays: list[float] = []
    response = fetch_https(
        SPEC,
        opener_factory=lambda: opener,
        now=_clock(),
        sleeper=delays.append,
    )
    assert opener.calls == 2
    assert delays == [2]
    assert [attempt.outcome for attempt in response.attempts] == [
        "transport_error",
        "success",
    ]
    assert response.attempts[0].retry_delay_seconds == 2
    assert response.headers == {}


def test_fetch_caps_retry_after_and_never_retries_404_or_redirect() -> None:
    opener = _Opener([_http_error(429, {"Retry-After": "100"}), _Response(b"ok")])
    delays: list[float] = []
    assert (
        fetch_https(
            SPEC,
            opener_factory=lambda: opener,
            now=_clock(),
            sleeper=delays.append,
            retry_after_cap_seconds=7,
        ).status
        == 200
    )
    assert delays == [7]

    for status, outcome in ((404, "http_other"), (302, "redirect")):
        failing = _Opener([_http_error(status)])
        with pytest.raises(CaptureError) as exc_info:
            fetch_https(
                SPEC,
                opener_factory=lambda failing=failing: failing,
                now=_clock(),
                sleeper=lambda _seconds: pytest.fail("must not retry"),
            )
        assert failing.calls == 1
        assert exc_info.value.attempts[-1].outcome == outcome


def test_fetch_retries_5xx_once_and_rejects_oversize_or_wrong_url() -> None:
    opener = _Opener([_Response(b"", status=500), _Response(b"ok")])
    assert (
        fetch_https(
            SPEC,
            opener_factory=lambda: opener,
            now=_clock(),
            sleeper=lambda _seconds: None,
        )
        .attempts[0]
        .outcome
        == "http_5xx"
    )

    for response, message in (
        (_Response(b"123456789"), "byte cap"),
        (_Response(b"ok", url="https://example.test/other"), "response URL"),
    ):
        with pytest.raises(CaptureError, match=message) as exc_info:
            fetch_https(
                SPEC,
                opener_factory=lambda response=response: _Opener([response]),
                now=_clock(),
                max_attempts=1,
            )
        assert exc_info.value.attempts[-1].outcome == "response_rejected"


def test_artifact_evidence_replays_and_detects_tampering() -> None:
    response = fetch_https(
        SPEC,
        opener_factory=lambda: _Opener(
            [_Response(b"ok", headers={"Content-Type": "application/json"})]
        ),
        now=_clock(),
        max_attempts=1,
    )
    artifact = artifact_evidence(
        response,
        role="primary_body",
        raw_blob_path="data/raw/test/body.json",
    )
    assert replay_response(artifact, b"ok").request_fingerprint
    with pytest.raises(CaptureError, match="do not match"):
        replay_response(artifact, b"no")
    with pytest.raises(ValidationError, match="retrieval time"):
        ArtifactEvidence.model_validate(
            {
                **artifact.model_dump(),
                "retrieved_at_utc": NOW + timedelta(days=1),
            }
        )


def test_serialized_artifact_rejects_nonretryable_and_overlapping_history() -> None:
    response = fetch_https(
        SPEC,
        opener_factory=lambda: _Opener([URLError("temporary"), _Response(b"ok")]),
        now=_clock(),
        sleeper=lambda _seconds: None,
    )
    artifact = artifact_evidence(
        response,
        role="primary_body",
        raw_blob_path="data/raw/test/body.json",
    )
    payload = artifact.model_dump()
    payload["attempts"][0]["outcome"] = "http_other"
    payload["attempts"][0]["status"] = 404
    with pytest.raises(
        ValidationError,
        match=r"prohibited retry|non-retryable",
    ):
        ArtifactEvidence.model_validate(payload)

    payload = artifact.model_dump()
    payload["attempts"][1]["started_at_utc"] = payload["attempts"][0]["started_at_utc"]
    with pytest.raises(ValidationError, match="overlap"):
        ArtifactEvidence.model_validate(payload)
