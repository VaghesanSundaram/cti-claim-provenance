"""Credential-free HTTPS transport and replayable capture evidence."""

from __future__ import annotations

import hashlib
import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.client import HTTPMessage
from itertools import pairwise
from typing import Annotated, Any, Literal, Self
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qsl, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from cti_provenance.snapshot import ImmutableBlobStore, SnapshotManifest, SnapshotState
from cti_provenance.snapshot.manifest import safe_relative_posix_path

USER_AGENT = "cti-claim-provenance/0.1 (bounded research capture)"
ALLOWED_RESPONSE_HEADERS = frozenset({"etag", "last-modified", "content-type"})
_SENSITIVE_QUERY_NAMES = frozenset(
    {
        "apikey",
        "api_key",
        "access_token",
        "authorization",
        "auth",
        "key",
        "password",
        "secret",
        "token",
    }
)
_SHA256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
_NON_EMPTY = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
type AttemptOutcome = Literal[
    "success",
    "response_rejected",
    "transport_error",
    "http_429",
    "http_5xx",
    "http_other",
    "redirect",
]


def request_fingerprint(request_url: str) -> str:
    """Hash the exact stable GET request without credentials or transient headers."""
    payload = json.dumps(
        {
            "method": "GET",
            "url": request_url,
            "headers": {
                "accept-encoding": "identity",
                "user-agent": USER_AGENT,
            },
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return hashlib.sha256(payload).hexdigest()


class CaptureError(ValueError):
    """A request or response cannot safely participate in the frozen corpus."""

    def __init__(
        self, message: str, *, attempts: tuple[AttemptRecord, ...] = ()
    ) -> None:
        super().__init__(message)
        self.attempts = attempts


@dataclass(frozen=True)
class AttemptRecord:
    """One redacted request attempt suitable for a local attempt ledger."""

    attempt_number: int
    started_at_utc: datetime
    finished_at_utc: datetime
    outcome: AttemptOutcome
    status: int | None
    retry_delay_seconds: float | None


@dataclass(frozen=True)
class CapturedResponse:
    """Bytes and only the response metadata allowed into capture records."""

    request_url: str
    status: int
    body: bytes
    headers: dict[str, str]
    retrieved_at_utc: datetime
    attempts: tuple[AttemptRecord, ...] = ()

    def __post_init__(self) -> None:
        parsed = urlsplit(self.request_url)
        query_names = {name.casefold() for name, _ in parse_qsl(parsed.query)}
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.port is not None
            or parsed.fragment
            or query_names & _SENSITIVE_QUERY_NAMES
        ):
            raise CaptureError("request URL must be credential-free HTTPS")
        if set(self.headers) - ALLOWED_RESPONSE_HEADERS or any(
            key != key.lower() for key in self.headers
        ):
            raise CaptureError(
                "forbidden response metadata; use the lowercase header allowlist"
            )
        if self.status != 200:
            raise CaptureError("capture requires HTTP 200")
        if not isinstance(self.body, bytes) or not self.body:
            raise CaptureError("capture body must be non-empty bytes")
        if (
            self.retrieved_at_utc.tzinfo is None
            or self.retrieved_at_utc.utcoffset() != UTC.utcoffset(self.retrieved_at_utc)
        ):
            raise CaptureError("retrieval time must be UTC")

    @property
    def request_fingerprint(self) -> str:
        """Bind the exact method, URL, and stable request headers."""
        return request_fingerprint(self.request_url)


@dataclass(frozen=True)
class FetchSpec:
    """Exact allowlist and resource ceiling for one logical GET."""

    url: str
    allowed_host: str
    allowed_path: str
    allowed_query: tuple[tuple[str, str], ...] = ()
    max_bytes: int = 2_000_000
    timeout_seconds: float = 15.0
    retry_delay_seconds: float = 1.0


class _NoRedirect(HTTPRedirectHandler):
    """Make urllib surface redirects as HTTP errors instead of following them."""

    def redirect_request(
        self,
        req: Request,
        fp: Any,
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> None:
        return None


def _utc(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        raise CaptureError("attempt time must be UTC")
    return value.astimezone(UTC)


def _validate_spec(spec: FetchSpec) -> None:
    parsed = urlsplit(spec.url)
    actual_query = parse_qsl(parsed.query, keep_blank_values=True)
    query_names = [name.casefold() for name, _ in actual_query]
    if (
        parsed.scheme != "https"
        or (parsed.hostname or "").lower() != spec.allowed_host.lower()
        or parsed.path != spec.allowed_path
        or parsed.username
        or parsed.password
        or parsed.port is not None
        or parsed.fragment
        or sorted(actual_query) != sorted(spec.allowed_query)
        or len(actual_query) != len(spec.allowed_query)
        or len(query_names) != len(set(query_names))
        or set(query_names) & _SENSITIVE_QUERY_NAMES
    ):
        raise CaptureError("request URL is outside the exact source allowlist")
    if spec.max_bytes <= 0 or spec.timeout_seconds <= 0 or spec.retry_delay_seconds < 0:
        raise CaptureError("fetch ceilings must be positive and bounded")


def validate_fetch_spec(spec: FetchSpec) -> None:
    """Validate one frozen fetch specification without performing a request."""
    _validate_spec(spec)


def _retry_after_seconds(headers: Any, cap: float) -> float | None:
    raw = headers.get("Retry-After") or headers.get("retry-after")
    if raw is None:
        return None
    try:
        value = float(raw)
    except ValueError:
        return None
    if value < 0:
        return None
    return min(value, cap)


def fetch_https(
    spec: FetchSpec,
    *,
    max_attempts: Literal[1, 2] = 2,
    retry_after_cap_seconds: float = 30.0,
    opener_factory: Callable[[], Any] | None = None,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
    sleeper: Callable[[float], None] = time.sleep,
) -> CapturedResponse:
    """Fetch one exact resource with at most one safe, identical retry."""
    _validate_spec(spec)
    if max_attempts not in {1, 2} or retry_after_cap_seconds < 0:
        raise CaptureError("retry policy exceeds the frozen attempt ceiling")
    request = Request(
        spec.url,
        method="GET",
        headers={"User-Agent": USER_AGENT, "Accept-Encoding": "identity"},
    )
    opener = (
        opener_factory() if opener_factory is not None else build_opener(_NoRedirect())
    )
    attempts: list[AttemptRecord] = []
    for attempt_number in range(1, max_attempts + 1):
        started = _utc(now())
        retry_delay: float | None = None
        try:
            response = opener.open(request, timeout=spec.timeout_seconds)
            with response:
                status = int(response.getcode())
                if status != 200:
                    headers = dict(response.headers.items())
                    outcome: AttemptOutcome
                    if 300 <= status < 400:
                        outcome = "redirect"
                    elif status == 429:
                        outcome = "http_429"
                    elif 500 <= status < 600:
                        outcome = "http_5xx"
                    else:
                        outcome = "http_other"
                    retryable = outcome in {"http_429", "http_5xx"}
                    if retryable and attempt_number < max_attempts:
                        retry_delay = max(
                            spec.retry_delay_seconds,
                            _retry_after_seconds(headers, retry_after_cap_seconds)
                            or 0.0,
                        )
                    finished = _utc(now())
                    attempts.append(
                        AttemptRecord(
                            attempt_number,
                            started,
                            finished,
                            outcome,
                            status,
                            retry_delay,
                        )
                    )
                    if retry_delay is None:
                        raise CaptureError(
                            "HTTP response is not an accepted complete snapshot",
                            attempts=tuple(attempts),
                        )
                    sleeper(retry_delay)
                    continue
                body = response.read(spec.max_bytes + 1)
                if not body or len(body) > spec.max_bytes:
                    finished = _utc(now())
                    attempts.append(
                        AttemptRecord(
                            attempt_number,
                            started,
                            finished,
                            "response_rejected",
                            200,
                            None,
                        )
                    )
                    raise CaptureError(
                        "response body is empty or exceeds the byte cap",
                        attempts=tuple(attempts),
                    )
                headers = {
                    key.lower(): value
                    for key, value in response.headers.items()
                    if key.lower() in ALLOWED_RESPONSE_HEADERS
                }
                if response.geturl() != spec.url:
                    finished = _utc(now())
                    attempts.append(
                        AttemptRecord(
                            attempt_number,
                            started,
                            finished,
                            "response_rejected",
                            200,
                            None,
                        )
                    )
                    raise CaptureError(
                        "response URL does not match the exact request",
                        attempts=tuple(attempts),
                    )
                finished = _utc(now())
                attempts.append(
                    AttemptRecord(
                        attempt_number,
                        started,
                        finished,
                        "success",
                        200,
                        None,
                    )
                )
                return CapturedResponse(
                    spec.url,
                    200,
                    body,
                    headers,
                    finished,
                    tuple(attempts),
                )
        except HTTPError as exc:
            status = int(exc.code)
            outcome = "http_other"
            if 300 <= status < 400:
                outcome = "redirect"
            elif status == 429:
                outcome = "http_429"
            elif 500 <= status < 600:
                outcome = "http_5xx"
            else:
                outcome = "http_other"
            retryable = outcome in {"http_429", "http_5xx"}
            if retryable and attempt_number < max_attempts:
                retry_delay = max(
                    spec.retry_delay_seconds,
                    _retry_after_seconds(exc.headers, retry_after_cap_seconds) or 0.0,
                )
            finished = _utc(now())
            attempts.append(
                AttemptRecord(
                    attempt_number,
                    started,
                    finished,
                    outcome,
                    status,
                    retry_delay,
                )
            )
            if retry_delay is None:
                raise CaptureError(
                    "HTTP response is not an accepted complete snapshot",
                    attempts=tuple(attempts),
                ) from exc
            sleeper(retry_delay)
        except (TimeoutError, URLError, OSError) as exc:
            if attempt_number < max_attempts:
                retry_delay = spec.retry_delay_seconds
            finished = _utc(now())
            attempts.append(
                AttemptRecord(
                    attempt_number,
                    started,
                    finished,
                    "transport_error",
                    None,
                    retry_delay,
                )
            )
            if retry_delay is None:
                raise CaptureError(
                    "transport failed without a usable response",
                    attempts=tuple(attempts),
                ) from exc
            sleeper(retry_delay)
    raise CaptureError("capture attempt ceiling exhausted", attempts=tuple(attempts))


class AttemptEvidence(BaseModel):
    """Strict serialized form of one redacted request attempt."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    attempt_number: int = Field(ge=1, le=2)
    started_at_utc: datetime
    finished_at_utc: datetime
    outcome: AttemptOutcome
    status: int | None
    retry_delay_seconds: float | None = Field(ge=0)

    @model_validator(mode="after")
    def validate_attempt(self) -> Self:
        _utc(self.started_at_utc)
        _utc(self.finished_at_utc)
        if self.finished_at_utc < self.started_at_utc:
            raise ValueError("attempt cannot finish before it starts")
        if (self.outcome in {"success", "response_rejected"}) != (self.status == 200):
            raise ValueError("only success or response rejection may have HTTP 200")
        if self.outcome == "transport_error" and self.status is not None:
            raise ValueError("transport errors cannot declare an HTTP status")
        if self.outcome == "redirect" and (
            self.status is None or not 300 <= self.status < 400
        ):
            raise ValueError("redirect outcome requires a 3xx status")
        if self.outcome == "http_429" and self.status != 429:
            raise ValueError("http_429 outcome requires status 429")
        if self.outcome == "http_5xx" and (
            self.status is None or not 500 <= self.status < 600
        ):
            raise ValueError("http_5xx outcome requires a 5xx status")
        if self.outcome == "http_other" and (
            self.status is None
            or self.status == 200
            or self.status == 429
            or 300 <= self.status < 400
            or 500 <= self.status < 600
        ):
            raise ValueError("http_other outcome requires another non-200 status")
        if self.outcome == "success" and self.retry_delay_seconds is not None:
            raise ValueError("successful attempts cannot declare retry delay")
        if (
            self.outcome in {"response_rejected", "redirect", "http_other"}
            and self.retry_delay_seconds is not None
        ):
            raise ValueError("non-retryable outcomes cannot declare retry delay")
        return self


def validate_attempt_sequence(
    attempts: list[AttemptEvidence],
    *,
    terminal_success: bool,
    minimum_retry_delay_seconds: float = 0.0,
) -> None:
    """Validate one complete per-resource attempt history."""
    if not 1 <= len(attempts) <= 2:
        raise ValueError("attempt history must contain one or two attempts")
    if minimum_retry_delay_seconds < 0:
        raise ValueError("minimum retry delay cannot be negative")
    if [attempt.attempt_number for attempt in attempts] != list(
        range(1, len(attempts) + 1)
    ):
        raise ValueError("attempt numbers must be consecutive")
    for attempt, later in pairwise(attempts):
        if later.started_at_utc < attempt.finished_at_utc:
            raise ValueError("attempts overlap or run out of order")
        if attempt.outcome not in {"transport_error", "http_429", "http_5xx"}:
            raise ValueError("attempt history contains a prohibited retry")
        if (
            attempt.retry_delay_seconds is None
            or attempt.retry_delay_seconds < minimum_retry_delay_seconds
        ):
            raise ValueError("retry delay is missing or below the required minimum")
        if later.started_at_utc < attempt.finished_at_utc + timedelta(
            seconds=attempt.retry_delay_seconds
        ):
            raise ValueError("retry started before its declared delay elapsed")
    final = attempts[-1]
    if final.retry_delay_seconds is not None:
        raise ValueError("terminal attempt cannot declare a retry delay")
    if terminal_success != (final.outcome == "success"):
        raise ValueError("terminal attempt outcome does not match resource status")


class ArtifactEvidence(BaseModel):
    """Hash-bound evidence for one captured primary or supporting artifact."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    role: Literal["primary_body", "commit_lineage", "published_checksum"]
    request_url: _NON_EMPTY
    request_fingerprint: _SHA256
    status: Literal[200]
    retrieved_at_utc: datetime
    response_headers: dict[str, str]
    sha256: _SHA256
    byte_length: int = Field(gt=0)
    raw_blob_path: _NON_EMPTY
    attempts: list[AttemptEvidence] = Field(min_length=1, max_length=2)

    @model_validator(mode="after")
    def validate_artifact(self) -> Self:
        _utc(self.retrieved_at_utc)
        safe_relative_posix_path(self.raw_blob_path)
        parsed = urlsplit(self.request_url)
        query_names = {
            name.casefold()
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True)
        }
        if (
            parsed.scheme != "https"
            or parsed.username
            or parsed.password
            or parsed.port is not None
            or parsed.fragment
            or query_names & _SENSITIVE_QUERY_NAMES
        ):
            raise ValueError("artifact request URL must be credential-free HTTPS")
        if self.request_fingerprint != request_fingerprint(self.request_url):
            raise ValueError("artifact request fingerprint does not match URL")
        if set(self.response_headers) - ALLOWED_RESPONSE_HEADERS or any(
            key != key.lower() for key in self.response_headers
        ):
            raise ValueError("artifact headers exceed the response allowlist")
        if self.attempts[-1].outcome != "success":
            raise ValueError("accepted artifact must end in a successful attempt")
        validate_attempt_sequence(self.attempts, terminal_success=True)
        if self.attempts[-1].finished_at_utc != self.retrieved_at_utc:
            raise ValueError(
                "artifact retrieval time must equal the successful attempt"
            )
        return self


class NvdDerivation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    kind: Literal["nvd_observed"] = "nvd_observed"
    cve_id: Literal["CVE-2021-44228"]


class KevDerivation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    kind: Literal["cisa_kev_commit"] = "cisa_kev_commit"
    stable_entity_id: Literal["cisa-kev-catalog"]
    commit_sha: Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
    commit_time_utc: datetime
    compare_status: Literal["ahead", "identical"]

    @model_validator(mode="after")
    def validate_commit_time(self) -> Self:
        _utc(self.commit_time_utc)
        return self


class RedHatDerivation(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)
    kind: Literal["red_hat_published_checksum"] = "red_hat_published_checksum"
    tracking_id: Literal["RHSA-2021:5133"]
    revision_version: _NON_EMPTY
    current_release_date_utc: datetime
    published_sha256: _SHA256

    @model_validator(mode="after")
    def validate_release_time(self) -> Self:
        _utc(self.current_release_date_utc)
        return self


type SourceDerivation = NvdDerivation | KevDerivation | RedHatDerivation


class SourceStateEvidenceRecord(BaseModel):
    """Versioned offline proof used to reconstruct one SnapshotState."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    version: Literal["phase2-source-evidence-v1"]
    snapshot_id: _NON_EMPTY
    source_name: Literal["nvd", "cisa_kev", "red_hat_rhsa"]
    verifier_version: Literal["phase2-source-verifier-v1"]
    artifacts: list[ArtifactEvidence] = Field(min_length=1, max_length=3)
    derivation: SourceDerivation
    license_or_terms_note: _NON_EMPTY

    @model_validator(mode="after")
    def validate_source_shape(self) -> Self:
        roles = [artifact.role for artifact in self.artifacts]
        expected = {
            "nvd": ({"primary_body"}, "nvd_observed"),
            "cisa_kev": (
                {"primary_body", "commit_lineage"},
                "cisa_kev_commit",
            ),
            "red_hat_rhsa": (
                {"primary_body", "published_checksum"},
                "red_hat_published_checksum",
            ),
        }
        expected_roles, expected_kind = expected[self.source_name]
        if set(roles) != expected_roles or len(roles) != len(expected_roles):
            raise ValueError("source evidence has missing or duplicate artifact roles")
        if self.derivation.kind != expected_kind:
            raise ValueError("source evidence derivation does not match source")
        if not all(
            artifact.raw_blob_path.startswith("data/raw/")
            for artifact in self.artifacts
        ):
            raise ValueError("source evidence artifacts must remain under data/raw")
        if self.source_name == "nvd":
            primary = next(
                artifact
                for artifact in self.artifacts
                if artifact.role == "primary_body"
            )
            if any(
                attempt.retry_delay_seconds is not None
                and attempt.retry_delay_seconds < 6
                for attempt in primary.attempts[:-1]
            ):
                raise ValueError("NVD retries require at least six seconds")
        return self


def artifact_evidence(
    response: CapturedResponse,
    *,
    role: Literal["primary_body", "commit_lineage", "published_checksum"],
    raw_blob_path: str,
) -> ArtifactEvidence:
    """Create a strict artifact record from an actual successful fetch."""
    if not response.attempts:
        raise CaptureError("artifact evidence requires an actual attempt ledger")
    digest = hashlib.sha256(response.body).hexdigest()
    return ArtifactEvidence(
        role=role,
        request_url=response.request_url,
        request_fingerprint=response.request_fingerprint,
        status=200,
        retrieved_at_utc=response.retrieved_at_utc,
        response_headers=response.headers,
        sha256=digest,
        byte_length=len(response.body),
        raw_blob_path=raw_blob_path,
        attempts=[
            AttemptEvidence(
                attempt_number=attempt.attempt_number,
                started_at_utc=attempt.started_at_utc,
                finished_at_utc=attempt.finished_at_utc,
                outcome=attempt.outcome,
                status=attempt.status,
                retry_delay_seconds=attempt.retry_delay_seconds,
            )
            for attempt in response.attempts
        ],
    )


def replay_response(artifact: ArtifactEvidence, body: bytes) -> CapturedResponse:
    """Reconstruct and revalidate a response from one offline artifact."""
    if (
        len(body) != artifact.byte_length
        or hashlib.sha256(body).hexdigest() != artifact.sha256
    ):
        raise CaptureError("offline artifact bytes do not match evidence record")
    attempts = tuple(
        AttemptRecord(
            attempt.attempt_number,
            attempt.started_at_utc,
            attempt.finished_at_utc,
            attempt.outcome,
            attempt.status,
            attempt.retry_delay_seconds,
        )
        for attempt in artifact.attempts
    )
    response = CapturedResponse(
        artifact.request_url,
        artifact.status,
        body,
        artifact.response_headers,
        artifact.retrieved_at_utc,
        attempts,
    )
    if response.request_fingerprint != artifact.request_fingerprint:
        raise CaptureError("offline request fingerprint does not match")
    return response


def store_capture(
    response: CapturedResponse,
    *,
    store: ImmutableBlobStore,
    raw_blob_path: str,
    manifest: SnapshotManifest,
    state: SnapshotState,
    source_evidence: SourceStateEvidenceRecord,
) -> SnapshotState:
    """Cross-bind exact request/response evidence before immutable storage."""
    digest = hashlib.sha256(response.body).hexdigest()
    response_base = response.request_url.split("?", 1)[0]
    manifest_url = str(manifest.source_url)
    media_type = response.headers.get("content-type", "application/octet-stream")
    primary_artifacts = [
        artifact
        for artifact in source_evidence.artifacts
        if artifact.role == "primary_body"
    ]
    expected_artifact = artifact_evidence(
        response,
        role="primary_body",
        raw_blob_path=raw_blob_path,
    )
    if (
        manifest.sha256 != digest
        or manifest.byte_length != len(response.body)
        or manifest.raw_blob_path != raw_blob_path
        or state.manifest != manifest
        or manifest.retrieved_at_utc != response.retrieved_at_utc
        or manifest.http_status != response.status
        or manifest.http_etag != response.headers.get("etag")
        or manifest.http_last_modified != response.headers.get("last-modified")
        or manifest.media_type != media_type
        or source_evidence.snapshot_id != manifest.snapshot_id
        or source_evidence.source_name != manifest.source_name
        or primary_artifacts != [expected_artifact]
        or (
            manifest_url != response.request_url
            and not (manifest.source_name == "nvd" and manifest_url == response_base)
        )
    ):
        raise CaptureError("capture request/response and manifest do not cross-bind")
    store.put_bytes(raw_blob_path, response.body, expected_sha256=digest)
    return state


def store_evidence_artifact(
    response: CapturedResponse,
    *,
    store: ImmutableBlobStore,
    artifact: ArtifactEvidence,
) -> None:
    """Store a supporting artifact only after its evidence record cross-binds."""
    expected = artifact_evidence(
        response,
        role=artifact.role,
        raw_blob_path=artifact.raw_blob_path,
    )
    if expected != artifact:
        raise CaptureError("supporting artifact does not match its evidence record")
    store.put_bytes(
        artifact.raw_blob_path,
        response.body,
        expected_sha256=artifact.sha256,
    )
