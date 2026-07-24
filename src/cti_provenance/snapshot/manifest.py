"""Frozen snapshot-manifest contract.

Source-specific admissibility and state-selection algorithms intentionally live
outside this module. This model only validates the recorded provenance inputs.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Annotated, Literal, Self
from urllib.parse import parse_qs, urlsplit

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    HttpUrl,
    StringConstraints,
    model_validator,
)

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
_SOURCE_CLASSES = {
    "cisa_directive": "government",
    "cve_program": "standards_body",
    "nvd": "government",
    "cisa_kev": "government",
    "mitre_attack": "standards_body",
    "netscaler_advisory": "vendor",
    "red_hat_rhsa": "vendor",
    "vendor_advisory": "vendor",
    "synthetic_control": "synthetic",
}


def safe_relative_posix_path(value: str) -> PurePosixPath:
    """Validate one canonical Windows-safe relative POSIX path."""
    path = PurePosixPath(value)
    if (
        not value
        or "\\" in value
        or ":" in value
        or "//" in value
        or path.is_absolute()
        or value != "/".join(path.parts)
    ):
        raise ValueError("path must be a canonical safe relative POSIX path")
    for part in path.parts:
        device_name = part.rstrip(". ").split(".", 1)[0].upper()
        if (
            part in {"", ".", ".."}
            or part.endswith((".", " "))
            or device_name in _WINDOWS_RESERVED_NAMES
        ):
            raise ValueError("path must be a canonical safe relative POSIX path")
    return path


def _approved_source_url(source_name: str, source_url: str) -> bool:
    if source_name == "synthetic_control":
        return source_url.startswith("urn:cti-provenance:")
    parsed = urlsplit(source_url)
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or parsed.port
        or parsed.fragment
    ):
        return False
    host = (parsed.hostname or "").lower()
    path = parsed.path
    if parsed.query and source_name != "nvd":
        return False
    if source_name == "cisa_directive":
        return host in {"cisa.gov", "www.cisa.gov"} and path.startswith(
            "/news-events/directives/"
        )
    if source_name == "cve_program":
        return host == "raw.githubusercontent.com" and path.startswith(
            "/CVEProject/cvelistV5/"
        )
    if source_name == "nvd":
        if host == "services.nvd.nist.gov" and path == "/rest/json/cves/2.0":
            return not parsed.query
        if host == "nvd.nist.gov" and re.fullmatch(
            r"/vuln/detail/CVE-\d{4}-\d{4,}/change-record", path
        ):
            query = parse_qs(parsed.query, strict_parsing=True, keep_blank_values=True)
            return (
                set(query) == {"changeRecordedOn"}
                and len(query["changeRecordedOn"]) == 1
                and bool(query["changeRecordedOn"][0])
            )
        return False
    if source_name == "cisa_kev":
        return (
            host == "github.com"
            and (path == "/cisagov/kev-data" or path.startswith("/cisagov/kev-data/"))
        ) or (
            host == "raw.githubusercontent.com"
            and path.startswith("/cisagov/kev-data/")
        )
    if source_name == "mitre_attack":
        return (
            host == "github.com"
            and (
                path == "/mitre-attack/attack-stix-data"
                or path.startswith("/mitre-attack/attack-stix-data/")
            )
        ) or (
            host == "raw.githubusercontent.com"
            and path.startswith("/mitre-attack/attack-stix-data/")
        )
    if source_name == "netscaler_advisory":
        return host in {"netscaler.com", "www.netscaler.com"} and path.startswith(
            "/blog/news/"
        )
    if source_name == "red_hat_rhsa":
        return host == "security.access.redhat.com" and path.startswith(
            "/data/csaf/v2/advisories/"
        )
    if source_name == "vendor_advisory":
        return (
            (
                host == "archive.apache.org"
                and path.startswith("/dist/httpd/CHANGES_2.4.")
                and not parsed.query
            )
            or (
                host == "raw.githubusercontent.com"
                and path.startswith("/nodejs/nodejs.org/")
                and path.endswith(
                    "/apps/site/pages/en/blog/vulnerability/may-2025-security-releases.md"
                )
                and not parsed.query
            )
            or (
                host == "raw.githubusercontent.com"
                and re.fullmatch(
                    r"/django/django/[0-9a-f]{40}/docs/releases/5\.0\.[23]\.txt",
                    path,
                )
                is not None
                and not parsed.query
            )
            or (
                host == "api.github.com"
                and re.fullmatch(
                    r"/repos/(rust-lang/rust|python/cpython|jenkinsci/jenkins)/"
                    r"git/tags/[0-9a-f]{40}",
                    path,
                )
                is not None
                and not parsed.query
            )
            or (
                host == "raw.githubusercontent.com"
                and re.fullmatch(
                    r"/rust-lang/blog\.rust-lang\.org/[0-9a-f]{40}/"
                    r"posts/2024-04-09-cve-2024-24576\.md",
                    path,
                )
                is not None
                and not parsed.query
            )
            or (
                host == "raw.githubusercontent.com"
                and re.fullmatch(
                    r"/python/cpython/[0-9a-f]{40}/Misc/NEWS\.d/3\.11\.4\.rst",
                    path,
                )
                is not None
                and not parsed.query
            )
            or (
                host == "raw.githubusercontent.com"
                and re.fullmatch(
                    r"/jenkins-infra/jenkins\.io/[0-9a-f]{40}/"
                    r"content/security/advisory/2017-12-14\.adoc",
                    path,
                )
                is not None
                and not parsed.query
            )
            or (
                host == "raw.githubusercontent.com"
                and re.fullmatch(
                    r"/postgres/postgres/REL_15_[45]/doc/src/sgml/release-15\.sgml",
                    path,
                )
                is not None
                and not parsed.query
            )
        )
    return False


def _utc_datetime(value: datetime) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must be timezone-aware")
    if value.utcoffset() != UTC.utcoffset(value):
        raise ValueError("timestamp must use the UTC offset")
    return value.astimezone(UTC)


UtcDateTime = Annotated[datetime, AfterValidator(_utc_datetime)]
NonEmptyString = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]
Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]


class SnapshotManifest(BaseModel):
    """Provenance record for one immutable raw snapshot."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    snapshot_id: NonEmptyString
    source_name: Literal[
        "cisa_directive",
        "cve_program",
        "nvd",
        "cisa_kev",
        "mitre_attack",
        "netscaler_advisory",
        "red_hat_rhsa",
        "synthetic_control",
        "vendor_advisory",
    ]
    source_class: Literal["government", "standards_body", "vendor", "synthetic"]
    source_url: HttpUrl | Annotated[str, StringConstraints(pattern=r"^urn:")]
    retrieved_at_utc: UtcDateTime
    http_status: Literal[200]
    http_etag: str | None
    http_last_modified: str | None
    effective_date_if_known: UtcDateTime | None
    effective_date_basis: Literal[
        "publisher_version", "signed_release", "field", "unknown"
    ]
    available_by_utc: UtcDateTime
    available_by_basis: Literal[
        "observed_retrieval",
        "upstream_version",
        "signed_release",
        "publisher_timestamp_with_observation",
        "publisher_declared_version",
        "synthetic_fixture",
    ]
    upstream_identifier: str | None
    upstream_version: str | None
    media_type: NonEmptyString
    byte_length: int = Field(ge=0)
    sha256: Sha256
    raw_blob_path: NonEmptyString
    fetcher_version: NonEmptyString
    normalization_version: NonEmptyString
    license_or_terms_note: NonEmptyString

    @model_validator(mode="after")
    def validate_manifest_relationships(self) -> Self:
        safe_relative_posix_path(self.raw_blob_path)
        if not SHA256_RE.fullmatch(self.sha256):
            raise ValueError("sha256 must be lowercase hexadecimal")
        if self.source_class != _SOURCE_CLASSES[self.source_name]:
            raise ValueError("source_name requires its configured source_class")
        if not _approved_source_url(self.source_name, str(self.source_url)):
            raise ValueError("source_url is not approved for source_name")
        if self.http_status != 200:
            raise ValueError("snapshot manifest requires a complete HTTP 200 response")
        if (
            self.available_by_basis == "observed_retrieval"
            and self.available_by_utc != self.retrieved_at_utc
        ):
            raise ValueError(
                "observed_retrieval requires available_by_utc == retrieved_at_utc"
            )
        if self.source_name == "synthetic_control":
            if self.available_by_basis != "synthetic_fixture":
                raise ValueError(
                    "synthetic_control requires the synthetic_fixture basis"
                )
        elif self.available_by_basis == "synthetic_fixture":
            raise ValueError(
                "synthetic_fixture basis is reserved for synthetic_control"
            )
        return self
