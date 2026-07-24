"""Capture the three exact NVD records for the bounded egress-safe replacements."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path

from cti_provenance.ingest.base import (
    AttemptRecord,
    CaptureError,
    FetchSpec,
    fetch_https,
    request_fingerprint,
)

CVES = (
    "CVE-2023-22515",
    "CVE-2024-4577",
    "CVE-2024-49138",
)


def _attempts(values: Iterable[AttemptRecord]) -> list[dict[str, object]]:
    return [
        {
            "attempt_number": item.attempt_number,
            "started_at_utc": item.started_at_utc.isoformat(),
            "finished_at_utc": item.finished_at_utc.isoformat(),
            "outcome": item.outcome,
            "status": item.status,
            "retry_delay_seconds": item.retry_delay_seconds,
        }
        for item in values
    ]


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    raw_root = root / "data/raw/portfolio-egress-replacements-v1"
    manifest_path = (
        root / "data/manifests/portfolio-egress-replacements-capture-v1.json"
    )
    if manifest_path.exists():
        raise SystemExit(
            "capture manifest already exists; semantic retries are forbidden"
        )
    raw_root.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, object]] = []
    for cve_id in CVES:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        spec = FetchSpec(
            url=url,
            allowed_host="services.nvd.nist.gov",
            allowed_path="/rest/json/cves/2.0",
            allowed_query=(("cveId", cve_id),),
            max_bytes=1_000_000,
            timeout_seconds=30.0,
        )
        try:
            response = fetch_https(spec, max_attempts=2)
        except CaptureError as exc:
            records.append(
                {
                    "source_id": f"nvd-{cve_id.lower()}",
                    "url": url,
                    "request_fingerprint": request_fingerprint(url),
                    "outcome": "failed",
                    "attempts": _attempts(exc.attempts),
                }
            )
            continue
        path = raw_root / f"nvd-{cve_id.lower()}.json"
        path.write_bytes(response.body)
        records.append(
            {
                "source_id": f"nvd-{cve_id.lower()}",
                "url": response.request_url,
                "request_fingerprint": response.request_fingerprint,
                "outcome": "success",
                "status": response.status,
                "sha256": hashlib.sha256(response.body).hexdigest(),
                "byte_length": len(response.body),
                "retrieved_at_utc": response.retrieved_at_utc.isoformat(),
                "response_headers": response.headers,
                "raw_blob_path": path.relative_to(root).as_posix(),
                "terms_disposition": (
                    "NVD attribution required; only hashes and minimal derived "
                    "spans are tracked; raw bytes remain gitignored"
                ),
                "attempts": _attempts(response.attempts),
            }
        )
    payload = {
        "version": "portfolio-egress-replacements-capture-v1",
        "scope": "three NVD records for exactly five egress-safe replacements",
        "records": records,
    }
    manifest_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(manifest_path)
    return 0 if all(item["outcome"] == "success" for item in records) else 1


if __name__ == "__main__":
    raise SystemExit(main())
