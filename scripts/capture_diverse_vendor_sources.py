"""Capture three exact vendor references already pinned by frozen CISA CSAFs."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from cti_provenance.ingest.base import (
    CaptureError,
    FetchSpec,
    fetch_https,
    request_fingerprint,
)

PLAN = (
    (
        "guralp-firmware-and-software",
        FetchSpec(
            url="https://www.guralp.com/customer-support/firmware-and-software",
            allowed_host="www.guralp.com",
            allowed_path="/customer-support/firmware-and-software",
            max_bytes=2_000_000,
        ),
        "guralp-firmware-and-software.html",
    ),
    (
        "kunbus-2025-0000002-remediation",
        FetchSpec(
            url=(
                "https://www.kunbus.com/files/media/misc/"
                "kunbus-2025-0000002-remediation.pdf"
            ),
            allowed_host="www.kunbus.com",
            allowed_path="/files/media/misc/kunbus-2025-0000002-remediation.pdf",
            max_bytes=5_000_000,
        ),
        "kunbus-2025-0000002-remediation.pdf",
    ),
    (
        "ecovacs-dsa20250509001",
        FetchSpec(
            url="https://www.ecovacs.com/global/userhelp/dsa20250509001",
            allowed_host="www.ecovacs.com",
            allowed_path="/global/userhelp/dsa20250509001",
            max_bytes=2_000_000,
        ),
        "ecovacs-dsa20250509001.html",
    ),
)


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    raw_root = root / "data/raw/portfolio-diverse-v1"
    manifest_path = root / "data/manifests/portfolio-diverse-capture-batch1.json"
    if manifest_path.exists():
        raise SystemExit(
            "capture manifest already exists; semantic retries are forbidden"
        )
    raw_root.mkdir(parents=True, exist_ok=True)
    records: list[dict[str, object]] = []
    for source_id, spec, filename in PLAN:
        try:
            response = fetch_https(spec, max_attempts=2)
        except CaptureError as exc:
            records.append(
                {
                    "source_id": source_id,
                    "url": spec.url,
                    "request_fingerprint": request_fingerprint(spec.url),
                    "outcome": "failed",
                    "attempts": [
                        {
                            "attempt_number": item.attempt_number,
                            "started_at_utc": item.started_at_utc.isoformat(),
                            "finished_at_utc": item.finished_at_utc.isoformat(),
                            "outcome": item.outcome,
                            "status": item.status,
                            "retry_delay_seconds": item.retry_delay_seconds,
                        }
                        for item in exc.attempts
                    ],
                }
            )
            continue
        path = raw_root / filename
        path.write_bytes(response.body)
        records.append(
            {
                "source_id": source_id,
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
                    "hash and minimal-span retention pending source-specific review; "
                    "raw bytes remain gitignored"
                ),
                "attempts": [
                    {
                        "attempt_number": item.attempt_number,
                        "started_at_utc": item.started_at_utc.isoformat(),
                        "finished_at_utc": item.finished_at_utc.isoformat(),
                        "outcome": item.outcome,
                        "status": item.status,
                        "retry_delay_seconds": item.retry_delay_seconds,
                    }
                    for item in response.attempts
                ],
            }
        )
    payload = {
        "version": "portfolio-diverse-capture-batch1-v1",
        "scope": "three vendor references pinned by frozen CISA CSAF sources",
        "records": records,
    }
    manifest_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(manifest_path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
