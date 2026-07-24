from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def test_portfolio_capture_ledger_accounting_and_url_uniqueness() -> None:
    ledger = json.loads(
        (ROOT / "data/manifests/portfolio-capture-ledger-v1.json").read_text(
            encoding="utf-8"
        )
    )
    attempts = ledger["attempts"]
    successes = [item for item in attempts if item["outcome"] == "success"]
    setup_failures = [
        item for item in attempts if item["outcome"] == "local_setup_failure"
    ]
    assert ledger["successful_captures"] == len(successes) == 105
    assert ledger["total_attempts"] == len(attempts) == 119
    assert ledger["semantic_retries"] == 0
    assert ledger["transport_setup_retries"] == len(setup_failures) == 11
    assert len({item["url"] for item in successes}) == len(successes)
    assert all(item["status"] == 200 for item in successes)
    assert all(item["sha256"] and item["raw_blob_path"] for item in successes)
    assert all(
        item["failure_stage"]
        in {"local_http_client_assembly_load", "local_hash_helper_compatibility"}
        and item["attempt_number"] == 1
        and item["status"] is None
        and item["byte_length"] == 0
        for item in setup_failures
    )
    by_fingerprint: dict[str, list[dict[str, object]]] = {}
    for item in attempts:
        by_fingerprint.setdefault(item["request_fingerprint"], []).append(item)
    assert all(
        any(
            retry["attempt_number"] == 2
            and retry["url"] == failure["url"]
            and retry["outcome"] in {"success", "http_failure"}
            for retry in by_fingerprint[failure["request_fingerprint"]]
        )
        for failure in setup_failures
    )
    wordpress_404 = [
        item
        for item in attempts
        if item["source_id"] == "wordpress-terms" and item["outcome"] == "http_failure"
    ]
    assert len(wordpress_404) == 1
    assert wordpress_404[0]["status"] == 404
    assert wordpress_404[0]["sha256"] is None
    assert wordpress_404[0]["raw_blob_path"] is None

    curl_404s = [
        item
        for item in attempts
        if item["source_id"] in {"curl-release-8.3.0", "curl-release-8.4.0"}
        and item["outcome"] == "http_failure"
    ]
    assert len(curl_404s) == 2
    assert all(item["status"] == 404 for item in curl_404s)
