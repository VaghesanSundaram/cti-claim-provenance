"""Import a valid result prefix after a terminal provider-only failure."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cti_provenance.claims.diverse_portfolio_v4 import canonical_sha256
from cti_provenance.experiments.portfolio_diverse_execution import (
    _provider_result_requires_run_stop,
    load_provider_results,
)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-redacted-root", type=Path, required=True)
    parser.add_argument("--target-redacted-root", type=Path, required=True)
    args = parser.parse_args()
    source = args.source_redacted_root.resolve(strict=True)
    target = args.target_redacted_root.resolve()
    if target.exists() and any(target.iterdir()):
        raise ValueError("recovery target must be absent or empty")

    results_path = source / "results.jsonl"
    attempts_path = source / "attempt-events.jsonl"
    raw_lines = [
        line for line in results_path.read_text(encoding="utf-8").splitlines() if line
    ]
    results = load_provider_results(results_path)
    if len(results) != len(raw_lines):
        raise ValueError("source results contain duplicates or malformed rows")
    failures = [
        item for item in results if _provider_result_requires_run_stop(item.result_kind)
    ]
    if len(failures) != 1 or failures[0] != results[-1]:
        raise ValueError("expected exactly one terminal provider failure at the tail")
    if failures[0].result_kind != "api_error" or failures[0].http_status != 503:
        raise ValueError("only a terminal HTTP 503 is eligible for this recovery")
    valid = results[:-1]
    if [item.ordinal for item in valid] != list(range(len(valid))):
        raise ValueError("valid source results are not a contiguous prefix")

    target.mkdir(parents=True, exist_ok=True)
    imported_path = target / "results.jsonl"
    imported_path.write_text(
        "\n".join(raw_lines[:-1]) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    receipt = {
        "schema_version": "portfolio-diverse-provider-recovery-import-v1",
        "source_results_sha256": _sha256(results_path),
        "source_attempt_events_sha256": _sha256(attempts_path),
        "imported_result_count": len(valid),
        "imported_last_ordinal": valid[-1].ordinal if valid else None,
        "excluded_failure": {
            "slot_id": failures[0].slot_id,
            "ordinal": failures[0].ordinal,
            "result_kind": failures[0].result_kind,
            "http_status": failures[0].http_status,
            "attempt_count": failures[0].attempt_count,
        },
    }
    receipt["receipt_sha256"] = canonical_sha256(receipt)
    (target / "recovery-import.json").write_text(
        json.dumps(receipt, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(
        f"{len(valid)} results imported; retry ordinal {failures[0].ordinal}; "
        f"receipt {receipt['receipt_sha256']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
