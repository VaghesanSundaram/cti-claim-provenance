"""Compatibility entry point for the repository release scanner."""

from __future__ import annotations

import argparse
from pathlib import Path

from cti_provenance.release import (
    Finding,
    ManualReview,
    candidate_paths,
    scan_file,
    scan_repository,
    scan_text,
)

__all__ = [
    "Finding",
    "ManualReview",
    "candidate_paths",
    "scan_file",
    "scan_repository",
    "scan_text",
]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--secrets-only",
        action="store_true",
        help="scan tracked and unignored candidate files for credentials",
    )
    parser.parse_args()

    root = Path(__file__).resolve().parents[1]
    findings, manual_reviews = scan_repository(root)
    for finding in findings:
        relative = finding.path.relative_to(root)
        print(
            f"possible secret: {relative}:{finding.line_number} "
            f"({finding.pattern_name})"
        )
    for review in manual_reviews:
        print(
            f"manual review required: {review.path.relative_to(root)} ({review.reason})"
        )
    if findings or manual_reviews:
        return 1
    print("secret-disclosure scan passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
