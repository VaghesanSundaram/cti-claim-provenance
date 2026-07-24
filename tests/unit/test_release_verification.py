from __future__ import annotations

from pathlib import Path

import pytest

from scripts.verify_release import scan_file, scan_text


def test_secret_scanner_reports_location_without_secret_value() -> None:
    canary = "sk-" + "examplecanaryvalue123456789"
    findings = scan_text(Path("candidate.txt"), f"prefix {canary} suffix")
    assert len(findings) == 1
    assert findings[0].pattern_name == "openai-style-key"
    assert canary not in repr(findings)


def test_secret_scanner_allows_empty_example_assignments() -> None:
    text = "\n".join(
        [
            "OPENAI_API_KEY=",
            "ANTHROPIC_API_KEY=",
            "GEMINI_API_KEY=",
            "NVD_API_KEY=",
            "GITHUB_TOKEN=",
        ]
    )
    assert scan_text(Path(".env.example"), text) == []


def test_secret_scanner_flags_nonempty_documented_assignment() -> None:
    value = "do-" + "not-commit-this"
    findings = scan_text(Path("candidate.env"), f"NVD_API_KEY={value}")
    assert [finding.pattern_name for finding in findings] == [
        "nonempty-secret-assignment"
    ]


@pytest.mark.parametrize(
    ("value", "expected_pattern"),
    [
        (
            "AIza" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r",
            "google-api-key",
        ),
        (
            "-----BEGIN " + "ENCRYPTED PRIVATE KEY-----",
            "private-key-header",
        ),
    ],
)
def test_secret_scanner_covers_google_and_encrypted_private_key_shapes(
    value: str, expected_pattern: str
) -> None:
    findings = scan_text(Path("candidate.txt"), value)
    assert [finding.pattern_name for finding in findings] == [expected_pattern]
    assert value not in repr(findings)


@pytest.mark.parametrize(
    ("data", "reason"),
    [
        (b"text\x00binary", "binary-or-nul"),
        (b"\xff\xfe", "non-utf8"),
    ],
)
def test_unscannable_candidate_files_fail_closed(
    tmp_path: Path, data: bytes, reason: str
) -> None:
    path = tmp_path / "candidate"
    path.write_bytes(data)
    findings, manual_review = scan_file(path)
    assert findings == []
    assert manual_review is not None
    assert manual_review.reason == reason


def test_candidate_symlink_is_not_followed(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.write_text("ordinary text", encoding="utf-8")
    link = tmp_path / "candidate-link"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation is unavailable on this Windows configuration")
    findings, manual_review = scan_file(link)
    assert findings == []
    assert manual_review is not None
    assert manual_review.reason == "link-or-junction"
