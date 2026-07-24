from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from cti_provenance.cli import _build_parser, main
from cti_provenance.release import (
    DEMO_REPORT_PATH,
    RELEASE_REPORT_PATH,
    _broken_markdown_links,
    _candidate_relative_paths,
    _forbidden_artifact_paths,
    _nonportable_text_paths,
    _personal_email_paths,
    _text_candidates,
    render_portfolio_demo,
    render_portfolio_release_readiness,
    run_portfolio_demo,
    run_portfolio_release_readiness,
    verify_portfolio_full_rebuild,
)

ROOT = Path(__file__).resolve().parents[2]


def test_clean_checkout_demo_validates_exact_active_denominators() -> None:
    summary = run_portfolio_demo(ROOT)

    assert summary.inventory_family_count == 24
    assert summary.public_family_count == 16
    assert (summary.development_family_count, summary.validation_family_count) == (
        8,
        8,
    )
    assert summary.future_candidate_count == 8
    assert summary.matched_case_count == 48
    assert dict(summary.challenge_type_counts) == {
        "instruction_like_poison": 4,
        "lower_authority_contradiction": 4,
        "stale": 4,
        "unsupported_assertion": 4,
    }
    assert (
        summary.clean_recall_at_6,
        summary.control_recall_at_6,
        summary.challenge_recall_at_6,
    ) == (16, 16, 16)
    assert (summary.review_item_count, summary.review_unique_family_count) == (20, 16)
    assert (
        summary.repeatability_agreement_count,
        summary.repeatability_pair_count,
    ) == (4, 4)
    assert summary.abstention_status == "not_evaluated"
    assert summary.abstention_portfolio_case_count == 0
    assert summary.provider_calls == 0
    assert render_portfolio_demo(summary) == ROOT.joinpath(
        *DEMO_REPORT_PATH.parts
    ).read_text(encoding="utf-8")


def test_release_check_passes_automated_gates_and_stops_at_two_decisions() -> None:
    readiness = run_portfolio_release_readiness(ROOT)

    assert readiness.status == "ready_for_user_decisions"
    assert all(check.passed for check in readiness.checks)
    assert len(readiness.user_decisions) == 1
    assert "noreply" in readiness.user_decisions[0]
    assert any(
        check.name == "apache_2_license" and check.passed for check in readiness.checks
    )
    assert render_portfolio_release_readiness(readiness) == ROOT.joinpath(
        *RELEASE_REPORT_PATH.parts
    ).read_text(encoding="utf-8")


def test_active_cli_is_focused_and_provider_free_commands_pass() -> None:
    help_text = _build_parser().format_help()
    assert "portfolio-demo" in help_text
    assert "portfolio-rebuild" in help_text
    assert "portfolio-release-check" in help_text
    assert "pilot-readiness" not in help_text
    assert "portfolio-yield-slice" not in help_text
    assert "provider-canary" not in help_text

    assert main(["portfolio-demo", "--root", str(ROOT)]) == 0
    assert main(["portfolio-release-check", "--root", str(ROOT)]) == 0


def test_active_docs_state_the_measured_boundaries() -> None:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "scaffolded" not in readme.casefold()
    assert "24 audited-distinct" in readme
    assert "48 matched" in readme
    assert "not evaluated" in readme
    assert "not a confirmatory" in readme
    assert "publisher-declared version evidence" in readme.casefold()
    assert "portfolio-demo" in readme
    assert "three-family-slice" not in readme
    assert "pilot-readiness" not in readme


def test_release_checks_include_untracked_candidate_files(tmp_path: Path) -> None:
    subprocess.run(["git", "init", "-q"], cwd=tmp_path, check=True)
    forbidden = tmp_path / "artifacts/private/untracked.txt"
    forbidden.parent.mkdir(parents=True)
    forbidden.write_text("candidate\n", encoding="utf-8")
    personal = tmp_path / "notes.md"
    personal_email = "vaghesan" + "@" + "gmail.com"
    personal.write_text(
        "C:" + "\\Users\\person\\repo\ncontact: " + personal_email + "\n"
        "[missing](does-not-exist.md)\n",
        encoding="utf-8",
    )

    paths = _candidate_relative_paths(tmp_path)
    texts = _text_candidates(tmp_path, paths)

    assert _forbidden_artifact_paths(paths) == ["artifacts/private/untracked.txt"]
    assert _nonportable_text_paths(texts) == ["notes.md"]
    assert _personal_email_paths(texts) == ["notes.md"]
    assert _broken_markdown_links(tmp_path, texts) == ["notes.md:3"]


def test_full_rebuild_fails_closed_without_ignored_source_cache(
    tmp_path: Path,
) -> None:
    tracked_clone = tmp_path / "candidate-copy"
    for relative in _candidate_relative_paths(ROOT):
        source = ROOT.joinpath(*relative.parts)
        target = tracked_clone.joinpath(*relative.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)

    with pytest.raises(ValueError, match=r"source-cache"):
        verify_portfolio_full_rebuild(tracked_clone)
