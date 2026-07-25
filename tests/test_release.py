from __future__ import annotations

from pathlib import Path

from cti_provenance.release import run_release_check

ROOT = Path(__file__).resolve().parents[1]


def test_release_bundle_is_coherent() -> None:
    result = run_release_check(ROOT)
    assert result.passed, result.render()


def test_cli_release_check_aliases() -> None:
    from cti_provenance.cli import main

    assert main(["release-check", "--root", str(ROOT)]) == 0
    assert main(["portfolio-release-check", "--root", str(ROOT)]) == 0
