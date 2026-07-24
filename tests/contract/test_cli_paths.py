from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from cti_provenance.cli import main

ROOT = Path(__file__).resolve().parents[2]


def test_no_argument_defaults_discover_repo_from_nested_cwd(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.chdir(ROOT / "tests")
    assert main(["schema", "check"]) == 0
    assert main(["config", "check"]) == 0
    assert main(["config", "provider-check"]) == 0


def test_outside_checkout_fails_cleanly_without_explicit_paths(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    monkeypatch.chdir(tmp_path)
    assert main(["schema", "check"]) == 2
    assert main(["config", "check"]) == 2
    assert main(["config", "provider-check"]) == 2
    captured = capsys.readouterr()
    assert "pass --output-dir" in captured.err
    assert "pass --sources" in captured.err
    assert "pass --root" in captured.err
    assert str(tmp_path) not in captured.err


def test_explicit_paths_work_outside_checkout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    schema_dir = tmp_path / "schemas"
    config_dir = tmp_path / "configs"
    config_dir.mkdir()
    sources = config_dir / "sources.yaml"
    authority = config_dir / "authority-policy.yaml"
    shutil.copyfile(ROOT / "configs" / "sources.yaml", sources)
    shutil.copyfile(ROOT / "configs" / "authority-policy.yaml", authority)

    monkeypatch.chdir(tmp_path)
    assert main(["schema", "export", "--output-dir", str(schema_dir)]) == 0
    assert main(["schema", "check", "--output-dir", str(schema_dir)]) == 0
    assert (
        main(
            [
                "config",
                "check",
                "--sources",
                str(sources),
                "--authority-policy",
                str(authority),
            ]
        )
        == 0
    )


@pytest.mark.legacy
def test_provider_canary_cli_fails_closed_before_network_without_approval(
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    redacted = ROOT / "artifacts/provider/redacted/test-cli-blocked"
    assert (
        main(
            [
                "provider-canary",
                "--root",
                str(ROOT),
                "--approval",
                str(tmp_path / "missing-approval.json"),
                "--redacted-root",
                str(redacted),
                "--private-root",
                str(tmp_path / "private"),
            ]
        )
        == 1
    )
    captured = capsys.readouterr()
    assert captured.err == "provider canary blocked before acceptance\n"
    assert not redacted.exists()
