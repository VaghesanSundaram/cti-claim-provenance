"""Small release hygiene entry point used by CI."""

from __future__ import annotations

import argparse
from pathlib import Path

from cti_provenance.release import run_release_check


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--secrets-only", action="store_true")
    parser.add_argument("--root", type=Path, default=Path.cwd())
    args = parser.parse_args()
    result = run_release_check(args.root)
    if args.secrets_only:
        checks = [check for check in result.checks if check.name == "release_hygiene"]
        ok = all(check.passed for check in checks)
        for check in checks:
            print(f"{'PASS' if check.passed else 'FAIL'} {check.name}: {check.detail}")
        return 0 if ok else 1
    print(result.render())
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
