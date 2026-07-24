# Third-party and source notices

This repository does not relicense third-party software or CTI source material.
Each dependency and source remains subject to its own upstream terms.

## Python dependencies

Runtime dependencies are [Pydantic](https://github.com/pydantic/pydantic) and
[PyYAML](https://github.com/yaml/pyyaml). Development uses
[uv](https://github.com/astral-sh/uv),
[Hatchling](https://github.com/pypa/hatch),
[mypy](https://github.com/python/mypy),
[pytest](https://github.com/pytest-dev/pytest), and
[Ruff](https://github.com/astral-sh/ruff). Versions are resolved by
`uv.lock`; installed distributions carry their authoritative license text and
metadata. No dependency source is vendored here.

## CTI source material

Raw source captures are excluded from Git when redistribution is not clearly
permitted. The active reviewer packet records a nonempty source/license-or-
terms disposition for all 29 included source snapshots. The active manifest,
capture ledger, and source inventory bind exact locators and hashes:

- [`data/manifests/portfolio-active-corpus-v2.json`](data/manifests/portfolio-active-corpus-v2.json)
- [`data/manifests/portfolio-capture-ledger-v1.json`](data/manifests/portfolio-capture-ledger-v1.json)
- [`docs/portfolio-source-inventory-v1.md`](docs/portfolio-source-inventory-v1.md)

Tracked source-derived material is limited to metadata, hashes, bounded
evidence spans, normalized records where permitted, and deterministic recipes.
Attribution, non-endorsement, and reuse conditions in each recorded disposition
still apply. A future software `LICENSE` will cover only project-authored code
and documentation to the extent stated; it will not override source-data or
dependency terms.
