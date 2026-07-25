# Third-party and source notices

This repository does not relicense third-party software or CTI source material.
Each dependency and source remains subject to its own upstream terms.

## Python dependencies

Runtime dependencies are [Pydantic](https://github.com/pydantic/pydantic),
[pypdf](https://github.com/py-pdf/pypdf), and
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
permitted. The release bundle retains source identifiers, hashes, bounded
evidence spans, and explicit terms dispositions needed to audit the benchmark.

Tracked source-derived material is limited to metadata, hashes, bounded
evidence spans, normalized records where permitted, and deterministic recipes.
Attribution, non-endorsement, and reuse conditions in each recorded disposition
still apply. The Apache-2.0 `LICENSE` covers only project-authored code and
documentation; it does not override source-data or dependency terms.
