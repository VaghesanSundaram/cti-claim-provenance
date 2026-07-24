# Overbuilding cleanup inventory

Baseline: private `main` at correction checkpoint `ce0d854`. Successor: current
release-candidate worktree before its final commit.

| Measure | Before | After | Change |
|---|---:|---:|---:|
| Candidate tracked files | 271 | 273 | +2 |
| Source Python files | 71 | 69 | -2 |
| Source Python physical lines | 25,055 | 24,488 | -567 (-2.3%) |
| Test Python files | 50 | 48 | -2 |
| Test Python physical lines | 12,963 | 12,412 | -551 (-4.3%) |
| Active collected tests | 484 | 450 | -34 |
| Historical tests excluded from the active gate | 0 | 21 | +21 explicit |
| CLI physical lines | 1,179 | 378 | -801 (-67.9%) |
| Top-level CLI commands | 13 | 6 | -7 |
| `AGENTS.md` lines | 469 | 122 | -347 (-74.0%) |
| Active Section 0 lines | about 293 | 48 | -245 (-83.6%) |
| Total execution-plan lines | 4,244 | 4,292 | +48 |
| Exported schemas | 17 | 16 | -1 |
| Reports | 27 | 30 | +3 |

The total plan grew slightly because the historical record was preserved as
requested. Its old corpus/research roadmap is now behind a closed historical
heading; agents are directed to read only the 48-line active Section 0. The
three added reports are the canonical demo, release-readiness result, and this
inventory.

## Removed from the active surface

- the `pilot-readiness` CLI command, its 19 stale Phase-2 blockers, its runtime
  adapter, and its integration test;
- active double-review/adjudication CLI options and the exported adjudication
  schema; the single-reviewer mode is now the library default;
- phase-named proof/yield/scale/minimum/challenge commands from the CLI;
- unreachable scale/minimum scripted-oracle runners and their integration
  tests; and
- public documentation that centered the three-family demo or required ignored
  source bytes for the canonical path.

Exact historical reproduction remains available at `ce0d854`. Frozen reports,
configs, manifests, source-specific normalizers, and immutable v1 artifacts
were not rewritten.

## Retained and why

- Snapshot/hash, normalization, cutoff/admissibility, authority, exact-span,
  lexical retrieval, deterministic grading, and dataset-integrity code protect
  the demonstrated result and remain active.
- Source-specific loaders and the proof/yield/challenge builder chain remain
  because `portfolio-rebuild` verifies the v2 derivatives from exact ignored
  source caches.
- Provider execution internals remain library-only for a possible later
  separately authorized descriptive experiment; no provider command is exposed
  and no new provider machinery was added.
- Legacy review and readiness structures inside shared modules remain isolated
  compatibility code. Their tests are marked `legacy` and excluded from the
  active gate. Splitting the shared dataset-audit module solely to remove those
  classes would create high-risk churn without changing the release result.
- Historical phase configs, schemas still used by optional provider validation,
  and old reports remain because hashes and frozen reproduction refer to them.

The practical reduction is therefore concentrated where users and agents feel
it: one obvious demo, one explicit full rebuild, one release check, six visible
CLI commands, concise active instructions, and no obsolete research-scale gate
in the normal workflow.
