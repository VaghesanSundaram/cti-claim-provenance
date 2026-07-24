# V6 manager-audit handoff

The exact V5 review log is canonical: 48 active decisions, zero unresolved
items, reviewer `reviewer-a17`, and file SHA-256
`c81b62e16961688208b5348501fd577849e1826039723e493ba1838f84752577`.
The agent prepared the entries; the user's explicit “lgtm” is the human-review
act.

V6 changes exactly two user-approved contracts and preserves the other 62
question hashes. Its 64 contracts form 51 semantic-pair groups and 24
dependency clusters; they are not 64 independent factual phenomena.

| Artifact | File SHA-256 | Semantic SHA-256 |
|---|---|---|
| `data/benchmark/portfolio-diverse-draft-v6.json` | `479bdcce12b9213717e49ae52fe68218bc15d791fea7fb085c5d89271a44ead0` | `de5cd022684ba8ac2d099adff5408e4473d87d12884ef9a67fc16bb04936469c` |
| `data/benchmark/portfolio-diverse-packets-v6.json` | `aef36c3fe3ed77972baf4717f55365b0f6a1f3af5eab7c64e2046a0a12be24ef` | `cfd161cf2c96522ee3a045ed6d47e837b7da10b015045e8320962df5a7a2f641` |
| `data/benchmark/portfolio-diverse-v5-to-v6.json` | `dd695fa4abf881e47db77cbd6b8eba2a619e863837f07971396f6137a31da10f` | `55eaa448558b30de9a5c0cc7a43946096b6a311d3b67f0290cbf44ae89cb833f` |
| `configs/experiments/portfolio-diverse-v6-openai-luna.json` | `ee15cb599b71757364b6ac64c00a99119d73c04fbe875b9558f697f820513ad3` | `8cd3eccaa8767a9f501c3a1ce755b6718b60efe286aba701cc2643a19655da8e` |
| `data/benchmark/portfolio-diverse-provider-schedule-v1.json` | `5e9992a9cc2e1d78bf9c1e11103fbdc7e3e5cb96afa977f661a9b804c780c4f4` | `7c4e6c8bf27d0e3fd0b424c59129e9c9ffdeedc2b41768530963e990616857a8` |

The frozen Luna plan has 192 cells, one generation per cell, and at most 384
attempts. Its cache-write-inclusive reservation is $19.968 under the $30 cap.
No provider call has occurred.

Provider execution is blocked. Conservative source review does not authorize
provider egress for five questions using ECOVACS, Güralp, or KUNBUS evidence,
covering ten scheduled cells. Do not run the other 59 questions as a
cherry-picked primary subset.

Local validation passed: 41 focused tests; 487 full tests with 3 skips and 21
legacy deselections; formatting; lint; strict typing; schema/config checks;
provider-free demo; secret scan; historical portfolio release check; package
build; and `git diff --check`. Hosted Ubuntu/Windows CI remains pending the
checkpoint push.

The local sandbox exposes `.codex/EXECUTION_PLAN.md` read-only, so its monitor
block could not be updated. Manager audit must resolve that durable-state
update and the egress decision before any provider execution.
