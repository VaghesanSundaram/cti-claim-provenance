# Bounded corpus-feasibility inventory

Date: 2026-07-21

Final decision: **FEASIBLE for the smallest three-family provider-free slice.**
The preserved Ivanti and NetScaler families are joined by commit-addressed CVE
Program versions of CVE-2024-3094. MOVEit remains rejected because its captured
v7/v8 bodies have no material semantic delta.

## Capture boundary

The replacement authorization allowed four families and 12 successful GETs.
The search stopped after the second candidate and used five successful GETs,
with no retry, provider call, credential, redirect, live-service mutation, or
new transport mechanism. Exact bodies remain under gitignored `data/raw/`.
Tracked metadata and hashes are in:

- `data/manifests/corpus-replacement-search-v1.json`;
- `data/manifests/corpus-feasibility-seven-url-v1.json`; and
- `data/manifests/three-family-corpus-v1.json`.

## Replacement candidate matrix

| Candidate | Source states inspected | Decision |
|---|---|---|
| CISA ED 25-03 Cisco devices | ED page plus separately addressed core-dump/hunt supplement | Rejected. The pages are complementary, not preserved historical states of one claim. |
| CVE-2024-3094 | Official CVE List V5 commit history plus initial and 2024-04-18 commit-addressed records | Accepted. The CNA state changes from unenumerated/default affected to explicit affected versions `5.6.0` and `5.6.1` with default unaffected. |

No third or fourth replacement candidate was inspected because the accepted
candidate closed the search gate.

## Material deltas

| Family | Independently addressable publisher states | Material change used |
|---|---|---|
| CVE-2024-3094 / xz | CVE List V5 commits `e6d66b8...` and `f839db1...` | The later CNA record explicitly enumerates xz `5.6.0` and `5.6.1` as affected and changes the default to unaffected. |
| Ivanti ED 24-01 | CISA Supplemental Directions V1 and V2 | V1 requires disconnection; V2 supersedes V1 and adds the February 8 update for CVE-2024-22024 by February 12. |
| NetScaler CVE-2023-4966 | Vendor posts published October 23 and November 20 | The later investigation post adds a concrete SSLVPN log-review pattern beyond patch and session-clearing guidance. |

## Exactly three reviewed questions

1. From CVE Program commit `f839db1...`, which exact xz versions does the CNA
   container explicitly mark affected? Answer: `5.6.0` and `5.6.1`.
2. Under CISA Supplemental Direction V1, what immediate network action was
   required by February 2? Answer: disconnect all instances of the named
   Ivanti solution products from agency networks.
3. In NetScaler's November 20 investigation guidance, what SSLVPN
   `TCPCONNSTAT` pattern should investigators review? Answer: the same source IP
   accessing sessions of multiple users.

The exact cases and manager review bindings are in
`data/benchmark/dev/three-family-cases.jsonl` and
`annotations/three-family-review.jsonl`. Claim/evidence details are documented
in `docs/three-family-claims-evidence.md`.

Authority grading is declared by and hash-bound to the distinct
`configs/authority-policy-three-family-v1.yaml` catalog. The CVE evidence spans
include each version together with its sibling `status: affected` value. Gold
loading rejects evidence outside the case's cutoff-selected allowed snapshot.

## Temporal and redistribution boundary

All historical times are **publisher-declared version evidence**, not proof
that these exact bytes were independently observed on those historical dates.
The bytes were observed during the 2026 bounded captures. Cutoff selection is
therefore phrased only in terms of the named publisher version. Earlier
cutoffs fail closed. Raw source bodies, headers, and quarantine material are
not tracked or redistributed.

## Result and stop condition

`uv run cti-provenance three-family-slice` deterministically produces three
supported claims with accepted authority, admissible cutoff selection, exact
hash-bound evidence, and zero provider calls. The tracked report is
`reports/three-family-slice.md`. This closes the provider-free corpus gate; no
additional family, transport, schema mechanism, attack case, or provider run is
authorized by this result.
