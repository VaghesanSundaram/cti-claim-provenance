# Three-family provider-free corpus slice

Status: **smoke-tested; scope=three_family_scripted_oracle**. This is a deterministic real-source development slice, not a model evaluation or historical-availability proof.

## Results

- Questions: 3/3 completed, exactly one per family.
- Supported atomic claims: 3/3.
- Citation support: 4/4.
- Temporal admissibility: 4/4.
- Accepted predicate authority: 4/4.
- Provider calls/tokens/cost: 0 / 0 / $0.00.
- Deterministic replay: the tracked JSONL and this report are compared byte-for-byte in integration tests.

## Answer keys

- CVE-2024-3094: xz versions `5.6.0` and `5.6.1`.
- Ivanti ED 24-01 V1: disconnect all instances of the named solution products from agency networks by February 2, 2024.
- NetScaler CVE-2023-4966: review the same source IP accessing sessions of multiple users.

## Temporal boundary

All historical times are publisher-declared version evidence. The exact bytes were observed only during the 2026 captures; the slice does not claim independent observation of those bytes at the historical dates. Pre-version cutoffs fail closed and produce no eligible document.

Exact raw bodies remain gitignored. The repository tracks only hashes, metadata, questions, short evidence mappings, and derived results.
