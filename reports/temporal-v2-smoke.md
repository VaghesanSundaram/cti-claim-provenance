# Temporal v2.1 provider smoke

Status: valid execution smoke. These ten cells remain part of the frozen
520-cell denominator.

## Execution

- Commit: `e5a4da1cfeb3bdeea3efd9a0bae49c424388e1a7`
- Manifest: `0d58a976a9d55074a395b3f859cd173c08ac43889390878c0d969efc5285bc4b`
- Ledger: `${CTI_TEMPORAL_RAW_DIR}/smoke-v2.1-ledger.jsonl`
- Ledger SHA-256:
  `a0bc8daa6e3f60967c7857f8509b79107fe8537e9bccc8a771e602db6c551ab6`
- Cells: 10 completed; 0 retries; 0 uncertain or open attempts
- Route: all ten returned `gpt-5.6-luna`, service tier `default`, and status
  `completed`
- Usage: 6,031 input tokens; 0 cached input tokens; 3,392 output tokens
- Cost at the frozen prices: USD 0.005277
- Provider latency: 1,759.725 ms minimum; 4,382.195 ms mean; 9,077.728 ms
  maximum

The earlier v2.0 diagnostic smoke also completed ten calls, but the harness did
not record latency. Those raw responses and its ledger remain preserved outside
the repository and are excluded from every v2.1 result and denominator. Its
cost was USD 0.005404. Total provider cost through this checkpoint is USD
0.010680.

## Inspection

Every smoke output and raw response was inspected. No request leakage,
unexpected tool use, model mismatch, refusal, parse failure, persistence gap,
or schema-pairing defect was found. Structured conditions returned their exact
required shapes. Prompt-only conditions returned valid requested JSON.

The outputs exposed real model errors, not harness errors. The `temporal-04`
factorial answers generally described an `unaffected` entry but omitted the
required proposition that the later record's default became unaffected. One
also omitted the corresponding evidence alias. The `temporal-03` direct A
answer `Linux` correctly answered which platform was added; the question did
not require restating the change direction. The smoke validated execution and
grading behavior; final adjudication is reported in
[`temporal-v2-results.md`](temporal-v2-results.md).

## Scaling decision

The smoke satisfied Checkpoint 3. The full run has since completed under the
same manifest.
