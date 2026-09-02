# Point-in-Time CTI Claim Provenance

[![CI](https://github.com/VaghesanSundaram/cti-claim-provenance/actions/workflows/ci.yml/badge.svg)](https://github.com/VaghesanSundaram/cti-claim-provenance/actions/workflows/ci.yml)

Security facts change over time. A vulnerability answer can be correct today
and still be wrong for a historical cutoff because it uses evidence that was
published later, cites the wrong authority, or combines claims that its sources
do not support.

This project publishes a benchmark for that problem. It records dated source
evidence, point-in-time cutoff and authority rules, typed expected answers,
human review, privacy-safe result projections, and deterministic metric
recomputation.

## Engineering highlights

- **64 reviewed questions** covering direct extraction, changes over time,
  insufficient pre-cutoff evidence, disagreements between authorities, and
  multi-source synthesis.
- **24 source/dependency groups** used as the split unit so closely related
  questions do not leak across development and validation data.
- Point-in-time cutoff and source-authority rules with exact source hashes and
  evidence spans.
- Typed expected answers, including explicit abstention cases.
- Group-aware split isolation and a documented human-review record.
- A privacy-safe 192-row result table and sanitized V1 model outputs for direct
  inspection and aggregate recomputation. See
  [`reports/evaluation-outputs.jsonl`](reports/evaluation-outputs.jsonl).
- A completed 520-cell temporal follow-up with five trials per factorial cell,
  cluster-weighted effects, and public metric recomputation.
- Offline integrity checks and metric recomputation from the public result
  cells.

## What I designed and validated

I designed the benchmark schema, question families, cutoff and authority rules,
evidence packets, typed expected-answer format, abstention cases, review record,
split constraints, privacy-safe result projection, and aggregate checks.

The evaluation scores evidence binding separately from exact answer
construction. A response can cite the right source material and still fail to
construct the expected point-in-time answer.

## What the public release contains

This public repository contains the reviewed benchmark corpus, evidence
packets, human-review record, privacy-safe result projection, sanitized final
model outputs, and metric recomputation. It omits provider response envelopes,
encrypted reasoning, restricted source bodies, and the original generation
pipeline. The V1 artifacts support direct answer inspection and verification of
the published aggregates, but not a provider-level replay of the original run.

The completed v2 design is documented in
[docs/temporal-v2-evaluation.md](docs/temporal-v2-evaluation.md), with results
in [reports/temporal-v2-results.md](reports/temporal-v2-results.md). Across 19
equally weighted dependency clusters, explicit state decomposition changed
semantic accuracy by -1.05 percentage points (descriptive 95% interval: -5.26
to +2.63). It did not improve the primary outcome.

## V1 evaluation

I compared two complete model pipelines using GPT-5.6 Luna:

- **Citation-prompted:** the prompt requested the answer and supporting
  evidence.
- **Constrained:** the same task also used an API-enforced structured response
  schema.

Every question ran once. The 192 scored cells include all 64 clean questions
plus matched control and challenge variants for the original extraction
subset.

Two metrics are reported separately:

- **Evidence binding:** the response selected evidence that supports the
  requested claim, is available by the cutoff, and has the right authority.
- **Exact answer:** the response also matched the benchmark's complete typed
  answer representation.

| Pipeline | Evidence binding | Exact answer | Correct abstention |
|---|---:|---:|---:|
| Citation-prompted | 80/96 (83.3%) | 32/96 (33.3%) | 7/8 |
| Constrained | **83/96 (86.5%)** | 25/96 (26.0%) | 6/8 |

The constrained pipeline selected supporting evidence slightly more often, with
the largest gain on time-sensitive questions. It did **not** improve complete
typed-answer matching: the net score fell by seven cases, and neither pipeline
produced an exact answer on the 24 temporal cases. Manual review found that the
net decline was driven mainly by datatype and normalization mismatches, not
factual reversals; see
[`reports/evaluation-results.md`](reports/evaluation-results.md).

The useful finding is therefore mixed. Structured output helped organize
evidence, but the generic union schema did not reliably produce each question's
required answer datatype.

## Question-specific schema replication

A targeted follow-up replaced the generic union with a schema derived from each
question's public answer datatype. Across 24 extraction and abstention questions,
two conditions, and three trials, all 144 responses completed. The explicit
shared prompt and the strict schema condition both produced 72/72 contract-valid
responses, so schema enforcement did not improve typed validity or meet the
predeclared success threshold. Evidence binding was 63/72 without enforcement
and 65/72 with enforcement. A complete output audit found no incomplete or
format-invalid responses. Agent-reviewed semantic accuracy was 67/72 versus
68/72, a descriptive one-response difference that does not establish an
improvement; see
[`reports/schema-v1.1-results.md`](reports/schema-v1.1-results.md).

The full experimental design is documented in
[docs/methodology.md](docs/methodology.md), and the slice-level interpretation
is summarized in
[reports/evaluation-results.md](reports/evaluation-results.md).

## Experimental design

```text
dated source snapshots
        |
        v
normalization + source hashes
        |
        v
cutoff and authority filtering
        |
        v
evidence packet + model response
        |
        v
claim, citation, cutoff, and authority grading
```

The study design keeps source eligibility and grading outside the model. It also
distinguishes "no answer is supported by the available evidence" from a wrong
answer, rather than forcing every question to be answered.

## Limits

- One model and one generation per cell; there is no repeatability or
  statistical-significance estimate.
- The 64 questions contain 24 related source groups, not 64 independent facts.
- One human reviewer approved the gold answers.
- The two conditions compare bundled pipelines, so the experiment does not
  isolate the causal effect of schema enforcement.
- Exact-answer scoring is intentionally strict and should not be described as
  general factual accuracy.
- V2 final answers received one Codex adjudication, not independent human
  review; response shape could reveal the method.

## Validate the public artifacts

```powershell
uv sync --frozen
uv run cti-provenance validate
```

This offline check validates corpus and packet integrity and recomputes v1 and
v2 metrics from public cells. It does not call a model API or access the
network. Use `uv run cti-provenance recompute-v2` for the v2 analysis alone.

The project targets Python 3.12. CI runs formatting, linting, strict type
checking, focused tests, and metric recomputation on Ubuntu.

Apache-2.0 covers project-authored code and documentation. Source material
retains its original terms; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
