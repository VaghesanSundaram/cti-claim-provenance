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
- A privacy-safe 192-row result table that reproduces the published aggregate
  without including model responses or restricted source text.
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
packets, human-review record, privacy-safe result projection, and metric
recomputation. It does not include the original provider-run collection and
generation pipeline. The v1 artifacts therefore support inspection of the
benchmark design and verification of the published aggregates, but not a full
rerun of the model experiment.

The frozen v2 offline design is documented in
[docs/temporal-v2-evaluation.md](docs/temporal-v2-evaluation.md). It tests
temporal answer construction from the 24 approved temporal packets. No v2
provider request has been authorized or sent.

## Evaluation

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
answer construction: exact-answer performance fell by seven cases, and neither
pipeline produced an exact answer on the 24 temporal cases.

The useful finding is therefore mixed. Structured output helped organize
evidence, but schema enforcement alone did not solve temporal reasoning or
canonical answer construction.

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

## Validate the public artifacts

```powershell
uv sync --frozen
uv run cti-provenance validate
```

This offline check validates corpus and packet integrity and recomputes the v1
metrics from all 192 public cells. It does not call a model API or access the
network.

The project targets Python 3.12. CI runs formatting, linting, strict type
checking, focused tests, and metric recomputation on Ubuntu.

Apache-2.0 covers project-authored code and documentation. Source material
retains its original terms; see
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
