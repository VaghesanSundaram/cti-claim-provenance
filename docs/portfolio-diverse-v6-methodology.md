# Diverse portfolio V6 methodology and completed result

V6 is a human-reviewed, point-in-time CTI benchmark with 64 semantic answer
contracts: 16 extraction, 24 temporal comparison, 8 cutoff/insufficiency
abstention, 8 authority-divergence, and 8 multi-source synthesis contracts.
They form 51 semantic-pair groups and 24 source/dependency clusters; they are
not 64 independent factual phenomena. V5 remains immutable. V6 records two
approved corrections and five egress-safe replacements in
[`portfolio-diverse-v5-to-v6.json`](../data/benchmark/portfolio-diverse-v5-to-v6.json).

## Evaluation

The completed one-sample GPT-5.6 Luna run contains 192 cells: both conditions
on 64 clean questions, plus matched clean/control/challenge variants for the
16 retained extraction questions. It compares bundled pipelines, not an
isolated intervention: `citation_prompted` versus
`claim_evidence_constrained` (prompt plus API schema enforcement). No repeats,
significance test, stability estimate, or causal claim is supported.

The preregistered primary metric is **provenance/evidence-binding correctness**:
correct abstention, or correct target predicate, component role, and exact
required evidence binding. The secondary metric is **strict canonical typed
value exactness**. It is intentionally stricter: a supported answer can fail
when its value is paraphrased or serialized differently. Natural-language
authority wording is descriptive; authority is enforced by predicate and cited
evidence, not byte-for-byte wording.

| Condition | Evidence-binding correctness | Strict canonical exactness |
| --- | ---: | ---: |
| Citation-prompted | 80/96 (83.3%) | 32/96 (33.3%) |
| Claim/evidence constrained | 83/96 (86.5%) | 25/96 (26.0%) |

The constrained pipeline had 7 paired evidence-binding wins, 85 ties, and 4
losses (mean paired delta +0.031; dependency-family macro delta +0.044). The
largest slice difference was temporal comparison, 18/24 to 23/24. The result is
descriptive: it suggests a small evidence-binding gain in this frozen corpus,
while strict canonical exactness decreased. It does not demonstrate broad CTI
generalization or a causal schema-enforcement effect.

All 192 final cells completed with valid parses and returned `gpt-5.6-luna`.
Accounted cost was $0.660676 (270,844 input and 64,972 output tokens). The
historical connectivity blocker remains recorded for audit, but is not the
current evaluation state.

## Reproducibility and boundaries

[`portfolio-diverse-model-evaluation-v1.json`](../reports/portfolio-diverse-model-evaluation-v1.json)
is the aggregate. The tracked
[`per-cell redacted projection`](../reports/portfolio-diverse-model-evaluation-v1-cells.jsonl)
contains only case/condition identifiers, grades, token/cost accounting, and
request/response/output hashes—never provider text, source bodies, secrets, or
private artifacts. Its verifier recomputes the aggregate from those rows.

Publisher-declared version evidence establishes what a named version says and
its declared time, not independently observed historical availability. One
reviewer approved labels; there is no inter-reviewer reliability statistic.
Controls/challenges cover only the retained extraction subset, and abstention
tests only enumerated benchmark insufficiency causes.
