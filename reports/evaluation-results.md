# Evaluation results

The study evaluated 64 questions once under each of two pipelines, with 96
scored cells per condition after including the matched control and challenge
variants for the original extraction subset.

| Pipeline | Evidence binding | Exact answer | Correct abstention |
|---|---:|---:|---:|
| Citation-prompted | 80/96 (83.3%) | 32/96 (33.3%) | 7/8 |
| Constrained | 83/96 (86.5%) | 25/96 (26.0%) | 6/8 |

The constrained pipeline improved evidence binding by three cases, driven
mainly by time-sensitive questions. Its typed exact-answer score declined by
seven cases; the matched review below separates representation differences from
substantive answer failures.

## Matched output review

A manual review of every pair whose exact-answer outcome changed found 11
losses and four wins for the constrained pipeline. Eight losses were
representation mismatches rather than factual reversals: the response gave a
version string or applicability mapping where the answer contract required a
boolean, or included a product prefix that the exact normalizer did not accept.
One additional loss abstained correctly but selected the wrong abstention reason
code. The remaining two losses were genuine missed answers: the constrained
response abstained despite sufficient evidence.

All four wins were also representation changes. Three converted a scalar
version into the required one-element set, and one removed an unaccepted product
prefix. The negative exact-answer delta therefore primarily measures alignment
with the benchmark's typed answer contract, not a decline in factual accuracy.
Because each cell ran once, this review identifies the observed mechanism but
does not establish a stable causal effect of schema enforcement.

The sanitized model responses are in
[`evaluation-outputs.jsonl`](evaluation-outputs.jsonl). The 11 reviewed losses
and their classifications are in
[`evaluation-regressions.jsonl`](evaluation-regressions.jsonl).
Each sanitized response was matched to its preserved provider output using the
recorded SHA-256. Public case IDs replace development identifiers; provider
envelopes and encrypted reasoning are excluded.

Temporal questions were the clearest failure mode. Evidence binding improved
from 18/24 to 23/24, but strict exact-answer performance remained 0/24 in both
conditions. The model often selected a relevant dated source while still
omitting or misrepresenting part of the required change.

The defensible conclusion is narrow: the constrained pipeline modestly improved
evidence selection, while its generic union schema did not reliably enforce the
question-specific answer datatype. A follow-up should compare generic and
question-specific schemas while grading semantic correctness separately from
typed-contract adherence.
