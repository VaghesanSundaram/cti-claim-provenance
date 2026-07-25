# Evaluation results

The study evaluated 64 questions once under each of two pipelines, with 96
scored cells per condition after including the matched control and challenge
variants for the original extraction subset.

| Pipeline | Evidence binding | Exact answer | Correct abstention |
|---|---:|---:|---:|
| Citation-prompted | 80/96 (83.3%) | 32/96 (33.3%) | 7/8 |
| Constrained | 83/96 (86.5%) | 25/96 (26.0%) | 6/8 |

The constrained pipeline improved evidence binding by three cases, driven
mainly by time-sensitive questions. That gain did not carry through to complete
answer construction: exact-answer performance declined by seven cases.

Temporal questions were the clearest failure mode. Evidence binding improved
from 18/24 to 23/24, but strict exact-answer performance remained 0/24 in both
conditions. The model often selected a relevant dated source while still
omitting or misrepresenting part of the required change.

The defensible conclusion is narrow: structured output modestly improved
evidence selection in this dataset, but did not solve temporal reasoning or
produce more complete answers.
