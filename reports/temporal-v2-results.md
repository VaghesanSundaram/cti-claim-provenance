# Temporal v2.1 results

The explicit old-state/new-state/change decomposition did not improve semantic
final-answer correctness. Its equal-cluster effect was **-1.05 percentage
points** with a descriptive 95% bootstrap interval of **-5.26 to +2.63
points**. The interval includes both harm and benefit, so this experiment does
not support a positive decomposition claim.

## Primary result

The factorial contains 480 cells: 24 questions, four conditions, and five
trials. Rates below give each of the 19 dependency clusters equal weight.

| Condition | Method | Schema | Correct cells | Equal-cluster rate | Pass^5 question-conditions |
|---|---|---:|---:|---:|---:|
| A | Direct | Prompt only | 109/120 | 89.12% | 20/24 |
| B | Direct | API enforced | 114/120 | 93.68% | 22/24 |
| C | State first | Prompt only | 110/120 | 89.47% | 21/24 |
| D | State first | API enforced | 111/120 | 91.23% | 20/24 |

| Estimated effect | Percentage points | Descriptive 95% interval |
|---|---:|---:|
| State decomposition | -1.05 | -5.26 to +2.63 |
| Schema enforcement | +3.16 | 0.00 to +7.37 |
| Interaction | -2.81 | -8.42 to +2.11 |

Schema enforcement had a small positive descriptive estimate. Its interval
touches zero, and the study was not designed for a confirmatory significance
claim. The interaction estimate also includes zero.

Across all 520 cells, including the 40 oracle cells, 484 final answers were
semantically correct, 32 were semantically wrong, and four had invalid shapes.
All 40 oracle answers were semantically correct. Exact canonical-string matches
were 0/520; this shows that the canonical representation remained too strict
for semantic accuracy, not that every response was wrong. Evidence binding was
correct for 411/480 factorial cells and 34/40 oracle cells.

Most semantic failures were concentrated in four questions: nine omitted a
required CVE identifier, 19 omitted a later default-state change, two claimed a
membership change was indeterminate, and two omitted a required firmware
identifier. Three of the four invalid shapes were blank state-first outputs for
one mapping case.

## Execution and limits

The valid run used `gpt-5.6-luna` with medium reasoning and completed 520 usable
cells. It consumed 321,630 input tokens and 154,217 output tokens. Known valid-
run cost was USD 0.249386. One connection ended before response headers were
received. That attempt remains an uncertain, possibly billable audit event; a
user-authorized replacement supplied the evaluated cell. The earlier invalid
v2.0 diagnostic cost USD 0.005404.

Final answers were adjudicated once by Codex against the frozen case rubrics.
This is not an independent human review. Condition labels were hidden, but the
response shape could reveal the method. Thirteen packets also contained
evaluator-authored absence assertions, so the experiment tests answer
construction from supplied state evidence, not independent state discovery.

## Minimal-code review

The baseline had five Python files and 463 lines; the final repository has
seven and 1,545. Runtime dependencies fell from three to one, and development
dependencies from five to three. The added code is the provider runner,
recovery path, grader, analysis, and focused tests; the 334-line hard-coded
release checker and unused parsing dependencies were removed. No duplicate
provider path remains. Five non-test files exceed the four-file preference
because public v2 recomputation is isolated from the already-frozen grader.
The minimal-code instruction helped remove release theater and dependencies,
but its line threshold was a review trigger, not a useful success metric.

The public cell table is
[`temporal-v2-cells.jsonl`](temporal-v2-cells.jsonl), its machine-readable
summary is [`temporal-v2-summary.json`](temporal-v2-summary.json), and review
decisions are in
[`../annotations/temporal-v2-semantic-review.json`](../annotations/temporal-v2-semantic-review.json).
Run `uv run cti-provenance recompute-v2` to reproduce the factorial analysis
from those public cells without a provider call.
