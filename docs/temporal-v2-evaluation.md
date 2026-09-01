# Temporal answer construction experiment

Status: frozen offline design; no provider request is authorized.

## Question and scope

V1 showed 0/24 strict canonical temporal answers under both published
conditions. It did not retain public raw responses, so it did not establish
that all 48 outputs were semantically wrong. V2 tests whether an explicit
old-state, new-state, and change decomposition improves semantic final answers
and whether API schema enforcement changes outcomes independently.

Thirteen of the 24 approved packets include deterministic, evaluator-authored
absence assertions for an earlier source state. They are useful state evidence,
but they are not publisher text and already supply an oracle-like conclusion.
V2 therefore tests **answer construction from supplied state evidence**. It
does not test independent discovery of every old state. The factorial requests
contain no reviewed final answer or delta label.

## Frozen design

The factorial has 24 existing temporal questions, 19 dependency clusters, four
conditions, and five trials. A and B ask for a direct final answer. C and D add
explicit old-state, new-state, and change fields. B and D apply an API response
schema; A and C request the identical JSON shape only in the prompt. Evidence,
document order, final-answer field, model settings, and token limit are fixed
across all four conditions. The decomposition factor is the instruction plus
its additional fields, not an isolated chain-of-thought intervention.

The common response has `final_answer` and `citations`. State-first responses
also have `old_state`, `old_state_citations`, `new_state`,
`new_state_citations`, `change`, and `change_citations`. State values preserve
the corpus type: string, string set, or mapping. Citation values are packet
span aliases. Missing fields, invalid types, invalid JSON, refusals, unknown
aliases, and incomplete required citations fail closed.

The 480 factorial cells are supplemented by 40 oracle cells. The oracle gives
the reviewed old and new values and asks only for the change and final answer.
Its eight cases are `temporal-03`, `temporal-04`, `temporal-05`,
`temporal-18`, `temporal-19`, `temporal-20`, `temporal-22`, and
`temporal-24`. They cover eight clusters, both splits, both outcomes, and every
state shape without consulting v1 performance. Oracle results are excluded
from factorial effects.

Within each question/trial block, condition order follows a rotated Latin
order. Question blocks interleave dependency clusters, and oracle cells are
distributed through each trial. This balances provider drift without treating
trials as independent questions.

## Frozen grading and analysis

The primary outcome is semantic correctness of the common `final_answer`.
Automatic semantic passes require equality after only Unicode, case,
whitespace, punctuation, set-order, or mapping-key normalization against a
frozen accepted expression. There is no fuzzy score, substring-only rule, or
model judge. Other completed answers go to one reviewer who sees the question,
evidence, frozen case rubric, and redacted answer, but not condition, trial, or
canonical-match status. Missing a required proposition or adding a material
contradiction fails. Canonical equality remains a separate metric.

State-first old state, new state, and change are graded separately. Evidence
binding requires every component's reviewed evidence through the packet's
private alias mapping. The supplied temporal packets contain only eligible,
predicate-appropriate evidence; post-cutoff and authority metrics are therefore
reported as not applicable for this experiment, not as evidence of perfect
performance.

The schedule-level primary denominator includes every planned cell. Provider
failure, refusal, invalid JSON, unresolved review, or other non-semantic outcome
scores 0 and is also reported separately. Trials are averaged within each
question-condition, questions are averaged within each dependency cluster,
then the 19 clusters receive equal weight. The effects are:

- decomposition: `0.5 × ((C − A) + (D − B))`;
- schema: `0.5 × ((B − A) + (D − C))`; and
- interaction: `(D − C) − (B − A)`.

Descriptive 95% intervals use 10,000 fixed-seed (`20260901`) bootstrap samples
of whole dependency clusters. Five-trial reliability reports each bit vector,
the pass count, and an all-five-pass indicator called `pass^5`; it is not a
probability estimate. No p-value or confirmatory significance claim is made.

## Leakage, retries, and stop rules

Factorial requests are built only from an allowlisted packet projection. They
exclude readable references, expected components, delta labels, derivation
records, evidence IDs, source IDs and hashes, authority rationales, ambiguity
notes, and evaluator bindings. The 13 typed absence assertions are recorded as
an explicit supplied-state exception. Oracle old/new values are a separate
tagged exception. Every unique request is inspected and the ordered request set
is regenerated byte-identically before egress.

Only a connection failure before acceptance, rate limit, or server error with
no accepted output can retry, once. A completed refusal, parse or semantic
failure, and any uncertain possibly billed outcome never retries. The run stops
on model mismatch, schedule or request hash drift, ledger mismatch, unexpected
egress, uncertain outcome, or cost-accounting risk.

Provider approval requires the exact commit, descriptor, prompt, rubric,
grader, schedule, and request-set hashes; endpoint and SDK; model and settings;
all 520 ordered cell IDs; ten smoke IDs; input size and token accounting; egress
inventory; ignored unsynchronized raw-output directory; ledger and retry rules;
current pricing source; base and retry-inclusive projection; and the USD 10
hard cap. Route, settings support, tokenizer, retention behavior, and pricing
must be verified as current facts before approval.
