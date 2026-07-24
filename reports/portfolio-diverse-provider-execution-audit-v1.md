# CTI provider execution audit v1

## Final disposition

The 192-cell GPT-5.6 Luna evaluation completed with 192 unique scheduled
results. Every final cell returned a completed provider response and passed the
local response parser. Accounted provider cost was `$0.660676`.

The primary metric is exact claim provenance: correct abstention, or the exact
predicate, component role, and required evidence bindings. Canonical typed-value
exactness is a stricter secondary metric. Natural-language `authority_scope`
wording is descriptive and is not compared byte-for-byte because authority is
enforced by the predicate and exact cited evidence.

## Pre-execution repairs

Provider diagnostics exposed three implementation defects before the final run:

1. Pydantic emitted an empty schema for unrestricted `JsonValue`. The strict
   Responses schema now enumerates only the value shapes used by the corpus, and
   a recursive test rejects unconstrained schema nodes.
2. Candidate packets did not expose the internal predicate or expected component
   roles even though the grader required them. Packets now expose
   `target_predicate` and slice-derived `supported_component_kinds`; no answer
   value, citation, or abstention label is disclosed.
3. The grader treated free-form authority wording as an exact label and crashed
   when a model emitted a known predicate outside the V6 policy catalog.
   Authority wording is now unscored, while wrong predicates return an incorrect
   grade rather than terminating the run.

HTTP/API failures now stop the schedule before subsequent cells. Transient
provider failures receive at most two retries with 2-second and 8-second
backoffs. The retry-inclusive reservation is `$29.952` under the fixed `$30`
cap.

All provider calls made before these repairs are diagnostics and are excluded
from the final result set.

## Provider recovery

After 86 valid final cells, one scheduled cell received two HTTP 503 responses.
The run stopped. A hash-bound recovery receipt imported only the 86 contiguous
valid results, excluded the 503 row, and resumed at the failed ordinal. The
delayed recovery returned HTTP 200 on its first attempt. No valid cell was
repeated and the 503 was not scored as a model failure.

## Findings

| Condition | Provenance | Canonical exact |
| --- | ---: | ---: |
| Citation-prompted | 80/96 (83.3%) | 32/96 (33.3%) |
| Claim/evidence constrained | 83/96 (86.5%) | 25/96 (26.0%) |

The constrained pipeline gained three provenance-correct cells overall:
7 paired wins, 85 ties, and 4 losses. The dependency-family macro delta was
`+0.044`. This is a small descriptive difference, not a statistically
established effect.

On the 64 clean semantic questions, provenance was 54/64 for citation-prompted
and 57/64 for constrained. The largest slice difference was temporal comparison:
18/24 versus 23/24. Authority divergence was 8/8 versus 7/8; abstention was 7/8
versus 6/8; synthesis was 7/8 for both; and single-source extraction was 40/48
for both.

Strict canonical exactness was lower under the constrained condition and was
zero for both conditions on temporal, authority-divergence, and synthesis
questions. The model often selected the correct evidence while paraphrasing or
structuring the value differently from the corpus's canonical representation.
This is why provenance and canonical serialization are reported separately.

Control/challenge results did not show a large consistent provenance effect:
control was 13/16 versus 12/16, and challenge was 13/16 versus 14/16.

## Integrity

- Plan semantic digest:
  `ce2da4b6de35d73b5383b48b8413997e9d20c645f127ab17b4f38788a847dd71`
- Schedule semantic digest:
  `0f52f92a1cf9a320a674f9a955f27133f9e091d0141c12090664fc2e5905c002`
- Final summary digest:
  `f4ba765ba153dec0a13bc0f5ec866a006dc7b311250f9bf4a47442ac45a6b356`
- Redacted result-set SHA-256:
  `64b22fdeaee934c28bd07e8e1e8ed6bfd17f8eca06c071a1c5160c3f18ca2f3e`
- Recovery receipt SHA-256:
  `8b9396547cfc17999aae51e3c9f19c7f7c9d5ef9ad4d2c7a533c3564d4b9ffad`

The final aggregate report is
`reports/portfolio-diverse-model-evaluation-v1.json` with a readable rendering
in `reports/portfolio-diverse-model-evaluation-v1.md`. Raw provider responses
remain outside the repository and synchronized folders.

## Limitations

This is one sample per cell. The 64 questions span 24 dependency clusters and
are not 64 independent factual phenomena. Control/challenge packets cover only
the 16 retained extraction questions. The comparison bundles prompt wording
with API schema enforcement, so it does not identify a standalone causal effect
of schema enforcement.
