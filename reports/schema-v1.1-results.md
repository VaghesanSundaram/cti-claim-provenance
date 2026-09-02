# Question-specific schema rerun

## Result

The corrected 144-cell run does not show that strict question-specific JSON Schema improves typed output over an explicit shared prompt. Both conditions produced 72/72 contract-valid responses, so the predeclared requirement of at least a 10-point typed-validity gain was not met. The schema condition therefore does not pass the success threshold, regardless of semantic adjudication.

| Metric | Citation-prompted | Question-specific schema |
|---|---:|---:|
| Completed responses | 72/72 | 72/72 |
| Typed-contract validity | 72/72 | 72/72 |
| Semantic answers after agent review | 67/72 | 68/72 |
| Consistent answers across all three trials | 21/24 | 22/24 |
| Evidence binding | 63/72 | 65/72 |
| Correct abstention reason | 17/24 | 14/24 |

All 48 extraction responses in the citation-prompted condition cited the required evidence, compared with 47/48 under schema enforcement. On the abstention slice, both conditions abstained correctly on 24/24 responses; evidence binding was 15/24 versus 18/24. The schema condition selected the benchmark's exact abstention reason less often.

## Complete response audit

All 144 provider outcomes were complete JSON objects with exactly the five required fields. Every response used the required schema version and case ID, matched its declared answer datatype, used a valid answer/abstention relationship, and supplied citations as a string array. No response was incomplete or scored as semantically wrong because of its format.

The deterministic grader resolved 112 answers as correct and nine as incorrect. Agent review checked all 23 remaining type-valid nonmatches against their questions, reviewed answers, and required evidence. All 23 preserve the requested facts. They only add product names to version values or express the Ivanti and NetScaler answers as longer sentences. The decisions are recorded in [`../annotations/schema-v1.1-agent-review.jsonl`](../annotations/schema-v1.1-agent-review.jsonl). This was not condition-blinded or human validation, so the resulting semantic scores are descriptive.

Definite semantic failures were unsupported abstentions on positive extraction questions. The citation-prompted failures were two PostgreSQL membership answers, two CISA ransomware-use answers, and one CISA KEV membership answer. The schema failures were one PostgreSQL answer and all three CISA KEV membership trials.

The 16 evidence-binding failures were also substantive rather than formatting failures. Fifteen omitted a required comparison span in an abstention case; one schema response both abstained incorrectly and returned no citation. All cited identifiers were otherwise well-formed and belonged to the supplied packet. Seventeen of 48 abstention responses chose the wrong reason code even though every response correctly declined to answer.

## Conclusion

The explicit datatype instruction fixed the V1 representation problem by itself: both conditions achieved 72/72 typed-contract validity. Strict schema enforcement therefore added no measurable formatting benefit and failed the predeclared threshold.

After agent review, schema enforcement changed semantic accuracy by only one response (94.4% versus 93.1%): three paired wins, two paired losses, and 67 ties. It improved evidence binding by two responses but reduced exact abstention-reason accuracy by three. The direction also varied by case: the schema condition recovered two CISA ransomware-use trials but failed all three CISA KEV membership trials. These small, inconsistent movements do not support a claim that strict schema enforcement improved answer quality.

## Execution record

- Model: `gpt-5.6-luna`, medium reasoning, default service tier.
- Run: 2026-09-02; 24 questions, two conditions, three trials.
- Provider outcomes: 144 completed, zero incomplete, zero retries, and zero provider errors.
- Usage: 78,741 input tokens and 25,071 output tokens.
- Estimated cost from the frozen pricing: $0.0458.
- Summed provider latency: 419.1 seconds.
- Runner commit: `d01d97e`; grading correction: `0cc52b2`.
- Frozen manifest binding: `c8a87ddd14725577baff4a99a20a1f035994697c750581e58c959130099fde2b`.

The public cell table is [`schema-v1.1-cells.jsonl`](schema-v1.1-cells.jsonl). It includes every sanitized model output, cell identity, usage record, and deterministic grade. Provider envelopes and reasoning data remain outside the repository.

## Limits

This is a targeted development-set replication on one model and 24 questions. Three trials measure repeatability but do not create 144 independent questions. The fixed baseline-first order is a minor time-order limitation. The agent semantic review was performed after condition labels were visible and does not satisfy the predeclared blinded-review method; a human or properly blinded review would be required for a confirmatory semantic estimate.
