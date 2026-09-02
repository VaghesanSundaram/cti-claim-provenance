# Question-specific schema rerun

## Result

The corrected 144-cell run does not show that strict question-specific JSON Schema improves typed output over an explicit shared prompt. Both conditions produced 72/72 contract-valid responses, so the predeclared requirement of at least a 10-point typed-validity gain was not met. The schema condition therefore does not pass the success threshold, regardless of the pending semantic reviews.

| Metric | Citation-prompted | Question-specific schema |
|---|---:|---:|
| Completed responses | 72/72 | 72/72 |
| Typed-contract validity | 72/72 | 72/72 |
| Automatic semantic matches | 55/72 | 57/72 |
| Review-required paraphrases | 12/72 | 11/72 |
| Definite semantic failures | 5/72 | 4/72 |
| Evidence binding | 63/72 | 65/72 |
| Correct abstention reason | 17/24 | 14/24 |

All 48 extraction responses in the citation-prompted condition cited the required evidence, compared with 47/48 under schema enforcement. On the abstention slice, both conditions abstained correctly on 24/24 responses; evidence binding was 15/24 versus 18/24. The schema condition selected the benchmark's exact abstention reason less often.

The 23 review-required outputs are concentrated in four extraction cases. They add product prefixes to version sets or express the Ivanti and NetScaler answers as longer sentences. These surface forms appear consistent on inspection, but remain unresolved because the run predeclared explicit review for type-valid nonmatches; agent inspection is not recorded as human validation.

Definite semantic failures were unsupported abstentions on positive extraction questions. The citation-prompted failures were two PostgreSQL membership answers, two CISA ransomware-use answers, and one CISA KEV membership answer. The schema failures were one PostgreSQL answer and all three CISA KEV membership trials.

## Execution record

- Model: `gpt-5.6-luna`, medium reasoning, default service tier.
- Run: 2026-09-02; 24 questions, two conditions, three trials.
- Provider outcomes: 144 completed, zero incomplete, zero retries, and zero provider errors.
- Usage: 78,741 input tokens and 25,071 output tokens.
- Estimated cost from the frozen pricing: $0.0458.
- Summed provider latency: 419.1 seconds.
- Runner commit: `d01d97e`; grading correction: `0cc52b2`.
- Frozen manifest binding: `c8a87ddd14725577baff4a99a20a1f035994697c750581e58c959130099fde2b`.

The public cell table is [`schema-v1.1-cells.jsonl`](schema-v1.1-cells.jsonl). It includes every sanitized model output, cell identity, usage record, and current grade. Provider envelopes and reasoning data remain outside the repository.

## Limits

This is a targeted development-set replication on one model and 24 questions. Three trials measure repeatability but do not create 144 independent questions. The fixed baseline-first order is a minor time-order limitation. No claim of semantic improvement should be made until the review-required outputs receive the recorded review specified by the design.
