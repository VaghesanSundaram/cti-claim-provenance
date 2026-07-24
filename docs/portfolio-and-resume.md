# Portfolio and resume guide

## Two-sentence description

Built a point-in-time CTI benchmark that checks whether answers bind to
cutoff-eligible, authority-appropriate evidence spans. Evaluated two bundled
GPT-5.6 Luna pipelines across 192 single-sample cells: the constrained pipeline
had 86.5% evidence-binding correctness versus 83.3% for citation prompting,
but lower strict canonical-answer exactness (26.0% versus 33.3%).

## Resume bullets

- Built a 64-question, 24-dependency-cluster CTI provenance benchmark spanning
  extraction, temporal comparison, abstention, authority-divergence, and
  multi-source synthesis; encoded human-reviewed cutoff and source bindings.
- Evaluated 192 GPT-5.6 Luna cells comparing citation prompting with a bundled
  claim/evidence-constrained pipeline; observed 86.5% vs. 83.3% evidence-binding
  correctness, with a documented canonical-answer exactness tradeoff.
- Implemented deterministic grading, hash-bound redacted result records, and a
  provider-free verifier that recomputes published aggregate metrics without
  storing model text or source bodies.

## Interview-safe explanation

The result is not “the model is 86.5% accurate.” It means that in this frozen
benchmark it supplied the expected kind of claim with the required evidence
binding 86.5% of the time. It less often matched the benchmark’s exact canonical
answer representation, and the two pipelines differ in both prompts and schema
enforcement, so this is a measured tradeoff rather than a causal proof.

## Limits

- One generation per cell; no repeatability or significance estimate.
- 24 dependency clusters, not 64 independent facts.
- One human reviewer; no inter-reviewer agreement.
- Controls/challenges cover only 16 extraction questions.
- Raw provider output and source bodies are deliberately excluded.
