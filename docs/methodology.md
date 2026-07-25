# Methodology

## Research question

Can a model answer point-in-time cybersecurity questions using only evidence
that was available by a stated cutoff and appropriate for the requested claim?
Does enforcing a structured response schema improve that behavior?

## Corpus

The evaluated corpus contains 64 human-reviewed questions across 24
source/dependency groups. Questions cover:

- direct extraction from an authoritative source;
- changes between two dated source states;
- cases where the available evidence is insufficient and the model should
  abstain;
- disagreements between sources with different authority; and
- claims that require combining multiple sources.

Related questions share a dependency-group identifier. Development and
validation splits are disjoint at that group level, which prevents versions of
the same underlying source event from appearing on both sides of the split.

Each question binds a cutoff, eligible evidence spans, an authority rule, and a
typed expected answer. Source snapshots are identified by cryptographic hashes.

## Compared pipelines

Every question ran once under two conditions using the same model and evidence
packet:

1. **Citation-prompted:** a normal prompt requested an answer and citations.
2. **Constrained:** the API also enforced a structured response schema.

The conditions therefore compare two complete pipelines. They do not isolate
schema enforcement from every other interaction it may have with generation.

## Scoring

The evaluator reports two distinct outcomes:

- **Evidence binding** checks whether the cited evidence supports the requested
  claim, was available by the cutoff, and came from the required authority.
- **Exact answer** additionally requires every typed answer component to match
  the reviewed reference representation.

Abstention questions are scored separately: the correct behavior is to decline
to assert a fact when the cutoff-eligible evidence cannot support it.

## Validity limits

This is a descriptive study with one model response per cell and one human
reviewer. The 64 questions represent 24 related source groups, not 64
independent observations. The results do not establish statistical
significance or broad model generalization.
