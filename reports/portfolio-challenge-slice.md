# Portfolio matched retrieval-challenge slice

Status: **evaluated offline; scope=portfolio_pilot_retrieval_only**. This is not a provider/model evaluation.

## Corpus and packets

- Audited-distinct public development/validation families: 16/16.
- Split: 8 dev / 8 validation.
- Matched variants: 48/48 (clean, benign control, challenge).
- Holdout candidates exposed to packets, retrieval, prompts, or graders: 0/8.
- Reciprocal clean/challenge pairs passing dataset integrity: 16/16.
- Benign control cases bound to exact packet membership: 16/16.

## Retrieval

- clean relevant document at rank 1: 12/16.
- clean retrieval recall@6: 16/16.
- control relevant document at rank 1: 0/16.
- control retrieval recall@6: 16/16.
- challenge relevant document at rank 1: 0/16.
- challenge retrieval recall@6: 16/16.
- Challenge changed the relevant-document rank: 15/16 families.
- Challenge and benign control had the same relevant-document rank: 16/16 families.
- Every packet contains more than six documents, so top-k never returns the entire packet: 48/48 variants.
- Provider calls/tokens/cost: 0 / 0 / $0.00.

## Boundary

The synthetic passages are safe, non-operational retrieval controls. They test ranking and packet construction; they do not measure model reasoning, citation faithfulness, or attack success. Official source states remain publisher-declared version evidence unless separately observed by the historical cutoff.
