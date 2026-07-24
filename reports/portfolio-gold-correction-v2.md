# Portfolio gold correction v2

Status: **corrected and evaluated offline; no provider/model result exists**.

## Correction

- Family: `portfolio-yield-cisa-kev-cve-2021-27137`.
- Frozen v1 qualifier: `product=Accellion FTA`.
- Active v2 qualifier: `product=DD-WRT`.
- Source: CISA KEV snapshot `cisa-kev-2026-07-21-f17a5ced05e7`, exact raw SHA-256 `f17a5ced05e70c4abbc893bed7ffd52c8dd53ed4fb112c95380f8de53c5ba597`, locator `/vulnerabilities/3`. The record says `vendorProject=DD-WRT` and `product=DD-WRT`.
- Temporal basis remains unchanged. This source is publisher-declared version evidence, not proof of independently observed historical availability.

The additive overlay is `portfolio-gold-correction-v2`. It binds the six frozen v1 inputs and maps their single defective family to the corrected successor. No frozen v1 config, case, packet, report, manifest, or decision predecessor was rewritten.

## Reviewer log

- Exact log SHA-256: `9064e11c415052441daa0eecaf8181b6b20775324b9cef90d3e327b2f1eb643b`.
- Immutable records: 21; active decisions: 20; unresolved items: 0.
- The appended decision `66dae977-b2eb-4cdc-a305-cfc90630a7ef` supersedes `a91b0891-d337-4bbe-a1ce-83fde45ee8e7`.
- Exact intra-rater repeatability: 4/4 resurfaced pairs. This measures repeatability, not correctness of the gold labels.
- Correction queue: `portfolio-yield-cisa-kev-cve-2021-27137`.

## Active successor artifacts

- Public base cases: 16/16 in `data/benchmark/portfolio-public-cases-v2.jsonl`; exactly one base-case gold qualifier changed.
- Matched cases: 48/48 in `data/benchmark/challenges/portfolio-challenge-cases-v2.jsonl`; exactly the clean/control/challenge gold for that family changed.
- Review packet: 20/20 items in `annotations/packets/portfolio-dev-validation-review-v2.json`; exactly one hidden expected claim changed.
- Safe synthetic challenge documents are reused byte-for-byte from v1 because the correction does not affect them.

## Deterministic metric impact

- Four-case yield oracle: 4/4 exact claims remained supported with admissible, accepted, exact-hash evidence before and after correction.
- Challenge dataset-integrity audit: passed for 48/48 v2 cases.
- Retrieval metrics: unchanged. Recall@6 remained 16/16 for each of clean, benign-control, and challenge variants.
- Provider calls, tokens, and cost: 0 / 0 / $0.00.

There is no portfolio provider result, so no model sensitivity analysis is claimed or fabricated. The project still has one human reviewer; the mechanical source correction did not require a second review.
