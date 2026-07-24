# Human review guide

## Purpose and blinding

This workflow reviews benchmark questions, labels, and claim-to-evidence
bindings before comparative model evaluation. The current portfolio packet
contains 16 development/validation families plus four blinded resurfaced items
(20 items total). It is a **portfolio-scale pilot** review, not a model result.
It contains no model output, experimental condition, pass/fail field, aggregate
result, or preferred system answer. Do not consult model results while
reviewing.

Use an anonymous identifier such as `reviewer-a17`; do not enter a name or
email address. This packet uses the project-approved **single-reviewer** mode.
Exported decisions are append-only: a correction creates a later record whose
`supersedes_decision_id` points to the earlier record. Never edit or delete a
prior line.

## Review each item

Read the question, cutoff, original answer/abstention, atomic claim, source
metadata, exact span, bounded context, and alternate candidate spans.

- **Fully supported** means the exact span entails the complete typed claim,
  including qualifiers. A passage that merely mentions the same CVE, product,
  advisory, or score is only relevant and does not support the claim.
- **Partially supported** means the span entails a material part but not all of
  the typed claim. Record what is missing.
- **Relevant but unsupported** means the source is on topic but does not entail
  the claim.
- **Contradicts** means the span affirmatively conflicts with the claim. State
  the conflict in the required reason.
- **Unclear** is for a genuine unresolved interpretation, not a shortcut for
  incomplete reading. Explain the ambiguity.

Assess factual correctness separately from evidence support. A fact may be
correct in the world but unsupported by the frozen evidence and must be marked
accordingly.

## Dates and authority

Use `available_by_utc`, its basis, and the question cutoff—not publication date
alone—to decide cutoff eligibility. An item is ineligible if the required
source state became available after the cutoff. Do not repair an early answer
with later knowledge.

Authority is predicate-specific. CISA governs KEV membership and dates; the
named scoring authority governs its CVSS score; a vendor advisory governs its
product state. NVD or CISA mention of a Red Hat product can corroborate but does
not replace a sufficiently precise Red Hat product-state statement.

Red Hat timestamps in this packet are **publisher-declared version evidence**:
they describe the frozen advisory version observed by the project, not
independently observed historical availability. Preserve that qualification
when assessing cutoff eligibility.

Synthetic control passages are never source authority. They are visible only
to test contradiction, poison, or distractor handling.

## Abstention and alternate evidence

Abstention is correct when the required source state is not cutoff-eligible,
the authoritative evidence is absent or insufficiently specific, authoritative
sources genuinely conflict without a frozen resolution rule, or the question
cannot be answered as written. Do not fill a gap from memory.

Mark alternate evidence only when a different frozen span could support or
materially change the label. Identify the span and explain why. A nearby,
topically related span is not automatically alternate support.

## Single-reviewer limitation

Only one reviewer is used for this packet. There is no inter-reviewer
agreement statistic and no adjudication stage. This is a deliberate resource
constraint and must remain visible as a methodological limitation. Corrections
still append a new record and preserve the original decision.

## Resurfacing, repeatability, and freeze

Four of the 16 families are selected by a frozen deterministic pseudorandom
rule and reappear at least five items later under different opaque item/case
IDs, producing a preregistered 25% resurfacing sample. The linkage manifest is
withheld in a gitignored manager-private path until all 20 decisions have been
exported. Intra-rater consistency measures repeatability, not correctness of
the gold labels. It is not inter-rater agreement or human calibration.

Review every available source and question type. If wording or rules change,
update this guide or create a new versioned case/packet set; do not silently
mutate reviewed material.

Freeze labels before opening any model results. Later label corrections
require a new benchmark version and a documented sensitivity analysis; they
never overwrite the original result. Any later claim of calibrated human
agreement would require a separately authorized protocol and additional human
review; this single-reviewer artifact cannot support that claim.

## Local use

1. Open `annotations/review-app/index.html` directly in a browser.
2. Load `annotations/packets/portfolio-dev-validation-review-v1.json`.
3. Enter an anonymous reviewer ID, use filters or **Next unresolved**, and
   append one decision per item.
4. Export canonical decision JSONL and preserve it as an immutable file.
5. Validate the packet and log in single-reviewer mode with:

   ```text
   uv run cti-provenance review validate --packet PACKET.json \
     --decisions DECISIONS.jsonl --review-mode single_reviewer \
     --summary REVIEW-SUMMARY.md
   ```

The app uses browser local storage only for resume. It has no account,
analytics, external database, network request, or deployment path. Export
regularly; browser storage is not the archival record.

After the exported decision log is returned, the manager verifies all 20
decisions, hashes the exact log, opens the private linkage manifest, and derives
the repeatability/correction report. Every packet source includes its frozen
license or terms disposition; only bounded evidence context is reproduced.

The historical 12-item Log4Shell packet remains plumbing-only and is preserved
unchanged. It does not count toward this portfolio review.
