# Portfolio yield gate v1

Status: **PASS for continued scaling toward a defensible 24-family portfolio
pilot; not evidence that the 36-family target is feasible.** Log4Shell remains
plumbing-only and is excluded.

Date: 2026-07-21

## Evidence at the gate

- 10 accepted eligible families: 7 development, 3 validation, and 0 holdout
  candidates. Log4Shell is preserved separately as plumbing-only.
- Current dominant-source mix: 4 vendor/project, 3 public coordination, and 3
  structured CTI/vulnerability families (40%, 30%, and 30%). This is a gate
  sample, not the intended final balance.
- Seven families were accepted during this capture program from 33 successful
  captures and 42 total attempts. The program screened at least 19 candidates
  across all three source strata before this gate.
- The capture ledger has 87 successful captures and 138 total attempts left.
  The observed yield is 7 / 33 = 21.2% accepted families per successful
  capture. Holding that rate projects about 18 more accepted families and about
  28 total including the three eligible pre-program families. This supports
  attempting a 24-family minimum but does not support planning on all 36.
- Reaching 24 at the observed yield would use about 66 of the 87 remaining
  successful captures. The projection is evidence for continuing, not a quota
  or permission to weaken acceptance rules.

## Diversity and implementation decision

A 24-family endpoint should target 12 vendor/project, 7 public-coordination,
and 5 structured families (50%, 29.2%, and 20.8%). The next batches therefore
need eight vendor, four public-coordination, and two structured additions unless
later audited rejections require an equivalent in-band mix.

The six program additions use a declarative family specification and closed
source/predicate registries. The yield batch added three reusable extraction
shapes—JSON membership, patterned release-version text, and exact HTML
membership—without a per-template oracle switch. The next batch must reuse
these shapes or demonstrate a genuinely repeated new shape; continued bespoke
normalizer growth fails this gate.

All accepted yield questions are deterministic, cutoff-aware, hash-bound, and
graded against exact evidence spans. Their temporal basis is publisher-declared
version evidence only and does not establish independently observed historical
availability. WordPress 6.9.2/6.9.4 was not accepted because the attempted
official terms locator returned 404 and retention/reproduction terms remained
unresolved.

## Annotation-load projection

At the 24-family minimum, 24 base family questions plus matched
clean/challenge/control packets for at least 16 families produce at least 48
packet variants before any optional second base question. Blinded resurfacing
of 20–30% implies roughly 10–15 repeat reviews. One human reviewer remains a
label-validity limitation; intra-rater consistency measures repeatability, not
gold correctness.

## Decision

Proceed to balanced scaling toward the 24-family minimum and continue to call
the result a **portfolio-scale pilot**. Re-run the
yield/diversity/leakage gate at each batch boundary and stop if source mix,
dependency independence,
deterministic grading, retrieval difficulty, licensing, or remaining capture
budget no longer supports the minimum. Do not claim broad CTI generalization,
model improvement, or 36-family feasibility from this gate.
