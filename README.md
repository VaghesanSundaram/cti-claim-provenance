# Point-in-Time CTI Claim Provenance

This project asks a narrow question: given frozen, dated cyber-threat-
intelligence sources and a cutoff, can a system emit only the atomic claims
supported by eligible evidence, cite the exact spans, use the right authority,
and avoid later knowledge?

The repository contains a provider-free portfolio benchmark and validation
harness. Provenance is part of correctness: an answer can be currently true and
still fail if its evidence was unavailable at the cutoff, cites the wrong
publisher, or does not entail the claim.

## Result

Status: **completed descriptive model evaluation plus a provider-free portfolio
pilot**. The completed V6 model result is not a confirmatory study, a broad
accuracy claim, or a red-team result.

- 24 audited-distinct source/advisory families in the inventory.
- 16 reviewed public families in current metrics: 8 development and 8
  validation.
- 8 metadata-only future evaluation candidates, excluded from questions,
  packets, retrieval, grading, and every current metric.
- 48 matched evidence-selection cases: clean, benign control, and safe
  synthetic challenge for each public family.
- Controlled lexical recall@6: 16/16 clean, 16/16 benign control, and 16/16
  challenge packets. This verifies the frozen packet and retriever contract; it
  does not establish broad retrieval robustness.
- One human reviewer completed 20/20 items over 16 unique families. Four items
  were resurfaced later under blinded identifiers, with 4/4 exact intra-rater
  repeatability. Repeatability is not proof that the gold labels are correct.
- All 16 portfolio cases are answerable. Portfolio abstention performance is
  therefore **not evaluated**; Log4Shell abstention cases remain historical
  plumbing tests and are not counted here.
- The historical 16-family pilot used 0 provider calls. The completed V6 model
  evaluation used 192 GPT-5.6 Luna cells for $0.660676.

The four challenge types are stale evidence, lower-authority contradiction,
safe instruction-like poison, and plausible unsupported assertion—four
families each. They are matched synthetic evidence-selection controls, not a
realistic attack distribution and not evidence of model attack resistance.

The active DD-WRT correction is additive: the frozen v1 packet remains intact,
while v2 corrects the CISA KEV CVE-2021-27137 product qualifier from Accellion
FTA to DD-WRT. Deterministic grades and retrieval metrics did not change.

### V6 benchmark

The released V6 benchmark contains 64 human-reviewed semantic
answer contracts: 16 unchanged grounded extractions, 24 temporal comparisons,
8 cutoff/insufficiency abstentions, 8 authority-divergence questions, and 8
multi-source syntheses. These are grouped into 51 semantic pairs and 24
dependency clusters; they are not 64 independent factual phenomena.

The user approved all 48 new V5 labels through the append-only single-reviewer
workflow. V6 applies two approved corrections, plus five explicitly approved
egress-safe replacements that remove ECOVACS, Güralp, and KUNBUS vendor text
from active provider inputs. The replacements use bounded CISA coordinator
evidence while preserving case IDs, slices, dependencies, and splits. In the
V5-to-V6 lineage, 57 question hashes are unchanged, two are revised, and five
are replaced.

The completed descriptive model evaluation has 192 single-sample cells. It
compares two bundled pipelines—citation-prompted versus constrained—on all 64
clean questions, plus matched control/challenge variants for the 16 unchanged
extraction cases. Both prompts state the complete response contract; only the
constrained pipeline adds API schema enforcement, so the design does not
isolate a causal schema-enforcement effect. All 64 active inputs were
egress-eligible and human-reviewed. Citation prompting achieved 80/96 (83.3%)
evidence-binding-correct outcomes; the constrained pipeline achieved 83/96
(86.5%). Strict canonical typed-value exactness was 32/96 (33.3%) versus 25/96
(26.0%). These are distinct metrics: evidence-binding correctness is not
generic answer accuracy. See
[`the completed evaluation`](reports/portfolio-diverse-model-evaluation-v1.md)
and its [safe per-cell projection](reports/portfolio-diverse-model-evaluation-v1-cells.jsonl).

## Quickstart

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/).

```powershell
uv sync --frozen
uv run cti-provenance portfolio-demo
```

`portfolio-demo` uses only tracked, redistributable bounded artifacts. It needs
no API key, ignored capture, network request, or model provider and succeeds on
a clean checkout. It verifies active hashes, 16 base cases, 48 matched cases,
the review log, exact repeatability denominators, source-term dispositions, and
the publishable summary in
[`reports/portfolio-demo.md`](reports/portfolio-demo.md).

The current public-candidate safety check is also offline:

```powershell
uv run cti-provenance portfolio-release-check
```

It checks the candidate secret scan, forbidden artifact paths, portable tracked
text, current-file personal-email exposure, local Markdown links, source-term
dispositions, the clean-checkout demo, and the Ubuntu/Windows CI contract. It
does not publish, rewrite history, choose a license, tag, or release.

## How it works

```text
frozen source state + content hash
        -> normalized document + exact evidence spans
        -> cutoff and predicate-authority filter
        -> deterministic lexical packet
        -> atomic claim/evidence envelope
        -> exact claim, span, cutoff, and authority grading
```

The active artifact map is
[`data/manifests/portfolio-active-corpus-v2.json`](data/manifests/portfolio-active-corpus-v2.json).
The benchmark family—not an individual question, CVE, chunk, or repeat—is the
independence and split unit.

Publisher-declared version evidence proves what a named publisher version says
and its declared revision time. It does **not** prove that the exact content was
independently observed or publicly available then. That stronger claim requires
an actual observation or archive by the cutoff.

## Full rebuild and historical reproduction

The clean-checkout demo validates tracked derivatives. Rebuilding normalization
and evidence from source bytes is intentionally separate:

```powershell
uv run cti-provenance portfolio-rebuild
```

This command has no live-web fallback. It succeeds only when every exact
gitignored source cache is supplied at the manifest paths with the expected
hashes; otherwise it fails closed. Pinned locators, hashes, capture outcomes,
and retention decisions are documented in
[`docs/portfolio-source-inventory-v1.md`](docs/portfolio-source-inventory-v1.md)
and
[`data/manifests/portfolio-capture-ledger-v1.json`](data/manifests/portfolio-capture-ledger-v1.json).
Acquire only sources whose terms permit it, then verify each exact hash before
derivation.

Historical phase commands and the obsolete Phase-2 readiness audit are not the
active product. Their exact pre-cleanup reproduction point is commit `ce0d854`;
frozen reports remain in Git for auditability.

## Limits and release boundary

- V6 is one generation per cell, with no repeatability or significance estimate.
- Evidence-binding correctness requires the expected predicate, component role,
  and evidence bindings; strict canonical exactness additionally requires the
  benchmark's typed value representation.
- Exact citations can show support but cannot prove a model causally relied on
  them.
- One reviewer limits gold-label validity; no inter-reviewer statistic exists.
- The historical 16-family pilot has no abstention cases. V6 has eight
  human-reviewed abstention contracts, but model abstention performance remains
  unevaluated.
- Synthetic matched controls do not represent real-world attack prevalence.
- Log4Shell is plumbing-only; XZ, Ivanti, and NetScaler are feasibility
  evidence, not broad generalization.
- Raw source captures remain gitignored. The tracked packet records 29/29
  nonempty source/license-or-terms dispositions; source material keeps its own
  terms and is not covered merely by a future software license.

Apache-2.0 covers project-authored code and documentation only; it does not
override CTI-source or dependency terms. This repository is the sanitized,
single-commit public export. Raw source captures, provider responses, secrets,
and private development history are intentionally excluded.

See [`docs/portfolio-and-resume.md`](docs/portfolio-and-resume.md) for a concise
portfolio explanation,
[`docs/portfolio-pilot-methodology.md`](docs/portfolio-pilot-methodology.md) for
the historical provider-free pilot methodology,
[`docs/portfolio-diverse-v6-methodology.md`](docs/portfolio-diverse-v6-methodology.md)
for the V6 evaluation, [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) for
dependency/source boundaries, and [`AGENTS.md`](AGENTS.md) for the repository
contract.
