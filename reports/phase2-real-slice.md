# Phase 2 real-source local-capture replay

Status: **smoke-tested; scope=local_real_source_scripted_oracle**. This is a provider-free deterministic development proof, not a model evaluation, baseline, generalization result, or clean-clone reproduction.

`CVE-2021-44228` (Log4Shell) remains explicitly plumbing-only. The slice checks frozen-byte replay, cutoff selection, lexical retrieval, document-derived claim construction, evidence resolution, authority, and abstention. It makes no new substantive Log4Shell finding.

## Results

- Cases: 12 total; 8 answerable; 4 abstention.
- Document-derived atomic claim support: 8/8 (100.0%).
- Correct abstention: 4/4 (100.0%).
- Citation support: 8/8 (100.0%).
- Temporal admissibility: 8/8 (100.0%).
- Accepted predicate authority: 8/8 (100.0%).
- Evidence coverage: 8/8 (100.0%).
- Retrieval recall@4: 8/8 (100.0%).
- Post-cutoff leakage: 0 observed in the three exact boundary cases.
- Provider calls/tokens/cost: 0 / 0 / $0.00.

## Combined treatment diagnostic

- Clean case: `real-nvd-cvss-clean`.
- Treated case: `real-nvd-cvss-combined-treatment`.
- The project-authored treatment combines a lower-authority conflicting CVSS value with inert instruction-like text. It is retrieved but cannot be selected as NVD authority by the document-derived oracle. This is a combined plumbing diagnostic, not an isolated contradiction estimand or evidence of model resistance.

## Temporal and authenticity boundaries

- NVD is an observed HTTPS snapshot eligible only from its recorded retrieval time; its internal publication and modification fields do not backdate the bytes and the capture is not cryptographic publisher proof.
- CISA KEV is bound to the tracked official repository commit and commit-lineage evidence.
- Red Hat revision 3 is checksum-matched. Its `current_release_date` is publisher-declared version evidence only, never independently observed historical availability.
- Exact raw and normalized payloads remain local and gitignored. A clean checkout must fail closed until a separate redistribution/archive decision supplies the exact bytes.

## Attribution and redistribution notes

- NVD source: https://services.nvd.nist.gov/rest/json/cves/2.0 . This report contains derived atomic facts and provenance identifiers, not redistributed response bodies.
- CISA KEV source: https://github.com/cisagov/kev-data . CISA publishes KEV data under CC0; use of agency names does not imply endorsement.
- Red Hat source: https://security.access.redhat.com/data/csaf/v2/advisories/2021/rhsa-2021_5133.json . Security data is used under CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/). This project records derived normalized claims and provenance; it is not endorsed by Red Hat and any transformation is a project modification.

## Interpretation boundary

The oracle reads retrieved normalized fields and never copies gold answers or abstention labels to construct its output. Gold is used only by the deterministic grader after answer generation. The next provider evaluation remains separately gated by an explicit model, cases, repetitions, cost ceiling, and evidence plan.
