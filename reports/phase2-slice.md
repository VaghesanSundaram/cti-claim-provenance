# Phase 2 offline plumbing slice

Status: deterministic offline development plumbing path; **not a provider evaluation**.

`CVE-2021-44228` (Log4Shell) is plumbing-only. These fixtures test contracts, cutoff filtering, retrieval, evidence resolution, and grading; they do not constitute a new Log4Shell finding or evidence of benchmark generalization.

The project-authored Red Hat fixture is bound only by its project manifest hash; it is not upstream checksum evidence. It models the policy that a real Red Hat `current_release_date` is publisher-declared version evidence only after the exact upstream body is verified against Red Hat's published checksum. The date is not independently observed historical availability.

## Results

- Cases: 12 total; 9 answerable; 3 abstention.
- Atomic claim accuracy/support: 9/9 (100.0%).
- Correct abstention: 3/3 (100.0%).
- Citation support: 9/9 (100.0%).
- Temporal accuracy: 9/9 (100.0%).
- Synthetic represented-source policy routing: 9/9 (100.0%); real-source authority and authenticity remain untested.
- Evidence coverage: 9/9 (100.0%).
- Retrieval recall@4: 9/9 (100.0%).
- Abstention precision/recall/coverage: 3/3 (100.0%) / 3/3 (100.0%) / 3/12 (25.0%).
- Post-cutoff leakage: 0 observed in the deterministic fixture gate; the cutoff-leakage test keeps later physical documents outside ranking.
- Declared treatment retrieval exposure: 1/1 (100.0%).
- Provider calls/tokens/cost: 0 / 0 / $0.00.

## Per-representation and predicate diagnostics

| Representation | Predicate | Cases | Supported | Evidence covered | Retrieved |
|---|---|---:|---:|---:|---:|
| Synthetic NVD | `cve.cvss.score` | 2 | 2/2 | 2/2 | 2/2 |
| Synthetic NVD | `cve.modified_at` | 1 | 1/1 | 1/1 | 1/1 |
| Synthetic NVD | `cve.published_at` | 1 | 1/1 | 1/1 | 1/1 |
| Synthetic CISA KEV | `kev.date_added` | 1 | 1/1 | 1/1 | 1/1 |
| Synthetic CISA KEV | `kev.due_date` | 1 | 1/1 | 1/1 | 1/1 |
| Synthetic CISA KEV | `kev.is_member` | 1 | 1/1 | 1/1 | 1/1 |
| Synthetic Red Hat | `vendor.affected_versions` | 1 | 1/1 | 1/1 | 1/1 |
| Synthetic Red Hat | `vendor.fixed_versions` | 1 | 1/1 | 1/1 | 1/1 |

## Adversarial-pair diagnostic

- Clean retrieval (`p2-cvss-clean`): phase2-nvd-log4shell.
- Contradiction-treatment retrieval (`p2-cvss-contradiction`): phase2-nvd-log4shell, phase2-contradictory-log4shell.
- The declared treatment must be retrieved for the slice to pass. Contradiction classification and attack success rate are **not yet implemented / not applicable** to this scripted-oracle gate.

## Uncertainty and not-yet-tested inventory

- Deterministic fixture failures: none in this run.
- Real-source capture, real-source authority/authenticity, model behavior, contradiction inference, statistical uncertainty, and provider safety outcomes remain untested.

## Interpretation boundary

The scripted oracle is a plumbing check, not a baseline model. Phase 2 cannot be called evaluated or improved until the separately approved provider conditions run on frozen data with cost reconciliation.
