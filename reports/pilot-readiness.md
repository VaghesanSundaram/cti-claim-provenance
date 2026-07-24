# Provider-free pilot-readiness audit

Status: **not_ready**.

This is a deterministic entry-gate audit of tracked candidate metadata. It is not a provider evaluation, benchmark freeze, or claim of representative coverage.

The current Log4Shell material is **plumbing-only**. Red Hat timing remains **publisher-declared version evidence**, not observed historical availability.

## Candidate binding

- Candidate version: `phase2-real-pilot-candidate-v1`
- Candidate manifest SHA-256: `d77b9132121d6b5b3851e903b66936c2b8edfcdbd0e5ddced7ba177e5692cecb`
- Source manifest `data/manifests/phase2-offline-fixtures.jsonl` SHA-256: `9292806a191e643b6856920bb6dc226ce3b85807b521131d3d2bda880da582a2`
- Source manifest `data/manifests/phase2-snapshots.jsonl` SHA-256: `f636b157922b990ad6c81fce3816a16cfacfc93ac6c1619c6b2617241107daf7`
- Authority policy SHA-256: `c65be6a9501100701f86550cde031b5df0179caff968cf78202e39d51929429d`
- Case-record binding SHA-256: `1661384858f317b9d89ee61b9d803e33ffb480a52ab6a9718c87ae6cdf5709ff`
- Document-identity binding SHA-256: `4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945` (0 records)

The candidate binding is not an immutable benchmark freeze.

## Coverage denominators

| Split | Cases |
|---|---:|
| dev | 12 |
| holdout | 0 |
| validation | 0 |

- Real-source cases: 12
- Synthetic-control cases: 0
- Real entity families: 1
- Real case families: 11
- Paired attacked real cases: 1
- Abstention cases: 4

| Real source bound by source manifest | Status |
|---|---|
| `cisa_kev` | present |
| `nvd` | present |
| `red_hat_rhsa` | present |

| Real source resolved from scored evidence | Status |
|---|---|
| none | none |

| Scored predicate | Status |
|---|---|
| `cve.cvss.score` | present |
| `cve.modified_at` | present |
| `cve.published_at` | present |
| `kev.date_added` | present |
| `kev.due_date` | present |
| `kev.is_member` | present |
| `vendor.fixed_versions` | present |

| Truth mode | Cases |
|---|---:|
| observed_snapshot | 5 |
| upstream_versioned | 7 |

| Attack family | Cases |
|---|---:|
| contradiction | 1 |
| none | 11 |

## Blocking findings

| Code | Severity | Evidence |
|---|---|---|
| `adjudication_incomplete` | blocker | Blinded disagreement adjudication is not complete. |
| `agreement_statistic_missing` | blocker | Human-review agreement has not been calculated. |
| `annotation_protocol_missing` | blocker | A versioned blinded annotation protocol is required. |
| `bound_source_missing` | blocker | Missing bound source manifests: mitre_attack |
| `calibration_acceptance_threshold_undeclared` | blocker | Agreement can be calculated, but an acceptable threshold or excluded-stratum policy has not been preregistered. |
| `confirmatory_cell_missing` | blocker | Missing authority/predicate cells: cisa_kev:kev.is_member, mitre_attack:attack.relationship_present, nvd:cve.published_at, red_hat_rhsa:vendor.fixed_versions |
| `confirmatory_cell_missing_by_split` | blocker | dev is missing authority/predicate cells: cisa_kev:kev.is_member, mitre_attack:attack.relationship_present, nvd:cve.published_at, red_hat_rhsa:vendor.fixed_versions |
| `confirmatory_cell_missing_by_split` | blocker | validation is missing authority/predicate cells: cisa_kev:kev.is_member, mitre_attack:attack.relationship_present, nvd:cve.published_at, red_hat_rhsa:vendor.fixed_versions |
| `confirmatory_predicate_missing` | blocker | Missing real confirmatory predicates: attack.relationship_present |
| `confirmatory_source_missing` | blocker | Missing real confirmatory sources: cisa_kev, mitre_attack, nvd, red_hat_rhsa |
| `document_metadata_missing` | blocker | Referenced evidence/treatment documents lack audit identities. |
| `double_annotation_minimum_unmet` | blocker | Phase 6 requires 50 double-annotated entailment judgments; candidate records 0. |
| `observed_change_case_missing` | blocker | No clean real entity/template family contains distinct source states. |
| `pair_treatment_metadata_missing` | blocker | Declared treatment documents lack the identities needed to verify the paired corpus delta. |
| `paired_attack_minimum_unmet` | blocker | Phase 7 requires at least 40 paired attack cases; candidate has 1. |
| `pilot_schedule_budget_unfrozen` | blocker | Exact case forms, schedule hashes, retries, and cost ceiling are not frozen. |
| `positive_readiness_gate_unimplemented` | blocker | Positive readiness is fail-closed until calibration evidence-span binding and acceptance policy, per-split strata, and pricing-currentness evidence have dedicated validators. |
| `single_entity_corpus` | blocker | A one-entity corpus cannot support a broader pilot. |
| `validation_split_missing` | blocker | Validation split is empty. |

## Interpretation boundary

A `not_ready` result is the expected correct outcome for the current one-entity development slice. The audit machinery can detect missing split isolation, source/predicate coverage, paired controls, temporal change cases, calibration evidence, and a frozen retry-inclusive schedule; it does not supply those missing scientific inputs.

A positive `ready` transition is mechanically disabled until real calibration evidence-span binding and acceptance, per-split strata, and current pricing evidence are validated and independently reviewed.

No provider call, credential read, live-source request, or ignored raw/normalized artifact is required by this report.
