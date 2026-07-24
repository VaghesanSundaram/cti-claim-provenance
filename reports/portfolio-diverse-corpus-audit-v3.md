# Diverse portfolio corpus audit v3

- Status: `manager_audit_ready`
- Unique semantic questions: 65
- Existing reviewed v2 labels: 16
- New labels awaiting manager audit: 49
- Source/dependency families: 24
- Corpus SHA-256: `40272ede96be6b4e288992e33ff81b75ed3f0101461e75419cb472c711da7139`
- Review packet SHA-256: `c60dda98178c1f4acb7356da28cdeb26fbc5df2725db3bcd129168c4e28ea400`

## Questions by substantive slice

- `authority_divergence`: 8
- `cutoff_or_insufficiency_abstention`: 8
- `multi_source_synthesis`: 8
- `single_source_extraction`: 16
- `temporal_comparison`: 25

## Packet variants

- `benign_control`: 16
- `challenge`: 16
- `clean`: 65

The 65 clean packets cover every question. Matched benign-control and challenge variants remain the frozen 16-case subset; their controlled retrieval result is not a claim of model or real-world attack robustness.

## Gate

Parent manager acceptance is required before the user opens the review packet; provider calls remain blocked.

## Manager-audit risks

- Authority-divergence and multi-source questions intentionally share some families; the audit must reject any pair that differs only in wording.
- Twenty evidence items are deterministic field or absence derivations, not literal source spans, and require recipe-level inspection.
- The three newly captured vendor documents remain raw-excluded; their minimal-span public redistribution disposition is not yet a release claim.
- The three draft reasoning predicates have a strict local all-evidence oracle but are not yet wired into the provider experiment's central authority/exact-grader maps; that integration remains blocked on corpus acceptance and human review.

## Limitations

- The 16 retained extraction labels are the unchanged reviewed v2 cases.
- The 49 new labels are manager-audit candidates, not approved gold.
- Only the retained 16 cases currently have matched control/challenge variants.
- Publisher-declared version evidence is not independently observed history.
- All eight authority cases test scoped attribution, not universal source rank.
