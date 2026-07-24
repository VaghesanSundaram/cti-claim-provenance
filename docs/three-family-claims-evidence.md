# Three-family claims and evidence

This document records the three development questions, answer keys, exact
evidence addresses, authority rules, and temporal limits used by the
provider-free scripted oracle.

| Family | Predicate and answer | Evidence address | Authority | Cutoff basis |
|---|---|---|---|---|
| CVE-2024-3094 | `cve.affected_versions = [5.6.0, 5.6.1]` | `cve-program-cve-2024-3094-cve-3094-f839db1bd834:affected-version-0` and `:affected-version-1` | CVE Program CNA record at the named commit | Publisher-declared official-repository commit time |
| Ivanti ED 24-01 | `directive.required_action = disconnect all instances of the named solution products from agency networks by 2024-02-02` | `cisa-ed-24-01-cisa-ivanti-v1-96e00cfa8be1:required-disconnect` | CISA Supplemental Direction V1 | Conservative end of the page's publisher-declared 2024-02-05 update date |
| NetScaler CVE-2023-4966 | `vendor.recommended_action = review the same Source IP accessing sessions of multiple users` | `netscaler-cve-2023-4966-netscaler-nov20-6c104a9397cf:ssl-vpn-source-ip-pattern` | NetScaler's named investigation post | Page's publisher-declared `dateModified` |

Each normalized evidence span stores character offsets, a span-text SHA-256,
the raw snapshot identifier and SHA-256, and the source-specific normalization
version. CVE JSON spans include both version and `status: affected`, and
round-trip as canonical JSON to exact RFC 6901 object pointers.
HTML evidence is matched exactly in normalized visible text; because these
pages do not expose a stable immutable DOM locator, the span records that
limitation instead of inventing one.

The oracle constructs values from the cutoff-selected normalized documents.
Gold claims are loaded only for deterministic grading. If no named publisher
version is cutoff-eligible or the target field is absent, the oracle abstains.
Tests exercise this behavior at one second before each answer-bearing declared
version, including the between-version state for CVE and NetScaler.

Authority grading is bound to
`configs/authority-policy-three-family-v1.yaml`; the historical
`authority-policy-v1` catalog remains unchanged.

None of these dates proves independently observed historical availability.
The exact bytes were captured in 2026 and remain gitignored. The tracked
manifest binds the local bytes but does not backdate them.
