# Portfolio source and family inventory v1

Status: 24-family minimum accepted after independent fail-first review; source
capture is closed because the 36-family target is infeasible within the frozen
budget

Mode: `portfolio-scale-pilot-v1`

Date: 2026-07-21

## Program accounting

- New-program successful source captures: 105 / 120; 15 remain.
- New-program total controlled-transport attempts: 119 / 180; 61 remain.
- Provider/model calls: 0.
- Semantic retries and duplicate successful URLs: 0 and 0.
- Eleven attempts ended as local transport-setup failures before any request was
  issued. Eight later HTTP 200 bodies were preserved and hash-bound without a
  semantic retry; six newly captured annotated tag objects were hashed from
  their retained bytes after a local PowerShell hash-helper mismatch, without
  another GET. One WordPress terms request and two incorrect curl release-note
  paths returned 404. All outcomes remain in the append-only capture ledger.
- Existing raw/quarantine bytes remain gitignored.
- Historical capture budgets are recorded separately and are not subtracted
  from this new program.

## Acceptance rules

A family must have two independently addressable official states or a real
cutoff admissibility change, a substantive semantic delta, deterministic
non-operational gold, defensible authority and temporal basis, acceptable
retention/reproduction terms, and no dependency-lineage or near-duplicate split
conflict. Browser/search discovery is provisional; a family is not accepted
until every source body used for the decision is captured through controlled
transport and hash-bound.

## Existing family inventory

| Family ID | Split | Dominant stratum | Dependency lineage | Status and boundary |
|---|---|---|---|---|
| `log4shell-plumbing-only` | dev | vendor/project | Log4Shell / Red Hat RHSA-2021:5133 plus NVD/KEV plumbing sources | Preserved plumbing-only; not representative evidence |
| `cve-2024-3094-xz` | dev | structured CTI/vulnerability | CVE-2024-3094 / xz / CVE List V5 commit lineage | Accepted feasibility family; publisher-version evidence only |
| `ivanti-ed-24-01` | dev | public coordination/exploitation | ED 24-01 / Ivanti Connect Secure and Policy Secure / CISA supplemental directions | Accepted feasibility family; publisher-version evidence only |
| `netscaler-cve-2023-4966` | dev | vendor/project | CVE-2023-4966 / NetScaler ADC and Gateway vendor guidance | Accepted feasibility family; publisher-version evidence only |

The three eligible feasibility families, three proof families, four
yield-batch families, and five first-scale families consume eight development
slots and seven validation slots.
Log4Shell remains plumbing-only and is excluded from the eligible-family count.
No holdout-candidate membership is assigned yet.

## Prospective allocation

Across 36 families, target 17–19 vendor/project, 10–11 coordination, and 7–8
structured families. The final count must remain within the protocol's
45–55%, 25–35%, and 20–25% bands. Assign one dominant stratum per family and
keep shared KEV catalog, ATT&CK release, vendor/product, incident, template, and
challenge-generator dependencies in one split.

The next proof batch should add two to four maximally different families and
prefer one reusable official source type from each stratum. Candidate discovery
and licensing rows will be appended after primary-source screening; no question
is authored before acceptance.

## Source ledger

This ledger records discovery decisions, not accepted evidence. Exact bodies
used for eligibility, labels, or retention decisions must first pass controlled
transport and hash binding.

| Source | Authority use | Version shape | Temporal basis | Retention disposition before capture |
|---|---|---|---|---|
| Apache `httpd` archive release notes | Project primary for release security corrections and affected-release claims | Independently addressable `CHANGES_2.4.50` and `CHANGES_2.4.51` files, with directory-index declared times | Publisher-declared release-version evidence only | Apache-2.0 license body captured and hash-bound; exact release notes remain gitignored and are reproduced by pinned URL/hash recipe |
| CISA `kev-data` | CISA primary for KEV membership, required action, due date, and ransomware-use field | Commit-addressed catalog snapshots | Publisher-declared catalog-version evidence; not independently observed availability | Repository advertises CC0; verify the commit-addressed `LICENSE` body before acceptance |
| MITRE `attack-stix-data` | MITRE primary for ATT&CK object identity, relationships, platforms, and release membership | Signed/annotated release tags resolved to full commits and versioned STIX bundles | Publisher-declared release-version evidence | Approved-public-release notice is visible in discovery; verify commit-addressed `LICENSE.txt` before acceptance |
| Atlassian security advisories | Vendor primary for affected/fixed products and update log | Mutable advisory plus publisher update log | Publisher-declared revision evidence only unless immutable revisions are found | Terms and immutable revision identity unresolved; metadata-only candidate |
| Node.js security releases | Project primary for affected/fixed release lines | Dated post plus signed release tags | Publisher-declared release-version evidence | Blog-text retention unresolved; tagged source/release metadata may be reproducible |
| Django security releases | Project primary for fixed branches/releases | Dated release post plus tagged releases/changesets | Publisher-declared release-version evidence | BSD software terms do not automatically cover prose; retention unresolved |
| CERT/CC vulnerability notes | Coordinator primary for coordination chronology and vendor statements | Note revisions and dated vendor statements | Depends on independently addressable revisions | Reuse terms and exact revision identity unresolved |
| CVE List V5 | CNA/CVE Program primary for versioned CVE record content | Commit-addressed CVE JSON | Publisher-version evidence; commit observation is not historical page availability | Repository terms apply; candidate lineages must be separated from an existing incident |
| NVD change history | NVD primary for NVD scoring and recorded change events | API change events plus vulnerability snapshots | Observed API capture or publisher-declared change event, explicitly distinguished | Public-data terms documented elsewhere; exact reproducibility and request budget required |

## Candidate matrix

The bounded design screen covered 18 candidate families across all three
strata. `Proof` means selected for exact controlled capture; it does not mean
accepted. No semantic claim or label below may be promoted from discovery text.

| Candidate family | Dominant stratum | Candidate delta and predicate | Exact-version prospect | Prospective split | Design decision |
|---|---|---|---|---|---|
| Apache HTTP Server CVE-2021-41773/42013 | vendor/project | 2.4.50 fix followed by 2.4.51 incomplete-fix correction; affected version | Apache archive `CHANGES_2.4.50` and `CHANGES_2.4.51` | dev | **Accepted proof**: 2.4.51 states that CVE-2021-42013 affects 2.4.49 and 2.4.50; the initially captured commit-level aggregate `CHANGES` files were rejected as corpus states because they did not preserve this release-note delta |
| Atlassian Confluence CVE-2022-26134 | vendor/project | advisory update log may change affected/fixed versions | Mutable advisory; immutable revisions not yet resolved | unassigned | Hold: a current page's old update dates are not historical availability or immutable source states |
| Node.js May 2025 security release | vendor/project | released security versions become available | Commit-addressed pre-release and released documents | validation | **Accepted yield gate**: exact commit bodies, commit metadata, and MIT license are hash-bound; temporal basis is publisher-declared version evidence |
| Django January 2019 security releases | vendor/project | fixed branch/release and changeset relationship | Dated posts, tags, and changesets | unassigned | Hold: promising immutable code state; prose retention unresolved |
| Django CVE-2024-27351 / 5.0.2 to 5.0.3 | vendor/project | 5.0.2 release note lacks CVE-2024-27351; immutable fix-commit 5.0.3 note names it | Official commit metadata, raw release notes, and BSD-3-Clause repository license | validation | **Accepted yield gate**: exact bytes and publisher commit times are hash-bound; website prose was not used |
| Fortinet FG-IR-19-043 | vendor/project | possible affected/fixed-version revision | Vendor page revision identity unclear | unassigned | Reject for proof batch: no independently addressable semantic revisions established |
| Jenkins 2023-02-09 advisory | vendor/project | fixed image/plugin versions | Advisory plus release tags/digests | unassigned | Hold: needs exact image/tag identity and terms |
| WordPress 6.9.2 to 6.9.4 correction | vendor/project | release correction and fixed version | Tagged releases and dated posts | unassigned | Reject for this batch: the official terms locator returned 404, so retention/reproduction terms remain unresolved |
| GitLab historical advisory | vendor/project | candidate affected/fixed scope change | Historical locator redirects to a current page | unassigned | Reject: locator is not an independently addressable frozen state |
| CISA KEV CVE-2026-0257 | public coordination/exploitation | `knownRansomwareCampaignUse` changes `Unknown` to `Known` | CISA mirror commits `87ba74fc7c502adcf482fc7b06e65ce9ea4d9ef2` and `bc9dbb256ec16f37b646b564770af99b0a96cbe1` | dev | **Accepted proof**: exact catalogs, public commit metadata, ancestry, and CC0 license are hash-bound |
| CISA KEV CVE-2021-27137 | public coordination/exploitation | absent then present in the catalog | Reused hash-bound CISA catalog commits from the proof batch | dev | **Accepted yield gate**: distinct incident, same catalog dependency and split; no new source capture was needed |
| CISA KEV CVE-2024-1709 | public coordination/exploitation | KEV addition and due date | Older exact mirror history not established in discovery | unassigned | Superseded for proof by a commit-addressable in-repository change |
| CERT VU#309662 Secure Boot | public coordination/exploitation | dated vendor statements may alter affected/mitigated scope | Note plus vendor statements | unassigned | Hold: exact revision delta and reuse terms unproven |
| CISA/Atlassian CVE-2023-22515 | public coordination/exploitation | KEV membership/due date plus vendor scope | Catalog state and vendor advisory | unassigned | Hold: preserve one KEV catalog dependency per split and avoid duplicating vendor lineage |
| CISA/Fortinet CVE-2023-27997 | public coordination/exploitation | KEV status/due date plus vendor fixed versions | Catalog state and PSIRT advisory | unassigned | Hold: same KEV dependency and vendor terms need audit |
| MITRE ATT&CK Enterprise v15.1 to v16.0 | structured CTI/vulnerability | T1027.011 platform applicability changes from Windows to Windows and Linux | Official tags `v15.1` and `v16.0`, resolved to commits `23b23819d2b074f76d75815f6e3b9c6228113ab6` and `baa85d58a6eda286bca799fd8a237af1a6a0721e` | dev | **Accepted proof**: exact bundles, release/tag metadata, commit mapping, and required license designation are hash-bound |
| MITRE ATT&CK Enterprise v16.0 to v16.1 | structured CTI/vulnerability | minor release corrections | Tagged STIX bundles | unassigned | Reject for initial proof: likely correction-heavy and shares the selected ATT&CK release dependency |
| MITRE ATT&CK Enterprise v16 to v17 | structured CTI/vulnerability | major release object/platform changes | Tagged STIX bundles | unassigned | Hold: same ATT&CK release lineage must stay in one split and not inflate family independence |
| CVE-2024-1709 CVE/NVD history | structured CTI/vulnerability | CNA/NVD record field changes | CVE commits and NVD change events | unassigned | Hold: exact semantic delta and authority-specific predicate not yet audited |
| NVD CVE-2024-3400 CPE history | structured CTI/vulnerability | PAN-OS 10.2.2-h5 is absent then present in NVD's CPE applicability | Independently addressable NVD change-event records | validation | **Accepted yield gate**: exact change-history metadata, event pages, and NVD terms evidence are hash-bound; NVD is authority only for its own applicability record |
| NVD CVE-2024-21762 CPE history | structured CTI/vulnerability | FortiOS 6.0 upper-bound correction | Initial and modified analysis event pages plus history API | validation | **Accepted first scale batch**: exact history delta, event states, hashes, spans, and NVD-specific authority pass provider-free replay |
| NVD CVE-2023-20115 CPE history | structured CTI/vulnerability | Cisco Nexus 3636C-R hardware CPE addition | Initial and reanalysis event pages plus history API | validation | **Accepted first scale batch**: exact history delta, event states, hashes, spans, and NVD-specific authority pass provider-free replay |
| Rust CVE-2024-24576 | vendor/project | Rust 1.77.2 fixed-release declaration | Commit-addressed project blog source, tag records, dual licenses | dev | **Accepted first scale batch**: tag-to-commit identity, license evidence, semantic delta, exact span, and publisher authority pass provider-free replay |
| CPython CVE-2023-24329 | vendor/project | Python 3.11.4 security-change declaration | Commit-addressed NEWS source, tag records, PSF license | validation | **Accepted first scale batch**: tag-to-commit identity, license evidence, semantic delta, exact span, and publisher authority pass provider-free replay |
| Jenkins CVE-2017-1000503/1000504 | vendor/project | weekly 2.95 fixed-release declaration | Commit-addressed advisory, tag records, CC BY-SA policy | validation | **Accepted first scale batch**: tag-to-commit identity, license evidence, semantic delta, exact span, and publisher authority pass provider-free replay |
| CERT/NVD CVE record for Secure Boot | structured CTI/vulnerability | scoring/reference changes | CVE/NVD histories | unassigned | Reject as a separate family: same incident dependency as VU#309662 unless kept nested |

The three proof candidates deliberately exercise three reusable shapes: archived
project release text, commit-addressed structured catalog states, and tagged
STIX releases. They remain one development batch. All CISA KEV documents in
this batch share one catalog dependency; all selected ATT&CK documents share
one release lineage. Neither may later be split or counted as multiple
independent families merely by choosing more entries or techniques.

## Completed controlled captures for the proof batch

The batch used 18 unique successful exact-URL captures in 18 attempts with no
retry. The first nine captured two candidate states and one license for each
source. Apache's two commit-level aggregate `CHANGES` candidates were retained
only as gitignored diagnostics after they failed the semantic-delta gate. The
accepted Apache replacement used two archive release notes plus the archive
index. Four public unauthenticated commit/release metadata records and two
annotated-tag objects then bound CISA ancestry and the exact ATT&CK `v15.1` and
`v16.0` tag-to-commit mappings. The ledger records every URL, request
fingerprint, hash, length, timestamp, outcome, and ignored local path. No raw
byte is a tracked corpus artifact.

The accepted proof families record dominant stratum, incident/campaign,
vendor/product, source-release, challenge-generator, coarsest dependency, and
prospective split in `configs/portfolio-proof-families-v1.yaml`. Shared
dependencies are mechanically forbidden from crossing prospective splits.

## Yield-gate batch and decision

The second batch accepted CISA KEV CVE-2021-27137, the Node.js May 2025
security-release versions, and NVD's CVE-2024-3400 CPE applicability change.
They add one development and two validation families, bringing the audited
total to 10 eligible families (7 development, 3 validation). The current mix is
4 vendor/project, 3 public-coordination, and 3 structured families. Exact cases,
source bindings, and provider-free oracle
outputs are in the `portfolio-yield-*` artifacts.

The yield gate passes for balanced scaling toward 24. At 7 accepted program
families from 33 successful captures, the observed 21.2% yield projects roughly
28 eligible families if it holds over the 87 remaining successful-capture
slots. This supports attempting 24 but is not evidence that 36 is feasible.
The full projection, source-mix target, annotation load,
and stop conditions are recorded in `reports/portfolio-yield-gate-v1.md`.

## First scale batch

The five captured candidates all passed normalization and audit, bringing the
eligible total to 15: eight development, seven validation, and no holdout
candidates. The dominant-source mix is now seven vendor/project, three public
coordination, and five structured CTI/vulnerability families (46.7%, 20.0%,
and 33.3%). This intermediate mix is intentionally not described as final
diversity. A balanced 24-family minimum now needs approximately five vendor,
three coordination, and one structured addition to land at 12 / 6 / 6
(50% / 25% / 25%).

The program has 60 successful captures and 70 attempts remaining. The five
families added here consumed 21 successful captures, so the observed scale-
batch rate alone is insufficient to promise all 36 families. It still permits
a bounded nine-family minimum-completion batch if source reuse and immutable
official locators keep the average below 6.7 captures per accepted family.
That is a feasibility constraint, not permission to weaken evidence,
licensing, independence, or semantic-delta requirements.

All five questions use publisher-declared version evidence only. The 2026
capture timestamp proves when these exact bytes were observed locally; it does
not prove historical public availability at the publisher-declared dates.
The tracked manager audit is not the single-human calibration packet.

## Second scale batch capture plan

Discovery screened official primary-source metadata without promoting browser
content to evidence. The bounded minimum-completion batch selects exactly nine
candidate families: PostgreSQL CVE-2023-5868 for the eighth validation slot;
curl CVE-2023-38545, Kubernetes CVE-2023-5528, Git CVE-2022-41903, and Tomcat
CVE-2023-46589 as vendor/project holdout candidates; CISA ICSA-25-212-01,
ICSA-25-121-01, and ICSA-25-135-19 as coordination holdout candidates; and NVD
CVE-2024-6387 description history as a structured holdout candidate.

The five project families each have two tagged release-note states, two tag
reference records, and one project license locator. The three CISA families
have seven total commit-addressed CSAF states plus one shared CISA terms-policy
locator. NVD begins with one history record; exact event URLs may be added only
from the retained history response. The initial plan therefore contains 34
new exact URLs. A self-imposed batch ceiling of 46 successful captures and 50
attempts permits only necessary annotated-tag objects and NVD event pages
identified from those responses. It does not enlarge the program-wide 120/180
caps, permit semantic retries, or authorize another source family.

The planned final 24-family mix is 12 vendor/project, 6 coordination, and 6
structured families. Only PostgreSQL may enter the validation loader and case
set during this batch. The other eight may exist only as holdout-candidate
metadata and hash/provenance records; they must not enter prompt, retrieval,
policy, grader, or question-authoring work before the encrypted holdout
protocol is activated.

Candidate-specific risks remain fail-closed: release text must contain a real
security predicate rather than generic version metadata; CISA product/fix
claims remain vendor-qualified even when CISA is publisher/coordinator; CISA
raw redistribution is not assumed; and an NVD history event proves only what
NVD recorded. Any candidate that fails semantic delta, exact version identity,
terms, authority, or split independence is rejected without replacement
infrastructure.

### Second scale capture outcome

The frozen batch completed 40 successful captures in 44 attempts. Two local
PowerShell compatibility failures occurred before a request and were retried
once under the existing fingerprint; the two planned curl release-note paths
returned 404 and were not semantically retried. All six annotated-tag objects
and both NVD event pages derived from retained responses succeeded once. The
program ledger therefore stands at 100 successful captures and 114 attempts,
with 20 captures and 66 attempts remaining.

Offline inspection of the retained exact bytes provisionally passes PostgreSQL
CVE-2023-5868, all three CISA CSAF lineages, and NVD CVE-2024-6387. PostgreSQL
15.5 newly names CVE-2023-5868; the three CISA histories add product/remediation
scope; and NVD records a substantive description change on 2024-07-02. Git
2.39.1 newly declares that it merges the security fix from v2.30.7, but its
claim remains limited to that publisher security-release declaration unless a
stronger source is captured. These are audit findings, not accepted-family
increments, until tracked source metadata, licensing disposition, dependency
lineage, and deterministic checks bind them.

The intended curl evidence is absent because both exact paths returned 404.
The captured Kubernetes changelog does not name CVE-2023-5528, and the Tomcat
changelog does not tie its observed behavioral changes to CVE-2023-46589.
Those three candidates therefore fail closed on the current bytes. Any repair
capture requires a separately frozen, exact-URL plan and must stay within the
20 remaining successful-capture slots; no browser-only text may repair the
evidence.

### Frozen second scale repair capture

The repair batch contains exactly five one-shot public official URLs and may
use at most five successful captures and five attempts. Redirect following,
retries, alternate locators, and additional sources are disabled; any failure
leaves its candidate rejected.

| Source ID | Exact URL | Purpose |
|---|---|---|
| `curl-release-notes-8.3.0-repair` | `https://raw.githubusercontent.com/curl/curl/curl-8_3_0/RELEASE-NOTES` | Bind the pre-fix tagged publisher state |
| `curl-release-notes-8.4.0-repair` | `https://raw.githubusercontent.com/curl/curl/curl-8_4_0/RELEASE-NOTES` | Bind the post-fix tagged publisher state |
| `curl-cve-2023-38545-advisory-repair` | `https://curl.se/docs/CVE-2023-38545.html` | Tie affected 8.3.0 and fixed 8.4.0 to the named CVE |
| `kubernetes-cve-2023-5528-advisory-repair` | `https://discuss.kubernetes.io/t/security-advisory-cve-2023-5528-insufficient-input-sanitization-in-in-tree-storage-plugin-leads-to-privilege-escalation-on-windows-nodes/26080` | Tie the captured v1.28.3/v1.28.4 states to affected scope and fixed v1.28.4 |
| `tomcat-cve-2023-46589-security-page-repair` | `https://tomcat.apache.org/security-9.html` | Tie the captured 9.0.82/9.0.83 states to affected and fixed versions |

These current advisory pages provide publisher declarations, not independent
proof that the same page bytes were historically available on their declared
dates. Acceptance, if any, remains publisher-declared version evidence.

All five repair URLs returned HTTP 200 exactly once with redirects disabled.
The repair evidence closes the three source gaps without adding a family or
alternate locator: curl's 8.4.0 note links CVE-2023-38545 and its advisory
declares 8.3.0 affected/8.4.0 unaffected; the Kubernetes advisory identifies
kubelet v1.28.4 as fixed; and Tomcat identifies CVE-2023-46589 as fixed in
9.0.83 and affecting versions through 9.0.82. Exact bytes remain gitignored.

## Minimum-completion batch

The nine candidates now pass the manager's retained-byte semantic audit.
PostgreSQL is the eighth validation family and has one cutoff-aware question,
exact evidence span, dedicated closed authority policy, and provider-free
scripted-oracle output. The other eight are metadata-only holdout candidates:
no question, gold, prompt, retriever, grader, or policy artifact contains their
candidate IDs. They are not described as blind or sealed because the encrypted
two-key protocol has not been activated.

The eligible inventory is therefore 24 families excluding Log4Shell: 8
development, 8 validation, and 8 holdout candidates. Its dominant-source mix is
12 vendor/project, 6 public coordination/exploitation, and 6 structured
CTI/vulnerability families (50%, 25%, and 25%). Every count is family-level;
questions, CVEs, source states, and repeated samples are not counted as
independent observations.

The 36-family target is infeasible within the frozen capture budget. Twelve
additional eligible families would require at least 24 successful source-state
captures even before tag, terms, or authority support, while only 15 successful
captures remain. No further source capture is justified. The 24-family corpus
is a **portfolio-scale pilot**, not the 100-family confirmatory protocol and not
evidence of broad CTI generalization or model improvement.

Independent fail-first review found no remaining P0/P1 issue after the manager
bound every candidate family to exact ordered sources, rejected duplicate and
cross-split raw support, used conservative end-of-day PostgreSQL publisher
times, and asserted the exact semantic delta for every retained lineage. Fresh
local validation passed 466 tests with 3 intentional skips plus formatting,
lint, strict typing, schema/config validation, deterministic replay, credential
scanning, package build, and diff checks.

## Clean-clone and release posture

Permitted public bytes may be reproduced from immutable official locators with
hash verification. When redistribution is uncertain or disallowed, the tracked
artifact contains only a pinned manifest, hash, lawful minimal evidence span,
and deterministic verify/derive recipe; a clean clone fails closed with the
specific missing input. No raw body is committed by default.
