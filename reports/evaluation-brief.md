# Evaluation brief

Status: Phase 0 approved; protocol frozen for Phase 1 implementation
Protocol version: `phase0-v1`
Last updated: 2026-07-18

## Decision summary

This project evaluates a benchmark contract, not a generic CTI assistant and
not the novelty of atomic claims, citations, temporal QA, or adversarial RAG in
isolation.

The narrow contribution is:

> A CTI benchmark and deterministic evaluation harness for whether atomic
> historical claims are supported by inspectable, cutoff-eligible evidence
> spans of appropriate predicate-specific authority, including
> insufficient-evidence, contradiction, wrong-date, weak-authority, and
> poisoned or distractor retrieval cases.

No scoped prior work reviewed in Phase 0 was found to combine all of these
elements. That is an inference from a focused review, not proof of absence.
The project must not claim to be the first CTI RAG benchmark, citation
benchmark, temporal QA benchmark, atomic-fact evaluator, or RAG-poisoning
evaluation.

### Phase 2 plumbing-only entity

`CVE-2021-44228` (Log4Shell) is used only as a familiar, cross-source entity
for plumbing validation in the smallest development slice. Results from this
entity test ingestion contracts, temporal filtering, evidence locators,
retrieval, and deterministic grading; they are not new Log4Shell findings and
must not be presented as evidence of benchmark representativeness.

Red Hat `current_release_date` is interpreted only as publisher-declared
version evidence for the exact final, checksum-matched CSAF revision. It is not
an independently observed historical publication time and cannot make the
current body eligible for a cutoff earlier than that declared version date.

## Research question and hypotheses

Primary question:

> Does deterministic claim-evidence enforcement improve supported historical
> claim precision without a practically important loss of supported claim
> recall relative to citation prompting, when retrieval and all non-treatment
> generation factors are held constant?

The final confirmatory comparison is the paired contrast:

`lexical_claim_evidence_constrained - lexical_citation_prompted`

Co-primary outcomes:

1. **Supported historical claim precision.** The numerator is emitted atomic
   claims whose typed value is correct and whose cited span resolves, entails
   the claim, is cutoff-admissible, and satisfies the predicate authority
   policy. The denominator is every emitted material atomic claim.
2. **Supported historical claim recall.** The numerator is the same supported
   correct claims, matched one-to-one to expected claims. The denominator is
   every expected material claim.

Directional hypotheses:

- superiority: constrained claim-evidence output increases supported historical
  claim precision;
- non-inferiority: constrained claim-evidence output does not reduce supported
  historical claim recall by more than 5 percentage points.

Five percentage points is the provisional minimum practically important
difference and non-inferiority margin. The pilot may refine variance and sample
size, but it may not change the outcome definitions or select a more favorable
direction. Any margin change requires a new protocol version before holdout.

Secondary outcomes include atomic exact-value accuracy, ordinary claim
precision/recall/F1, citation resolution, entailment, temporal validity,
authority precision, post-cutoff leakage, contradiction handling, correct and
unnecessary abstention, retrieval recall at declared K, attack success,
refusal/parse/provider failure, latency, tokens, and cost.

## Estimand and statistical unit

The primary estimand is a **claim-micro paired condition effect** across the
eligible confirmatory holdout families under the frozen retrieval corpus,
provider model, schedule, and failure policy.

For condition `k`, scheduled repeat slot `r`, and case `c`, define:

- `TP[k,r,c]`: number of one-to-one matched expected claims that satisfy typed
  value correctness, evidence resolution and entailment, cutoff admissibility,
  and predicate authority;
- `EMIT[k,r,c]`: number of emitted material claims, including unsupported,
  duplicate, wrong-value, wrong-authority, and invalid-evidence claims from an
  otherwise valid answer envelope;
- `GOLD[c]`: number of expected material claims in the case's unique
  confirmatory predicate/source cell.

Then:

```text
precision[k] = sum(TP[k,r,c]) / sum(EMIT[k,r,c])
recall[k]    = sum(TP[k,r,c]) / sum(GOLD[c])
```

Every preregistered repeat slot contributes once. A transient retry remains
inside its original slot and does not create a new experimental observation.
If all exact-request transport attempts for a slot fail, or the final response
has an invalid answer envelope, that slot has `TP=0`, `EMIT=0`, and retains its
`GOLD` denominator. An otherwise valid envelope with an invalid or missing
evidence reference retains the affected claim in `EMIT` with no supported TP.

The paired effects are:

```text
delta_precision = precision[claim_evidence] - precision[citation_prompted]
delta_recall    = recall[claim_evidence] - recall[citation_prompted]
```

The paired bootstrap resamples `case_family_id` clusters with replacement
within each of the four frozen confirmatory predicate/source cells, preserving
the observed number of families per cell. Each draw pools the selected
attempt-, repeat-, case-, and family-level counts and recomputes the same micro
ratios and paired deltas. Repeats, cases, and claims are never sampled as
independent units. The final seed and number of draws will be frozen before the
pilot; the default is 10,000 draws with a checked-in seed.

- If the observed `sum(EMIT)` is zero for either primary condition, precision
  and its superiority test are undefined and no improvement claim is allowed.
- A bootstrap draw with a zero precision denominator is recorded as degenerate.
  Percentile intervals may use defined draws only when at least 99% of draws are
  defined; otherwise the precision interval and superiority test are withheld.
- The two co-primary tests use Holm correction at family-wise
  `alpha = 0.05`. All other inferential results are secondary or descriptive.
- Every scheduled repeat slot remains in the intention-to-evaluate denominator.
  Every transport attempt remains in the immutable operational ledger.
  Refusal, parse failure, local safety block, timeout, and provider failure are
  also reported separately by condition.
- On an answerable case, a slot that emits no usable claims contributes false
  negatives to recall. It contributes no emitted claims to precision; paired
  recall and explicit failure/coverage metrics prevent abstention or failure
  from appearing as an unqualified gain.
- Unanswerable cases are excluded from claim-recall denominators and scored in
  the preregistered abstention outcomes.

No repeat-level pseudo-replication and no post-hoc choice among metrics is
permitted.

## Required conditions and treatment isolation

All three conditions receive the same cutoff-filtered documents, document
order, evidence-ID vocabulary, non-treatment instructions, atomic-claim answer
envelope, provider/model, context and output budgets, decoding, timeout,
transient retry policy, schedule, parser implementation, and grader versions.

### Lexical direct answer

- Utility/factual baseline only; it is not part of the primary provenance
  contrast.
- Uses the same atomic-claim envelope.
- Evidence IDs are allowed to be empty and the prompt says citations are not
  required.
- Citation, evidence-coverage, and authority-by-citation metrics are marked
  not applicable, not failed.

### Lexical citation prompted

- Receives the same exposed evidence IDs as the constrained condition.
- The only treatment instruction is: cite the evidence IDs supporting each
  material atomic claim when possible.
- `evidence_ids` may be empty in the provider-facing schema.
- Missing, nonexistent, or inadmissible evidence is graded as missing or
  invalid; it does not trigger a repair request.

### Lexical claim-evidence constrained

- The only treatment instruction is: every material claim must cite at least
  one supporting allowed evidence ID; if no allowed evidence supports the
  claim, abstain from that claim.
- The provider-facing schema applies `minItems: 1` to `evidence_ids` for emitted
  material claims.
- After receipt, deterministic local validation checks evidence-ID foreign
  keys, admissibility, and answer-envelope invariants.

This is explicitly a **bundled enforcement treatment** consisting of the
stable instruction delta, schema cardinality constraint, and deterministic
foreign-key validation. Results must not be described as the causal effect of
prompt wording alone.

### Invalid output and retries

- No semantic repair, paraphrase, evidence substitution, or model retry follows
  parse, schema, evidence-ID, authority, or entailment failure.
- Documented transient transport failures may retry the exact semantic request
  under the ordinary bounded policy. Every attempt receives a new attempt ID
  and remains in the ledger.
- A provider-side structured-output rejection before inference is an
  infrastructure failure. It is never silently converted to a different schema.
- A malformed envelope, duplicate claim ID, wrong run/case identity, or any
  provider-schema violation makes the whole scheduled slot unusable:
  `TP=0`, `EMIT=0`, with the expected claims retained in recall.
- In an otherwise valid envelope, an empty citation-condition `evidence_ids`
  list or a nonexistent, wrong-snapshot, or inadmissible evidence ID invalidates
  only that claim's support. The claim remains in `EMIT`; other claims remain
  gradable.
- The constrained provider schema rejects an empty `evidence_ids` list through
  `minItems: 1`. A returned violation is a whole-envelope schema failure.
- Parser and validator versions are identical across the primary conditions.

## Claim and grade contracts

Gold and generated `AtomicClaim` records contain typed subject, predicate,
object, qualifiers, evidence IDs, and confidence. Grader-derived decisions are
stored separately so generated output cannot declare itself correct.

`ClaimGrade` must include:

```yaml
claim_grade_id: string
run_id: string
case_id: string
generated_claim_id: string|null
expected_claim_id: string|null
predicate: string
value_match: exact | partial | mismatch | not_applicable
evidence_assessments:
  - evidence_id: string
    resolution: resolved | missing | wrong_snapshot
    entailment: supported | partial | unsupported | not_applicable
    temporality: admissible | post_cutoff | invalid_basis | not_applicable
    authority: accepted | weak | wrong | unresolved | not_applicable
    span_hash_match: boolean|null
contradiction: none | lower_authority | peer_authority | primary_authority
claim_support: supported | unsupported | contradictory | ungradable
abstention_outcome: correct | unnecessary | missed | not_applicable
generated_confidence: number|null
deterministic_grader_version: string
authority_policy_version: string
normalization_version: string
human_judgment_id: string|null
notes_code: string|null
```

The deterministic grader produces the structural, typed-value, resolution,
temporality, authority-policy, and aggregate support decisions. Human-blinded
judgments are permitted for vendor-span entailment or unresolved official-source
definition conflicts and are linked by immutable judgment ID. A model may
prioritize cases for audit but cannot be the sole correctness or entailment
grader.

Expected claims must be unique by:

`(subject.type, subject.id, predicate, canonical_qualifiers, object.datatype)`.

Multiple expected values for that key are represented as one typed set/list
claim. Generated claim IDs must be unique within an answer. Matching partitions
claims by the same key, sorts generated claims by stable `claim_id`, matches the
first exact typed-value claim when present, and otherwise pairs the first claim
only for mismatch diagnostics. At most one generated claim matches an expected
claim; every additional duplicate is an unmatched false positive. There is no
fuzzy or model-selected tie-breaking.

## Evidence-span definition

An exact evidence span is defined over versioned normalized UTF-8 text with:

- start and end character offsets;
- normalized document hash;
- exact span-text hash;
- raw JSON pointer, selector, or extraction-map locator;
- raw snapshot ID and hash;
- normalization version.

The normalized offset is the scoring address. The raw locator and extraction
map must round-trip the span to the immutable raw source field. A span without a
working raw mapping is ineligible for gold unless a documented
`raw_locator_unavailable` exception is human-reviewed before freeze.

## Temporal admission and source-state selection

`allowed_snapshot_ids` is derived output, never a manual authority. The dataset
builder recomputes and validates it from source manifests and the case cutoff.

For each `(source_name, upstream_identifier)`:

1. validate the declared truth mode and `available_by_basis`;
2. reject unsupported or internally inconsistent basis evidence;
3. retain versions with `available_by_utc <= case.as_of`;
4. find the maximum admissible `available_by_utc`;
5. collapse byte-identical duplicates at that time;
6. apply only the source-specific validated ordering below when distinct states
   share that time;
7. fail the manifest when distinct maximum-time states remain incomparable;
8. exclude all later versions and older duplicates from the ordinary corpus
   view.

An older version may appear only as an explicitly declared stale/adversarial
treatment with a distinct treatment document ID. Aggregate feeds produce one
source snapshot; documents derived from that feed inherit its availability
decision.

Per-source algorithms:

| Source | Truth mode and `available_by` derivation | Required evidence | Invalid behavior |
|---|---|---|---|
| NVD CVE API | `observed_snapshot`; `available_by_utc = retrieved_at_utc` for the exact payload | successful bounded request, response metadata without secrets, byte hash | Distinct bytes at the same retrieval timestamp are a fatal collision; never order by snapshot ID or backdate to `published`/`lastModified` |
| CISA KEV | `upstream_versioned` for a pinned `cisagov/kev-data` commit; use the official repository commit time as the publisher-version bound | commit SHA, canonical file hash, commit metadata, CISA mirror relationship | At equal time, select a state only when its commit is a descendant of the others; unrelated/incomparable heads fail; missing provenance falls back to `observed_snapshot` |
| MITRE ATT&CK | `upstream_versioned`; use the official release publication time for a release-specific STIX bundle | release tag, parsed ATT&CK semantic version, commit SHA, release metadata, bundle hash | At equal time, compare validated semantic release versions; equal version with distinct bytes or unparsable/incomparable versions fail; mutable “latest” is observed only |
| Red Hat RHSA CSAF | Publisher-declared version evidence (stored internally as `publisher_timestamp_with_observation`); use `current_release_date` only when it equals the final revision date and the frozen bytes match Red Hat’s published SHA-256 | final status, tracking ID, validated CSAF integer/semantic version scheme, complete revision history, publisher-declared current release date, published checksum, retrieval time | The publisher-declared date is not an independently observed historical publication time; at equal time, use the validated CSAF version/revision order; equal version with distinct bytes or inconsistent history fails; a current body never answers as an unavailable prior revision |
| Synthetic control | `synthetic_control`; availability is the fixture manifest time chosen by the generator | deterministic generator version, monotonic integer fixture sequence, fixture hash, declared cutoff | Equal sequence with distinct bytes or missing sequence fails; synthetic results remain separate |

An invalid basis makes the snapshot inadmissible. `snapshot_id` is never a
chronological comparator.

## Predicate-specific authority

Initial policy:

| Predicate | Primary authority | Acceptable corroboration | Conflict action |
|---|---|---|---|
| NVD publication/modified time | NVD frozen record | CVE Program only when definitions align | preserve named-source values; do not merge |
| Named CVSS score/version | the named scoring authority in the claim | other authorities reported separately | wrong authority fails; no score blending |
| KEV membership/date added/due date | CISA KEV | none required | CISA governs; record conflicts |
| Red Hat affected/fixed product state | Red Hat RHSA CSAF/VEX | NVD/CISA as secondary context only | prefer explicit Red Hat state; abstain on ambiguous product mapping |
| ATT&CK relationship | pinned MITRE ATT&CK STIX release | none required | score only the pinned release |

Abstention is correct both for insufficient admissible evidence and for an
unresolved conflict among equally applicable primary authorities. The
abstention reason distinguishes these cases.

## Sources, legality, and release posture

The initial vendor family is **Red Hat RHSA CSAF/VEX**. A bounded Phase 0 check
of `RHSA-2026:0001` matched Red Hat’s published SHA-256 and confirmed final
tracking metadata, three revisions, four CVEs, and explicit fixed-product
status. The check created no repository snapshot.

| Source | Access/rate posture | Terms/license evidence | Local storage, transformation, and quotation | Raw/derived release posture |
|---|---|---|---|---|
| NVD | public API: 5 requests per rolling 30 seconds without a key; six-second spacing recommended | NIST/NVD public-data and required no-endorsement notice | bounded raw capture and independently authored normalized fields are allowed for research; quote only the selected public fields needed for evidence and preserve source attribution | default public artifact is normalized facts plus hash/fetch recipe and the NVD no-endorsement notice until the exact artifact is reviewed |
| CISA KEV | bounded public canonical/Git mirror fetch | official `cisagov/kev-data` repository states CC0; linked third-party content excluded | pinned catalog bytes, derived fields, and necessary catalog excerpts may be stored and transformed under CC0; linked advisory content is not copied | pinned raw JSON/commit and derived data may be released with CC0/no-endorsement handling |
| MITRE ATT&CK | pinned release bundle only; bounded public GitHub fetch | MITRE repository license permits use/copy with copyright/license preservation | release-specific STIX bytes, derived relationships, and exact object excerpts may be stored and transformed while retaining the license/copyright designation | raw pinned bundle or derived records may be released only with the required license designation |
| Red Hat RHSA CSAF | sequential cached selection; no broad crawl; back off on 429/5xx | Red Hat Security Data states CC BY 4.0 with Red Hat attribution and original link | selected raw CSAF, normalized product-state fields, and exact supporting excerpts may be stored and transformed with Red Hat attribution, original link, and modification notice | small selected raw fixtures and derived records may be released with attribution, license link, canonical URL, and modification statement |

Source pages, linked references, PDFs, or other third-party content are not
inherited into these permissions. Unknown or ambiguous content defaults to a
hash, metadata, and fetch/derive recipe. Release/publication remains separately
unauthorized.

Material source ledger:

| Source | Type/date | Supported decision | Caveat |
|---|---|---|---|
| [NVD developer guidance](https://nvd.nist.gov/developers/start-here) | official documentation; updated 2025-02-25; accessed 2026-07-18 | public/keyed rate limits, spacing, UTC/API behavior, attribution notice | does not provide historical payload versions |
| [CISA KEV data repository](https://github.com/cisagov/kev-data) | official CISA-maintained repository; accessed 2026-07-18 | canonical-source relationship, near-current mirror, public commit history, CC0 posture | mirror may lag the canonical CISA site by minutes |
| [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data) | official MITRE repository; accessed 2026-07-18 | release-specific STIX bundles and license-bearing copy path | mutable latest bundle is not historical evidence |
| [Red Hat Security Data](https://access.redhat.com/security/data) | official vendor page; accessed 2026-07-18 | CC BY 4.0 data license and CSAF/VEX fixed/unfixed product content | attribution and original link are required |
| [Red Hat CSAF advisory index](https://security.access.redhat.com/data/csaf/v2/advisories/) | official vendor directory; accessed 2026-07-18 | advisory JSON, signatures, published SHA-256 files, bounded fixture availability | directory modification time is not the advisory publication time |
| [OASIS CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/cs03/csaf-v2.0-cs03.html) | official standard; accessed 2026-07-18 | mandatory tracking ID, release dates, version, and revision history | each selected vendor document still requires conformance validation |

## Split feasibility and confirmatory cells

The approximately 50/25/25 pilot family split is for development workflow only;
the pilot uses development and validation, never holdout.

Before final holdout construction, the confirmatory cells are exactly:

| Stratum ID | Primary source | Primary predicate |
|---|---|---|
| `nvd_published` | NVD | `cve.published_at` |
| `kev_membership` | CISA KEV | `kev.is_member` |
| `attack_relationship` | MITRE ATT&CK | `attack.relationship_present` |
| `redhat_fixed` | Red Hat RHSA CSAF | `vendor.fixed_versions` |

Every confirmatory `case_family_id` is assigned to exactly one stratum and all
of its paired cases share that assignment. A confirmatory case contains scored
expected material claims only for that cell's source/predicate. Multi-predicate
questions and all other source/predicate cells are descriptive and excluded
from the co-primary estimand.

Before final holdout construction:

- target at least 100 holdout base `case_family_id` clusters across at least
  four scored predicates and all four source families;
- require at least 20 holdout case families in each of the four enumerated
  confirmatory cells;
- keep each clean/adversarial pair in one split;
- keep entity/advisory, vendor/product, template, and attack-generator families
  in one split;
- label cells below 20 as descriptive and exclude them from confirmatory
  stratum claims without changing the overall frozen denominator;
- run and store a prospective split-feasibility table before sealing.

If source quality cannot populate those cells without ambiguous or duplicate
cases, narrow the confirmatory scope rather than weaken family isolation or pad
the dataset.

## Holdout custody and projections

Custodian decision: **manager-custodian model, confirmed by the user on
2026-07-18**.

The root manager acts as evaluation custodian. Subagents and prompt, retrieval,
generator, prediction-runner, and grader implementers never receive key
material or plaintext outside their authorized stage. The manager alone creates
and holds two separate age-v1 X25519 identities:

1. holdout-input recipient/identity;
2. holdout-gold recipient/identity.

Identity files remain outside the repository, OneDrive, Codex configuration,
environment, command arguments, logs, and all subagent context. Key material is
not generated until the holdout-sealing phase.

The encrypted input bundle contains only:

- pseudonymous case/linkage ID;
- question and `as_of`;
- derived allowed corpus/snapshot manifest reference;
- authority policy IDs;
- condition-independent case metadata needed for prediction.

The separately encrypted gold bundle contains:

- the same pseudonymous linkage ID;
- expected atomic claims and exact evidence IDs;
- abstention and adjudication labels;
- gold schema and grader compatibility versions.

Each bundle contains an encrypted internal manifest with its plaintext payload
hash, schema version, count, and random linkage IDs. The repository records only
ciphertext hashes and schema versions. No public linkage commitment or third
commitment key exists. After the gold stage is authorized, the offline grader
validates exact linkage-ID equality inside the two decrypted bundles.
Development agents see synthetic calibration bundles, public schemas, and
opaque ciphertext hashes only.

At Phase 9, plaintext is decrypted to an access-controlled
temporary path outside the repository and OneDrive. The input stage is
read-only. The prediction CLI requires a configured private artifact root,
resolves it, and rejects any output under the repository, OneDrive, or another
declared sync root. The complete prediction bundle remains under that external
access-controlled immutable root; only its hash and a non-sensitive run
manifest are committed and pushed. Immediately before gold grading, the manager
rehashes the bundle and requires equality with the pushed commitment. Gold is
then activated. An offline grader receives no provider credentials or network.
Temporary plaintext is removed in a `finally` path and cleanup is verified;
secure erasure of filesystem remnants is not claimed.

Any premature access, count/ID disclosure, key reuse, linkage mismatch,
prediction mutation, or cleanup failure invalidates the benchmark version.

This is mechanical role separation, not independent human custody. The manager
must freeze prompt, retrieval, grader, and inclusion decisions before sealing;
must not inspect decrypted holdout content before its authorized stage; and
must report the absence of an independent custodian as a study limitation.

## Provider-safety boundary

Protocol version `provider-safety-v1` is adopted before any model call.
Authorization manifests, the stable provider request envelope, and safety
events follow `docs/provider-safety-protocol.md`.

For this project, prohibited “third-party target identifiers” means live
operational identifiers such as credentials, private or public target IPs,
active domains/hostnames, account IDs, access paths, or production
configuration. Public documentary identifiers needed for benign CTI evidence
analysis—CVE, CWE, ATT&CK, RHSA, product names, canonical advisory URLs, and
source-internal evidence IDs—are allowed.

The first study excludes IOC-bearing spans and operational exploit detail.
Provider context is assembled from an allowlist of normalized fields and exact
evidence spans. Disallowed content causes deterministic field/span exclusion,
not in-place text substitution that would corrupt evidence offsets.

A provider refusal is scored once and never triggers semantic reformulation,
provider switching, fragmentation, encoding, translation, or safety-setting
weakening.

## Pilot budget and stop rules

- Phase 0 and all offline Phase 1 work: no paid model calls.
- Vertical-slice paid ceiling: $2, but not authorization.
- Pilot paid ceiling: $6 including retries, but not authorization.
- Before either run, the manager must request approval naming provider/model,
  cases, conditions, repeats, planned calls, token bound, price access date,
  retry-inclusive dollar cap, and cancellation rule.
- A 5% canary stops if parser or infrastructure failures exceed 10%.
- A source/label stratum stops for repair if audited corrections exceed 5%.
- The project narrows or stops under the canonical plan’s licensing, temporal,
  agreement, retrieval, treatment-validity, or $80 full-study criteria.

## Focused prior-art comparison

| Work | Established contribution | Difference from this protocol |
|---|---|---|
| [CTIConnect (2026)](https://cticonnect.github.io/) | heterogeneous CTI RAG, cross-source retrieval, expert-verified QA | no historical availability/snapshot contract, exact span-provenance grade, predicate authority policy, or declared abstention/adversarial pairing found in the reviewed page |
| [CTIBench (2024)](https://proceedings.neurips.cc/paper_files/paper/2024/hash/5acd3c628aa1819fbf07c39ef73e7285-Abstract-Datasets_and_Benchmarks_Track.html) | CTI task and model-capability benchmark | not a frozen claim-provenance evaluation |
| [TempRAGEval/MRAG (2025)](https://aclanthology.org/2025.findings-emnlp.167/) | temporal perturbations, gold evidence, time-sensitive retrieval | not CTI and no reviewed source-availability/authority contract |
| [ALCE (2023)](https://aclanthology.org/2023.emnlp-main.398/) | end-to-end cited answers and citation quality | no CTI, historical availability, or authority axis |
| [AttributionBench (2024)](https://aclanthology.org/2024.findings-acl.886/) | claim-to-cited-evidence support evaluation | evaluator benchmark rather than point-in-time CTI system benchmark |
| [FActScore (2023)](https://arxiv.org/abs/2305.14251) | atomic-fact decomposition and source support | no attached evidence IDs, cutoff corpus, or predicate authority |
| [PoisonedRAG (2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/zou-poisonedrag) | knowledge-corruption attacks against RAG | not a CTI temporal/provenance benchmark |

## Phase 0 gate

The manager may pass Phase 0 only when:

- [x] the contribution boundary is narrow and adjacent work is named;
- [x] the primary contrast, outcomes, estimand, analysis unit, failure policy,
      and minimum meaningful effect are frozen;
- [x] the treatment delta and bundled-enforcement interpretation are frozen;
- [x] the `ClaimGrade` contract is frozen for Phase 1 implementation;
- [x] temporal basis algorithms and exact source-state selection are frozen;
- [x] Red Hat RHSA CSAF is selected and a bounded official hash check passed;
- [x] source access, attribution, storage, and release defaults are recorded;
- [x] prospective split feasibility and minimum confirmatory cells are defined;
- [x] the manager-custodian model and two-stage key boundary are recorded;
- [x] public CTI identifiers and provider exclusions are reconciled;
- [x] safety schemas, refusal handling, budgets, and stop rules are adopted;
- [x] `reports/threat-model.md` is completed after user context confirmation;
- [x] an independent reviewer confirms that the critical Phase 0 findings are
      resolved in this record.

Independent sign-off: `phase0_gate_review`, 2026-07-18, verdict
`pass_phase0`; no remaining blockers.
