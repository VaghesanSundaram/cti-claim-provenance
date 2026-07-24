# Evaluation brief v2 — portfolio-scale pilot

Status: corpus-construction protocol frozen; exact evaluation candidate,
provider schedule, power decision, and holdout remain unfrozen

Protocol version: `portfolio-pilot-v2`

Effective date: 2026-07-21

## Narrow research question

Given frozen dated CTI source versions and a question with a cutoff, can a
model emit only claims supported by eligible evidence, cite exact spans from the
appropriate authority, and abstain when the eligible record is insufficient,
despite stale, post-cutoff, lower-authority, contradictory, or irrelevant
distractors?

V2 is a portfolio-scale pilot. It does not replace the v1 confirmatory protocol,
which requires at least 100 holdout family clusters and at least 20 families in
each of four confirmatory cells. Log4Shell remains plumbing-only. The XZ,
Ivanti, and NetScaler pack remains feasibility evidence, not an evaluation.

## Sampling unit and dependency audit

The primary unit is an audited advisory/version family: one bounded incident or
product/advisory lineage and all related source versions, CVEs, questions,
paraphrases, packet variants, and attack variants. Those nested observations
and repeated generations do not increase the independent family count.

For every family, record:

- incident or campaign lineage;
- vendor and product lineage;
- exact source release, commit, or raw-snapshot lineage;
- question-template family;
- challenge-generator family;
- dominant source stratum; and
- the coarsest shared dependency used for sensitivity analysis.

Assign an entire dependency lineage to one split before question writing. Keep
families derived from one KEV catalog or ATT&CK release in one split and repeat
the analysis clustered at that shared dependency.

## Portfolio target and source mix

Target 36 audited-distinct families: 8 development, 8 validation, and 20
encrypted holdout candidates. A 24–35-family corpus may be reported only as a
portfolio pilot. With fewer than 20 distinct holdout families, all comparative
results are descriptive.

Assign exactly one dominant stratum per family:

1. 45–55% vendor/project advisory or release lineages;
2. 25–35% public coordination/exploitation lineages; and
3. 20–25% structured CTI/vulnerability lineages.

Cover affected/unaffected/fixed versions, product/platform applicability, KEV
status and deadlines, required or recommended action, advisory revision state,
CVSS value plus scoring authority, and only primary-supported IOC or technique
mapping. Include explicit answerable and named-reason abstention cases.

## Family eligibility and temporal basis

A family is eligible only when it has:

- at least two independently addressable official source states or a cutoff
  relationship that creates a real admissibility change;
- a substantive semantic delta rather than formatting, wording-only, or file
  metadata;
- an atomic non-operational claim with deterministic extraction and grading;
- a defensible predicate-specific authority and temporal basis;
- acceptable retention or clean-clone reproducibility terms; and
- no cross-split near-duplicate or dependency-lineage conflict.

Each source version records source organization, exact source ID and immutable
locator, content hash, publisher timestamp, observation/capture timestamp,
temporal-basis class, license/terms disposition, and dependency lineage.

`publisher_declared_version_evidence` proves only what the named publisher
version says and its declared version time. It never proves independently
observed historical availability. The latter requires an actual observation or
archive by the cutoff.

## Cases and matched challenges

Create one or two high-quality base questions per family. Abstention must have a
testable cause: no eligible state, insufficient product/version specificity,
authority conflict, or evidence only after cutoff.

For a preregistered subset of at least 16 families, create matched clean and
challenge packets plus a benign control where relevant. Allowed challenges are
outdated or post-cutoff official states, lower-authority contradictions,
irrelevant same-vendor/entity material, edition ambiguity, plausible
unsupported assertions, and safe synthetic instruction-like wrappers. Labels
come only from frozen deterministic source/cutoff rules and the human review,
never an LLM judge.

Retrieval must be nontrivial: relevant evidence coexists with plausible stale,
same-entity, same-vendor, or otherwise confusable material, and `top-k` cannot
equal the entire corpus. Report retrieval recall separately from generation.

## Conditions and treatment isolation

Use the same case, packet, retriever output, prompt scaffold, model snapshot,
decoding settings, and call budget across conditions. Change only the
response/evidence contract:

1. direct answer: atomic answer/abstain without a citation requirement;
2. citation prompted: atomic answer/abstain with supplied source/span IDs; and
3. claim-evidence constrained: typed claim/evidence envelope plus local schema,
   foreign-key, cutoff, authority, and exact-span validation.

Clean versus challenge packets are paired scenario variants, not additional
conditions. The primary matched package comparison is condition 3 minus
condition 2. Direct answer is a separate secondary factual/abstention baseline.
No result may be attributed causally to one validator component.

## V2 primary score and estimand

For an answerable case:

```text
family_case_score = 2TP / (2TP + FP + FN)
```

A true positive requires an exact atomic gold match and evidence that passes
span integrity, cutoff, and authority checks. Empty output scores zero when a
gold claim exists. For an unanswerable case, score one only for a valid
abstention with no emitted claim; otherwise score zero.

Average case, packet, and repeat scores within each family, then weight each
holdout family equally. The primary effect is the mean paired family-score
difference between constrained and citation-prompted. Preserve v1 claim-micro
precision and recall as named secondary outcomes. Score direct answer on atomic
claim match and abstention without citation metrics.

## Inference and reporting boundary

Repeated generations measure stochastic variability and are paired across
conditions where possible; they do not add families. Three repeats is only a
planning placeholder until a separately authorized development/validation
provider pilot estimates variance, or the conclusion is explicitly limited to
the sampled-run configuration.

Use a family-cluster bootstrap and a sensitivity analysis at the coarsest
shared dependency. Do not use response-level confidence intervals. With 20
holdout families, at most one predeclared top-level mixed-corpus comparison may
receive inferential wording, and only if a prospective precision/power analysis
frozen before holdout construction supports it. Source, predicate, attack, and
vendor slices remain descriptive.

Report family-macro supported historical correctness; claim precision/recall;
cutoff admissibility and post-cutoff leakage; evidence entailment and span
integrity; citation precision/recall; authority; correct/unnecessary abstention;
contradiction handling; clean-to-challenge degradation and attack success;
retrieval recall@k; parse/refusal/provider/infrastructure failures; tokens,
latency, and cost. A supporting citation does not prove causal model reliance.

`status=improved` is allowed only if the prospective analysis supports the
narrow claim and the later preregistered frozen-holdout result meets its
threshold. Otherwise use `status=evaluated; scope=portfolio_pilot`.

## One-reviewer protocol

The user is the only human reviewer. Present source text, cutoff, expected
atomic claim, exact span, authority, and answerability in the existing blinded
review workflow. Require reasons for ambiguous, unsupported, or changed labels.
Randomly resurface 20–30% later with blinded identifiers/order and report
intra-rater consistency as repeatability, not gold correctness. Preserve
append-only decisions and immutable supersession. Do not report inter-rater
agreement or call agent review human calibration.

Use at most two consolidated human gates: development/validation calibration
before protocol freeze and isolated holdout custody/label review after prompts,
retrieval, graders, exclusions, metrics, and analysis freeze. Without the
second custody gate, call the final split a held-out test set rather than blind
or sealed.

## Freeze and provider boundary

Before any expanded-corpus model call, freeze exact family/case/split/packet
IDs, source hashes, exclusions, prompts and condition definitions, model and
provider settings, schedule/retries/failure policy, outcomes and thresholds,
cluster/resampling method, token/cost ceiling, benchmark version, validity
window, contamination risk, and refresh policy.

Implement and test the existing encrypted two-key, two-stage protocol before
calling holdout blind or sealed. No provider call is authorized by this brief.
Stop with an exact new provider proposal for separate approval.

## Research and source basis

- [CTIBench](https://arxiv.org/abs/2406.07599)
- [ALCE citation evaluation](https://aclanthology.org/2023.emnlp-main.398/)
- [PAT-Questions temporal QA](https://aclanthology.org/2024.findings-acl.777/)
- [PoisonedRAG](https://www.usenix.org/conference/usenixsecurity25/presentation/zou-poisonedrag)
- [NIST adversarial ML taxonomy](https://csrc.nist.gov/pubs/ai/100/2/e2025/final)
- [Official CVE List v5 repository](https://github.com/CVEProject/cvelistV5)
- [NVD vulnerability/change-history API](https://nvd.nist.gov/developers/vulnerabilities)
- [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [OASIS CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html)
- [MITRE ATT&CK version history](https://attack.mitre.org/resources/versions/)
- [MITRE ATT&CK STIX data](https://github.com/mitre-attack/attack-stix-data)

These references motivate coverage and methodology. They do not validate the
resulting corpus or authorize a stronger claim.
