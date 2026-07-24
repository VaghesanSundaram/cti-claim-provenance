# Provider-Safety Protocol For The Security Projects

Status: installed required project control
Purpose: make legitimate defensive research scope explicit and reproducible
without bypassing, weakening, disguising, or evading provider safeguards.

## Decision

Do not implement guardrail circumvention, jailbreaks, obfuscation, prompt
laundering, classifier probing, retry variants intended to slip past a refusal,
or routing whose purpose is to obtain content another provider blocked.

Instead, make the authorized defensive scope machine-readable, keep all
security actions local and simulated, request only the detail necessary for the
defensive metric, log safety outcomes, and use the provider's support or
approved-access path when a clearly benign workflow is repeatedly blocked.

Provider safety checks remain valid system behavior. A refusal or additional
check is an evaluation outcome, not a harness failure to be bypassed.

## Required Implementation

### 1. Authorization manifest

Every model-backed scenario must reference a versioned manifest:

```yaml
authorization_id: string
project: cross_tool_authz | cti_provenance
purpose: defensive_evaluation
owner: local_project
target_kind: synthetic_fixture | frozen_public_document
target_ids: [string]
target_network_access: false
provider_transport:
  allowed: boolean
  provider: openai | anthropic | google | none
  endpoint_class: official_model_api | none
external_or_live_target: false
data_classification: synthetic | public
allowed_outcomes:
  - identify_or_classify
  - cite_evidence
  - recommend_remediation
  - propose_local_regression_test
  - evaluate_simulated_policy_behavior
prohibited_outcomes:
  - credential_collection
  - persistence
  - evasion_or_stealth
  - malware_or_phishing
  - data_exfiltration
  - destructive_action
  - denial_of_service
  - live_target_scanning_or_exploitation
approved_by: project_protocol
protocol_version: string
```

The runner must refuse any scenario lacking a valid manifest or requesting an
outcome outside it. A manifest documents scope; it does not override provider
policy or authorize external activity.

`target_network_access: false` prohibits the model, simulated tools, retrieval,
corpus, and evaluated task from reaching any live target. It does not describe
the separately controlled transport to a model provider. Provider egress is
allowed only when `provider_transport.allowed` is true for the named official
endpoint and the manager is executing a user-approved run. No other component
receives network access.

### 2. Provider request envelope

Build prompts from a fixed, versioned template that states:

- this is defensive evaluation over a named local synthetic fixture or frozen
  public document;
- no networked, external, third-party, production, or live target is involved;
- the requested output is limited to the declared defensive outcome;
- exploit payloads, credentials, persistence, evasion, exfiltration,
  destructive actions, and safety-control circumvention are out of scope;
- evidence, uncertainty, remediation, and local regression tests are preferred.

Do not add repetitive declarations solely to manipulate a classifier. The
scope statement should be short, truthful, stable across conditions, and held
constant in comparative experiments.

### 3. Fixture and corpus controls

Project 1:

- Use invented service names, synthetic records, fake tokens, local state
  machines, and non-routable identifiers.
- Application-level prompt-injection cases may request only simulated,
  reversible state changes inside the mock services.
- Do not ask the model to defeat the provider's safeguards. The tested boundary
  is the project's deterministic authorization monitor.
- Measure policy decisions and simulated state transitions, not the production
  of real exploit code.

Project 2:

- Use frozen public CTI documents and synthetic controls without live-web
  fallback during evaluation.
- Treat malicious or instruction-bearing source text as quoted evidence data.
  Structural delimiters and metadata may distinguish data from instructions;
  do not obfuscate content to evade provider detection.
- Ask for atomic claims, evidence, contradiction handling, dates, authority,
  and abstention—not malware creation, live intrusion, or operational attack
  steps.

Both projects:

- Exclude real credentials, account identifiers, private data, production
  configuration, live IP addresses, access paths, and third-party target
  identifiers from model inputs.
- Apply an outbound-network deny check in offline tests.
- Keep unredacted provider requests/responses local and gitignored.

Partition safety evaluation cases explicitly:

- `benign_defensive`: secure review, remediation, detection, configuration, or
  evidence analysis;
- `sensitive_simulation`: non-operational diagnosis/remediation on an owned
  local synthetic fixture;
- `must_refuse`: unauthorized targeting, malware/phishing, denial of service,
  credential theft, persistence, evasion, security-control bypass, or scaled
  compromise.

Report false-positive refusal on the first two classes separately from unsafe
assistance or failed redirection on the third. Human-review disagreements must
be adjudicated without showing reviewers the provider/model condition.

### 4. Safety-event handling

Record a redacted event for every provider call:

```yaml
run_id: string
scenario_id: string
authorization_id: string
provider: string
model: string
timestamp: string
request_template_version: string
safety_outcome: allowed | refused | additional_check | blocked | unknown
provider_request_id_redacted: string|null
retry_count: integer
response_used_for_scoring: boolean
notes: string|null
```

Rules:

- Do not automatically paraphrase, fragment, encode, translate, or switch
  providers after a safety refusal.
- Retry only documented transient infrastructure errors, using the exact same
  semantic request and the ordinary bounded retry policy.
- Classify refusals separately from parser, harness, grader, and task failures.
- Preserve the original denominator and report missingness/refusal rate by
  condition. Do not silently drop blocked cases.
- If the request contains detail unnecessary to the defensive metric, revise
  the protocol on development data, document the change, and create a new
  prompt version. Never tune wording on final holdout safety outcomes.
- For repeated false positives on a stable, clearly defensive request, preserve
  the exact redacted request metadata and use the provider's support, feedback,
  appeal, or approved cybersecurity-access path.

### 5. Provider adapter boundary

Each provider adapter must implement the same interface:

```text
preflight(authorization_manifest, scenario, request) -> allow | local_block
estimate_cost(request) -> upper_bound
invoke(request, approved_run) -> provider_result
classify_safety_outcome(provider_result) -> SafetyOutcome
redact_for_artifact(provider_result) -> redacted_result
```

Preflight is deterministic and provider-independent. Provider-specific safety
settings must remain documented, versioned, and constant within a comparison.
Do not lower or disable a safety setting merely to improve benchmark completion.

### 6. Tests

- Every model scenario has a valid authorization manifest.
- Missing, malformed, external-target, or prohibited-outcome manifests fail
  locally before a provider request.
- Canary credentials and private-data markers are rejected or redacted.
- Network-deny tests prove mock/offline components cannot reach live targets.
- A safety refusal produces one safety event and no automatic semantic retry.
- Safety outcomes retain their denominator and cannot be converted to ordinary
  model errors or silently excluded.
- Comparative conditions use the same safety scope statement and provider
  safety configuration.
- Holdout safety outcomes cannot change prompts, labels, exclusions, or
  provider routing for the primary result.
- Redacted artifacts contain no request IDs, secrets, private data, or
  prohibited operational detail.

## Provider-Specific Notes

OpenAI:

- Current usage policies prohibit malicious or abusive compromise, unsolicited
  safety testing, and safeguard circumvention.
- OpenAI advises narrow, defensive framing and omission of exploit detail that
  is unnecessary for prevention or remediation. Rewording does not change
  whether an underlying request is allowed.
- Additional cyber safety checks can occur even for legitimate work. Repeated
  false positives should use Support/feedback; advanced authorized workflows
  may require Trusted Access for Cyber, which does not remove all safeguards.

Anthropic:

- Current policy supports vulnerability discovery with the system owner's
  consent while prohibiting unauthorized access/exploitation, malware,
  disruption, persistence, surveillance, and control bypass.
- Treat a policy refusal as final for that request and use provider support or
  an approved research channel rather than reformulating to evade it.

Google Gemini:

- Current terms prohibit compromising services, malware/phishing, disruption,
  and circumvention of safety filters.
- Google recommends narrower functionality, human oversight, explicit safety
  metrics, and adversarial testing. Configurable safety settings are product
  controls, not authorization to bypass the prohibited-use policy.
- Current Gemini API abuse-monitoring documentation describes retention and
  possible authorized human review of submitted prompts/context/outputs. Submit
  only synthetic/public, non-confidential artifacts unless applicable data
  arrangements have been reviewed.

## Source Ledger

| Source | Type / date | Claims supported | Caveats | Confidence |
|---|---|---|---|---|
| [OpenAI Usage Policies](https://openai.com/policies/usage-policies/) | Official policy; effective 2025-10-29 | Prohibits unauthorized compromise, unsolicited safety testing, and safeguard circumvention | Broad policy; not a benchmark implementation guide | High |
| [OpenAI additional cyber safety checks](https://help.openai.com/en/articles/20001326-additional-safety-checks-for-biological-and-cybersecurity-requests-in-chatgpt-codex-and-the-api) | Official Help Center; current as reviewed 2026-07-18 | Narrow defensive scope, omit unnecessary exploit detail, extra checks may occur, use support for repeated benign blocks | Product behavior can change; no guarantee a request will be served | High |
| [OpenAI Trusted Access for Cyber](https://help.openai.com/en/articles/20001258-trusted-access-for-cyber) | Official Help Center; current as reviewed 2026-07-18 | Approved path for authorized cyber workflows; ownership, controlled scope, and safeguards remain required | Approval-based and not an entitlement | High |
| [Anthropic Usage Policy update](https://www.anthropic.com/news/usage-policy-update) | Official policy announcement; 2025-08-15 | Supports owner-authorized vulnerability discovery; prohibits malicious compromise categories | Summary points to the full evolving usage policy | High |
| [Anthropic Usage Policy](https://www.anthropic.com/legal/aup) | Official policy; effective 2025-09-15 as reviewed | Owner-authorization distinction and prohibited malicious cyber activity/guardrail bypass | Policy can change; recheck before paid runs | High |
| [Anthropic responsible disclosure policy](https://www.anthropic.com/responsible-disclosure-policy) | Official policy; last updated 2025-02-14 | Good-faith research minimizes harm, data access, disruption, and exploitation beyond proof | Applies specifically to Anthropic systems, but useful containment principles | High |
| [Google Generative AI Prohibited Use Policy](https://policies.google.com/terms/generative-ai/use-policy?gl=US&hl=en-US) | Official policy; last modified 2024-12-17 | Prohibits compromise, malware/phishing, disruption, and safety-filter circumvention | Service-specific terms may add restrictions | High |
| [Gemini API Additional Terms](https://ai.google.dev/gemini-api/terms) | Official terms; effective 2026-03-23 as reviewed | Requires prohibited-use compliance and forbids bypassing protective measures | Applies specifically to Gemini API/AI Studio | High |
| [Gemini API abuse monitoring](https://ai.google.dev/gemini-api/docs/usage-policies?hl=en) | Official developer documentation; updated 2026-06-09 as reviewed | Describes abuse monitoring, retention, and possible authorized human review | Data handling may differ under other products/contracts | High |
| [Google safety and factuality guidance](https://developers.google.com/machine-learning/resources/safety-gen-ai) | Official developer guidance; current as reviewed 2026-07-18 | Recommends narrower functionality, human oversight, rate limits, prompt-injection defenses, and safety testing | General guidance, not a cyber authorization policy | High |
| [Google adversarial testing guidance](https://developers.google.com/machine-learning/guides/adv-testing) | Official developer guidance; updated 2025-08-25 | Define prohibited behavior and test safeguards against a declared failure taxonomy | General generative-AI evaluation guidance | High |

## Residual Uncertainty

Provider policies, model safeguards, and access programs change. Re-open current
official policy and product documentation before each paid evaluation or public
release. Even a fully compliant request may receive an automated safety check;
this protocol improves clarity and containment but cannot guarantee acceptance.
