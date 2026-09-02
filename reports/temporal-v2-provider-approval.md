# Temporal v2 provider approval package

Status: execution complete. The approved v2.1 run produced 520 usable cells;
results are in [`temporal-v2-results.md`](temporal-v2-results.md).

Revision note: the authorized v2.0 smoke completed ten calls but did not record
latency. Those cells are preserved as invalid diagnostic runs. V2.1 adds only
provider-call latency capture, changes no prompt or approved egress, and must
repeat the smoke before scaling.

## Frozen execution

- API: `POST https://api.openai.com/v1/responses`
- SDK: `openai==2.54.0`, exactly locked
- Model: `gpt-5.6-luna`
- Settings: reasoning effort `medium`; maximum 800 output tokens; service tier
  `default`; `store=false`; background disabled; no tools; no seed;
  temperature omitted so the provider default applies
- Structured Outputs: enabled only for B, D, and oracle; A/B and C/D prompt
  bodies are byte-identical within each case and trial
- Schedule: 480 factorial cells plus 40 oracle cells; 520 total
- Attempts: at most two per cell; 1,040 maximum

Official OpenAI documentation lists Luna on the Responses endpoint with
Structured Outputs support and current prices of USD 0.20 per million input
tokens, USD 0.02 per million cached input tokens, and USD 1.20 per million
output tokens. The Responses reference documents `store=false`,
`max_output_tokens`, reasoning effort, service tier, and JSON Schema response
format. Sources were accessed at `2026-09-02T00:07:13Z`:
[Luna model](https://developers.openai.com/api/docs/models/gpt-5.6-luna) and
[Responses create](https://developers.openai.com/api/reference/cli/resources/responses/methods/create).

## Frozen hashes

- Schedule: `97642191177dd66bc7064443821ef5ce07656ef323254fb3ddd80842c8c54923`
- Ordered request set: `fd2118bcba13bd8340d3ee0d9962eed27aaaff502f81c7cdefb3c829016524d3`
- Descriptor: `cc91635a414e10b1fe9a87771edbbe64282586d3e5dea35a9e57a9d95b34134d`
- Direct prompt: `d44a5b2143692d79ce7e07f1adbe610408c32a316628c0ccd3363189b6b1189b`
- State-first prompt: `ff9fd41e40f79dc83de82715db114b78e93f77b722ca1e3fbbd334e45f8cfe0f`
- Rubric: `a43b570ade15c8597d22e29384a76bf2bb9fc1619f351b4a52556b36ec3b5c3d`
- Grader: `cf1ee9f606274105977c4181efc76ac925c3cb734801297c130b5f25203076a1`
- Harness: `7e4dce4bd8aa93b04e731b3b6ba31b11bdcd6c79edeab23588fe04dd47e338ec`
- Manifest: `0d58a976a9d55074a395b3f859cd173c08ac43889390878c0d969efc5285bc4b`
- Questions: `54bd55941b600332890f26639853048df97a017930e1beb77e04985673c591f7`
- Packets: `4460ea8c4b8e6f52584b37cf0470c81b54afb231a4a1da64b6df68c2444a6478`

The containing Git commit is recorded after Checkpoint 2 because a commit
cannot contain its own hash.

## Egress and cost

The unique egress inventory contains 24 approved packets, 48 neutral documents,
and 51 span aliases: 25,625 UTF-8 bytes with SHA-256
`23414d338f360afe557c494f846423664a11f3b3800cba948cec6aee28fbe114`.
Requests are built from an allowlist and exclude final answers, delta labels,
source IDs and hashes, evidence IDs, evaluator bindings, derivation records,
authority rationales, and ambiguity notes. Thirteen named packets contain the
documented supplied-state absence assertions; the study does not claim to test
independent discovery of those states. Oracle requests explicitly supply old
and new gold states.

The complete ordered requests are 1,423,875 UTF-8 bytes. The largest serialized
request is 3,835 bytes. No token-count endpoint was called because that would
be provider egress before approval. The cost gate conservatively reserves 3,835
input tokens per attempt, greater than the request byte count can tokenize to,
and assumes zero cache discount:

- 520-attempt ceiling: `520 × (3,835 × $0.20/M + 800 × $1.20/M)` =
  **USD 0.898040**.
- 1,040-attempt retry ceiling: twice the above = **USD 1.796080**.
- Hard stop: **USD 10.00**, including any possibly billable uncertain outcome.

Raw responses will be written append-only outside the repository and outside
synchronized folders at the absolute directory supplied through
`CTI_TEMPORAL_RAW_DIR`. The prepared absolute local value is recorded only in
the private workspace status, not in public artifacts.

## Ten-cell smoke

The smoke uses trial 1 for dependency-distinct `temporal-03` and `temporal-04`
under A/B/C/D plus their two oracle cells. Its cell IDs are:

1. `6d6fd6af9690999027c1e804cd120ce3d099bde68efee6d72e695e1562050eeb`
2. `9f3e3efeb05fe6c1e9aaf732e614216e14819df9b769de096d9ace9a2379ec99`
3. `9126fed0a378509a995d3c33ccb61ea9a15d9d5a242800a764098e25ac5f26ba`
4. `5e0fe4c7626c0d554b9bbb40c9d819bf07e97589567bdd9630ae176ef3369ea7`
5. `365fc6feb2fb19524f839f61e18229eee7d1743b461e747a771b5eb58c329d54`
6. `87ef1163268d87064ad19f729013ec8289da2a80b3fa9fd5838d9174eb59f6a8`
7. `a3e395c5bfcd2ff46356e6cead6f8fba2f7b66b3b7b8fcc588462de335416571`
8. `201624add40c4f27cdd569fe7e39d38a8c889d9d7e3083af9a6bc54f1defa46e`
9. `c24c00a0879cdb20bd27e8485c3c72bc5da5939acad6336491db6e46b5a5cc51`
10. `06a0d0d41855fdc90a6b20a85d905802a401bb7e1919a889d5e0f44e4e901cc1`

## Retry and stop rules

One retry is allowed only for an explicit rate limit or provider server error
with no accepted output. SDK retries are disabled. A connection or timeout is
treated as an uncertain possibly billable outcome and stops without retry. A
completed refusal, invalid JSON, schema/semantic failure, model mismatch,
ledger mismatch, schedule/request hash drift, unexpected egress, raw-output
write failure, or cost-accounting uncertainty also stops or fails closed as
defined by the manifest. Completed cells are never repeated on resume.

At this checkpoint, approval covered only the ten-cell smoke. Later user
authorization covered the remaining cells and one replacement for an uncertain
connection attempt. The original uncertain attempt was preserved rather than
silently treated as unsent.
