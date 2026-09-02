# Temporal v2 provider approval package

Status: awaiting user approval. No v2 provider request has been sent.

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

- Schedule: `614da5a9b4ee3789d4fcd8302e3e49f6ef214f379f612e0ffe00d01718ea21ee`
- Ordered request set: `fd2118bcba13bd8340d3ee0d9962eed27aaaff502f81c7cdefb3c829016524d3`
- Descriptor: `6f53e0beaf99972b0c08af767bce8bd41623aaf076bdedda8d524baa03bbb449`
- Direct prompt: `d44a5b2143692d79ce7e07f1adbe610408c32a316628c0ccd3363189b6b1189b`
- State-first prompt: `ff9fd41e40f79dc83de82715db114b78e93f77b722ca1e3fbbd334e45f8cfe0f`
- Rubric: `d13126610e2b7daf0ee6b51547f96252a281be8de2a53cfd3e79e117e3346fb8`
- Grader: `cf1ee9f606274105977c4181efc76ac925c3cb734801297c130b5f25203076a1`
- Harness: `5becc49d5b41c82484d784b331948c8fadf11b2386a098abd92752f4d1e248aa`
- Manifest: `1d032ef7a76131d43f037377f4eea1ff0294c91d1c7e50c574ca92e22490d8f1`
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

1. `3e9a64e680c24fbd4a03c9ffa9ede82ee0f9b87a7aa37eac33e455ef863ea6f3`
2. `0fc5827b76b9fc69788ec58515b6cffc4f11c3b3fa3eeae07aa87e061d156171`
3. `f95dbccd8ae74969cdb130fce4692fb8d439dc0b9c9c40e0f9da41cb0e59e05d`
4. `92a8dc67b7586aee5825c028c3d83b1edb79a66cdfd16c0abcf08f1d1cc2bc87`
5. `59edb3548e81a899054aa11a009187e717c232d57e73b9fb6d259301d5994a1e`
6. `1350ab5796f87f2b8ee5cb983ffee92d11003e7f905ad389d772666b091b5fd9`
7. `821094bbfff10baef02b0c4aa10bc89c59e39a6416ad6d3f5beb1237dca555d4`
8. `f990b952f212246e4e8aedff418225446e0e672f35d459e76b01651a0821b2b9`
9. `af52740fa044b5a5906e4f97d03f4e93016f6d6c9898d7568d5790bfad16baab`
10. `7bf130181aca41ec39b9cc421407387b8bcb61506c16925da75125513f6a8482`

## Retry and stop rules

One retry is allowed only for an explicit rate limit or provider server error
with no accepted output. SDK retries are disabled. A connection or timeout is
treated as an uncertain possibly billable outcome and stops without retry. A
completed refusal, invalid JSON, schema/semantic failure, model mismatch,
ledger mismatch, schedule/request hash drift, unexpected egress, raw-output
write failure, or cost-accounting uncertainty also stops or fails closed as
defined by the manifest. Completed cells are never repeated on resume.

Approval authorizes only the ten-cell smoke followed by inspection. It does not
authorize the remaining 510 cells, a merge to public main, a tag, a release, or
deployment. A valid smoke receives its own Checkpoint 3 before any later full
run decision.
