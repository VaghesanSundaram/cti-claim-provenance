# CTI diverse portfolio model evaluation v1

- Model: `gpt-5.6-luna` (192 cells)
- Design: 64 semantic questions, 24 dependency clusters, 192 single-sample cells; citation-prompted versus claim-evidence-constrained bundled pipeline variants.
- Citation-prompted provenance outcomes: 80/96 (0.833); strict semantic exact 32/96 (0.333).
- Constrained provenance outcomes: 83/96 (0.865); strict semantic exact 25/96 (0.260).
- Paired provenance delta (constrained minus citation): 0.031; dependency-family macro delta: 0.044.
- Paired outcomes: 7 wins / 85 ties / 4 losses.
- Accounted provider cost: `$0.660676`; tokens: 270844 input, 64972 output.

## Packet variants

- clean: citation provenance 54/64; constrained 57/64.
- control: citation provenance 13/16; constrained 12/16.
- challenge: citation provenance 13/16; constrained 14/16.

## Limitations

- One generation per cell; no run-to-run variance or stability estimate.
- Exactly 64 answer contracts span 51 semantic-pair groups and 24 dependency clusters; they are not 64 independent factual phenomena.
- The 8 abstention questions test enumerated benchmark insufficiency causes only.
- Control/challenge packets cover the 16 retained extraction questions, not all 64 questions.
- The comparison bundles prompt wording with API schema enforcement and does not isolate either mechanism causally.
- The preregistered primary provenance metric grades predicate, component role, exact evidence bindings, and abstention; the stricter semantic metric additionally requires canonical typed values. Natural-language authority_scope wording is descriptive because authority is enforced by predicate and evidence binding.

These are descriptive, single-sample results. They do not establish statistical significance, run-to-run stability, broad CTI generalization, or causal attribution to schema enforcement alone.
