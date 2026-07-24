# CTI claim-provenance portfolio demo

Status: **evaluated offline; provider-free portfolio pilot**. This is not a model evaluation.

- Inventory: 24 audited-distinct families: 16 reviewed public families (8 development, 8 validation) plus 8 metadata-only future evaluation candidates excluded from every current metric.
- Matched evidence-selection cases: 48/48: clean, benign control, and safe synthetic challenge for each public family.
- Challenge mix: instruction_like_poison 4, lower_authority_contradiction 4, stale 4, unsupported_assertion 4.
- Controlled lexical recall@6: clean 16/16, benign control 16/16, challenge 16/16. This is a packet/retrieval check, not evidence of general retrieval robustness.
- Single-reviewer gold audit: 20/20 items over 16 unique families; 4/4 exact blinded resurfacing agreement. Intra-rater repeatability does not establish gold-label correctness.
- Portfolio answerability: 16/16 answerable and 0 abstention cases. Portfolio abstention performance is not evaluated.
- Source terms dispositions: 29/29; provider calls: 0.
- The corrected CISA KEV CVE-2021-27137 qualifier is `product=DD-WRT`.

Publisher-declared version evidence proves what a named publisher version says and its declared time; it does not prove independently observed historical availability. The synthetic challenges measure controlled evidence selection only, not model reasoning, citation faithfulness, realistic attack prevalence, or adversarial robustness.
