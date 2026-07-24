# Active portfolio pilot inventory

This is the concise active successor to the historical corpus-expansion
inventory. Source capture is closed.

- Inventory families: 24 audited-distinct advisory/version lineages.
- Public evaluated-offline families: 16 (8 development, 8 validation).
- Metadata-only future evaluation candidates: 8; they have no authored
  question or gold and are excluded from packets, retrieval, grading, and
  metrics.
- Public matched cases: 48 (16 clean, 16 benign control, 16 safe synthetic
  challenge).
- Dominant-source mix across the 24-family inventory: 12 vendor/project, 6
  public coordination/exploitation, and 6 structured CTI/vulnerability.
- Controlled captures used during construction: 105 successful exact-byte
  captures in 119 attempts. No further capture is required or authorized for
  this release candidate.
- Raw captures remain gitignored. Active public artifacts use exact hashes,
  bounded lawful spans, terms dispositions, and pinned source recipes.

The 16 public cases are all answerable. Abstention is therefore not evaluated
for this portfolio. The active metric and artifact details are in
[`portfolio-demo.md`](../reports/portfolio-demo.md) and
[`portfolio-active-corpus-v2.json`](../data/manifests/portfolio-active-corpus-v2.json).

Log4Shell is plumbing-only. XZ, Ivanti, and NetScaler are feasibility evidence.
Publisher-declared version dates do not prove independently observed historical
availability.
