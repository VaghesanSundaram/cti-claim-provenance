# Portfolio release readiness

Status: **ready_for_user_decisions**. The repository remains private.

## Automated checks

- PASS — `clean_checkout_demo`: tracked provider-free 24/16/48 summary matches deterministic output.
- PASS — `candidate_secret_scan`: no candidate credential patterns or unscannable files.
- PASS — `forbidden_artifact_paths`: no candidate raw, private, quarantine, provider, or protected evaluation paths.
- PASS — `portable_candidate_text`: no user-specific absolute path appears in candidate text.
- PASS — `personal_email_in_candidate_files`: personal author email absent from current candidate files.
- PASS — `internal_markdown_links`: all candidate Markdown local links resolve.
- PASS — `source_terms_dispositions`: 29/29 active snapshot dispositions are nonempty.
- PASS — `dual_platform_ci_contract`: Ubuntu/Windows workflow contains the full release-candidate gate.
- PASS — `apache_2_license`: Apache-2.0 license is tracked for project-authored material only.

## Remaining user decisions

1. Choose the public-history/visibility strategy. Private main history contains a personal Gmail author address; the recommended default is a sanitized single-commit export authored with the GitHub noreply address.

No visibility change, history rewrite, license choice, tag, or release is performed by this check.
