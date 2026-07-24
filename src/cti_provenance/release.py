"""Provider-free portfolio demo and public-release safety checks."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from cti_provenance.dataset import BenchmarkCase
from cti_provenance.experiments.portfolio_challenge_runner import (
    PortfolioChallengeResult,
    render_portfolio_challenge_cases,
    render_portfolio_challenge_jsonl,
    render_portfolio_challenge_report,
    render_portfolio_public_cases,
    run_portfolio_challenge_slice,
)
from cti_provenance.experiments.portfolio_yield_runner import run_portfolio_yield_slice
from cti_provenance.grading.portfolio_review import build_portfolio_review_packet
from cti_provenance.grading.review_workflow import (
    ReviewDecision,
    ReviewPacket,
    load_jsonl_records,
    render_review_packet,
    validate_review_log,
)
from cti_provenance.normalize import NormalizedDocument

MAX_TEXT_FILE_BYTES = 5 * 1024 * 1024
ACTIVE_MANIFEST_PATH = PurePosixPath("data/manifests/portfolio-active-corpus-v2.json")
FUTURE_CANDIDATE_PATH = PurePosixPath(
    "data/manifests/portfolio-holdout-candidates-v1.json"
)
DEMO_REPORT_PATH = PurePosixPath("reports/portfolio-demo.md")
RELEASE_REPORT_PATH = PurePosixPath("reports/portfolio-release-readiness.md")
_PERSONAL_EMAIL = "vaghesan" + "@" + "gmail.com"
_REBUILD_MANIFEST_PATHS = (
    PurePosixPath("data/manifests/three-family-corpus-v1.json"),
    PurePosixPath("data/manifests/portfolio-proof-corpus-v1.json"),
    PurePosixPath("data/manifests/portfolio-yield-corpus-v1.json"),
    PurePosixPath("data/manifests/portfolio-scale-corpus-v1.json"),
    PurePosixPath("data/manifests/portfolio-minimum-corpus-v1.json"),
)


@dataclass(frozen=True)
class SecretPattern:
    """Named pattern whose match contents must never be printed."""

    name: str
    regex: re.Pattern[str]


@dataclass(frozen=True)
class Finding:
    """Non-secret location of a possible credential."""

    path: Path
    line_number: int
    pattern_name: str


@dataclass(frozen=True)
class ManualReview:
    """Candidate that cannot be safely cleared by the text scanner."""

    path: Path
    reason: str


SECRET_PATTERNS = (
    SecretPattern(
        "private-key-header",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
        ),
    ),
    SecretPattern("age-secret-key", re.compile(r"AGE-SECRET-KEY-1[0-9A-Z]+")),
    SecretPattern(
        "openai-style-key",
        re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"),
    ),
    SecretPattern(
        "github-token",
        re.compile(r"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b"),
    ),
    SecretPattern("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    SecretPattern("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    SecretPattern(
        "nonempty-secret-assignment",
        re.compile(
            r"^\s*(?:export\s+)?"
            r"(?:NVD_API_KEY|OPENAI_API_KEY|ANTHROPIC_API_KEY|GEMINI_API_KEY|"
            r"GITHUB_TOKEN)\s*[:=]\s*[\"']?[^\"'\s#][^\"'\r\n#]*"
        ),
    ),
)


class PortfolioDemoSummary(BaseModel):
    """Exact denominators for the tracked provider-free portfolio result."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    status: Literal["evaluated_offline_provider_free"]
    inventory_family_count: Literal[24]
    public_family_count: Literal[16]
    development_family_count: Literal[8]
    validation_family_count: Literal[8]
    future_candidate_count: Literal[8]
    matched_case_count: Literal[48]
    challenge_type_counts: tuple[tuple[str, int], ...]
    clean_recall_at_6: Literal[16]
    control_recall_at_6: Literal[16]
    challenge_recall_at_6: Literal[16]
    review_item_count: Literal[20]
    review_unique_family_count: Literal[16]
    active_review_decision_count: Literal[20]
    immutable_review_record_count: Literal[21]
    repeatability_agreement_count: Literal[4]
    repeatability_pair_count: Literal[4]
    answerable_public_case_count: Literal[16]
    abstention_portfolio_case_count: Literal[0]
    abstention_status: Literal["not_evaluated"]
    source_terms_disposition_count: int = Field(ge=1)
    provider_calls: Literal[0]
    corrected_product: Literal["DD-WRT"]


class ReleaseCheck(BaseModel):
    """One public-release candidate check without leaking matched content."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    name: str = Field(min_length=1)
    passed: bool
    detail: str = Field(min_length=1)


class PortfolioReleaseReadiness(BaseModel):
    """Automated result with genuine user decisions kept separate."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    status: Literal["failed", "ready_for_user_decisions"]
    checks: tuple[ReleaseCheck, ...]
    user_decisions: tuple[str, ...]


class PortfolioRebuildSummary(BaseModel):
    """Exact full-rebuild comparison when ignored source caches are supplied."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    public_case_count: Literal[16]
    matched_case_count: Literal[48]
    challenge_result_count: Literal[16]
    review_item_count: Literal[20]
    yield_case_count: Literal[4]


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _jsonl[ModelT: BaseModel](path: Path, model: type[ModelT]) -> list[ModelT]:
    return [
        model.model_validate_json(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _manifest_artifacts(root: Path, manifest: dict[str, object]) -> None:
    artifacts: list[dict[str, object]] = []
    for key in ("overlay", "review_decisions"):
        value = manifest.get(key)
        if not isinstance(value, dict):
            raise ValueError(f"active manifest lacks {key}")
        artifacts.append(value)
    for key in ("successors", "reused_artifacts"):
        value = manifest.get(key)
        if not isinstance(value, list) or not all(
            isinstance(item, dict) for item in value
        ):
            raise ValueError(f"active manifest lacks {key}")
        artifacts.extend(value)
    for artifact in artifacts:
        relative = artifact.get("path")
        expected = artifact.get("sha256")
        if not isinstance(relative, str) or not isinstance(expected, str):
            raise ValueError("active manifest artifact binding is incomplete")
        candidate = root / relative
        if not candidate.is_file() or _sha256(candidate) != expected:
            raise ValueError(f"active artifact hash mismatch: {relative}")


def _repeatability(
    packet: ReviewPacket, decisions: list[ReviewDecision]
) -> tuple[int, int]:
    superseded = {
        decision.supersedes_decision_id
        for decision in decisions
        if decision.supersedes_decision_id is not None
    }
    active = {
        decision.item_id: decision
        for decision in decisions
        if decision.decision_id not in superseded
    }
    grouped: dict[str, list[str]] = defaultdict(list)
    for item in packet.items:
        grouped[item.case_sha256].append(item.item_id)
    repeated = [item_ids for item_ids in grouped.values() if len(item_ids) == 2]
    if len(grouped) != 16 or len(repeated) != 4:
        raise ValueError("review resurfacing inventory is invalid")

    def key(decision: ReviewDecision) -> tuple[object, ...]:
        verdict = decision.verdict
        return (
            verdict.factual_correctness,
            verdict.evidence_support,
            verdict.authority,
            verdict.cutoff,
            verdict.answerability,
            verdict.alternate_evidence_exists,
            verdict.question_quality,
            decision.label_changed,
        )

    agreement = sum(key(active[left]) == key(active[right]) for left, right in repeated)
    return agreement, len(repeated)


def run_portfolio_demo(root: Path) -> PortfolioDemoSummary:
    """Validate the active 24/16/48 portfolio entirely from tracked bytes."""

    resolved = root.resolve(strict=True)
    manifest = json.loads(
        resolved.joinpath(*ACTIVE_MANIFEST_PATH.parts).read_text(encoding="utf-8")
    )
    if manifest.get("schema_version") != "portfolio-active-corpus-v2":
        raise ValueError("active portfolio manifest version is invalid")
    _manifest_artifacts(resolved, manifest)

    public_cases = _jsonl(
        resolved / "data/benchmark/portfolio-public-cases-v2.jsonl", BenchmarkCase
    )
    challenge_cases = _jsonl(
        resolved / "data/benchmark/challenges/portfolio-challenge-cases-v2.jsonl",
        BenchmarkCase,
    )
    documents = _jsonl(
        resolved / "data/fixtures/portfolio-challenge-documents-v1.jsonl",
        NormalizedDocument,
    )
    results = _jsonl(
        resolved / "reports/portfolio-challenge-slice-v2.jsonl",
        PortfolioChallengeResult,
    )
    if len(public_cases) != 16 or Counter(case.split for case in public_cases) != {
        "dev": 8,
        "validation": 8,
    }:
        raise ValueError("active public family inventory is invalid")
    if len(challenge_cases) != 48 or len(documents) != 128 or len(results) != 16:
        raise ValueError("active matched packet inventory is invalid")
    if any(
        case.should_abstain or len(case.expected_claims) != 1 for case in public_cases
    ):
        raise ValueError("active public portfolio unexpectedly contains abstention")
    target = [
        case
        for case in public_cases
        if case.case_id == "portfolio-yield-cisa-kev-cve-2021-27137"
    ]
    if len(target) != 1 or target[0].expected_claims[0].qualifiers.product != "DD-WRT":
        raise ValueError("active DD-WRT correction is absent")

    case_by_id = {case.case_id: case for case in challenge_cases}
    if len(case_by_id) != 48 or any(
        case.split == "holdout" for case in challenge_cases
    ):
        raise ValueError("matched case identity or split is invalid")
    paired = [case for case in challenge_cases if case.paired_case_id is not None]
    if len(paired) != 32 or any(
        case.paired_case_id not in case_by_id
        or case_by_id[case.paired_case_id].paired_case_id != case.case_id
        for case in paired
    ):
        raise ValueError("matched clean/challenge pairing is invalid")
    if any(
        document.source_name != "synthetic_control"
        or document.fields.get("operational_content") is not False
        for document in documents
    ):
        raise ValueError("challenge documents are not safe synthetic controls")

    recall: Counter[str] = Counter()
    for result in results:
        if result.provider_calls != 0 or len(result.variants) != 3:
            raise ValueError("challenge result provider boundary is invalid")
        ids = {
            "clean": result.clean_case_id,
            "control": result.control_case_id,
            "challenge": result.challenge_case_id,
        }
        for variant in result.variants:
            if variant.relevant_at_k:
                recall[variant.variant] += 1
            if variant.packet_document_count <= variant.retrieval_depth:
                raise ValueError("retrieval packet is trivial at declared top-k")
            if set(case_by_id[ids[variant.variant]].allowed_snapshot_ids) != set(
                variant.packet_snapshot_ids
            ):
                raise ValueError("challenge result does not bind its packet case")
    if recall != {"clean": 16, "control": 16, "challenge": 16}:
        raise ValueError("tracked recall@6 result is incomplete")

    packet_v1 = ReviewPacket.model_validate_json(
        (
            resolved / "annotations/packets/portfolio-dev-validation-review-v1.json"
        ).read_text(encoding="utf-8")
    )
    packet_v2 = ReviewPacket.model_validate_json(
        (
            resolved / "annotations/packets/portfolio-dev-validation-review-v2.json"
        ).read_text(encoding="utf-8")
    )
    decisions = load_jsonl_records(
        resolved
        / "annotations/decisions/portfolio-dev-validation-review-v1-reviewer-a17.jsonl",
        ReviewDecision,
    )
    validation = validate_review_log(
        packet_v1, decisions, [], review_mode="single_reviewer"
    )
    agreement, repeated = _repeatability(packet_v1, decisions)
    if (
        len(packet_v2.items) != 20
        or len({item.case_sha256 for item in packet_v2.items}) != 16
        or validation.active_decision_count != 20
        or validation.unresolved_item_ids
        or len(decisions) != 21
        or (agreement, repeated) != (4, 4)
    ):
        raise ValueError("single-reviewer audit is incomplete")
    terms = packet_v2.source_license_or_terms
    if terms is None or not terms or any(not value.strip() for value in terms.values()):
        raise ValueError("active source terms dispositions are incomplete")

    future = json.loads(
        resolved.joinpath(*FUTURE_CANDIDATE_PATH.parts).read_text(encoding="utf-8")
    )
    isolation = future.get("isolation")
    families = future.get("families")
    if (
        not isinstance(isolation, dict)
        or not isinstance(families, list)
        or len(families) != 8
        or any(value is not False for value in isolation.values())
    ):
        raise ValueError("future candidate metadata is not safely isolated")

    challenge_types = Counter(result.challenge_type for result in results)
    return PortfolioDemoSummary(
        status="evaluated_offline_provider_free",
        inventory_family_count=24,
        public_family_count=16,
        development_family_count=8,
        validation_family_count=8,
        future_candidate_count=8,
        matched_case_count=48,
        challenge_type_counts=tuple(sorted(challenge_types.items())),
        clean_recall_at_6=16,
        control_recall_at_6=16,
        challenge_recall_at_6=16,
        review_item_count=20,
        review_unique_family_count=16,
        active_review_decision_count=20,
        immutable_review_record_count=21,
        repeatability_agreement_count=4,
        repeatability_pair_count=4,
        answerable_public_case_count=16,
        abstention_portfolio_case_count=0,
        abstention_status="not_evaluated",
        source_terms_disposition_count=len(terms),
        provider_calls=0,
        corrected_product="DD-WRT",
    )


def render_portfolio_demo(summary: PortfolioDemoSummary) -> str:
    """Render the publishable provider-free result with exact denominators."""

    challenge_types = ", ".join(
        f"{name} {count}" for name, count in summary.challenge_type_counts
    )
    return (
        "# CTI claim-provenance portfolio demo\n\n"
        "Status: **evaluated offline; provider-free portfolio pilot**. This is "
        "not a model evaluation.\n\n"
        "- Inventory: 24 audited-distinct families: 16 reviewed public families "
        "(8 development, 8 validation) plus 8 metadata-only future evaluation "
        "candidates excluded from every current metric.\n"
        "- Matched evidence-selection cases: 48/48: clean, benign control, and "
        "safe synthetic challenge for each public family.\n"
        f"- Challenge mix: {challenge_types}.\n"
        "- Controlled lexical recall@6: clean 16/16, benign control 16/16, "
        "challenge 16/16. This is a packet/retrieval check, not evidence of "
        "general retrieval robustness.\n"
        "- Single-reviewer gold audit: 20/20 items over 16 unique families; "
        "4/4 exact blinded resurfacing agreement. Intra-rater repeatability "
        "does not establish gold-label correctness.\n"
        "- Portfolio answerability: 16/16 answerable and 0 abstention cases. "
        "Portfolio abstention performance is not evaluated.\n"
        "- Source terms dispositions: "
        f"{summary.source_terms_disposition_count}/"
        f"{summary.source_terms_disposition_count}; provider calls: 0.\n"
        "- The corrected CISA KEV CVE-2021-27137 qualifier is `product=DD-WRT`.\n\n"
        "Publisher-declared version evidence proves what a named publisher "
        "version says and its declared time; it does not prove independently "
        "observed historical availability. The synthetic challenges measure "
        "controlled evidence selection only, not model reasoning, citation "
        "faithfulness, realistic attack prevalence, or adversarial robustness.\n"
    )


def _verify_rebuild_source_cache(root: Path) -> None:
    """Require every hash-bound ignored source input before derivation starts."""

    bindings: dict[str, str] = {}

    def collect(value: object) -> None:
        if isinstance(value, dict):
            for key in ("raw_blob_path", "path"):
                relative = value.get(key)
                expected = value.get("sha256")
                if (
                    isinstance(relative, str)
                    and relative.startswith("data/raw/")
                    and isinstance(expected, str)
                ):
                    previous = bindings.setdefault(relative, expected)
                    if previous != expected:
                        raise ValueError(
                            f"conflicting source-cache hashes for {relative}"
                        )
            for child in value.values():
                collect(child)
        elif isinstance(value, list):
            for child in value:
                collect(child)

    for manifest_path in _REBUILD_MANIFEST_PATHS:
        collect(
            json.loads(root.joinpath(*manifest_path.parts).read_text(encoding="utf-8"))
        )
    missing = [
        relative for relative in sorted(bindings) if not (root / relative).is_file()
    ]
    if missing:
        raise ValueError(
            "full rebuild requires hash-bound ignored source-cache files; "
            f"missing {len(missing)}/{len(bindings)}; first missing: {missing[0]}"
        )
    mismatched = [
        relative
        for relative, expected in sorted(bindings.items())
        if _sha256(root / relative) != expected
    ]
    if mismatched:
        raise ValueError(
            f"full rebuild source-cache hash mismatch; first mismatch: {mismatched[0]}"
        )


def verify_portfolio_full_rebuild(root: Path) -> PortfolioRebuildSummary:
    """Rebuild v2 from exact ignored caches and compare every active derivative."""

    resolved = root.resolve(strict=True)
    _verify_rebuild_source_cache(resolved)
    bundle = run_portfolio_challenge_slice(resolved, correction_version="v2")
    packet, _manifest = build_portfolio_review_packet(resolved, correction_version="v2")
    outputs = {
        "data/benchmark/portfolio-public-cases-v2.jsonl": (
            render_portfolio_public_cases(resolved, correction_version="v2")
        ),
        "data/benchmark/challenges/portfolio-challenge-cases-v2.jsonl": (
            render_portfolio_challenge_cases(bundle)
        ),
        "reports/portfolio-challenge-slice-v2.jsonl": (
            render_portfolio_challenge_jsonl(bundle)
        ),
        "reports/portfolio-challenge-slice-v2.md": (
            render_portfolio_challenge_report(bundle)
        ),
        "annotations/packets/portfolio-dev-validation-review-v2.json": (
            render_review_packet(packet)
        ),
    }
    for relative, rendered in outputs.items():
        path = resolved / relative
        if not path.is_file() or path.read_text(encoding="utf-8") != rendered:
            raise ValueError(
                f"full rebuild differs from tracked v2 artifact: {relative}"
            )
    yield_results = run_portfolio_yield_slice(resolved, correction_version="v2")
    if len(yield_results) != 4 or any(
        any(
            grade.value_match != "exact" or grade.claim_support != "supported"
            for grade in result.grades
        )
        for result in yield_results
    ):
        raise ValueError("full rebuild scripted oracle is not exact and supported")
    return PortfolioRebuildSummary(
        public_case_count=16,
        matched_case_count=48,
        challenge_result_count=16,
        review_item_count=20,
        yield_case_count=4,
    )


def candidate_paths(root: Path) -> list[Path]:
    """Return tracked and unignored untracked paths without reading ignored data."""

    completed = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=root,
        check=True,
        capture_output=True,
    )
    paths: list[Path] = []
    for raw in completed.stdout.split(b"\0"):
        if not raw:
            continue
        relative = Path(raw.decode("utf-8"))
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError("Git returned a candidate path outside the repository")
        path = root / relative
        if path.exists() or path.is_symlink():
            paths.append(path)
    return sorted(paths)


def scan_text(path: Path, text: str) -> list[Finding]:
    """Find possible secrets while returning locations, never matched values."""

    findings: list[Finding] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        for pattern in SECRET_PATTERNS:
            if pattern.regex.search(line):
                findings.append(Finding(path, line_number, pattern.name))
    return findings


def _is_link_like(path: Path) -> bool:
    if path.is_symlink():
        return True
    is_junction = getattr(path, "is_junction", None)
    return bool(is_junction is not None and is_junction())


def scan_file(path: Path) -> tuple[list[Finding], ManualReview | None]:
    """Scan one regular UTF-8 text file, failing closed for other file forms."""

    if _is_link_like(path):
        return [], ManualReview(path, "link-or-junction")
    try:
        if not path.is_file():
            return [], ManualReview(path, "not-a-regular-file")
        if path.stat().st_size > MAX_TEXT_FILE_BYTES:
            return [], ManualReview(path, "oversized")
        data = path.read_bytes()
    except OSError:
        return [], ManualReview(path, "unreadable")
    if b"\0" in data:
        return [], ManualReview(path, "binary-or-nul")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [], ManualReview(path, "non-utf8")
    return scan_text(path, text), None


def scan_repository(root: Path) -> tuple[list[Finding], list[ManualReview]]:
    """Scan candidate files and fail closed when a candidate is unscannable."""

    resolved = root.resolve(strict=True)
    findings: list[Finding] = []
    manual_reviews: list[ManualReview] = []
    for path in candidate_paths(resolved):
        relative = path.relative_to(resolved)
        current = resolved
        if any(_is_link_like(current := current / part) for part in relative.parts):
            manual_reviews.append(ManualReview(path, "link-or-junction"))
            continue
        path_findings, manual_review = scan_file(path)
        findings.extend(path_findings)
        if manual_review is not None:
            manual_reviews.append(manual_review)
    return findings, manual_reviews


def _candidate_relative_paths(root: Path) -> list[PurePosixPath]:
    """Return repository-relative tracked and unignored untracked candidates."""

    return [
        PurePosixPath(path.relative_to(root).as_posix())
        for path in candidate_paths(root)
    ]


def _text_candidates(root: Path, paths: list[PurePosixPath]) -> dict[str, str]:
    values: dict[str, str] = {}
    for relative in paths:
        path = root.joinpath(*relative.parts)
        if not path.is_file():
            continue
        if path.stat().st_size > MAX_TEXT_FILE_BYTES:
            continue
        try:
            values[relative.as_posix()] = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
    return values


def _broken_markdown_links(root: Path, texts: dict[str, str]) -> list[str]:
    pattern = re.compile(r"(?<!!)\[[^\]]+\]\(([^)]+)\)")
    broken: list[str] = []
    for relative, body in texts.items():
        if not relative.endswith(".md"):
            continue
        parent = root / PurePosixPath(relative).parent
        for match in pattern.finditer(body):
            raw = match.group(1).strip()
            if raw.startswith(("http://", "https://", "mailto:", "#")):
                continue
            target = raw.split("#", 1)[0].strip("<>")
            if target and not (parent / target).exists():
                line = body.count("\n", 0, match.start()) + 1
                broken.append(f"{relative}:{line}")
    return broken


def _forbidden_artifact_paths(paths: list[PurePosixPath]) -> list[str]:
    prefixes = (
        "data/raw/",
        "artifacts/private/",
        "artifacts/diagnostic-quarantine/",
        "artifacts/quarantine/",
        "artifacts/provider/",
        "data/benchmark/holdout",
        "data/holdout/",
    )
    return [path.as_posix() for path in paths if path.as_posix().startswith(prefixes)]


def _nonportable_text_paths(texts: dict[str, str]) -> list[str]:
    windows_user_root = re.compile(r"[A-Za-z]:\\" + "Users" + r"\\")
    posix_user_roots = ("/" + "Users/", "/" + "home/")
    return [
        relative
        for relative, body in texts.items()
        if windows_user_root.search(body)
        or any(root_marker in body for root_marker in posix_user_roots)
    ]


def _personal_email_paths(texts: dict[str, str]) -> list[str]:
    return [
        relative
        for relative, body in texts.items()
        if _PERSONAL_EMAIL in body.casefold()
    ]


def run_portfolio_release_readiness(root: Path) -> PortfolioReleaseReadiness:
    """Run automated public-candidate checks and isolate two user decisions."""

    resolved = root.resolve(strict=True)
    summary = run_portfolio_demo(resolved)
    checks: list[ReleaseCheck] = []

    expected_demo = render_portfolio_demo(summary)
    demo_path = resolved.joinpath(*DEMO_REPORT_PATH.parts)
    checks.append(
        ReleaseCheck(
            name="clean_checkout_demo",
            passed=demo_path.is_file()
            and demo_path.read_text(encoding="utf-8") == expected_demo,
            detail=(
                "tracked provider-free 24/16/48 summary matches deterministic output"
            ),
        )
    )

    secret_findings, manual_reviews = scan_repository(resolved)
    checks.append(
        ReleaseCheck(
            name="candidate_secret_scan",
            passed=not secret_findings and not manual_reviews,
            detail=(
                "no candidate credential patterns or unscannable files"
                if not secret_findings and not manual_reviews
                else "candidate tree contains a secret finding or unscannable file"
            ),
        )
    )

    paths = _candidate_relative_paths(resolved)
    forbidden = _forbidden_artifact_paths(paths)
    checks.append(
        ReleaseCheck(
            name="forbidden_artifact_paths",
            passed=not forbidden,
            detail=(
                "no candidate raw, private, quarantine, provider, or protected "
                "evaluation paths"
                if not forbidden
                else "candidate forbidden artifact path exists"
            ),
        )
    )

    texts = _text_candidates(resolved, paths)
    absolute_paths = _nonportable_text_paths(texts)
    checks.append(
        ReleaseCheck(
            name="portable_candidate_text",
            passed=not absolute_paths,
            detail=(
                "no user-specific absolute path appears in candidate text"
                if not absolute_paths
                else "user-specific absolute path appears in candidate text"
            ),
        )
    )
    current_email = _personal_email_paths(texts)
    checks.append(
        ReleaseCheck(
            name="personal_email_in_candidate_files",
            passed=not current_email,
            detail=(
                "personal author email absent from current candidate files"
                if not current_email
                else "personal author email appears in current candidate files"
            ),
        )
    )

    broken_links = _broken_markdown_links(resolved, texts)
    checks.append(
        ReleaseCheck(
            name="internal_markdown_links",
            passed=not broken_links,
            detail=(
                "all candidate Markdown local links resolve"
                if not broken_links
                else "candidate Markdown contains a broken local link"
            ),
        )
    )

    packet = ReviewPacket.model_validate_json(
        texts["annotations/packets/portfolio-dev-validation-review-v2.json"]
    )
    terms = packet.source_license_or_terms or {}
    checks.append(
        ReleaseCheck(
            name="source_terms_dispositions",
            passed=len(terms) == summary.source_terms_disposition_count
            and all(value.strip() for value in terms.values()),
            detail=(
                f"{len(terms)}/{len(terms)} active snapshot dispositions are nonempty"
            ),
        )
    )

    workflow = texts.get(".github/workflows/ci.yml", "")
    required_ci = (
        "ruff format --check",
        "ruff check",
        "mypy",
        "schema check",
        "config check",
        "pytest",
        "portfolio-demo",
        "portfolio-release-check",
        "uv build",
    )
    missing_ci = [value for value in required_ci if value not in workflow]
    checks.append(
        ReleaseCheck(
            name="dual_platform_ci_contract",
            passed="ubuntu-latest" in workflow
            and "windows-latest" in workflow
            and not missing_ci,
            detail=(
                "Ubuntu/Windows workflow contains the full release-candidate gate"
                if not missing_ci
                else "CI workflow lacks a required release-candidate step"
            ),
        )
    )

    license_path = resolved / "LICENSE"
    checks.append(
        ReleaseCheck(
            name="apache_2_license",
            passed=license_path.is_file()
            and "Apache License" in license_path.read_text(encoding="utf-8"),
            detail="Apache-2.0 license is tracked for project-authored material only",
        )
    )
    user_decisions = (
        (
            "Choose the public-history/visibility strategy. Private main history "
            "contains a personal Gmail author address; the recommended default is "
            "a sanitized single-commit export authored with the GitHub noreply "
            "address."
        ),
    )
    return PortfolioReleaseReadiness(
        status="ready_for_user_decisions"
        if all(check.passed for check in checks)
        else "failed",
        checks=tuple(checks),
        user_decisions=user_decisions,
    )


def render_portfolio_release_readiness(
    readiness: PortfolioReleaseReadiness,
) -> str:
    """Render automated checks separately from the two user decisions."""

    checks = "\n".join(
        f"- {'PASS' if check.passed else 'FAIL'} — `{check.name}`: {check.detail}."
        for check in readiness.checks
    )
    decisions = "\n".join(
        f"{index}. {value}" for index, value in enumerate(readiness.user_decisions, 1)
    )
    return (
        "# Portfolio release readiness\n\n"
        f"Status: **{readiness.status}**. The repository remains private.\n\n"
        "## Automated checks\n\n"
        f"{checks}\n\n"
        "## Remaining user decisions\n\n"
        f"{decisions}\n\n"
        "No visibility change, history rewrite, license choice, tag, or release "
        "is performed by this check.\n"
    )
