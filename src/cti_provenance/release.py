"""Integrity checks for the public-facing benchmark bundle."""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

EXPECTED_SLICE_COUNTS = {
    "single_source_extraction": 16,
    "temporal_comparison": 24,
    "cutoff_or_insufficiency_abstention": 8,
    "authority_divergence": 8,
    "multi_source_synthesis": 8,
}
EXPECTED_CONDITION_COUNTS = {
    "citation_prompted": {
        "n": 96,
        "evidence_binding_correct": 80,
        "exact_answer_correct": 32,
        "correct_abstention": 7,
        "expected_abstention": 8,
    },
    "claim_evidence_constrained": {
        "n": 96,
        "evidence_binding_correct": 83,
        "exact_answer_correct": 25,
        "correct_abstention": 6,
        "expected_abstention": 8,
    },
}
EXPECTED_VARIANT_COUNTS = {"clean": 64, "control": 16, "challenge": 16}
EXPECTED_HEADLINE = {
    "citation_prompted": {
        "n": 96,
        "provenance_correct": 80,
        "exact_correct": 32,
        "correct_abstentions": 7,
        "expected_abstentions": 8,
    },
    "claim_evidence_constrained": {
        "n": 96,
        "provenance_correct": 83,
        "exact_correct": 25,
        "correct_abstentions": 6,
        "expected_abstentions": 8,
    },
}
HEX64 = re.compile(r"^[0-9a-f]{64}$")
PERSONAL_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+@(?:gmail|hotmail|outlook|yahoo)\.com\b",
    re.IGNORECASE,
)
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"),
    re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\b(?:github_pat_[A-Za-z0-9_]{20,}|gh[pousr]_[A-Za-z0-9]{20,})\b"),
    re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
)
STALE_RELEASE_MARKERS = (
    "portfolio-diverse",
    "portfolio-proof",
    "portfolio-scale",
    "portfolio-yield",
    "portfolio-minimum",
    "phase2",
    "manager-audit",
    "provider preflight",
    "cost accounting",
    "token usage",
    "latency",
    "predecessor",
    "retained v",
)
TEXT_SUFFIXES = {".md", ".py", ".toml", ".yml", ".yaml", ".json", ".jsonl", ".txt"}


@dataclass(frozen=True)
class Check:
    name: str
    passed: bool
    detail: str


@dataclass(frozen=True)
class ReleaseCheckResult:
    checks: tuple[Check, ...]

    @property
    def passed(self) -> bool:
        return all(check.passed for check in self.checks)

    def render(self) -> str:
        status = "release_ready" if self.passed else "failed"
        lines = [f"release check: {status}"]
        for check in self.checks:
            prefix = "PASS" if check.passed else "FAIL"
            lines.append(f"{prefix} {check.name}: {check.detail}")
        return "\n".join(lines)


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for index, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        value = json.loads(line)
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{index} must contain a JSON object")
        records.append(value)
    return records


def _is_iso_utc(value: object) -> bool:
    if not isinstance(value, str) or not value.endswith("Z"):
        return False
    return "T" in value and len(value) >= len("2021-01-01T00:00:00Z")


def _check_corpus(root: Path) -> Check:
    corpus = _load_json(root / "data/benchmark/questions.json")
    questions = corpus.get("questions")
    if corpus.get("schema_version") != "cti-question-corpus-v1":
        return Check("corpus", False, "unexpected corpus schema")
    if not isinstance(questions, list) or len(questions) != 64:
        return Check("corpus", False, "expected exactly 64 questions")

    case_ids: set[str] = set()
    dependency_by_split: dict[str, set[str]] = defaultdict(set)
    evidence_ids: set[str] = set()
    source_hashes = 0
    for question in questions:
        if not isinstance(question, dict):
            return Check("corpus", False, "question entry is not an object")
        case_id = question.get("case_id")
        split = question.get("split")
        dependency_id = question.get("dependency_id")
        if not isinstance(case_id, str) or case_id in case_ids:
            return Check("corpus", False, "case IDs are missing or duplicated")
        if split not in {"dev", "validation"} or not isinstance(dependency_id, str):
            return Check("corpus", False, f"{case_id} has invalid split metadata")
        if not _is_iso_utc(question.get("cutoff_utc")):
            return Check("corpus", False, f"{case_id} has invalid cutoff")
        case_ids.add(case_id)
        dependency_by_split[split].add(dependency_id)
        for evidence in question.get("evidence", []):
            if not isinstance(evidence, dict):
                return Check("corpus", False, f"{case_id} has invalid evidence")
            evidence_id = evidence.get("evidence_id")
            source_sha = evidence.get("source_sha256")
            text_sha = evidence.get("text_sha256")
            if not isinstance(evidence_id, str) or evidence_id in evidence_ids:
                return Check("corpus", False, "evidence IDs are missing or duplicated")
            if not isinstance(source_sha, str) or not HEX64.match(source_sha):
                return Check("corpus", False, f"{evidence_id} has invalid source hash")
            if not isinstance(text_sha, str) or not HEX64.match(text_sha):
                return Check("corpus", False, f"{evidence_id} has invalid text hash")
            if not _is_iso_utc(evidence.get("source_available_by_utc")):
                return Check("corpus", False, f"{evidence_id} has invalid date")
            evidence_ids.add(evidence_id)
            source_hashes += 1

    split_overlap = dependency_by_split["dev"] & dependency_by_split["validation"]
    slice_counts = Counter(q.get("slice") for q in questions)
    dependency_count = len({q.get("dependency_id") for q in questions})
    ok = (
        dict(slice_counts) == EXPECTED_SLICE_COUNTS
        and dependency_count == 24
        and not split_overlap
        and source_hashes > 0
    )
    detail = (
        "64 questions, 24 dependency groups, expected slice counts, disjoint splits"
        if ok
        else "corpus counts or split isolation do not match the release design"
    )
    return Check("corpus", ok, detail)


def _check_packets(root: Path) -> Check:
    corpus = _load_json(root / "data/benchmark/questions.json")
    packets = _load_json(root / "data/benchmark/evidence-packets.json")
    cases = {q["case_id"] for q in corpus["questions"]}
    packet_rows = packets.get("packets")
    if packets.get("schema_version") != "cti-evidence-packets-v1":
        return Check("evidence_packets", False, "unexpected packet schema")
    if not isinstance(packet_rows, list) or len(packet_rows) != 64:
        return Check("evidence_packets", False, "expected exactly 64 packets")
    packet_cases = {row.get("case_id") for row in packet_rows if isinstance(row, dict)}
    packet_ids = {row.get("packet_id") for row in packet_rows if isinstance(row, dict)}
    expected_ids = {f"packet-{case_id}" for case_id in cases}
    if packet_cases != cases or packet_ids != expected_ids:
        return Check("evidence_packets", False, "packets do not match corpus cases")
    leaked_path = [
        row.get("case_id")
        for row in packet_rows
        if isinstance(row, dict)
        and "data/raw/" in json.dumps(row, sort_keys=True, ensure_ascii=False)
    ]
    if leaked_path:
        return Check("evidence_packets", False, "candidate packet exposes local paths")
    return Check("evidence_packets", True, "64 neutral packets match the corpus")


def _check_human_review(root: Path) -> Check:
    review = _load_json(root / "annotations/human-review.json")
    ok = (
        review.get("schema_version") == "cti-human-review-v1"
        and review.get("status") == "complete"
        and review.get("review_mode") == "single_reviewer"
        and review.get("reviewer_count") == 1
        and review.get("reviewed_question_count") == 64
        and review.get("unresolved_question_count") == 0
    )
    return Check(
        "human_review",
        ok,
        "single-reviewer calibration complete for all 64 questions"
        if ok
        else "human review summary is incomplete",
    )


def _cell_metric(records: list[dict[str, Any]], key: str) -> int:
    return sum(1 for record in records if record.get(key) is True)


def _check_results(root: Path) -> Check:
    cells = _load_jsonl(root / "reports/evaluation-cells.jsonl")
    summary = _load_json(root / "reports/evaluation-summary.json")
    if len(cells) != 192:
        return Check("results", False, "expected exactly 192 evaluation cells")
    if summary.get("schema_version") != "cti-evaluation-summary-v1":
        return Check("results", False, "unexpected summary schema")
    ordinals: list[int] = []
    for cell in cells:
        ordinal = cell.get("ordinal")
        if not isinstance(ordinal, int):
            return Check("results", False, "result ordinals must be integers")
        ordinals.append(ordinal)
    if sorted(ordinals) != list(range(192)):
        return Check("results", False, "result ordinals are not complete")
    if len({cell.get("cell_id") for cell in cells}) != 192:
        return Check("results", False, "cell IDs are not unique")

    by_condition = defaultdict(list)
    for cell in cells:
        if cell.get("schema_version") != "cti-evaluation-cell-v1":
            return Check("results", False, "unexpected cell schema")
        if (
            cell.get("result_kind") != "completed"
            or cell.get("parse_status") != "valid"
        ):
            return Check("results", False, "all published cells must be valid")
        by_condition[cell.get("condition")].append(cell)
    for condition, expected in EXPECTED_CONDITION_COUNTS.items():
        condition_cells = by_condition.get(condition, [])
        computed = {
            "n": len(condition_cells),
            "evidence_binding_correct": _cell_metric(
                condition_cells, "evidence_binding_correct"
            ),
            "exact_answer_correct": _cell_metric(
                condition_cells, "exact_answer_correct"
            ),
            "correct_abstention": _cell_metric(condition_cells, "correct_abstention"),
            "expected_abstention": _cell_metric(condition_cells, "expected_abstention"),
        }
        if computed != expected:
            return Check("results", False, f"{condition} aggregate mismatch")
        summary_row = summary.get("by_condition", {}).get(condition, {})
        for source, target in EXPECTED_HEADLINE[condition].items():
            if summary_row.get(source) != target:
                return Check("results", False, f"{condition} summary mismatch")
        variants = Counter(cell.get("variant") for cell in condition_cells)
        if dict(variants) != EXPECTED_VARIANT_COUNTS:
            return Check("results", False, f"{condition} variant counts mismatch")
    return Check(
        "results",
        True,
        "192 cells recompute to the documented condition-level findings",
    )


def _text_files(root: Path) -> dict[Path, str]:
    texts: dict[Path, str] = {}
    ignored_parts = {".git", ".venv", ".mypy_cache", ".pytest_cache", ".ruff_cache"}
    for path in root.rglob("*"):
        if not path.is_file() or any(part in ignored_parts for part in path.parts):
            continue
        if path.suffix.lower() in TEXT_SUFFIXES:
            texts[path.relative_to(root)] = path.read_text(encoding="utf-8")
    return texts


def _check_release_hygiene(root: Path) -> Check:
    texts = _text_files(root)
    problems: list[str] = []
    for relative, text in texts.items():
        lowered = text.lower()
        if PERSONAL_EMAIL.search(text):
            problems.append(f"{relative}: personal email")
        if any(pattern.search(text) for pattern in SECRET_PATTERNS):
            problems.append(f"{relative}: secret-like token")
        if relative != Path("src/cti_provenance/release.py") and (
            "codex://" in lowered or "source_thread_id" in lowered
        ):
            problems.append(f"{relative}: internal task metadata")
        if relative.parts and relative.parts[0] in {"README.md", "docs", "reports"}:
            for marker in STALE_RELEASE_MARKERS:
                if marker in lowered:
                    problems.append(f"{relative}: stale marker {marker}")
                    break
    return Check(
        "release_hygiene",
        not problems,
        "no secrets, personal email, internal task IDs, or old-version prose"
        if not problems
        else problems[0],
    )


def _check_docs(root: Path) -> Check:
    required = [
        root / "README.md",
        root / "docs/methodology.md",
        root / "reports/evaluation-results.md",
        root / "THIRD_PARTY_NOTICES.md",
        root / "LICENSE",
    ]
    missing = [path.name for path in required if not path.is_file()]
    if missing:
        return Check("docs", False, f"missing {missing[0]}")
    readme = (root / "README.md").read_text(encoding="utf-8")
    required_phrases = (
        "64 reviewed questions",
        "24 source/dependency groups",
        "Evidence binding",
        "Exact answer",
        "cti-provenance release-check",
    )
    if any(phrase not in readme for phrase in required_phrases):
        return Check("docs", False, "README is missing a required project summary")
    return Check(
        "docs", True, "README, methodology, results, license, and notices exist"
    )


def run_release_check(root: Path) -> ReleaseCheckResult:
    resolved = root.resolve(strict=True)
    checks = (
        _check_corpus(resolved),
        _check_packets(resolved),
        _check_human_review(resolved),
        _check_results(resolved),
        _check_docs(resolved),
        _check_release_hygiene(resolved),
    )
    return ReleaseCheckResult(checks=checks)
