"""Experiment contracts with cycle-safe lazy convenience exports."""

from __future__ import annotations

from typing import TYPE_CHECKING

from cti_provenance.experiments.ledger import RunRecord

if TYPE_CHECKING:
    from cti_provenance.experiments.real_reports import render_real_offline_report
    from cti_provenance.experiments.real_runner import (
        render_real_results_jsonl,
        run_real_offline_slice,
    )
    from cti_provenance.experiments.reports import render_offline_report
    from cti_provenance.experiments.runner import (
        OfflineCaseResult,
        SliceRunError,
        render_results_jsonl,
        run_offline_slice,
    )
    from cti_provenance.experiments.three_family_runner import (
        render_three_family_jsonl,
        render_three_family_report,
        run_three_family_slice,
    )

_RUNNER_EXPORTS = {
    "OfflineCaseResult",
    "SliceRunError",
    "render_results_jsonl",
    "run_offline_slice",
}
_REAL_RUNNER_EXPORTS = {"render_real_results_jsonl", "run_real_offline_slice"}
_THREE_FAMILY_EXPORTS = {
    "render_three_family_jsonl",
    "render_three_family_report",
    "run_three_family_slice",
}


def __getattr__(name: str) -> object:
    """Avoid importing dataset-dependent runners during package initialization."""

    if name in _RUNNER_EXPORTS:
        from cti_provenance.experiments import runner

        return getattr(runner, name)
    if name in _REAL_RUNNER_EXPORTS:
        from cti_provenance.experiments import real_runner

        return getattr(real_runner, name)
    if name in _THREE_FAMILY_EXPORTS:
        from cti_provenance.experiments import three_family_runner

        return getattr(three_family_runner, name)
    if name == "render_offline_report":
        from cti_provenance.experiments.reports import render_offline_report

        return render_offline_report
    if name == "render_real_offline_report":
        from cti_provenance.experiments.real_reports import render_real_offline_report

        return render_real_offline_report
    raise AttributeError(name)


__all__ = [
    "OfflineCaseResult",
    "RunRecord",
    "SliceRunError",
    "render_offline_report",
    "render_real_offline_report",
    "render_real_results_jsonl",
    "render_results_jsonl",
    "render_three_family_jsonl",
    "render_three_family_report",
    "run_offline_slice",
    "run_real_offline_slice",
    "run_three_family_slice",
]
