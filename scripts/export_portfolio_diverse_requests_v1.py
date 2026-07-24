"""Export exact frozen provider requests to an isolated private run directory."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

from cti_provenance.claims.diverse_portfolio_v4 import canonical_sha256
from cti_provenance.experiments.portfolio_diverse_provider import (
    PortfolioProviderPlan,
    PortfolioProviderSlot,
    build_portfolio_request,
)

ROOT = Path(__file__).resolve().parents[1]


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--private-root", type=Path, required=True)
    args = parser.parse_args()
    private_root = args.private_root.resolve()
    if (
        ROOT.resolve() in private_root.parents
        or "onedrive" in str(private_root).casefold()
    ):
        raise ValueError("request export must remain outside repo and OneDrive")
    plan = PortfolioProviderPlan.model_validate_json(
        (ROOT / "configs/experiments/portfolio-diverse-v6-openai-luna.json").read_text(
            encoding="utf-8"
        )
    )
    if plan.status != "ready_for_execution" or plan.egress_blocked_case_ids:
        raise ValueError("provider plan is not ready")
    schedule = json.loads(
        (ROOT / "data/benchmark/portfolio-diverse-provider-schedule-v1.json").read_text(
            encoding="utf-8"
        )
    )
    if schedule["schedule_sha256"] != plan.schedule_sha256:
        raise ValueError("plan and schedule differ")
    request_dir = private_root / "requests"
    response_dir = private_root / "responses"
    request_dir.mkdir(parents=True, exist_ok=True)
    response_dir.mkdir(parents=True, exist_ok=True)
    rows: list[dict[str, object]] = []
    for raw in schedule["slots"]:
        slot = PortfolioProviderSlot.model_validate(raw)
        request, packet = build_portfolio_request(root=ROOT, slot=slot)
        body = _canonical_bytes(request.payload())
        if hashlib.sha256(body).hexdigest() != slot.request_semantic_sha256:
            raise ValueError("request payload differs from frozen semantic hash")
        if packet["packet_sha256"] != slot.input_binding_sha256:
            raise ValueError("candidate packet differs from frozen input binding")
        request_path = request_dir / f"{slot.ordinal:03d}-{slot.slot_id}.json"
        if request_path.exists() and request_path.read_bytes() != body:
            raise ValueError("existing private request differs")
        request_path.write_bytes(body)
        rows.append(
            {
                "ordinal": slot.ordinal,
                "slot_id": slot.slot_id,
                "request_path": request_path.as_posix(),
                "request_sha256": slot.request_semantic_sha256,
                "response_path": (
                    response_dir / f"{slot.ordinal:03d}-{slot.slot_id}.json"
                ).as_posix(),
                "metadata_path": (
                    response_dir / f"{slot.ordinal:03d}-{slot.slot_id}.meta.json"
                ).as_posix(),
            }
        )
    manifest = {
        "schema_version": "portfolio-diverse-private-request-export-v1",
        "plan_semantic_digest": plan.semantic_digest,
        "schedule_sha256": plan.schedule_sha256,
        "planned_calls": len(rows),
        "rows": rows,
    }
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    (private_root / "request-manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    print(f"{len(rows)} requests {manifest['manifest_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
