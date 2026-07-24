"""Additive V6 contracts for approved corrections and five safe replacements."""

from __future__ import annotations

from typing import Literal

from pydantic import ConfigDict, Field

from cti_provenance.claims.diverse_portfolio_v4 import ReviewItemV4, ReviewPacketV4
from cti_provenance.claims.diverse_portfolio_v5 import (
    DiverseCorpusV5,
    PacketIndexV5,
)


class DiverseCorpusV6(DiverseCorpusV5):
    """V5 successor whose only semantic changes are the approved corrections."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["portfolio-diverse-draft-v6"]  # type: ignore[assignment]
    corpus_id: Literal["portfolio-diverse-v6-human-reviewed-candidate"]  # type: ignore[assignment]


class PacketIndexV6(PacketIndexV5):
    """Clean candidate packets regenerated from the corrected V6 corpus."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["portfolio-diverse-packets-v6"]  # type: ignore[assignment]


class ReviewPacketV6(ReviewPacketV4):
    """Compact human gate for only the five egress-safe replacements."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    schema_version: Literal["review-packet-v4"]  # type: ignore[assignment]
    packet_id: Literal[  # type: ignore[assignment]
        "portfolio-diverse-v6-egress-replacements-review"
    ]
    status: Literal["human_review_open"]  # type: ignore[assignment]
    items: list[ReviewItemV4] = Field(min_length=5, max_length=5)
