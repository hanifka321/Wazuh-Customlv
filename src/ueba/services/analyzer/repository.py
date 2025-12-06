from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Sequence, Tuple, TYPE_CHECKING

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ueba.db.models import Entity, EntityRiskHistory, NormalizedEvent
from ueba.services.mapper.utils import is_entity_excluded

if TYPE_CHECKING:  # pragma: no cover
    from .pipeline import AnalyzerResult

UTC = timezone.utc


def ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def window_bounds(observed_at: datetime) -> Tuple[datetime, datetime]:
    observed_utc = ensure_utc(observed_at)
    start = observed_utc.replace(hour=0, minute=0, second=0, microsecond=0)
    return start, start + timedelta(days=1)


@dataclass(frozen=True)
class EntityEventWindow:
    entity_id: int
    window_start: datetime
    window_end: datetime
    events: Sequence[NormalizedEvent]


class AnalyzerRepository:
    """Encapsulates analyzer-specific read/write operations."""

    REASON_GENERATOR = "analyzer_service"
    REASON_KIND = "daily_rollup"

    def __init__(self, session: Session, excluded_entities: Optional[Sequence[str]] = None):
        self.session = session
        self._excluded_entities = list(excluded_entities or [])

    # ------------------------------------------------------------------
    # Normalized event queries
    # ------------------------------------------------------------------
    def fetch_entity_event_windows(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> List[EntityEventWindow]:
        stmt = (
            select(NormalizedEvent, Entity.entity_value)
            .join(Entity, Entity.id == NormalizedEvent.entity_id)
            .where(
                NormalizedEvent.entity_id.is_not(None),
                NormalizedEvent.deleted_at.is_(None),
                NormalizedEvent.status == "active",
                Entity.deleted_at.is_(None),
                Entity.status == "active",
            )
        )

        if since is not None:
            stmt = stmt.where(NormalizedEvent.observed_at >= ensure_utc(since))
        if until is not None:
            stmt = stmt.where(NormalizedEvent.observed_at < ensure_utc(until))

        stmt = stmt.order_by(NormalizedEvent.entity_id, NormalizedEvent.observed_at)

        rows = self.session.execute(stmt).all()
        grouped: Dict[Tuple[int, datetime], List[NormalizedEvent]] = {}
        exclusion_cache: Dict[int, bool] = {}

        for event, entity_value in rows:
            if event.entity_id is None:
                continue

            entity_id = event.entity_id
            if entity_id not in exclusion_cache:
                exclusion_cache[entity_id] = self._is_entity_value_excluded(entity_value)

            if exclusion_cache[entity_id]:
                continue

            start, _ = window_bounds(event.observed_at)
            key = (entity_id, start)
            grouped.setdefault(key, [])
            grouped[key].append(event)

        windows = [
            EntityEventWindow(
                entity_id=entity_id,
                window_start=window_start,
                window_end=window_start + timedelta(days=1),
                events=grouped[(entity_id, window_start)],
            )
            for (entity_id, window_start) in sorted(
                grouped.keys(), key=lambda item: (item[0], item[1])
            )
        ]

        return windows

    def _is_entity_value_excluded(self, entity_value: str) -> bool:
        """Check if an entity value matches any exclusion patterns."""
        return is_entity_excluded(entity_value, self._excluded_entities)

    # ------------------------------------------------------------------
    # Entity risk history helpers
    # ------------------------------------------------------------------
    def persist_result(self, result: "AnalyzerResult") -> EntityRiskHistory:
        payload = {
            "generator": self.REASON_GENERATOR,
            "kind": self.REASON_KIND,
            "window_start": result.window_start.isoformat(),
            "window_end": result.window_end.isoformat(),
            "event_count": result.features.event_count,
            "highest_severity": result.features.highest_severity,
            "last_observed_at": result.features.last_observed_at.isoformat(),
            "rules": {
                "triggered": result.rule_evaluation.triggered_rules,
                "metadata": result.rule_evaluation.metadata,
            },
            "baseline": {
                "avg": result.baseline_avg,
                "sigma": result.baseline_sigma,
                "delta": result.delta,
                "is_anomalous": result.is_anomalous,
            },
        }
        reason = json.dumps(payload, sort_keys=True)

        existing = self._find_history(result.entity_id, result.window_end)
        if existing:
            existing.risk_score = result.risk_score
            existing.reason = reason
            return existing

        history = EntityRiskHistory(
            entity_id=result.entity_id,
            normalized_event_id=None,
            risk_score=result.risk_score,
            observed_at=result.window_end,
            reason=reason,
        )
        self.session.add(history)
        return history

    def latest_history_for_entity(self, entity_id: int) -> Optional[EntityRiskHistory]:
        stmt = (
            select(EntityRiskHistory)
            .where(
                EntityRiskHistory.entity_id == entity_id,
                EntityRiskHistory.deleted_at.is_(None),
            )
            .order_by(EntityRiskHistory.observed_at.desc())
            .limit(1)
        )
        return self.session.execute(stmt).scalar_one_or_none()

    def _find_history(self, entity_id: int, observed_at: datetime) -> Optional[EntityRiskHistory]:
        stmt = select(EntityRiskHistory).where(
            EntityRiskHistory.entity_id == entity_id,
            EntityRiskHistory.observed_at == ensure_utc(observed_at),
            EntityRiskHistory.deleted_at.is_(None),
        )
        return self.session.execute(stmt).scalar_one_or_none()

    # ------------------------------------------------------------------
    # Checkpoint helpers
    # ------------------------------------------------------------------
    def get_latest_checkpoint(self) -> Optional[datetime]:
        stmt = select(func.max(EntityRiskHistory.observed_at)).where(
            EntityRiskHistory.reason.is_not(None),
            EntityRiskHistory.reason.contains(f'"generator": "{self.REASON_GENERATOR}"'),
        )
        checkpoint = self.session.execute(stmt).scalar_one_or_none()
        return ensure_utc(checkpoint) if checkpoint is not None else None
