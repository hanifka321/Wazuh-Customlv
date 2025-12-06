from __future__ import annotations

import logging
import time
from datetime import datetime, timezone
from typing import List, Optional, Sequence

from ueba.config.mapping_loader import MappingLoaderError, load as load_mappings
from ueba.db.base import get_session_factory
from ueba.logging import AlertLogger

from .pipeline import AnalyzerPipeline
from .repository import AnalyzerRepository
from .baseline import BaselineCalculator

logger = logging.getLogger(__name__)


def default_until() -> datetime:
    """Default end time is start of current UTC day (exclusive)."""
    now = datetime.now(timezone.utc)
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


class AnalyzerService:
    """Service that processes normalized events into entity risk history."""

    def __init__(
        self,
        session_factory=None,
        pipeline: Optional[AnalyzerPipeline] = None,
        alert_logger: Optional[AlertLogger] = None,
        excluded_entities: Optional[Sequence[str]] = None,
    ):
        self.session_factory = session_factory or get_session_factory()
        self.pipeline = pipeline or AnalyzerPipeline()
        self.alert_logger = alert_logger or AlertLogger()
        if excluded_entities is not None:
            self._excluded_entities = list(excluded_entities)
        else:
            self._excluded_entities = self._load_excluded_entities_from_mapping()

    def _load_excluded_entities_from_mapping(self) -> List[str]:
        """Load excluded entities from mapping configuration."""
        try:
            resolver = load_mappings()
            return resolver.get_excluded_entities()
        except MappingLoaderError:
            logger.warning("Could not load mapping configuration for excluded entities")
            return []

    def run_once(
        self,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> int:
        """Process events once and return number of processed windows."""
        processed = 0
        until = until or default_until()

        with self.session_factory() as session:
            repository = AnalyzerRepository(session, excluded_entities=self._excluded_entities)
            baseline = BaselineCalculator(session)

            # Determine checkpoint
            checkpoint = since or repository.get_latest_checkpoint()
            if checkpoint and checkpoint >= until:
                logger.info(
                    "Analyzer checkpoint (%s) is newer than requested window (%s) - nothing to do",
                    checkpoint,
                    until,
                )
                return 0

            windows = repository.fetch_entity_event_windows(since=checkpoint, until=until)
            if not windows:
                logger.info("Analyzer found no windows to process")
                return 0

            for window in windows:
                result = self.pipeline.analyze(
                    entity_id=window.entity_id,
                    window_start=window.window_start,
                    window_end=window.window_end,
                    events=window.events,
                )

                baseline_stats = baseline.get_baseline(window.entity_id, window.window_end)
                is_anomalous, delta = baseline.is_anomalous(
                    window.entity_id,
                    window.window_end,
                    result.risk_score,
                )

                result = result.__class__(
                    entity_id=result.entity_id,
                    window_start=result.window_start,
                    window_end=result.window_end,
                    features=result.features,
                    rule_evaluation=result.rule_evaluation,
                    risk_score=result.risk_score,
                    baseline_avg=baseline_stats.avg,
                    baseline_sigma=baseline_stats.sigma,
                    delta=delta,
                    is_anomalous=is_anomalous,
                )

                repository.persist_result(result)

                if is_anomalous:
                    self.alert_logger.log_anomaly(
                        entity_id=result.entity_id,
                        risk_score=result.risk_score,
                        baseline_avg=result.baseline_avg or 0.0,
                        baseline_sigma=result.baseline_sigma or 0.0,
                        delta=result.delta or 0.0,
                        triggered_rules=result.rule_evaluation.triggered_rules,
                    )

                processed += 1

            session.commit()

        logger.info("Analyzer processed %s window(s)", processed)
        return processed

    def run_forever(
        self,
        interval_seconds: int = 300,
        since: Optional[datetime] = None,
        until: Optional[datetime] = None,
    ) -> None:
        """Continuously run the analyzer service at fixed intervals."""
        logger.info(
            "Starting analyzer loop (interval=%ss, since=%s, until=%s)",
            interval_seconds,
            since,
            until,
        )
        try:
            while True:
                self.run_once(since=since, until=until)
                since = None  # ensure subsequent runs rely on checkpoint
                time.sleep(interval_seconds)
        except KeyboardInterrupt:
            logger.info("Analyzer loop interrupted - shutting down")
