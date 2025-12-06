from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from ueba.config.mapping_loader import MappingResolver, ResolvedMapping

from .persistence import (
    EntityPayload,
    NormalizedEventPayload,
    PersistenceManager,
    RawAlertPayload,
)
from .utils import (
    compute_alert_hash,
    convert_to_int,
    get_nested_value,
    is_entity_excluded,
    parse_iso_timestamp,
)

logger = logging.getLogger(__name__)


@dataclass
class MappingMetrics:
    mapping_latency_ms: float = 0.0
    unmapped_fields: List[str] = field(default_factory=list)
    extraction_errors: Dict[str, str] = field(default_factory=dict)


@dataclass
class MappedAlert:
    entity_payload: Optional[EntityPayload]
    raw_alert_payload: RawAlertPayload
    normalized_event_payload: NormalizedEventPayload
    metrics: MappingMetrics


class AlertMapper:
    """Maps raw Wazuh alerts to normalized entities and events."""

    def __init__(self, resolver: MappingResolver) -> None:
        self.resolver = resolver
        self._excluded_entities = resolver.get_excluded_entities()

    def _resolve_mapping_value(
        self, alert: Dict[str, Any], path: Optional[str], metrics: MappingMetrics
    ) -> Any:
        if path is None:
            return None

        if isinstance(path, str):
            value = get_nested_value(alert, path)
            if value is not None:
                return value

            is_literal = "." not in path and not path.startswith("@")
            if is_literal:
                return path

            metrics.unmapped_fields.append(path)
            return None

        return path

    def map_alert(
        self,
        alert: Dict[str, Any],
        source: str = "wazuh",
        vendor: Optional[str] = None,
        product: Optional[str] = None,
    ) -> MappedAlert:
        start_time = time.time()
        metrics = MappingMetrics()

        rule_id = get_nested_value(alert, "rule.id") or alert.get("rule_id")
        groups = []
        groups_raw = get_nested_value(alert, "rule.groups") or alert.get("groups")
        if isinstance(groups_raw, list):
            groups = [str(g) for g in groups_raw]

        custom: Dict[str, str] = {}
        resolved: ResolvedMapping = self.resolver.lookup(
            source=source, rule_id=str(rule_id) if rule_id else None, groups=groups, custom=custom
        )

        entity_id_value = None
        entity_type_value = None
        entity_id_value = self._resolve_mapping_value(alert, resolved.entity_id, metrics)
        entity_type_value = self._resolve_mapping_value(alert, resolved.entity_type, metrics)

        severity_value = None
        severity_raw = self._resolve_mapping_value(alert, resolved.severity, metrics)
        if severity_raw is not None:
            severity_value = convert_to_int(severity_raw)

        timestamp_value: Optional[datetime] = None
        timestamp_raw = self._resolve_mapping_value(alert, resolved.timestamp, metrics)
        if timestamp_raw is not None:
            timestamp_value = parse_iso_timestamp(timestamp_raw)
            if timestamp_value is None:
                metrics.extraction_errors[resolved.timestamp or "timestamp"] = (
                    f"Failed to parse timestamp: {timestamp_raw}"
                )

        if not timestamp_value:
            timestamp_value = datetime.utcnow()

        enrichment_context: Dict[str, Any] = {}
        for enrich_key, enrich_path in resolved.enrichment.items():
            enrich_value = get_nested_value(alert, enrich_path)
            if enrich_value is not None:
                enrichment_context[enrich_key] = enrich_value

        entity_payload = None
        if entity_type_value and entity_id_value:
            entity_payload = EntityPayload(
                entity_type=entity_type_value,
                entity_value=str(entity_id_value),
                display_name=enrichment_context.get("agent_name")
                or enrichment_context.get("username"),
                attributes=enrichment_context,
            )

        dedupe_hash = compute_alert_hash(alert)

        raw_alert_payload = RawAlertPayload(
            dedupe_hash=dedupe_hash,
            entity_id=None,
            source=source,
            vendor=vendor,
            product=product,
            severity=severity_value,
            observed_at=timestamp_value,
            original_payload=alert,
            enrichment_context=enrichment_context or None,
        )

        event_type = f"{source}_alert"
        if rule_id:
            event_type = f"{source}_rule_{rule_id}"

        rule_description = enrichment_context.get("rule_description")
        summary = rule_description if isinstance(rule_description, str) else None

        normalized_event_payload = NormalizedEventPayload(
            raw_alert_id=None,
            entity_id=None,
            event_type=event_type,
            risk_score=float(severity_value) if severity_value else None,
            observed_at=timestamp_value,
            summary=summary,
            normalized_payload={
                "entity_type": entity_type_value,
                "entity_id": entity_id_value,
                "severity": severity_value,
                "timestamp": timestamp_value.isoformat() if timestamp_value else None,
                "enrichment": enrichment_context,
            },
            original_payload=alert,
        )

        metrics.mapping_latency_ms = (time.time() - start_time) * 1000
        return MappedAlert(
            entity_payload=entity_payload,
            raw_alert_payload=raw_alert_payload,
            normalized_event_payload=normalized_event_payload,
            metrics=metrics,
        )

    def map_and_persist(
        self, alert: Dict[str, Any], persistence: PersistenceManager, source: str = "wazuh"
    ) -> Dict[str, Any]:
        mapped = self.map_alert(alert, source=source)
        logger.debug(
            f"Mapped alert in {mapped.metrics.mapping_latency_ms:.2f}ms - "
            f"unmapped fields: {len(mapped.metrics.unmapped_fields)}"
        )

        entity = None
        if mapped.entity_payload:
            # Check if entity is excluded
            if is_entity_excluded(mapped.entity_payload.entity_value, self._excluded_entities):
                logger.debug(
                    f"Skipping excluded entity: {mapped.entity_payload.entity_type}/"
                    f"{mapped.entity_payload.entity_value}"
                )
            else:
                entity = persistence.upsert_entity(mapped.entity_payload)
                logger.debug(
                    f"Upserted entity: {entity.entity_type}/{entity.entity_value} (id={entity.id})"
                )
                mapped.raw_alert_payload.entity_id = entity.id
                mapped.normalized_event_payload.entity_id = entity.id

        raw_alert, was_duplicate = persistence.persist_raw_alert(mapped.raw_alert_payload)
        if was_duplicate:
            logger.info(f"Skipped duplicate alert: {mapped.raw_alert_payload.dedupe_hash}")
            return {
                "status": "skipped",
                "reason": "duplicate",
                "dedupe_hash": mapped.raw_alert_payload.dedupe_hash,
            }

        logger.debug(f"Persisted raw_alert (id={raw_alert.id})")

        mapped.normalized_event_payload.raw_alert_id = raw_alert.id
        normalized_event, _ = persistence.persist_normalized_event(mapped.normalized_event_payload)
        if normalized_event:
            logger.debug(f"Persisted normalized_event (id={normalized_event.id})")

        return {
            "status": "success",
            "entity_id": entity.id if entity else None,
            "raw_alert_id": raw_alert.id,
            "normalized_event_id": normalized_event.id if normalized_event else None,
            "metrics": {
                "mapping_latency_ms": mapped.metrics.mapping_latency_ms,
                "unmapped_fields": mapped.metrics.unmapped_fields,
                "extraction_errors": mapped.metrics.extraction_errors,
            },
        }
