from __future__ import annotations

import fnmatch
import hashlib
import json
from datetime import datetime
from typing import Any, Dict, Optional, Sequence


def get_nested_value(data: Dict[str, Any], path: str) -> Optional[Any]:
    """
    Extract a value from a nested dictionary using dot notation.

    Examples:
        get_nested_value({"agent": {"id": "123"}}, "agent.id") -> "123"
        get_nested_value({"@timestamp": "2024-01-01"}, "@timestamp") -> "2024-01-01"
        get_nested_value({"foo": "bar"}, "missing.key") -> None
    """
    if not path:
        return None

    keys = path.split(".")
    current: Any = data

    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
        if current is None:
            return None

    return current


def compute_alert_hash(alert: Dict[str, Any]) -> str:
    """
    Compute a deterministic hash for deduplication.

    Uses a combination of:
    - Alert ID if present (rule.id, id, _id, etc.)
    - Timestamp
    - A subset of key fields

    Returns a SHA-256 hex digest (64 characters).
    """
    components = []

    # Try various common ID fields
    alert_id = (
        alert.get("id")
        or alert.get("_id")
        or get_nested_value(alert, "rule.id")
        or get_nested_value(alert, "alert_id")
    )
    if alert_id:
        components.append(str(alert_id))

    # Timestamp
    timestamp = (
        alert.get("timestamp")
        or alert.get("@timestamp")
        or get_nested_value(alert, "timestamp")
        or get_nested_value(alert, "@timestamp")
    )
    if timestamp:
        components.append(str(timestamp))

    # Agent/host identifiers
    agent_id = get_nested_value(alert, "agent.id") or alert.get("agent_id")
    if agent_id:
        components.append(str(agent_id))

    # If no unique identifiers found, hash the entire payload
    if not components:
        payload_str = json.dumps(alert, sort_keys=True, default=str)
        return hashlib.sha256(payload_str.encode()).hexdigest()

    # Combine components and hash
    combined = "|".join(components)
    return hashlib.sha256(combined.encode()).hexdigest()


def parse_iso_timestamp(value: Any) -> Optional[datetime]:
    """
    Parse ISO 8601 timestamp strings to datetime objects.

    Handles various formats including:
    - 2024-01-01T10:30:00Z
    - 2024-01-01T10:30:00.123Z
    - 2024-01-01T10:30:00+00:00
    """
    if isinstance(value, datetime):
        return value

    if not isinstance(value, str):
        return None

    # Remove microseconds beyond 6 digits (Python limitation)
    if "." in value:
        parts = value.split(".")
        if len(parts) == 2 and len(parts[1]) > 6:
            # Keep only first 6 digits of microseconds
            suffix = parts[1][6:]
            if suffix.endswith("Z"):
                parts[1] = parts[1][:6] + "Z"
            elif "+" in suffix or "-" in suffix:
                tz_part = suffix[suffix.find("+") if "+" in suffix else suffix.find("-") :]
                parts[1] = parts[1][:6] + tz_part
            value = ".".join(parts)

    # Try parsing with different formats
    formats = [
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%S.%f%z",
        "%Y-%m-%d %H:%M:%S",
    ]

    for fmt in formats:
        try:
            return datetime.strptime(value, fmt)
        except (ValueError, TypeError):
            continue

    return None


def convert_to_int(value: Any, default: Optional[int] = None) -> Optional[int]:
    """Convert a value to int, returning default if conversion fails."""
    if isinstance(value, int):
        return value
    if isinstance(value, (str, float)):
        try:
            return int(float(value))
        except (ValueError, TypeError):
            return default
    return default


def is_entity_excluded(entity_value: Optional[str], excluded_patterns: Sequence[str]) -> bool:
    """
    Check if an entity value matches any exclusion patterns.

    Supports:
    - Exact matches (e.g., "root", "admin")
    - Wildcard patterns (e.g., "system_*", "service_*")

    Args:
        entity_value: The entity value to check (optional)
        excluded_patterns: List of patterns to match against

    Returns:
        True if entity should be excluded, False otherwise

    Examples:
        is_entity_excluded("root", ["root", "admin"]) -> True
        is_entity_excluded("system_account", ["system_*"]) -> True
        is_entity_excluded("user123", ["system_*", "service_*"]) -> False
    """
    if not entity_value or not excluded_patterns:
        return False

    candidate = str(entity_value)

    for pattern in excluded_patterns:
        if pattern is None:
            continue
        normalized_pattern = str(pattern)
        # Check exact match first
        if candidate == normalized_pattern:
            return True
        # Check wildcard match (case-sensitive)
        if fnmatch.fnmatchcase(candidate, normalized_pattern):
            return True

    return False
