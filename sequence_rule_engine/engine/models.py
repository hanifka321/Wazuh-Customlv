import hashlib
import json
from datetime import datetime
from typing import Any, Optional, Dict, List


class Event:
    """
    Represents a security event with timestamp, fields, and nested field access.
    """

    def __init__(
        self,
        fields: Dict[str, Any],
        timestamp: Optional[datetime] = None,
        event_id: Optional[str] = None,
    ):
        """
        Initialize an Event.

        Args:
            fields: Dictionary containing all event fields
            timestamp: Event timestamp (defaults to current time if not provided)
            event_id: Unique event identifier (auto-generated hash if not provided)
        """
        self.fields = fields
        self.timestamp = timestamp or datetime.now()

        if event_id:
            self.event_id = event_id
        else:
            event_str = json.dumps(fields, sort_keys=True)
            self.event_id = hashlib.sha256(event_str.encode()).hexdigest()

    def get(self, dotted_path: str, default: Any = None) -> Any:
        """
        Extract a field value using dotted path notation.

        Supports nested dictionary access using dot notation:
        - "agent.id" → self.fields["agent"]["id"]
        - "data.win.eventdata.status" → self.fields["data"]["win"]["eventdata"]["status"]

        Args:
            dotted_path: Dot-separated path to the field (e.g., "agent.id")
            default: Value to return if path doesn't exist

        Returns:
            The field value if found, otherwise the default value
        """
        if not dotted_path:
            return default

        keys = dotted_path.split(".")
        value = self.fields

        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default

        return value

    def __repr__(self) -> str:
        return f"Event(event_id={self.event_id[:8]}..., timestamp={self.timestamp})"


class Match:
    """
    Represents a completed sequence match from rule execution.

    Contains all the information about a successful sequence match,
    including the rule that triggered it, matched events, and correlation data.
    """

    def __init__(
        self,
        rule_id: str,
        rule_name: str,
        matched_event_ids: List[str],
        correlation_key: str,
        timestamp: datetime,
    ):
        """
        Initialize a Match object.

        Args:
            rule_id: The ID of the rule that matched
            rule_name: The name of the rule that matched
            matched_event_ids: List of event IDs that formed the sequence
            correlation_key: The correlation key (e.g., agent ID) that grouped events
            timestamp: When the match was completed
        """
        self.rule_id = rule_id
        self.rule_name = rule_name
        self.matched_event_ids = matched_event_ids
        self.correlation_key = correlation_key
        self.timestamp = timestamp

    def __repr__(self) -> str:
        return (
            f"Match(rule={self.rule_name}, "
            f"events={len(self.matched_event_ids)}, "
            f"key={self.correlation_key}, "
            f"time={self.timestamp})"
        )


def format_output(match: Match, format_str: str) -> str:
    """
    Format a match using the specified format string.

    Supported placeholders:
    - {timestamp}: Match completion timestamp
    - {name}: Rule name
    - {events}: Comma-separated list of matched event IDs
    - {correlation_key}: The correlation key
    - {rule_id}: Rule ID

    Args:
        match: The Match object to format
        format_str: Format string with placeholders

    Returns:
        Formatted string
    """
    # Default format if none provided
    if not format_str:
        format_str = "[{timestamp}] [{name}] [{events}]"

    # Replace placeholders with match data
    timestamp_str = match.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    events_str = ",".join(match.matched_event_ids)

    formatted = format_str.format(
        timestamp=timestamp_str,
        name=match.rule_name,
        events=events_str,
        correlation_key=match.correlation_key,
        rule_id=match.rule_id,
    )

    return formatted
