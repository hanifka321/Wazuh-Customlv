import hashlib
import json
from datetime import datetime
from typing import Any, Optional, Dict


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
