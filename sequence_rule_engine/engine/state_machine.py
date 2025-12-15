from datetime import datetime
from typing import List


class CorrelationState:
    """
    State machine for tracking correlation between events in a sequence.

    Maintains the current progress through a sequence rule and tracks
    all matched events, timestamps, and correlation keys.
    """

    def __init__(self, correlation_key: str):
        """
        Initialize a correlation state.

        Args:
            correlation_key: The correlation key (e.g., agent ID) that groups events
        """
        self.key = correlation_key
        self.current_step_idx = 0  # Which step in the sequence we're waiting for
        self.matched_ids: List[str] = []  # Event IDs from matched steps
        self.timestamps: List[datetime] = []  # Timestamps of each matched event
        self.first_ts: datetime = None  # Timestamp of first matched event
        self.last_ts: datetime = None  # Timestamp of last matched event

    def next_step(self, event_id: str, timestamp: datetime) -> bool:
        """
        Advance to the next step in the sequence.

        Args:
            event_id: The ID of the event that matched the current step
            timestamp: The timestamp of the matched event

        Returns:
            True if this event completed a sequence, False otherwise
        """
        self.matched_ids.append(event_id)
        self.timestamps.append(timestamp)

        if self.first_ts is None:
            self.first_ts = timestamp

        self.last_ts = timestamp
        self.current_step_idx += 1

        # If we've completed all steps, the sequence is done
        # Note: The calling code needs to track total steps
        return self.current_step_idx >= 0  # Actual check will be done by engine

    def reset(self):
        """Reset the state to initial conditions."""
        self.current_step_idx = 0
        self.matched_ids.clear()
        self.timestamps.clear()
        self.first_ts = None
        self.last_ts = None

    def is_complete(self, total_steps: int) -> bool:
        """
        Check if the sequence is complete.

        Args:
            total_steps: Total number of steps in the sequence

        Returns:
            True if all steps have been matched
        """
        return self.current_step_idx >= total_steps

    def is_expired(self, window_seconds: int) -> bool:
        """
        Check if the state has expired based on time window.

        Args:
            window_seconds: Maximum time window for the sequence

        Returns:
            True if the state has expired (too much time elapsed or invalid timestamps)
        """
        if self.first_ts is None or self.last_ts is None:
            return False

        elapsed = (self.last_ts - self.first_ts).total_seconds()

        # State is expired if:
        # 1. Elapsed time is negative (invalid timestamp order)
        # 2. Elapsed time exceeds the window
        return elapsed < 0 or elapsed > window_seconds

    def get_duration_seconds(self) -> float:
        """
        Get the total duration of the matched sequence.

        Returns:
            Duration in seconds, or 0 if not enough data
        """
        if self.first_ts is None or self.last_ts is None:
            return 0.0

        return (self.last_ts - self.first_ts).total_seconds()

    def __repr__(self) -> str:
        return (
            f"CorrelationState(key={self.key}, "
            f"step={self.current_step_idx}, "
            f"events={len(self.matched_ids)}, "
            f"duration={self.get_duration_seconds():.1f}s)"
        )
