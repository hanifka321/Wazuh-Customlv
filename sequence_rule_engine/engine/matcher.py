from typing import List, Dict, Any, Optional
from datetime import datetime
from .parser import parse_jsonl
from .extractor import DottedPathExtractor
from .where_parser import WhereExpressionParser


class SequenceMatch:
    def __init__(
        self,
        rule_name: str,
        timestamp: str,
        matched_event_ids: List[str],
        steps: List[Dict[str, Any]],
    ):
        self.rule_name = rule_name
        self.timestamp = timestamp
        self.matched_event_ids = matched_event_ids
        self.steps = steps

    def to_dict(self):
        return {
            "rule_name": self.rule_name,
            "timestamp": self.timestamp,
            "matched_event_ids": self.matched_event_ids,
            "steps": self.steps,
        }


class RuleMatcher:
    def __init__(self):
        self.extractor = DottedPathExtractor()
        self.where_parser = WhereExpressionParser()

    def test_rule(self, rule: Dict[str, Any], jsonl_logs: str) -> Dict[str, Any]:
        """
        Test a rule against sample JSONL logs.

        Args:
            rule: Rule dictionary with id, name, by, within_seconds, sequence
            jsonl_logs: JSONL formatted log entries

        Returns:
            Dictionary with matches and any errors
        """
        try:
            events = parse_jsonl(jsonl_logs)
            matches = self.match_sequence(rule, events)

            return {
                "success": True,
                "matches": [m.to_dict() for m in matches],
                "events_processed": len(events),
            }
        except Exception as e:
            return {"success": False, "error": str(e), "matches": [], "events_processed": 0}

    def match_sequence(
        self, rule: Dict[str, Any], events: List[Dict[str, Any]]
    ) -> List[SequenceMatch]:
        """
        Match events against a sequence rule.

        Args:
            rule: Rule definition
            events: List of event dictionaries

        Returns:
            List of SequenceMatch objects
        """
        matches: List[SequenceMatch] = []
        by_fields = rule.get("by", [])
        within_seconds = rule.get("within_seconds", 300)
        sequence_steps = rule.get("sequence", [])
        rule_name = rule.get("name", "Unknown Rule")

        if not sequence_steps or len(sequence_steps) < 2:
            return matches

        # Compile where expressions for each step
        step_predicates = []
        for step in sequence_steps:
            where_expr = step.get("where", "")
            predicate = self.where_parser.parse(where_expr)
            step_predicates.append((step.get("as", ""), predicate))

        # Group events by 'by' fields
        grouped_events = self._group_events(events, by_fields)

        # For each group, try to match the sequence
        for group_key, group_events in grouped_events.items():
            # Sort events by timestamp
            sorted_events = sorted(group_events, key=lambda e: e.get("timestamp", ""))

            # Try to find matching sequences
            group_matches = self._find_sequences_in_group(
                sorted_events, step_predicates, within_seconds, rule_name
            )
            matches.extend(group_matches)

        return matches

    def _group_events(
        self, events: List[Dict[str, Any]], by_fields: List[str]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """Group events by specified fields."""
        grouped: Dict[str, List[Dict[str, Any]]] = {}

        for event in events:
            # Extract values for grouping fields
            key_parts = []
            for field in by_fields:
                value = self.extractor.extract(event, field, "")
                key_parts.append(str(value))

            key = "|".join(key_parts) if key_parts else "default"

            if key not in grouped:
                grouped[key] = []
            grouped[key].append(event)

        return grouped

    def _find_sequences_in_group(
        self,
        events: List[Dict[str, Any]],
        step_predicates: List[tuple],
        within_seconds: int,
        rule_name: str,
    ) -> List[SequenceMatch]:
        """Find all matching sequences in a group of events."""
        matches = []

        # Try starting from each event
        for i in range(len(events)):
            match = self._try_match_from_event(
                events, i, step_predicates, within_seconds, rule_name
            )
            if match:
                matches.append(match)

        return matches

    def _try_match_from_event(
        self,
        events: List[Dict[str, Any]],
        start_idx: int,
        step_predicates: List[tuple],
        within_seconds: int,
        rule_name: str,
    ) -> Optional[SequenceMatch]:
        """Try to match a sequence starting from a specific event."""
        matched_events: List[Dict[str, Any]] = []
        step_details: List[Dict[str, Any]] = []

        for step_idx, (step_alias, predicate) in enumerate(step_predicates):
            # Find the next matching event for this step
            found = False

            for event_idx in range(start_idx + step_idx, len(events)):
                event = events[event_idx]

                # Check if event matches this step's predicate
                if predicate(event):
                    # Check time window if not the first step
                    if matched_events:
                        first_timestamp = matched_events[0].get("timestamp", "")
                        current_timestamp = event.get("timestamp", "")

                        if not self._within_time_window(
                            first_timestamp, current_timestamp, within_seconds
                        ):
                            break

                    matched_events.append(event)
                    step_details.append(
                        {
                            "step": step_idx + 1,
                            "alias": step_alias,
                            "matched": True,
                            "event": {
                                "timestamp": event.get("timestamp"),
                                "rule_id": self.extractor.extract(event, "rule.id", ""),
                            },
                        }
                    )
                    found = True
                    break

            if not found:
                return None

        # If we matched all steps, create a SequenceMatch
        if len(matched_events) == len(step_predicates):
            # Use the last event's timestamp as the match timestamp
            last_timestamp = matched_events[-1].get("timestamp", "")

            # Generate event IDs (using a simple hash or index)
            event_ids = [str(i) for i in range(len(matched_events))]

            return SequenceMatch(
                rule_name=rule_name,
                timestamp=last_timestamp,
                matched_event_ids=event_ids,
                steps=step_details,
            )

        return None

    def _within_time_window(self, start_time: str, end_time: str, window_seconds: int) -> bool:
        """Check if two timestamps are within the specified time window."""
        try:
            # Handle various timestamp formats
            for fmt in [
                "%Y-%m-%dT%H:%M:%S",
                "%Y-%m-%dT%H:%M:%S.%f",
                "%Y-%m-%d %H:%M:%S",
            ]:
                try:
                    start_dt = datetime.strptime(start_time[:19], fmt[:19])
                    end_dt = datetime.strptime(end_time[:19], fmt[:19])
                    delta = end_dt - start_dt
                    return delta.total_seconds() <= window_seconds
                except ValueError:
                    continue

            return True
        except Exception:
            return True
