from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional
from .state_machine import CorrelationState
from .compiler import CompiledRule, RuleCompiler
from .models import Event, Match


class SequenceEngine:
    """
    Core sequence matching engine with state machine for Wazuh alerts.

    Processes events against compiled sequence rules, maintaining correlation
    state per correlation key and detecting complete sequences within time windows.
    """

    def __init__(self):
        """Initialize the sequence engine."""
        self.compiler = RuleCompiler()
        # Map from correlation_key to CorrelationState objects
        self.state_map: Dict[str, CorrelationState] = {}
        # Store compiled rules for processing
        self.rules: List[CompiledRule] = []

    def load_rule(self, rule: Dict[str, Any]) -> CompiledRule:
        """
        Load and compile a single rule for processing.

        Args:
            rule: Rule dictionary with id, name, by, within_seconds, sequence, output

        Returns:
            CompiledRule object ready for processing
        """
        compiled_rule = self.compiler.compile_rule(rule)
        self.rules.append(compiled_rule)
        return compiled_rule

    def load_rules(self, rules: List[Dict[str, Any]]) -> List[CompiledRule]:
        """
        Load and compile multiple rules for processing.

        Args:
            rules: List of rule dictionaries

        Returns:
            List of CompiledRule objects
        """
        compiled_rules = []
        for rule in rules:
            compiled_rule = self.load_rule(rule)
            compiled_rules.append(compiled_rule)
        return compiled_rules

    def _extract_correlation_key(self, event: Event, by_fields: List[str]) -> Optional[str]:
        """
        Extract correlation key from event using by fields.

        Args:
            event: Event to extract correlation key from
            by_fields: List of field paths to use for correlation

        Returns:
            Correlation key string, or None if no valid key found
        """
        if not by_fields:
            return "default"  # Single global correlation if no by fields

        # Build correlation key from all by fields
        key_parts = []
        for field_path in by_fields:
            value = event.get(field_path)
            if value is None:
                # If any required field is missing, skip this event
                return None
            key_parts.append(str(value))

        if not key_parts:
            return None

        return "|".join(key_parts)

    def _cleanup_expired_states(self, now: datetime):
        """
        Remove expired correlation states based on rule timeouts.

        Args:
            now: Current timestamp for expiration checking
        """
        expired_keys = []

        for correlation_key, state in self.state_map.items():
            # Check against the most restrictive timeout (shortest duration)
            min_timeout = float("inf")
            for rule in self.rules:
                if rule.get_by_fields():
                    # This rule could potentially use this correlation key
                    # We'll be conservative and apply all timeouts
                    min_timeout = min(min_timeout, rule.within_seconds)

            if min_timeout != float("inf"):
                # Check if this state has been idle for too long
                if state.last_ts and now - state.last_ts > timedelta(seconds=min_timeout):
                    expired_keys.append(correlation_key)

        # Remove expired states
        for key in expired_keys:
            del self.state_map[key]

    def process_event(self, event: Event) -> List[Match]:
        """
        Process a single event against all loaded rules.

        Args:
            event: Event to process

        Returns:
            List of Match objects for any sequences that completed
        """
        matches = []

        for rule in self.rules:
            rule_matches = self._process_event_for_rule(event, rule)
            matches.extend(rule_matches)

        # Clean up expired states after processing
        self._cleanup_expired_states(event.timestamp)

        return matches

    def _process_event_for_rule(self, event: Event, rule: CompiledRule) -> List[Match]:
        """
        Process an event against a specific rule.

        Args:
            event: Event to process
            rule: Compiled rule to test against

        Returns:
            List of Match objects for sequences that completed with this rule
        """
        matches = []

        # Extract correlation key for this rule
        correlation_key = self._extract_correlation_key(event, rule.get_by_fields())
        if correlation_key is None:
            return matches  # Skip event if correlation key cannot be extracted

        # Get or create state for this correlation key
        if correlation_key not in self.state_map:
            self.state_map[correlation_key] = CorrelationState(correlation_key)

        state = self.state_map[correlation_key]

        # If we've already completed this sequence, start fresh
        if state.is_complete(rule.get_step_count()):
            state.reset()

        # Get the current step we should be looking for
        current_step_idx = state.current_step_idx
        if current_step_idx >= rule.get_step_count():
            # Sequence already complete, reset and start over
            state.reset()
            current_step_idx = 0

        # Check if current event matches the current step
        current_step = rule.steps[current_step_idx]
        if current_step.matches(event.fields):
            # Check if adding this event would exceed the window constraint
            if state.first_ts is not None:
                elapsed = (event.timestamp - state.first_ts).total_seconds()
                if elapsed > rule.within_seconds:
                    # Would exceed window, reset state and start fresh with this event
                    state.reset()
                    current_step_idx = 0
                    current_step = rule.steps[current_step_idx]
                    # Re-check if event matches the first step after reset
                    if not current_step.matches(event.fields):
                        return matches

            # Event matches! Advance to next step
            state.next_step(event.event_id, event.timestamp)

            # Check if this completes the sequence
            if state.is_complete(rule.get_step_count()):
                # Create a match for this completed sequence
                match = Match(
                    rule_id=rule.rule_id,
                    rule_name=rule.rule_name,
                    matched_event_ids=state.matched_ids.copy(),
                    correlation_key=correlation_key,
                    timestamp=event.timestamp,
                )
                matches.append(match)

                # Reset state for potential additional matches
                state.reset()

        return matches

    def process_events(self, events: List[Event]) -> List[Match]:
        """
        Process multiple events in sequence.

        Args:
            events: List of events to process in order

        Returns:
            List of Match objects for all sequences that completed
        """
        all_matches = []

        for event in events:
            event_matches = self.process_event(event)
            all_matches.extend(event_matches)

        return all_matches

    def get_state_summary(self) -> Dict[str, Dict[str, Any]]:
        """
        Get a summary of all current correlation states.

        Returns:
            Dictionary mapping correlation keys to state information
        """
        summary = {}
        for key, state in self.state_map.items():
            summary[key] = {
                "correlation_key": state.key,
                "current_step": state.current_step_idx,
                "matched_events": len(state.matched_ids),
                "first_timestamp": state.first_ts.isoformat() if state.first_ts else None,
                "last_timestamp": state.last_ts.isoformat() if state.last_ts else None,
                "duration_seconds": state.get_duration_seconds(),
                "is_expired": state.is_expired(float("inf")),  # Check with infinite window
            }
        return summary

    def reset_engine(self):
        """Reset the engine state, clearing all correlation states."""
        self.state_map.clear()

    def get_loaded_rules(self) -> List[CompiledRule]:
        """Get list of currently loaded rules."""
        return self.rules.copy()

    def remove_rule(self, rule_id: str) -> bool:
        """
        Remove a rule from the engine.

        Args:
            rule_id: ID of rule to remove

        Returns:
            True if rule was found and removed, False otherwise
        """
        for i, rule in enumerate(self.rules):
            if rule.rule_id == rule_id:
                del self.rules[i]
                return True
        return False
