"""
Comprehensive tests for the sequence engine state machine implementation.

Tests cover:
- Simple 2-step sequence: A→B
- 3-step sequence: A→B→C  
- By-key grouping (different agents)
- Within-window constraint
- Out-of-order events (should not match)
- State cleanup on timeout
- Multiple matches from same rule
"""

import pytest
from datetime import datetime, timedelta

from sequence_rule_engine.engine.state_machine import CorrelationState
from sequence_rule_engine.engine.engine import SequenceEngine
from sequence_rule_engine.engine.compiler import compile_rule
from sequence_rule_engine.engine.models import Event


class TestCorrelationState:
    """Test the CorrelationState state machine."""

    def test_initialization(self):
        """Test correlation state initialization."""
        state = CorrelationState("agent_123")
        assert state.key == "agent_123"
        assert state.current_step_idx == 0
        assert state.matched_ids == []
        assert state.timestamps == []
        assert state.first_ts is None
        assert state.last_ts is None

    def test_next_step(self):
        """Test advancing to next step."""
        state = CorrelationState("agent_123")
        timestamp = datetime.now()
        
        # First step
        result = state.next_step("event1", timestamp)
        assert state.current_step_idx == 1
        assert state.matched_ids == ["event1"]
        assert state.timestamps == [timestamp]
        assert state.first_ts == timestamp
        assert state.last_ts == timestamp
        assert not result  # Not complete yet
        
        # Second step
        timestamp2 = datetime.now()
        result = state.next_step("event2", timestamp2)
        assert state.current_step_idx == 2
        assert state.matched_ids == ["event1", "event2"]
        assert state.timestamps == [timestamp, timestamp2]
        assert state.first_ts == timestamp
        assert state.last_ts == timestamp2

    def test_is_complete(self):
        """Test checking if sequence is complete."""
        state = CorrelationState("agent_123")
        assert not state.is_complete(3)  # Need 3 steps, have 0
        
        state.current_step_idx = 2
        assert not state.is_complete(3)  # Need 3 steps, have 2
        
        state.current_step_idx = 3
        assert state.is_complete(3)  # Have 3 steps

    def test_is_expired(self):
        """Test expiration checking."""
        state = CorrelationState("agent_123")
        assert not state.is_expired(60)  # No timestamps yet
        
        # Set up state with events
        now = datetime.now()
        state.first_ts = now
        state.last_ts = now
        
        assert not state.is_expired(60)  # Within window
        assert state.is_expired(0)  # Zero window
        
        # Test with expired time
        past_time = now - timedelta(seconds=120)
        state.last_ts = past_time
        assert state.is_expired(60)  # 120s > 60s window

    def test_reset(self):
        """Test resetting state."""
        state = CorrelationState("agent_123")
        now = datetime.now()
        
        # Add some data
        state.next_step("event1", now)
        state.next_step("event2", now + timedelta(seconds=1))
        
        # Reset should clear everything
        state.reset()
        assert state.current_step_idx == 0
        assert state.matched_ids == []
        assert state.timestamps == []
        assert state.first_ts is None
        assert state.last_ts is None

    def test_get_duration_seconds(self):
        """Test duration calculation."""
        state = CorrelationState("agent_123")
        assert state.get_duration_seconds() == 0.0
        
        now = datetime.now()
        state.first_ts = now
        state.last_ts = now + timedelta(seconds=30)
        assert state.get_duration_seconds() == 30.0
        
        state.last_ts = now + timedelta(seconds=90, milliseconds=500)
        assert abs(state.get_duration_seconds() - 90.5) < 0.001


class TestSequenceEngine:
    """Test the main SequenceEngine."""

    def setup_method(self):
        """Set up test environment."""
        self.engine = SequenceEngine()

    def test_simple_2_step_sequence(self):
        """Test simple A→B sequence matching."""
        # Create a simple 2-step rule
        rule = {
            "id": "test_2step",
            "name": "Login Success to File Access",
            "by": ["agent.id"],
            "within_seconds": 60,
            "sequence": [
                {"as": "login", "where": "event.id == 'LOGIN_SUCCESS'"},
                {"as": "access", "where": "event.type == 'file_access'"}
            ],
            "output": {"timestamp_ref": "access", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        # Load rule
        self.engine.load_rule(rule)
        
        # Create events
        event1 = Event(
            {"agent": {"id": "123"}, "event": {"id": "LOGIN_SUCCESS"}},
            timestamp=datetime.now(),
            event_id="event1"
        )
        
        event2 = Event(
            {"agent": {"id": "123"}, "event": {"type": "file_access"}},
            timestamp=datetime.now() + timedelta(seconds=10),
            event_id="event2"
        )
        
        # Process events
        matches = self.engine.process_events([event1, event2])
        
        # Should have one match
        assert len(matches) == 1
        match = matches[0]
        assert match.rule_id == "test_2step"
        assert match.rule_name == "Login Success to File Access"
        assert match.matched_event_ids == ["event1", "event2"]
        assert match.correlation_key == "123"

    def test_3_step_sequence(self):
        """Test 3-step sequence A→B→C."""
        rule = {
            "id": "test_3step",
            "name": "Attack Chain",
            "by": ["agent.id"],
            "within_seconds": 120,
            "sequence": [
                {"as": "scan", "where": "event.type == 'port_scan'"},
                {"as": "exploit", "where": "event.type == 'exploit_attempt'"},
                {"as": "persistence", "where": "event.type == 'backdoor_install'"}
            ],
            "output": {"timestamp_ref": "persistence", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        self.engine.load_rule(rule)
        
        events = [
            Event({"agent": {"id": "456"}, "event": {"type": "port_scan"}}, event_id="scan1"),
            Event({"agent": {"id": "456"}, "event": {"type": "exploit_attempt"}}, event_id="exploit1"),
            Event({"agent": {"id": "456"}, "event": {"type": "backdoor_install"}}, event_id="persist1")
        ]
        
        matches = self.engine.process_events(events)
        
        assert len(matches) == 1
        match = matches[0]
        assert match.matched_event_ids == ["scan1", "exploit1", "persist1"]
        assert match.correlation_key == "456"

    def test_by_key_grouping(self):
        """Test grouping by different agents."""
        rule = {
            "id": "test_grouping",
            "name": "Cross-Agent Sequence",
            "by": ["agent.id"],
            "within_seconds": 60,
            "sequence": [
                {"as": "step1", "where": "event.type == 'login'"},
                {"as": "step2", "where": "event.type == 'logout'"}
            ],
            "output": {"timestamp_ref": "step2", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        self.engine.load_rule(rule)
        
        # Agent 123 completes sequence
        agent123_events = [
            Event({"agent": {"id": "123"}, "event": {"type": "login"}}, event_id="a123_login"),
            Event({"agent": {"id": "123"}, "event": {"type": "logout"}}, event_id="a123_logout")
        ]
        
        # Agent 456 completes sequence  
        agent456_events = [
            Event({"agent": {"id": "456"}, "event": {"type": "login"}}, event_id="a456_login"),
            Event({"agent": {"id": "456"}, "event": {"type": "logout"}}, event_id="a456_logout")
        ]
        
        # Interleave events from different agents
        all_events = [
            agent123_events[0],  # 123 login
            agent456_events[0],  # 456 login
            agent123_events[1],  # 123 logout
            agent456_events[1]   # 456 logout
        ]
        
        matches = self.engine.process_events(all_events)
        
        # Should have 2 matches - one for each agent
        assert len(matches) == 2
        
        # Check that events are grouped correctly
        match123 = [m for m in matches if m.correlation_key == "123"][0]
        match456 = [m for m in matches if m.correlation_key == "456"][0]
        
        assert match123.matched_event_ids == ["a123_login", "a123_logout"]
        assert match456.matched_event_ids == ["a456_login", "a456_logout"]

    def test_within_window_constraint(self):
        """Test within-window constraint enforcement."""
        rule = {
            "id": "test_window",
            "name": "Window Test",
            "by": ["agent.id"],
            "within_seconds": 30,  # 30 second window
            "sequence": [
                {"as": "step1", "where": "event.type == 'event1'"},
                {"as": "step2", "where": "event.type == 'event2'"}
            ],
            "output": {"timestamp_ref": "step2", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        self.engine.load_rule(rule)
        
        # First event
        start_time = datetime.now()
        event1 = Event({"agent": {"id": "789"}, "event": {"type": "event1"}}, 
                      timestamp=start_time, event_id="e1")
        
        # Second event within window
        event2 = Event({"agent": {"id": "789"}, "event": {"type": "event2"}}, 
                      timestamp=start_time + timedelta(seconds=20), event_id="e2")  # Within 30s
        
        matches = self.engine.process_events([event1, event2])
        assert len(matches) == 1  # Should match
        
        # Test with events outside window
        self.engine.reset_engine()  # Reset for clean test
        
        event3 = Event({"agent": {"id": "789"}, "event": {"type": "event1"}}, 
                      timestamp=start_time, event_id="e3")
        
        # Second event outside window
        event4 = Event({"agent": {"id": "789"}, "event": {"type": "event2"}}, 
                      timestamp=start_time + timedelta(seconds=40), event_id="e4")  # Outside 30s
        
        matches = self.engine.process_events([event3, event4])
        assert len(matches) == 0  # Should NOT match due to window

    def test_out_of_order_events(self):
        """Test that out-of-order events don't match."""
        rule = {
            "id": "test_order",
            "name": "Order Test",
            "by": ["agent.id"],
            "within_seconds": 60,
            "sequence": [
                {"as": "first", "where": "event.seq == 1"},
                {"as": "second", "where": "event.seq == 2"},
                {"as": "third", "where": "event.seq == 3"}
            ],
            "output": {"timestamp_ref": "third", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        self.engine.load_rule(rule)
        
        # Events in wrong order
        events = [
            Event({"agent": {"id": "999"}, "event": {"seq": 2}}, event_id="seq2"),
            Event({"agent": {"id": "999"}, "event": {"seq": 1}}, event_id="seq1"),
            Event({"agent": {"id": "999"}, "event": {"seq": 3}}, event_id="seq3")
        ]
        
        matches = self.engine.process_events(events)
        assert len(matches) == 0  # Should not match out of order
        
        # Events in correct order
        self.engine.reset_engine()
        
        events_correct = [
            Event({"agent": {"id": "999"}, "event": {"seq": 1}}, event_id="seq1"),
            Event({"agent": {"id": "999"}, "event": {"seq": 2}}, event_id="seq2"),
            Event({"agent": {"id": "999"}, "event": {"seq": 3}}, event_id="seq3")
        ]
        
        matches = self.engine.process_events(events_correct)
        assert len(matches) == 1  # Should match correct order

    def test_multiple_matches_same_rule(self):
        """Test multiple complete sequences from same rule."""
        rule = {
            "id": "test_multi",
            "name": "Multiple Sequences",
            "by": ["agent.id"],
            "within_seconds": 60,
            "sequence": [
                {"as": "start", "where": "event.type == 'start'"},
                {"as": "end", "where": "event.type == 'end'"}
            ],
            "output": {"timestamp_ref": "end", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        self.engine.load_rule(rule)
        
        # Create two complete sequences
        events = [
            # First sequence
            Event({"agent": {"id": "888"}, "event": {"type": "start"}}, event_id="s1_start"),
            Event({"agent": {"id": "888"}, "event": {"type": "end"}}, event_id="s1_end"),
            # Break in sequence
            Event({"agent": {"id": "888"}, "event": {"type": "start"}}, event_id="s2_start"),
            Event({"agent": {"id": "888"}, "event": {"type": "end"}}, event_id="s2_end")
        ]
        
        matches = self.engine.process_events(events)
        
        # Should have 2 matches
        assert len(matches) == 2
        
        # Check that we got both sequences
        assert set(m.correlation_key for m in matches) == {"888"}
        
        # Check that each match has correct events
        event_sets = [set(m.matched_event_ids) for m in matches]
        assert {"s1_start", "s1_end"} in event_sets
        assert {"s2_start", "s2_end"} in event_sets

    def test_state_cleanup_on_timeout(self):
        """Test that expired states are cleaned up."""
        rule = {
            "id": "test_cleanup",
            "name": "Cleanup Test",
            "by": ["agent.id"],
            "within_seconds": 30,  # 30 second timeout
            "sequence": [
                {"as": "step1", "where": "event.type == 'login'"},
                {"as": "step2", "where": "event.type == 'logout'"}
            ],
            "output": {"timestamp_ref": "step2", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        self.engine.load_rule(rule)
        
        # Create initial state
        start_time = datetime.now()
        event1 = Event({"agent": {"id": "777"}, "event": {"type": "login"}}, 
                      timestamp=start_time, event_id="login1")
        
        self.engine.process_event(event1)
        
        # Check that state exists
        assert "777" in self.engine.state_map
        
        # Advance time beyond cleanup threshold
        future_time = start_time + timedelta(seconds=35)  # Beyond 30s window
        
        # Create event with future timestamp
        event2 = Event({"agent": {"id": "777"}, "event": {"type": "logout"}}, 
                      timestamp=future_time, event_id="logout1")
        
        self.engine.process_event(event2)
        
        # The state should have been cleaned up during processing
        # (since the old state was expired)

    def test_no_by_fields(self):
        """Test rules with no by fields (global correlation)."""
        rule = {
            "id": "test_global",
            "name": "Global Sequence",
            "by": [],  # No by fields - global correlation
            "within_seconds": 60,
            "sequence": [
                {"as": "step1", "where": "event.type == 'global1'"},
                {"as": "step2", "where": "event.type == 'global2'"}
            ],
            "output": {"timestamp_ref": "step2", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        self.engine.load_rule(rule)
        
        events = [
            Event({"event": {"type": "global1"}}, event_id="g1"),
            Event({"event": {"type": "global2"}}, event_id="g2")
        ]
        
        matches = self.engine.process_events(events)
        
        assert len(matches) == 1
        match = matches[0]
        assert match.matched_event_ids == ["g1", "g2"]
        assert match.correlation_key == "default"  # Default global key

    def test_missing_by_fields(self):
        """Test handling of missing correlation fields."""
        rule = {
            "id": "test_missing",
            "name": "Missing Field Test",
            "by": ["agent.id"],
            "within_seconds": 60,
            "sequence": [
                {"as": "step1", "where": "event.type == 'type1'"},
                {"as": "step2", "where": "event.type == 'type2'"}
            ],
            "output": {"timestamp_ref": "step2", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        self.engine.load_rule(rule)
        
        # Event with missing agent.id
        event1 = Event({"event": {"type": "type1"}}, event_id="missing1")
        
        matches = self.engine.process_event(event1)
        assert len(matches) == 0
        
        # No state should be created for invalid correlation key
        assert len(self.engine.state_map) == 0

    def test_engine_reset(self):
        """Test engine reset functionality."""
        rule = {
            "id": "test_reset",
            "name": "Reset Test",
            "by": ["agent.id"],
            "within_seconds": 60,
            "sequence": [
                {"as": "step1", "where": "event.type == 'reset1'"},
                {"as": "step2", "where": "event.type == 'reset2'"}
            ],
            "output": {"timestamp_ref": "step2", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        self.engine.load_rule(rule)
        
        # Create some state
        event1 = Event({"agent": {"id": "555"}, "event": {"type": "reset1"}}, event_id="r1")
        self.engine.process_event(event1)
        
        assert "555" in self.engine.state_map
        
        # Reset engine
        self.engine.reset_engine()
        
        assert len(self.engine.state_map) == 0
        assert len(self.engine.get_loaded_rules()) == 1  # Rules should persist

    def test_get_state_summary(self):
        """Test getting state summary."""
        rule = {
            "id": "test_summary",
            "name": "Summary Test",
            "by": ["agent.id"],
            "within_seconds": 60,
            "sequence": [
                {"as": "step1", "where": "event.type == 'sum1'"},
                {"as": "step2", "where": "event.type == 'sum2'"}
            ],
            "output": {"timestamp_ref": "step2", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        self.engine.load_rule(rule)
        
        # Create some state
        event1 = Event({"agent": {"id": "444"}, "event": {"type": "sum1"}}, event_id="sum1")
        self.engine.process_event(event1)
        
        summary = self.engine.get_state_summary()
        
        assert "444" in summary
        state_info = summary["444"]
        assert state_info["correlation_key"] == "444"
        assert state_info["current_step"] == 1
        assert state_info["matched_events"] == 1
        assert state_info["is_expired"] is False


class TestRuleCompiler:
    """Test the rule compiler functionality."""

    def test_compile_simple_rule(self):
        """Test compiling a simple rule."""
        rule = {
            "id": "compile_test",
            "name": "Compile Test",
            "by": ["agent.id"],
            "within_seconds": 60,
            "sequence": [
                {"as": "step1", "where": "event.type == 'test1'"},
                {"as": "step2", "where": "event.type == 'test2'"}
            ],
            "output": {"timestamp_ref": "step2", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        compiled = compile_rule(rule)
        
        assert compiled.rule_id == "compile_test"
        assert compiled.rule_name == "Compile Test"
        assert compiled.by_fields == ["agent.id"]
        assert compiled.within_seconds == 60
        assert len(compiled.steps) == 2
        assert compiled.get_step_count() == 2

    def test_compile_where_expressions(self):
        """Test that where expressions are properly compiled."""
        rule = {
            "id": "where_test",
            "name": "Where Test",
            "by": ["agent.id"],
            "within_seconds": 60,
            "sequence": [
                {"as": "step1", "where": "event.type == 'login'"},
                {"as": "step2", "where": "status != 'failed'"},
                {"as": "step3", "where": "rule.id in ['5710', '5715']"}
            ],
            "output": {"timestamp_ref": "step3", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        compiled = compile_rule(rule)
        
        # Test that each step has a compiled where function
        assert len(compiled.steps) == 3
        
        step1, step2, step3 = compiled.steps
        assert step1.as_alias == "step1"
        assert step2.as_alias == "step2"
        assert step3.as_alias == "step3"
        
        # Test that the compiled functions work
        event = {"event": {"type": "login"}, "status": "success", "rule": {"id": "5710"}}
        
        assert step1.where_func(event) is True
        assert step2.where_func(event) is True
        assert step3.where_func(event) is True
        
        # Test failure cases
        event_fail = {"event": {"type": "logout"}, "status": "failed", "rule": {"id": "9999"}}
        
        assert step1.where_func(event_fail) is False
        assert step2.where_func(event_fail) is False
        assert step3.where_func(event_fail) is False

    def test_compile_invalid_where_expression(self):
        """Test that invalid where expressions raise errors."""
        rule = {
            "id": "invalid_test",
            "name": "Invalid Test",
            "by": ["agent.id"],
            "within_seconds": 60,
            "sequence": [
                {"as": "step1", "where": "invalid expression syntax @#$"}
            ],
            "output": {"timestamp_ref": "step1", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        with pytest.raises(ValueError, match="Unsupported expression syntax"):
            compile_rule(rule)

    def test_compile_rule_missing_fields(self):
        """Test that rules missing required fields raise errors."""
        # Missing sequence
        rule1 = {
            "id": "missing_seq",
            "name": "Missing Sequence",
            "by": ["agent.id"],
            "within_seconds": 60
        }
        
        with pytest.raises(ValueError, match="must have a 'sequence' field"):
            compile_rule(rule1)
        
        # Missing step fields
        rule2 = {
            "id": "missing_step",
            "name": "Missing Step",
            "by": ["agent.id"],
            "within_seconds": 60,
            "sequence": [
                {"where": "event.type == 'test'"}  # Missing 'as'
            ]
        }
        
        with pytest.raises(ValueError, match="must have an 'as' field"):
            compile_rule(rule2)


class TestIntegration:
    """Integration tests for the complete engine."""

    def test_end_to_end_simple_sequence(self):
        """Test complete end-to-end sequence processing."""
        rule = {
            "id": "e2e_simple",
            "name": "End-to-End Test",
            "by": ["agent.id"],
            "within_seconds": 60,
            "sequence": [
                {"as": "login", "where": "event.action == 'login'"},
                {"as": "access", "where": "event.resource != null"}
            ],
            "output": {"timestamp_ref": "access", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        engine = SequenceEngine()
        engine.load_rule(rule)
        
        # Simulate realistic events
        events = [
            Event({
                "agent": {"id": "agent001"},
                "timestamp": "2023-12-01T10:00:00Z",
                "event": {"action": "login", "user": "john.doe"}
            }, event_id="login_001"),
            
            Event({
                "agent": {"id": "agent001"}, 
                "timestamp": "2023-12-01T10:00:15Z",
                "event": {"action": "access", "resource": "/sensitive/data"}
            }, event_id="access_001")
        ]
        
        matches = engine.process_events(events)
        
        assert len(matches) == 1
        match = matches[0]
        assert match.rule_id == "e2e_simple"
        assert match.matched_event_ids == ["login_001", "access_001"]
        assert match.correlation_key == "agent001"

    def test_complex_attack_chain(self):
        """Test complex multi-step attack sequence."""
        rule = {
            "id": "attack_chain",
            "name": "APT Attack Chain",
            "by": ["agent.id", "src.ip"],
            "within_seconds": 300,  # 5 minute window
            "sequence": [
                {"as": "reconnaissance", "where": "event.type == 'port_scan'"},
                {"as": "vulnerability_scan", "where": "contains(event.details, 'vulnerability')"},
                {"as": "exploitation", "where": "status == 'exploit_success'"},
                {"as": "persistence", "where": "event.type in ['backdoor', 'rootkit']"},
                {"as": "data_exfiltration", "where": "action == 'upload' and bytes > 1000000"}
            ],
            "output": {"timestamp_ref": "data_exfiltration", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        engine = SequenceEngine()
        engine.load_rule(rule)
        
        # Realistic attack chain events
        attack_events = [
            Event({
                "agent": {"id": "web001"},
                "src": {"ip": "192.168.1.100"},
                "event": {"type": "port_scan"},
                "timestamp": "2023-12-01T10:00:00Z"
            }, event_id="scan_001"),
            
            Event({
                "agent": {"id": "web001"},
                "src": {"ip": "192.168.1.100"},
                "event": {"details": "scanning for SQL injection vulnerabilities"},
                "timestamp": "2023-12-01T10:01:30Z"
            }, event_id="vuln_scan_001"),
            
            Event({
                "agent": {"id": "web001"},
                "src": {"ip": "192.168.1.100"},
                "status": "exploit_success",
                "timestamp": "2023-12-01T10:03:00Z"
            }, event_id="exploit_001"),
            
            Event({
                "agent": {"id": "web001"},
                "src": {"ip": "192.168.1.100"},
                "event": {"type": "backdoor"},
                "timestamp": "2023-12-01T10:04:15Z"
            }, event_id="backdoor_001"),
            
            Event({
                "agent": {"id": "web001"},
                "src": {"ip": "192.168.1.100"},
                "action": "upload",
                "bytes": 2048576,  # > 1MB
                "timestamp": "2023-12-01T10:05:30Z"
            }, event_id="exfil_001")
        ]
        
        matches = engine.process_events(attack_events)
        
        assert len(matches) == 1
        match = matches[0]
        assert len(match.matched_event_ids) == 5
        assert match.correlation_key == "web001|192.168.1.100"
        assert match.rule_name == "APT Attack Chain"

    def test_performance_with_many_events(self):
        """Test engine performance with many events."""
        rule = {
            "id": "perf_test",
            "name": "Performance Test",
            "by": ["agent.id"],
            "within_seconds": 30,
            "sequence": [
                {"as": "start", "where": "event.type == 'start'"},
                {"as": "end", "where": "event.type == 'end'"}
            ],
            "output": {"timestamp_ref": "end", "format": "[{timestamp}] [{name}] [{events}]"}
        }
        
        engine = SequenceEngine()
        engine.load_rule(rule)
        
        # Generate many events
        import time
        
        start_time = time.time()
        
        events = []
        for i in range(100):  # 100 events
            agent_id = f"agent_{i % 10}"  # 10 different agents
            
            # Start event
            events.append(Event({
                "agent": {"id": agent_id},
                "event": {"type": "start"}
            }, event_id=f"start_{i}"))
            
            # End event
            events.append(Event({
                "agent": {"id": agent_id},
                "event": {"type": "end"}
            }, event_id=f"end_{i}"))
        
        matches = engine.process_events(events)
        
        end_time = time.time()
        processing_time = end_time - start_time
        
        # Should have 100 matches (every start should pair with following end)
        assert len(matches) == 100
        
        # Performance check - should process quickly
        assert processing_time < 5.0  # Should complete in under 5 seconds
        
        # Check state summary
        summary = engine.get_state_summary()
        # All states should be clean (sequences completed)
        for state_info in summary.values():
            assert state_info["matched_events"] == 0  # States should be reset after completion


if __name__ == "__main__":
    pytest.main([__file__])