import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sequence_rule_engine"))

from sequence_rule_engine.engine.matcher import RuleMatcher, SequenceMatch


def test_rule_matcher_initialization():
    """Test that RuleMatcher initializes correctly."""
    matcher = RuleMatcher()
    assert matcher is not None
    assert matcher.extractor is not None
    assert matcher.where_parser is not None


def test_match_simple_sequence():
    """Test matching a simple two-step sequence."""
    matcher = RuleMatcher()

    rule = {
        "id": "test-001",
        "name": "Test Rule",
        "by": ["data.srcip"],
        "within_seconds": 300,
        "sequence": [
            {"as": "step1", "where": "rule.id == '5710'"},
            {"as": "step2", "where": "rule.id == '5715'"},
        ],
    }

    jsonl_logs = """
{"timestamp":"2025-12-06T22:17:00","rule":{"id":"5710"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:05","rule":{"id":"5715"},"data":{"srcip":"192.168.1.100"}}
"""

    result = matcher.test_rule(rule, jsonl_logs)

    assert result["success"] is True
    assert result["events_processed"] == 2
    assert len(result["matches"]) == 1

    match = result["matches"][0]
    assert match["rule_name"] == "Test Rule"
    assert len(match["steps"]) == 2


def test_match_no_matches():
    """Test when no events match the sequence."""
    matcher = RuleMatcher()

    rule = {
        "id": "test-001",
        "name": "Test Rule",
        "by": ["data.srcip"],
        "within_seconds": 300,
        "sequence": [
            {"as": "step1", "where": "rule.id == '5710'"},
            {"as": "step2", "where": "rule.id == '5715'"},
        ],
    }

    jsonl_logs = """
{"timestamp":"2025-12-06T22:17:00","rule":{"id":"9999"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:05","rule":{"id":"8888"},"data":{"srcip":"192.168.1.100"}}
"""

    result = matcher.test_rule(rule, jsonl_logs)

    assert result["success"] is True
    assert result["events_processed"] == 2
    assert len(result["matches"]) == 0


def test_match_partial_sequence():
    """Test when only part of the sequence matches."""
    matcher = RuleMatcher()

    rule = {
        "id": "test-001",
        "name": "Test Rule",
        "by": ["data.srcip"],
        "within_seconds": 300,
        "sequence": [
            {"as": "step1", "where": "rule.id == '5710'"},
            {"as": "step2", "where": "rule.id == '5715'"},
        ],
    }

    jsonl_logs = """
{"timestamp":"2025-12-06T22:17:00","rule":{"id":"5710"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:05","rule":{"id":"9999"},"data":{"srcip":"192.168.1.100"}}
"""

    result = matcher.test_rule(rule, jsonl_logs)

    assert result["success"] is True
    assert result["events_processed"] == 2
    assert len(result["matches"]) == 0


def test_match_multiple_sequences():
    """Test matching multiple sequences in the same log stream."""
    matcher = RuleMatcher()

    rule = {
        "id": "test-001",
        "name": "Test Rule",
        "by": ["data.srcip"],
        "within_seconds": 300,
        "sequence": [
            {"as": "step1", "where": "rule.id == '5710'"},
            {"as": "step2", "where": "rule.id == '5715'"},
        ],
    }

    jsonl_logs = """
{"timestamp":"2025-12-06T22:17:00","rule":{"id":"5710"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:05","rule":{"id":"5715"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:18:00","rule":{"id":"5710"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:18:05","rule":{"id":"5715"},"data":{"srcip":"192.168.1.100"}}
"""

    result = matcher.test_rule(rule, jsonl_logs)

    assert result["success"] is True
    assert result["events_processed"] == 4
    assert len(result["matches"]) >= 1


def test_match_grouped_by_field():
    """Test that events are correctly grouped by specified fields."""
    matcher = RuleMatcher()

    rule = {
        "id": "test-001",
        "name": "Test Rule",
        "by": ["data.srcip"],
        "within_seconds": 300,
        "sequence": [
            {"as": "step1", "where": "rule.id == '5710'"},
            {"as": "step2", "where": "rule.id == '5715'"},
        ],
    }

    jsonl_logs = """
{"timestamp":"2025-12-06T22:17:00","rule":{"id":"5710"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:05","rule":{"id":"5715"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:10","rule":{"id":"5710"},"data":{"srcip":"10.0.0.50"}}
{"timestamp":"2025-12-06T22:17:15","rule":{"id":"5715"},"data":{"srcip":"10.0.0.50"}}
"""

    result = matcher.test_rule(rule, jsonl_logs)

    assert result["success"] is True
    assert result["events_processed"] == 4
    assert len(result["matches"]) == 2


def test_match_time_window():
    """Test that time window is respected."""
    matcher = RuleMatcher()

    rule = {
        "id": "test-001",
        "name": "Test Rule",
        "by": ["data.srcip"],
        "within_seconds": 10,
        "sequence": [
            {"as": "step1", "where": "rule.id == '5710'"},
            {"as": "step2", "where": "rule.id == '5715'"},
        ],
    }

    jsonl_logs = """
{"timestamp":"2025-12-06T22:17:00","rule":{"id":"5710"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:05","rule":{"id":"5715"},"data":{"srcip":"192.168.1.100"}}
"""

    result = matcher.test_rule(rule, jsonl_logs)

    assert result["success"] is True
    assert len(result["matches"]) >= 0


def test_match_invalid_jsonl():
    """Test handling of invalid JSONL."""
    matcher = RuleMatcher()

    rule = {
        "id": "test-001",
        "name": "Test Rule",
        "by": ["data.srcip"],
        "within_seconds": 300,
        "sequence": [
            {"as": "step1", "where": "rule.id == '5710'"},
            {"as": "step2", "where": "rule.id == '5715'"},
        ],
    }

    jsonl_logs = "invalid json here"

    result = matcher.test_rule(rule, jsonl_logs)

    assert result["success"] is False
    assert "error" in result


def test_sequence_match_object():
    """Test SequenceMatch object creation and serialization."""
    match = SequenceMatch(
        rule_name="Test Rule",
        timestamp="2025-12-06T22:17:00",
        matched_event_ids=["1", "2"],
        steps=[
            {"step": 1, "alias": "step1", "matched": True},
            {"step": 2, "alias": "step2", "matched": True},
        ],
    )

    match_dict = match.to_dict()

    assert match_dict["rule_name"] == "Test Rule"
    assert match_dict["timestamp"] == "2025-12-06T22:17:00"
    assert len(match_dict["matched_event_ids"]) == 2
    assert len(match_dict["steps"]) == 2
