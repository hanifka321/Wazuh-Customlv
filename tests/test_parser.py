import pytest
from sequence_rule_engine.engine.parser import parse_jsonl


def test_parse_jsonl_simple():
    """Test parsing simple JSONL with multiple events."""
    jsonl = """{"id": "1", "name": "event1"}
{"id": "2", "name": "event2"}
{"id": "3", "name": "event3"}"""

    events = parse_jsonl(jsonl)

    assert len(events) == 3
    assert events[0]["id"] == "1"
    assert events[1]["name"] == "event2"
    assert events[2]["id"] == "3"


def test_parse_jsonl_with_comments():
    """Test that comment lines (starting with #) are skipped."""
    jsonl = """# This is a comment
{"id": "1", "name": "event1"}
# Another comment
{"id": "2", "name": "event2"}"""

    events = parse_jsonl(jsonl)

    assert len(events) == 2
    assert events[0]["id"] == "1"
    assert events[1]["id"] == "2"


def test_parse_jsonl_with_empty_lines():
    """Test that empty lines are skipped."""
    jsonl = """{"id": "1", "name": "event1"}

{"id": "2", "name": "event2"}
    
{"id": "3", "name": "event3"}"""

    events = parse_jsonl(jsonl)

    assert len(events) == 3


def test_parse_jsonl_empty_string():
    """Test parsing empty string returns empty list."""
    events = parse_jsonl("")
    assert events == []

    events = parse_jsonl("   \n  \n  ")
    assert events == []


def test_parse_jsonl_only_comments():
    """Test that file with only comments returns empty list."""
    jsonl = """# Comment 1
# Comment 2
# Comment 3"""

    events = parse_jsonl(jsonl)
    assert events == []


def test_parse_jsonl_malformed_json():
    """Test that malformed JSON raises ValueError with line number."""
    jsonl = """{"id": "1", "name": "event1"}
{"id": "2", "name": "event2"
{"id": "3", "name": "event3"}"""

    with pytest.raises(ValueError) as exc_info:
        parse_jsonl(jsonl)

    assert "Line 2" in str(exc_info.value)
    assert "Invalid JSON" in str(exc_info.value)


def test_parse_jsonl_non_object():
    """Test that non-object JSON raises ValueError."""
    jsonl = """{"id": "1"}
["array", "instead", "of", "object"]
{"id": "3"}"""

    with pytest.raises(ValueError) as exc_info:
        parse_jsonl(jsonl)

    assert "Line 2" in str(exc_info.value)
    assert "Expected JSON object" in str(exc_info.value)


def test_parse_jsonl_wazuh_alert_structure():
    """Test parsing typical Wazuh alert structure."""
    jsonl = '{"timestamp":"2025-12-06T22:17:02.297+0700","rule":{"level":3,"description":"Auditbeat Integration","id":"500111"},"agent":{"id":"037","name":"deb12","ip":"103.153.61.108"},"data":{"user":{"name":"root"}}}'

    events = parse_jsonl(jsonl)

    assert len(events) == 1
    assert events[0]["rule"]["id"] == "500111"
    assert events[0]["agent"]["name"] == "deb12"
    assert events[0]["data"]["user"]["name"] == "root"


def test_parse_jsonl_mixed_valid_invalid():
    """Test that first error stops parsing."""
    jsonl = """{"id": "1"}
{"id": "2"}
invalid json here
{"id": "4"}"""

    with pytest.raises(ValueError) as exc_info:
        parse_jsonl(jsonl)

    assert "Line 3" in str(exc_info.value)


def test_parse_jsonl_nested_structures():
    """Test parsing deeply nested JSON structures."""
    jsonl = """{"a": {"b": {"c": {"d": {"e": "value"}}}}}"""

    events = parse_jsonl(jsonl)

    assert len(events) == 1
    assert events[0]["a"]["b"]["c"]["d"]["e"] == "value"
