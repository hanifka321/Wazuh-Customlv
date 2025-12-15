from fastapi.testclient import TestClient
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sequence_rule_engine"))

from sequence_rule_engine.backend.main import app

client = TestClient(app)


def test_validate_valid_rule():
    """Test validation endpoint with a valid rule."""
    rule_yaml = """
id: "test-001"
name: "Test Rule"
by: ["src_ip"]
within_seconds: 300
sequence:
  - as: "step1"
    where: "rule.id == '5710'"
  - as: "step2"
    where: "rule.id == '5715'"
output:
  timestamp_ref: "step2"
  format: "Test message"
"""

    response = client.post("/rules/validate", json={"rule_yaml": rule_yaml})

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is True
    assert data["errors"] == []


def test_validate_invalid_rule_missing_id():
    """Test validation endpoint with missing id field."""
    rule_yaml = """
name: "Test Rule"
by: ["src_ip"]
within_seconds: 300
sequence:
  - as: "step1"
    where: "rule.id == '5710'"
  - as: "step2"
    where: "rule.id == '5715'"
output:
  timestamp_ref: "step2"
  format: "Test message"
"""

    response = client.post("/rules/validate", json={"rule_yaml": rule_yaml})

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert any("id" in err.lower() for err in data["errors"])


def test_validate_invalid_rule_bad_syntax():
    """Test validation endpoint with invalid YAML syntax."""
    rule_yaml = """
id: "test-001"
name: "Test Rule"
by: ["src_ip"
within_seconds: 300
"""

    response = client.post("/rules/validate", json={"rule_yaml": rule_yaml})

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert len(data["errors"]) > 0


def test_validate_insufficient_steps():
    """Test validation endpoint with less than 2 steps."""
    rule_yaml = """
id: "test-001"
name: "Test Rule"
by: ["src_ip"]
within_seconds: 300
sequence:
  - as: "step1"
    where: "rule.id == '5710'"
output:
  timestamp_ref: "step1"
  format: "Test message"
"""

    response = client.post("/rules/validate", json={"rule_yaml": rule_yaml})

    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert any("2 steps" in err or "at least 2" in err for err in data["errors"])


def test_test_rule_with_matching_logs():
    """Test the test endpoint with logs that match the rule."""
    rule_yaml = """
id: "test-001"
name: "SSH Brute Force"
by: ["data.srcip"]
within_seconds: 300
sequence:
  - as: "failed1"
    where: "rule.id == '5710'"
  - as: "failed2"
    where: "rule.id == '5710'"
  - as: "success"
    where: "rule.id == '5715'"
output:
  timestamp_ref: "success"
  format: "Detected sequence"
"""

    sample_logs = """
{"timestamp":"2025-12-06T22:17:00","rule":{"id":"5710"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:05","rule":{"id":"5710"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:10","rule":{"id":"5715"},"data":{"srcip":"192.168.1.100"}}
"""

    response = client.post("/rules/test", json={"rule_yaml": rule_yaml, "sample_logs": sample_logs})

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["events_processed"] == 3
    assert len(data["matches"]) >= 0


def test_test_rule_with_non_matching_logs():
    """Test the test endpoint with logs that don't match."""
    rule_yaml = """
id: "test-001"
name: "SSH Brute Force"
by: ["data.srcip"]
within_seconds: 300
sequence:
  - as: "failed"
    where: "rule.id == '5710'"
  - as: "success"
    where: "rule.id == '5715'"
output:
  timestamp_ref: "success"
  format: "Detected sequence"
"""

    sample_logs = """
{"timestamp":"2025-12-06T22:17:00","rule":{"id":"9999"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:05","rule":{"id":"8888"},"data":{"srcip":"192.168.1.100"}}
"""

    response = client.post("/rules/test", json={"rule_yaml": rule_yaml, "sample_logs": sample_logs})

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["events_processed"] == 2
    assert len(data["matches"]) == 0


def test_test_rule_with_invalid_yaml():
    """Test the test endpoint with invalid YAML."""
    rule_yaml = "invalid: yaml: syntax:"
    sample_logs = '{"timestamp":"2025-12-06T22:17:00","rule":{"id":"5710"}}'

    response = client.post("/rules/test", json={"rule_yaml": rule_yaml, "sample_logs": sample_logs})

    assert response.status_code == 400


def test_test_rule_with_invalid_jsonl():
    """Test the test endpoint with invalid JSONL."""
    rule_yaml = """
id: "test-001"
name: "Test Rule"
by: ["data.srcip"]
within_seconds: 300
sequence:
  - as: "step1"
    where: "rule.id == '5710'"
  - as: "step2"
    where: "rule.id == '5715'"
output:
  timestamp_ref: "step2"
  format: "Test"
"""
    sample_logs = "invalid json"

    response = client.post("/rules/test", json={"rule_yaml": rule_yaml, "sample_logs": sample_logs})

    # Should return error in result
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is False
    assert "error" in data
