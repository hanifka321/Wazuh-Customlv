from fastapi.testclient import TestClient
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "sequence_rule_engine"))

from sequence_rule_engine.backend.main import app

client = TestClient(app)


def test_full_workflow_create_validate_test_delete():
    """Test the complete workflow: create, validate, test, and delete a rule."""

    rule_yaml = """
id: "e2e-test-001"
name: "E2E Test Rule"
by: ["data.srcip"]
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

    # Step 1: Validate the rule
    validate_response = client.post("/rules/validate", json={"rule_yaml": rule_yaml})
    assert validate_response.status_code == 200
    validate_data = validate_response.json()
    assert validate_data["valid"] is True

    # Step 2: Create the rule
    create_response = client.post(
        "/rules",
        json={
            "id": "e2e-test-001",
            "name": "E2E Test Rule",
            "by": ["data.srcip"],
            "within_seconds": 300,
            "sequence": [
                {"as": "step1", "where": "rule.id == '5710'"},
                {"as": "step2", "where": "rule.id == '5715'"},
            ],
            "output": {"timestamp_ref": "step2", "format": "Test message"},
        },
    )
    assert create_response.status_code == 201
    created_rule = create_response.json()
    assert created_rule["id"] == "e2e-test-001"

    # Step 3: Retrieve the rule
    get_response = client.get("/rules/e2e-test-001")
    assert get_response.status_code == 200
    retrieved_rule = get_response.json()
    assert retrieved_rule["id"] == "e2e-test-001"
    assert retrieved_rule["name"] == "E2E Test Rule"

    # Step 4: List all rules and verify our rule is there
    list_response = client.get("/rules")
    assert list_response.status_code == 200
    rules = list_response.json()
    rule_ids = [r["id"] for r in rules]
    assert "e2e-test-001" in rule_ids

    # Step 5: Test the rule with sample logs
    sample_logs = """
{"timestamp":"2025-12-06T22:17:00","rule":{"id":"5710"},"data":{"srcip":"192.168.1.100"}}
{"timestamp":"2025-12-06T22:17:05","rule":{"id":"5715"},"data":{"srcip":"192.168.1.100"}}
"""

    test_response = client.post(
        "/rules/test", json={"rule_yaml": rule_yaml, "sample_logs": sample_logs}
    )
    assert test_response.status_code == 200
    test_result = test_response.json()
    assert test_result["success"] is True
    assert test_result["events_processed"] == 2
    assert len(test_result["matches"]) >= 1

    # Step 6: Update the rule
    update_response = client.put(
        "/rules/e2e-test-001",
        json={
            "id": "e2e-test-001",
            "name": "E2E Test Rule Updated",
            "by": ["data.srcip"],
            "within_seconds": 600,
            "sequence": [
                {"as": "step1", "where": "rule.id == '5710'"},
                {"as": "step2", "where": "rule.id == '5715'"},
            ],
            "output": {"timestamp_ref": "step2", "format": "Updated message"},
        },
    )
    assert update_response.status_code == 200
    updated_rule = update_response.json()
    assert updated_rule["name"] == "E2E Test Rule Updated"
    assert updated_rule["within_seconds"] == 600

    # Step 7: Delete the rule
    delete_response = client.delete("/rules/e2e-test-001")
    assert delete_response.status_code == 204

    # Step 8: Verify the rule is deleted
    get_deleted_response = client.get("/rules/e2e-test-001")
    assert get_deleted_response.status_code == 404


def test_validation_catches_errors():
    """Test that validation properly catches various error conditions."""

    # Missing id
    rule_yaml_no_id = """
name: "Test"
by: ["field"]
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

    response = client.post("/rules/validate", json={"rule_yaml": rule_yaml_no_id})
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert any("id" in err.lower() for err in data["errors"])

    # Too few steps
    rule_yaml_one_step = """
id: "test-001"
name: "Test"
by: ["field"]
within_seconds: 300
sequence:
  - as: "step1"
    where: "rule.id == '5710'"
output:
  timestamp_ref: "step1"
  format: "Test"
"""

    response = client.post("/rules/validate", json={"rule_yaml": rule_yaml_one_step})
    assert response.status_code == 200
    data = response.json()
    assert data["valid"] is False
    assert any("2" in err or "at least" in err.lower() for err in data["errors"])


def test_test_endpoint_handles_errors():
    """Test that the test endpoint properly handles error conditions."""

    # Invalid YAML
    response = client.post(
        "/rules/test",
        json={"rule_yaml": "invalid: yaml: syntax:", "sample_logs": '{"test": "log"}'},
    )
    assert response.status_code == 400

    # Valid YAML but invalid JSONL
    valid_yaml = """
id: "test-001"
name: "Test"
by: ["field"]
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

    response = client.post(
        "/rules/test", json={"rule_yaml": valid_yaml, "sample_logs": "not valid json"}
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is False
    assert "error" in data
