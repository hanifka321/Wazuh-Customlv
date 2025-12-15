import os
import yaml
import json
from datetime import datetime
from fastapi import FastAPI, HTTPException, status
from typing import List, Dict, Any
from pydantic import BaseModel

from .models import Rule
from .storage import FileStorage
from ..engine.engine import SequenceEngine
from ..engine.models import Event

app = FastAPI(title="Wazuh Sequence Rule Engine")

# Initialize storage
# Assuming we run this from project root, or we need absolute path.
# Let's use an absolute path based on the file location.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(BASE_DIR, "rules")
storage = FileStorage(RULES_DIR)

# Initialize the sequence engine for testing
engine = SequenceEngine()


# Pydantic models for the test endpoint
class TestRuleRequest(BaseModel):
    rule_yaml: str
    logs_jsonl: str


class MatchResponse(BaseModel):
    rule_id: str
    rule_name: str
    matched_event_ids: List[str]
    correlation_key: str
    timestamp: str
    formatted_output: str


class TestRuleResponse(BaseModel):
    matches: List[MatchResponse]
    rule_info: Dict[str, Any]


@app.get("/health")
def health_check():
    return {"status": "ok"}


@app.get("/rules", response_model=List[Rule])
def list_rules():
    return storage.list_rules()


@app.post("/rules", response_model=Rule, status_code=status.HTTP_201_CREATED)
def create_rule(rule: Rule):
    try:
        created_rule = storage.create_rule(rule)
        return created_rule
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/rules/{rule_id}", response_model=Rule)
def get_rule(rule_id: str):
    rule = storage.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    return rule


@app.put("/rules/{rule_id}", response_model=Rule)
def update_rule(rule_id: str, rule: Rule):
    updated_rule = storage.update_rule(rule_id, rule)
    if not updated_rule:
        # If it returns None, maybe it didn't exist or failed.
        # Check if it existed first?
        # storage.update_rule implementation returns None if file doesn't exist.
        raise HTTPException(status_code=404, detail="Rule not found")
    return updated_rule


@app.delete("/rules/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(rule_id: str):
    success = storage.delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail="Rule not found")
    return


@app.post("/rules/test", response_model=TestRuleResponse)
def test_rule(request: TestRuleRequest):
    """
    Test a sequence rule against provided log events.

    This endpoint allows testing rule logic by providing:
    - rule_yaml: YAML-formatted rule definition
    - logs_jsonl: JSONL-formatted events to test against

    Returns:
        List of matches with formatted output
    """
    try:
        # Parse the rule YAML
        try:
            rule_data = yaml.safe_load(request.rule_yaml)
        except yaml.YAMLError as e:
            raise HTTPException(status_code=400, detail=f"Invalid YAML format: {e}")

        if not rule_data or not isinstance(rule_data, dict):
            raise HTTPException(status_code=400, detail="Rule YAML must contain a valid dictionary")

        # Parse the logs JSONL
        events = []
        try:
            logs_lines = (
                request.logs_jsonl.strip().split("\n") if request.logs_jsonl.strip() else []
            )
            for line_num, line in enumerate(logs_lines, start=1):
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                try:
                    event_data = json.loads(line)
                    if not isinstance(event_data, dict):
                        raise ValueError(
                            f"Line {line_num}: Expected JSON object, got {type(event_data).__name__}"
                        )

                    # Create Event object with timestamp if available
                    timestamp = None
                    if "timestamp" in event_data:
                        try:
                            timestamp = datetime.fromisoformat(event_data["timestamp"])
                        except (ValueError, TypeError):
                            pass

                    event = Event(event_data, timestamp=timestamp)
                    events.append(event)

                except json.JSONDecodeError as e:
                    raise HTTPException(
                        status_code=400, detail=f"Line {line_num}: Invalid JSON - {str(e)}"
                    )

        except Exception as e:
            raise HTTPException(status_code=400, detail=f"Error parsing logs: {e}")

        if not events:
            raise HTTPException(status_code=400, detail="No valid events found in logs")

        # Create a fresh engine instance for testing
        test_engine = SequenceEngine()

        # Load and compile the rule
        test_engine.load_rule(rule_data)

        # Process events
        matches = test_engine.process_events(events)

        # Format matches for response
        match_responses = []
        for match in matches:
            formatted_output = f"[{match.timestamp.strftime('%Y-%m-%d %H:%M:%S')}] [{match.rule_name}] [{','.join(match.matched_event_ids)}]"

            match_response = MatchResponse(
                rule_id=match.rule_id,
                rule_name=match.rule_name,
                matched_event_ids=match.matched_event_ids,
                correlation_key=match.correlation_key,
                timestamp=match.timestamp.isoformat(),
                formatted_output=formatted_output,
            )
            match_responses.append(match_response)

        # Return rule info and matches
        response = TestRuleResponse(
            matches=match_responses,
            rule_info={
                "rule_id": rule_data.get("id", ""),
                "rule_name": rule_data.get("name", ""),
                "by_fields": rule_data.get("by", []),
                "within_seconds": rule_data.get("within_seconds", 300),
                "step_count": len(rule_data.get("sequence", [])),
                "events_processed": len(events),
            },
        )

        return response

    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal error: {str(e)}")
