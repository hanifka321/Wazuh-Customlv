import os
import yaml  # type: ignore
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, ValidationError
from typing import List
from .models import Rule
from .storage import FileStorage

app = FastAPI(title="Wazuh Sequence Rule Engine")

# Add CORS middleware to allow frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize storage
# Assuming we run this from project root, or we need absolute path.
# Let's use an absolute path based on the file location.
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(BASE_DIR, "rules")
storage = FileStorage(RULES_DIR)


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


class ValidateRequest(BaseModel):
    rule_yaml: str


class TestRuleRequest(BaseModel):
    rule_yaml: str
    sample_logs: str


@app.post("/rules/validate")
def validate_rule(request: ValidateRequest):
    """
    Validate a rule YAML without saving it.
    """
    errors = []

    try:
        rule_data = yaml.safe_load(request.rule_yaml)

        if not isinstance(rule_data, dict):
            return {"valid": False, "errors": ["Rule must be a YAML object"]}

        # Check required fields
        if "id" not in rule_data:
            errors.append("Missing required field: id")
        if "name" not in rule_data:
            errors.append("Missing required field: name")
        if "by" not in rule_data:
            errors.append("Missing required field: by")
        elif not isinstance(rule_data.get("by"), list):
            errors.append("Field 'by' must be a list")
        if "within_seconds" not in rule_data:
            errors.append("Missing required field: within_seconds")
        if "sequence" not in rule_data:
            errors.append("Missing required field: sequence")
        elif not isinstance(rule_data.get("sequence"), list):
            errors.append("Field 'sequence' must be a list")
        elif len(rule_data.get("sequence", [])) < 2:
            errors.append("Sequence must have at least 2 steps")

        # Check sequence steps
        if "sequence" in rule_data and isinstance(rule_data["sequence"], list):
            for i, step in enumerate(rule_data["sequence"]):
                if not isinstance(step, dict):
                    errors.append(f"Step {i+1} must be an object")
                    continue
                if "as" not in step:
                    errors.append(f"Step {i+1} missing required field: as")
                if "where" not in step:
                    errors.append(f"Step {i+1} missing required field: where")

        # Try to parse with Pydantic model
        if not errors:
            try:
                Rule(**rule_data)
            except ValidationError as e:
                for err in e.errors():
                    field = ".".join(str(x) for x in err["loc"])
                    errors.append(f"{field}: {err['msg']}")

    except yaml.YAMLError as e:
        errors.append(f"Invalid YAML syntax: {str(e)}")
    except Exception as e:
        errors.append(f"Validation error: {str(e)}")

    return {"valid": len(errors) == 0, "errors": errors}


@app.post("/rules/test")
def test_rule(request: TestRuleRequest):
    """
    Test a rule against sample JSONL logs without saving it.
    """
    try:
        from ..engine.matcher import RuleMatcher

        rule_data = yaml.safe_load(request.rule_yaml)
        matcher = RuleMatcher()
        result = matcher.test_rule(rule_data, request.sample_logs)

        return result
    except yaml.YAMLError as e:
        raise HTTPException(status_code=400, detail=f"Invalid YAML: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Test error: {str(e)}")
