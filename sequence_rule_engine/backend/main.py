import os
from fastapi import FastAPI, HTTPException, status
from typing import List
from .models import Rule
from .storage import FileStorage

app = FastAPI(title="Wazuh Sequence Rule Engine")

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
