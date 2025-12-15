# Wazuh Sequence Rule Engine

This project implements a Sequence Rule Engine for Wazuh, allowing the definition of complex detection rules based on sequences of events.

## Project Overview

The Sequence Rule Engine consists of:
- **Backend**: A FastAPI application for managing rules (CRUD) and storing them.
- **Engine**: (Upcoming) The core logic to process events against the rules.
- **Frontend**: (Upcoming) A UI for managing rules.

## How to Run

1.  **Install Dependencies**:
    ```bash
    pip install -r requirements.txt
    ```

2.  **Start the Server**:
    Navigate to the `sequence_rule_engine` directory and run:
    ```bash
    uvicorn backend.main:app --reload
    ```
    The API will be available at `http://localhost:8000`.

## API Endpoints

-   `GET /health`: Health check.
-   `GET /rules`: List all rules.
-   `POST /rules`: Create a new rule.
-   `GET /rules/{id}`: Get details of a specific rule.
-   `PUT /rules/{id}`: Update a rule.
-   `DELETE /rules/{id}`: Delete a rule.

## Rule DSL Format

Rules are defined in JSON/YAML with the following structure:

```yaml
id: "rule-001"
name: "SSH Brute Force followed by Successful Login"
by: ["src_ip"]
within_seconds: 300
sequence:
  - as: "failed_login"
    where: "rule.id == '5710'"
  - as: "success_login"
    where: "rule.id == '5715'"
output:
  timestamp_ref: "success_login"
  format: "Detected brute force sequence from {src_ip}"
```

-   `id`: Unique identifier for the rule.
-   `name`: Human-readable name.
-   `by`: List of fields to group events by (e.g., source IP).
-   `within_seconds`: Time window for the sequence to complete.
-   `sequence`: Ordered list of steps.
    -   `as`: Alias for the step (used in output and subsequent steps).
    -   `where`: Expression to match the event.
-   `output`: Definition of the generated alert.
    -   `timestamp_ref`: Which step's timestamp to use for the alert.
    -   `format`: Message format for the alert.
