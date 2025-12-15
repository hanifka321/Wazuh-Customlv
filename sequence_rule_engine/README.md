# Wazuh Sequence Rule Engine

This project implements a Sequence Rule Engine for Wazuh, allowing the definition of complex detection rules based on sequences of events.

## Project Overview

The Sequence Rule Engine consists of:
- **Backend**: A FastAPI application for managing rules (CRUD), validation, and testing.
- **Engine**: Core logic for parsing events, extracting fields, and matching sequences.
- **Frontend**: Web UI for managing and testing rules (see `frontend/` directory).

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
-   `POST /rules/validate`: Validate a rule YAML without saving.
-   `POST /rules/test`: Test a rule against sample JSONL logs.

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
-   `sequence`: Ordered list of steps (minimum 2 required).
    -   `as`: Alias for the step (used in output and subsequent steps).
    -   `where`: Expression to match the event.
-   `output`: Definition of the generated alert.
    -   `timestamp_ref`: Which step's timestamp to use for the alert.
    -   `format`: Message format for the alert.

## Frontend

The web UI is available in the `frontend/` directory. To use it:

1. Start the backend server (see above)
2. Serve the frontend files using any HTTP server
3. Open in a web browser

The UI provides:
- Visual rule management with list and detail views
- Interactive rule editor with validation
- Test runner for testing rules against sample logs
- Dark mode interface
- Full CRUD operations

See `frontend/README.md` for more details.

## Testing

Run tests with pytest:

```bash
# Run all sequence rule engine tests
pytest tests/test_sequence_api.py tests/test_sequence_matcher.py -v

# Run specific test
pytest tests/test_sequence_api.py::test_validate_valid_rule -v
```

## Components

### Engine Components

- **parser.py**: Parses JSONL formatted event logs
- **extractor.py**: Extracts fields from nested JSON using dotted paths
- **where_parser.py**: Parses and evaluates WHERE expressions
- **matcher.py**: Matches events against sequence rules
- **models.py**: Event model with auto-generated IDs

### Backend Components

- **main.py**: FastAPI application with all endpoints
- **models.py**: Pydantic models for API requests/responses
- **storage.py**: Rule storage abstraction (file-based and SQLite)
