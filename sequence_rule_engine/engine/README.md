# Sequence Rule Engine - Engine Module

This module implements the core parsing and field extraction functionality for the Wazuh Sequence Rule Engine (Milestone 2).

## Components

### 1. JSONL Parser (`parser.py`)

Parses JSONL (JSON Lines) formatted event streams.

**Features:**
- Parses newline-delimited JSON
- Skips comment lines (starting with `#`)
- Skips empty lines
- Descriptive error messages with line numbers
- Validates JSON objects

**Usage:**
```python
from sequence_rule_engine.engine.parser import parse_jsonl

jsonl_data = '''
# Sample events
{"rule": {"id": "5710"}, "agent": {"name": "server1"}}
{"rule": {"id": "5715"}, "agent": {"name": "server1"}}
'''

events = parse_jsonl(jsonl_data)
# Returns: [{"rule": {"id": "5710"}, ...}, {"rule": {"id": "5715"}, ...}]
```

### 2. Event Model (`models.py`)

Represents security events with timestamp, fields, and nested field access.

**Features:**
- Auto-generated event ID (SHA-256 hash of fields)
- Timestamp management
- Dotted path field access
- Nested dictionary navigation

**Usage:**
```python
from sequence_rule_engine.engine.models import Event

event = Event(fields={
    "rule": {"id": "5710"},
    "agent": {"name": "server1"}
})

# Access nested fields
rule_id = event.get("rule.id")  # "5710"
agent_name = event.get("agent.name")  # "server1"
missing = event.get("missing.field", "default")  # "default"
```

### 3. Field Extractor (`extractor.py`)

Extracts values from nested dictionaries using dotted path notation.

**Features:**
- Dotted path notation support
- Graceful handling of missing fields
- Single and batch extraction
- Deep nesting support

**Usage:**
```python
from sequence_rule_engine.engine.extractor import DottedPathExtractor

extractor = DottedPathExtractor()
event = {
    "rule": {"id": "5710"},
    "data": {"user": {"name": "admin"}}
}

# Extract single field
rule_id = extractor.extract(event, "rule.id")  # "5710"

# Extract with default
status = extractor.extract(event, "status", "unknown")  # "unknown"

# Extract multiple fields
fields = extractor.extract_multiple(event, ["rule.id", "data.user.name"])
# Returns: {"rule.id": "5710", "data.user.name": "admin"}
```

### 4. Where Expression Parser (`where_parser.py`)

Parses and compiles where expressions into callable predicates for event filtering.

**Supported Operators:**
- `==` : Equality comparison
- `!=` : Inequality comparison
- `in` : List membership
- `contains(field, "text")` : Substring search
- `regex(field, "pattern")` : Regular expression matching

**Usage:**
```python
from sequence_rule_engine.engine.where_parser import WhereExpressionParser

parser = WhereExpressionParser()

# Equality
pred = parser.parse('rule.id == "5710"')
pred({"rule": {"id": "5710"}})  # True

# List membership
pred = parser.parse('rule.id in ["5710", "5715"]')
pred({"rule": {"id": "5710"}})  # True

# Substring search
pred = parser.parse('contains(user.name, "admin")')
pred({"user": {"name": "administrator"}})  # True

# Regular expression
pred = parser.parse('regex(ip, "192\\.168\\..*")')
pred({"ip": "192.168.1.100"})  # True
```

## Integration Example

Complete workflow for parsing and filtering Wazuh alerts:

```python
from sequence_rule_engine.engine.parser import parse_jsonl
from sequence_rule_engine.engine.models import Event
from sequence_rule_engine.engine.where_parser import WhereExpressionParser

# Parse JSONL alerts
jsonl = '''
{"timestamp":"2025-12-06T22:17:00","rule":{"id":"5710"},"agent":{"name":"server1"}}
{"timestamp":"2025-12-06T22:17:15","rule":{"id":"5715"},"agent":{"name":"server1"}}
'''

events = parse_jsonl(jsonl)

# Create Event objects
event_objects = [Event(fields=e) for e in events]

# Parse where expressions
parser = WhereExpressionParser()
failed_login = parser.parse('rule.id == "5710"')
success_login = parser.parse('rule.id == "5715"')

# Filter events
failed_events = [e for e in events if failed_login(e)]
success_events = [e for e in events if success_login(e)]

# Detect sequences
if len(failed_events) >= 3 and len(success_events) >= 1:
    print("Detected brute force sequence!")
```

## Wazuh Alert Support

All components are designed to work with typical Wazuh alert structures:

```python
{
    "timestamp": "2025-12-06T22:17:02.297+0700",
    "rule": {
        "level": 5,
        "description": "SSH authentication failed",
        "id": "5710"
    },
    "agent": {
        "id": "037",
        "name": "deb12",
        "ip": "103.153.61.108"
    },
    "data": {
        "srcip": "192.168.1.100",
        "dstuser": "root"
    }
}
```

Common field paths:
- `rule.id` - Rule identifier
- `rule.level` - Alert severity
- `agent.name` - Agent hostname
- `agent.ip` - Agent IP address
- `data.srcip` - Source IP (SSH/network events)
- `data.dstuser` - Destination user
- `data.win.eventdata.*` - Windows event data

## Testing

Run tests:
```bash
pytest tests/test_parser.py -v
pytest tests/test_extractor.py -v
pytest tests/test_where_parser.py -v
pytest tests/test_integration_m2.py -v
```

## Error Handling

All components handle errors gracefully:

- **Parser**: Returns descriptive errors with line numbers for malformed JSON
- **Extractor**: Returns `None` or default values for missing fields
- **Event**: Handles missing nested paths without exceptions
- **Where Parser**: Raises `ValueError` with clear messages for invalid syntax

## Next Steps (Milestone 3)

The next phase will implement:
- Sequence detection engine
- Time window management
- Event grouping by fields
- Rule evaluation and matching
- Alert generation
