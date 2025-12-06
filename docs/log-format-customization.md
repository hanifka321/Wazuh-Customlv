# Log Format & Customization Guide

This guide explains how Wazuh JSON alerts flow through the mapper, how to tune the YAML mappings, and how to troubleshoot field issues. Use `lgexamle.json` (intentionally spelled that way in the repo root) as your living reference sample.

---

## 1. Anatomy of a Wazuh JSON Alert

Each line in `lgexamle.json` is a standalone JSON object. Here is a trimmed example (reformatted for readability):

```json
{
  "timestamp": "2025-12-06T22:17:02.298+0700",
  "rule": {
    "level": 3,
    "description": "Auditbeat Integration",
    "id": "500111",
    "groups": ["auditbeat", "syscall", "network"]
  },
  "agent": {"id": "037", "name": "deb12", "ip": "103.153.61.108"},
  "manager": {"name": "svr9-wzh"},
  "full_log": "{...}" ,
  "decoder": {"name": "json"},
  "data": {
    "@timestamp": "2025-12-06T15:17:01.278Z",
    "event": {
      "module": "auditd",
      "category": ["file"],
      "action": "wrote-to-file"
    },
    "host": {
      "name": "deb12",
      "os": {"name": "Debian GNU/Linux"}
    },
    "user": {"name": "root"},
    "process": {"name": "cron", "pid": 331485}
  },
  "location": "/var/log/auditbeat/auditbeat-20251206-27.ndjson"
}
```

Key sections to notice:

| Section | Meaning |
|---------|---------|
| `timestamp` | When Wazuh forwarded the alert. Often local timezone. |
| `rule` | Wazuh rule metadata (`level`, `id`, `description`, `groups`). Used by selectors to override behavior. |
| `agent` | Source agent ID, host, and IP. Often becomes the `entity_id` for host entities. |
| `data` | Vendor/product-specific payload. Contains normalized fields such as `@timestamp`, `event`, `user`, `process`, etc. |
| `full_log` | Raw string version of the original alert. |
| `decoder` | Which Wazuh decoder parsed the event (`json`, `pam`, `windows_eventchannel`, ...). |

Different lines include different `rule.id`, `decoder.name`, and `data.*` structures. The mapper must be flexible enough to cope with these variations.

---

## 2. How the Mapper Parses JSON Alerts

The mapper pipeline (`src/ueba/services/mapper/mapper.py`) performs the following steps for every alert:

1. **Mapping Resolution**
   - `AlertMapper` asks the `MappingResolver` (from `mapping_loader.py`) which fields to extract based on `source`, `rule.id`, and `rule.groups`.
   - Canonical fields: `entity_id`, `entity_type`, `severity`, `timestamp`.

2. **Field Extraction**
   - `get_nested_value` walks dot-separated paths such as `agent.id` or `data.srcuser` to fetch values.
   - Literal overrides (e.g., `severity: "15"`) are supported because the mapper returns the literal string if the path lacks dots and `@` prefixes.

3. **Entity Construction**
   - If both `entity_type` and `entity_id` resolve, the mapper builds an `EntityPayload` and `PersistenceManager.upsert_entity` handles insert/update.

4. **Deduplication**
   - `compute_alert_hash` hashes the entire alert payload. If a matching `dedupe_hash` already exists in `raw_alerts`, the mapper skips the duplicate.

5. **Normalized Event Creation**
   - Event type defaults to `<source>_alert` but becomes `<source>_rule_<rule_id>` when a rule ID exists.
   - Severity is reused as a quick-and-dirty risk score placeholder until the analyzer applies its own scoring.

6. **Persistence**
   - `RawAlertPayload` and `NormalizedEventPayload` are persisted via SQLAlchemy. Foreign keys are stitched together once IDs exist.

---

## 3. Customizing Field Mappings with YAML

The default configuration lives in `config/mappings/default.yml`. Important concepts:

### 3.1 Layer Priorities

- `priority: global` layers must define all canonical fields.
- Additional files can declare `priority: integration` or `priority: emergency_override` to selectively override defaults.
- When multiple files exist, order is determined first by priority (global → integration → emergency) and then by file order.

### 3.2 Defaults vs. Selectors

```yaml
defaults:
  entity_id: "agent.id"
  entity_type: "host"
  severity: "rule.level"
  timestamp: "@timestamp"
  enrichment:
    agent_name: "agent.name"
    rule_description: "rule.description"
```

Selectors let you override those defaults when a match occurs:

```yaml
selectors:
  - name: rule-9100-overrides
    match:
      rule_id: "9100"
    fields:
      severity: "15"
      enrichment:
        analyst_note: "High confidence correlation"
```

Source-specific overrides live under `sources.<name>`. Example: for Wazuh login failures we convert events to user entities instead of host entities.

### 3.3 Loading Multiple Files

- Set `UEBA_MAPPING_PATHS` to a colon-separated list (Linux/macOS) or semicolon (Windows) of YAML files.
- Example: `export UEBA_MAPPING_PATHS=config/mappings/default.yml:/etc/ueba/corp-overrides.yml`
- If the environment variable is unset, the loader uses only `config/mappings/default.yml`.

---

## 4. Practical Customization Examples

### Example A – Treat PAM Authentication Failures as User Alerts

```yaml
# corp-overrides.yml
metadata:
  name: pam-failure-users
priority: integration
selectors:
  - name: pam-auth-failure
    match:
      group: "authentication_failed"
    fields:
      entity_type: "user"
      entity_id: "data.user.name"
      severity: "9"
      enrichment:
        username: "data.user.name"
        source_ip: "related.ip[0]"
```
*Result:* Alerts with `rule.groups` containing `authentication_failed` become user-centric, and the analyzer will track risk per username.

### Example B – Add a Windows Source Block with Custom Field Names

```yaml
sources:
  windows:
    defaults:
      entity_type: "host"
      entity_id: "data.win.system.computer"
      timestamp: "data.win.system.systemTime"
      severity: "data.win.system.level"
    selectors:
      - name: lockout
        match:
          custom:
            event_id: "4776"
        fields:
          event_id: "data.win.system.eventID"
          enrichment:
            target_user: "data.win.eventdata.targetUserName"
            status: "data.win.eventdata.status"
```
*Result:* When you run the mapper with `--source windows`, these defaults kick in automatically.

### Example C – Override Severity for a Correlation Rule

```yaml
selectors:
  - name: correlation-5715
    match:
      rule_id: "5715"
    fields:
      severity: "rule.level"
      enrichment:
        correlation: "rule.description"
```
This snippet (already present in `default.yml`) demonstrates how to copy rich context into the normalized payload for later analysis.

---

## 5. Troubleshooting Mapping Issues

| Symptom | Explanation | Fix |
|---------|-------------|-----|
| `Mapping file not found: ...` | Loader resolved a path that doesn’t exist. | Double-check `UEBA_MAPPING_PATHS` values and run from the repository root so relative paths resolve correctly. |
| `Missing required field(s) for global defaults` | A `priority: global` file is missing `entity_id`, `entity_type`, `severity`, or `timestamp`. | Add the missing keys or split the config so a global file always covers all four fields. |
| `Failed to parse timestamp` in mapper metrics | The timestamp string did not match ISO-8601. | Ensure your field points to an ISO timestamp (`2024-01-15T00:00:00Z`). If the log uses epoch seconds, map it to an enrichment key and convert inside a custom mapper extension. |
| Alerts classified as duplicates unexpectedly | The dedupe hash is based on the raw JSON body. If two alerts are identical, the mapper skips the second. | Include an event-specific field (e.g., `data.win.system.eventRecordID`) so each JSON line is unique. |
| Analyzer windows appear empty | Mapper did not attach an `entity_id`. | Verify your YAML resolves both `entity_type` and `entity_id`. Use the mapper logs or temporarily enable `--log-level DEBUG` to see unmapped fields. |

---

## 6. Quick Validation Tips

- **Dry-run the mapper** with higher verbosity: `python -m ueba.services.mapper.mapper_service --log-level DEBUG ...`
- **Inspect normalized payloads** directly:
  ```bash
  sqlite3 ueba.db "SELECT normalized_payload FROM normalized_events LIMIT 3;"
  ```
- **Unit test new mappings** by creating a tiny JSON fixture and running the mapper against it.

---

With these tools you can confidently explain the log schema to stakeholders, adapt the mapper to new data sources, and resolve issues quickly when fields do not populate as expected.
