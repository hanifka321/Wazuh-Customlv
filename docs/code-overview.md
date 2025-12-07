# Code & Architecture Overview

This document orients you within the Wazuh-Customlv UEBA codebase so you can trace data flow, understand the main modules, and locate the right entrypoints.

```
                ┌───────────────┐
                │  Wazuh Logs   │
                └──────┬────────┘
                       │ JSON (lgexamle.json, live streams, etc.)
                       ▼
 ┌────────────────────────────────────────────────────────────────────┐
 │ Mapper Service (src/ueba/services/mapper)                         │
 │  • collects alerts from stdin/file/queue                          │
 │  • applies YAML mappings                                          │
 │  • upserts Entities + Raw Alerts + Normalized Events              │
 └──────────────┬────────────────────────────────────────────────────┘
                │ SQLAlchemy ORM session
                ▼
         ┌───────────────────────┐
         │ SQLite / PostgreSQL   │
         └─────────┬─────────────┘
                   │ batched event windows
                   ▼
 ┌────────────────────────────────────────────────────────────────────┐
 │ Analyzer Service (src/ueba/services/analyzer)                      │
 │  • groups events per entity/day                                    │
 │  • extracts features, evaluates rules, scores risk                 │
 │  • persists EntityRiskHistory + anomaly log file                   │
 └──────────────┬────────────────────────────────────────────────────┘
                │ read models via SQLAlchemy
                ▼
 ┌────────────────────────────────────────────────────────────────────┐
 │ FastAPI + Dashboard (src/ueba/api, templates, static)              │
 │  • REST API exposes entities, history, events, feedback            │
 │  • Dark-mode dashboard consumes API via Basic Auth                 │
 └────────────────────────────────────────────────────────────────────┘
```

---

## 1. Core Database Layer (`src/ueba/db`)

| File | Responsibility | Key Call Sites |
|------|----------------|----------------|
| `base.py` | Creates the SQLAlchemy engine (`get_engine`), session factory (`get_session_factory`), and declarative `Base`. Automatically injects `DATABASE_URL` (defaults to `sqlite:///./ueba.db`). | Imported by mapper, analyzer, and API to open sessions |
| `models.py` | Defines ORM models: `Entity`, `RawAlert`, `NormalizedEvent`, `EntityRiskHistory`, `TPFPFeedback`, and `ThresholdOverride`. Includes helpful mixins for timestamps, soft delete, and status flags. | Used by persistence managers, repositories, and API routers |

Remember: any schema change requires updating this file **and** generating an Alembic migration.

---

## 2. Mapper Service (`src/ueba/services/mapper`)

| Component | Description |
|-----------|-------------|
| `mapper_service.py` | CLI entrypoint (`python -m ueba.services.mapper.mapper_service`). Parses command-line flags, picks an input source (stdin/file/queue stub), loads YAML mappings, and orchestrates ingestion.
| `inputs.py` | Provides iterable input sources: `StdInSource`, `FileTailSource` (with optional `--follow`), and `MessageQueueStubSource` for quick JSON-array testing.
| `mapper.py` | Contains `AlertMapper` which: resolves mapping rules, extracts entity data, calculates dedupe hashes, and produces `EntityPayload`, `RawAlertPayload`, and `NormalizedEventPayload`. The helper functions `get_nested_value`, `parse_iso_timestamp`, and `compute_alert_hash` live in `utils.py`.
| `persistence.py` | `PersistenceManager` writes the payloads using SQLAlchemy. It protects against duplicates via `dedupe_hash` and ensures entities are upserted rather than re-created.
| `utils.py` | Conversion helpers (e.g., `convert_to_int`, `parse_iso_timestamp`) so mapper logic stays clean.

**Main flow:** `run_mapper_service` → builds `AlertMapper` → iterates input → `map_and_persist` → `PersistenceManager` methods.

---

## 3. Configuration Layer (`src/ueba/config` + `/config/mappings`)

- `mapping_loader.py` handles YAML parsing, validation, priorities (`global`, `integration`, `emergency_override`), source-specific selectors, and merges.
- The default mapping file is `config/mappings/default.yml`. It ships with:
  - Canonical defaults (entity id, type, severity, timestamp)
  - Source overrides (`wazuh`, `osquery` examples)
  - Selector blocks that match on `rule_id`, `group`, or custom key/value pairs
- Set `UEBA_MAPPING_PATHS` to load multiple files. Later files with higher priority override earlier defaults.

---

## 4. Analyzer Service (`src/ueba/services/analyzer`)

| File | Role |
|------|------|
| `analyzer_service.py` | CLI harness. Handles `--mode once|daemon`, `--since`, `--until`, `--interval`, and `--database-url`. Once configured, it instantiates `AnalyzerService` and runs the requested mode.
| `service.py` | Core orchestration. Opens a session via `get_session_factory`, fetches windows from `AnalyzerRepository`, runs `AnalyzerPipeline`, compares against `BaselineCalculator`, logs anomalies, and stores results.
| `repository.py` | Data access helpers: `fetch_entity_event_windows`, `persist_result`, `get_latest_checkpoint`, etc. Groups normalized events into once-per-day windows per entity.
| `pipeline.py` | Defines the feature extraction + rule evaluation + scoring pipeline. Defaults to `SimpleFeatureExtractor`, `PlaceholderRuleEvaluator`, and `SimpleScoring`, all of which can be swapped for custom logic.
| `baseline.py` | Implements rolling baseline/standard deviation logic. Reads `UEBA_BASELINE_WINDOW_DAYS` and `UEBA_SIGMA_MULTIPLIER` from the environment.
| `service.py` + `AlertLogger` | When an anomaly is detected, it writes a structured JSON line into `ueba_alerts.log` using `src/ueba/logging/alert_logger.py`.

---

## 5. API & Dashboard Layer (`src/ueba/api`, `templates/`, `static/`)

| Component | Highlights |
|-----------|------------|
| `main.py` | Creates the FastAPI app, mounts static assets, wires routers, exposes `/login` for session tokens, and serves the Jinja dashboard template.
| `auth.py` | Implements HTTP Basic auth based on `UEBA_DASH_USERNAME` / `UEBA_DASH_PASSWORD`. The `get_api_credentials` helper is reused by routers.
| `routers/health.py` | Simple readiness endpoint.
| `routers/entities.py`, `events.py`, `feedback.py` | CRUD-style routers that query SQLAlchemy models using FastAPI dependencies.
| `schemas.py` | Pydantic models used by routers for request/response validation.
| `templates/dashboard.html` + `static/` | Dark-mode UI built with Bootstrap 5 + Bootswatch + Chart.js. The JS uses fetch calls to hit the API endpoints secured by Basic Auth.

---

## 6. Supporting Modules

- `src/ueba/logging/alert_logger.py` – newline-delimited JSON logger for analyzer anomalies.
- `src/ueba/utils` – helper utilities (datetime parsing, hashing, environment helpers).
- `scripts/` – convenience shell scripts (e.g., `scripts/migrate_sqlite.sh`).
- `tests/` – Pytest suite covering dashboard template, mapper config validation, analyzer math, etc.

---

## 7. Key Functions & Where They Live

| Task | Function / Class | Notes |
|------|------------------|-------|
| Run mapper from CLI | `run_mapper_service` + `main()` in `mapper_service.py` | Accepts flags for input type, mapping paths, DB URL, batch size. |
| Map a single alert | `AlertMapper.map_alert` | Returns a `MappedAlert` with entity/raw/event payloads and metrics. |
| Persist artifacts | `PersistenceManager.upsert_entity`, `.persist_raw_alert`, `.persist_normalized_event` | Called inside `map_and_persist`. |
| Run analyzer once | `AnalyzerService.run_once` | Accepts optional `since`/`until` datetimes and returns number of processed windows. |
| Fetch analysis windows | `AnalyzerRepository.fetch_entity_event_windows` | Groups normalized events into per-day buckets. |
| Calculate baseline & anomaly | `BaselineCalculator.is_anomalous` | Uses rolling average + sigma multiplier. |
| Expose API routes | Functions in `src/ueba/api/routers/*.py` | Each router file defines FastAPI endpoints tied to schemas and DB queries. |

---

## 8. Configuration Cheat Sheet

| File / Variable | Purpose |
|-----------------|---------|
| `.env` | Store `DATABASE_URL`, dashboard credentials, optional baseline settings. Loaded automatically by `ueba.db.base`. |
| `UEBA_MAPPING_PATHS` | Colon-separated list of YAML files consumed by `mapping_loader`. |
| `UEBA_ALERT_LOG_PATH` | Overrides the analyzer alert log location (defaults to `./ueba_alerts.log`). |
| `UEBA_BASELINE_WINDOW_DAYS`, `UEBA_SIGMA_MULTIPLIER` | Tune anomaly detection sensitivity. |
| `Makefile` targets | `make setup`, `make db-upgrade`, `make run-dashboard`, etc. |

Use `make help` to see every convenience task.

---

Armed with this overview, you can quickly drill down to the file or function you need when working tickets or implementing customizations. Pair this with the other documents for log-format guidance, non-technical intake, and daily operations.
