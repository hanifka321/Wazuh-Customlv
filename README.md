# Wazuh Custom - UEBA System

This repository contains a User and Entity Behavior Analytics (UEBA) system built to extend, automate, and enhance Wazuh operations. The system is designed to solve real-world use cases in threat detection, log analysis, and automation for Wazuh environments.

See `INTEGRATION_GUIDE_FRESH_GRADUATES.txt` for detailed onboarding.

## Architecture Overview

The UEBA system consists of two main services that share a consistent database schema:

1. **Mapper Service** - Ingests raw alerts and normalizes them into structured events
2. **Analyzer Service** - Analyzes normalized events to calculate entity risk scores

## Project Structure

```
.
├── src/ueba/              # Core UEBA package
│   ├── db/                # Database models and configuration
│   │   ├── base.py        # SQLAlchemy engine and session setup
│   │   └── models.py      # ORM models for all tables
│   └── __init__.py
├── alembic/               # Database migrations
│   ├── versions/          # Migration scripts
│   └── env.py             # Alembic environment configuration
├── scripts/               # Helper scripts
├── .env.example           # Example environment configuration
├── alembic.ini            # Alembic configuration
├── pyproject.toml         # Project dependencies and metadata
└── Makefile               # Convenience commands
```

## Database Schema

The system uses six core tables for Phase 0:

### 1. `entities`
Stores unique entities (users, hosts, IP addresses, etc.) tracked by the system.
- **Key fields**: `entity_type`, `entity_value`, `display_name`
- **Indexes**: Unique index on `(entity_type, entity_value)`
- **Mixins**: Timestamps, soft delete, status

### 2. `raw_alerts`
Stores raw alerts ingested from various sources (Wazuh, etc.).
- **Key fields**: `source`, `vendor`, `product`, `severity`, `observed_at`, `original_payload`
- **Indexes**: `(entity_id, observed_at)` for efficient queries
- **Foreign keys**: `entity_id` → `entities.id` (SET NULL on delete)
- **JSON fields**: `original_payload` (required), `enrichment_context` (optional)

### 3. `normalized_events`
Stores normalized, structured events derived from raw alerts.
- **Key fields**: `event_type`, `risk_score`, `observed_at`, `summary`
- **Indexes**: `(entity_id, observed_at)` for time-series queries
- **Foreign keys**: 
  - `raw_alert_id` → `raw_alerts.id` (SET NULL on delete)
  - `entity_id` → `entities.id` (SET NULL on delete)
- **JSON fields**: `normalized_payload`, `original_payload`

### 4. `entity_risk_history`
Tracks historical risk scores for each entity over time.
- **Key fields**: `entity_id`, `risk_score`, `observed_at`, `reason`
- **Indexes**: `(entity_id, observed_at)` for time-series analysis
- **Foreign keys**: 
  - `entity_id` → `entities.id` (CASCADE on delete)
  - `normalized_event_id` → `normalized_events.id` (SET NULL on delete)

### 5. `tp_fp_feedback`
Stores analyst feedback on true positives and false positives.
- **Key fields**: `entity_id`, `feedback_type`, `notes`, `submitted_by`, `submitted_at`
- **Foreign keys**:
  - `entity_id` → `entities.id` (CASCADE on delete)
  - `normalized_event_id` → `normalized_events.id` (SET NULL on delete)

### 6. `threshold_overrides`
Stores custom thresholds for specific entities or global rules.
- **Key fields**: `analyzer_key`, `metric`, `threshold_value`, `comparison`, `effective_from`, `effective_to`
- **Foreign keys**: `entity_id` → `entities.id` (SET NULL on delete, NULL = global override)

### Common Features

All tables include:
- **Timestamps**: `created_at`, `updated_at` (auto-managed)
- **Soft delete**: `deleted_at` (NULL = active)
- **Status flags**: `status` (default: 'active')

## Setup

**New to the project?** See `INTEGRATION_GUIDE_FRESH_GRADUATES.txt` for a complete step-by-step onboarding guide covering environment setup, core concepts, risk scoring algorithms, testing, and troubleshooting.

### Prerequisites

- Python 3.9+
- SQLite (included) or PostgreSQL (optional)

### Quick Start

1. **Clone and enter the repository**:
   ```bash
   cd /path/to/repository
   ```

2. **Set up environment**:
   ```bash
   # Copy example environment file
   cp .env.example .env
   
   # Edit .env to configure your database (optional)
   # Default is SQLite at ./ueba.db
   vim .env
   ```

3. **Install dependencies and run migrations**:
   ```bash
   make setup      # Create venv and install dependencies
   make db-upgrade # Apply all migrations
   ```

### Using PostgreSQL

To use PostgreSQL instead of SQLite:

1. Install PostgreSQL support:
   ```bash
   source venv/bin/activate
   pip install psycopg[binary]
   ```

2. Update `.env`:
   ```bash
   DATABASE_URL=postgresql+psycopg://username:password@localhost:5432/ueba
   ```

3. Run migrations:
   ```bash
   make db-upgrade
   ```

## Database Connection for Services

Both the **mapper** and **analyzer** services obtain database connections using the same approach:

```python
from ueba.db.base import get_session_factory

# Get a session factory
SessionFactory = get_session_factory()

# Use in application
with SessionFactory() as session:
    # Your database operations here
    entities = session.query(Entity).all()
    session.commit()

# Or use the pre-configured SessionLocal
from ueba.db.base import SessionLocal

with SessionLocal() as session:
    # Your operations
    pass
```

The connection is automatically configured from the `DATABASE_URL` environment variable.

## Migration Commands

### Helper Script (SQLite)

```bash
./scripts/migrate_sqlite.sh
```

This script ensures `DATABASE_URL` points to `sqlite:///$(pwd)/ueba.db` and then runs `alembic upgrade head`. Optionally set `DATABASE_URL` before running to override the location.

### Using Make (Recommended)

```bash
# Apply all pending migrations
make db-upgrade

# Rollback the last migration
make db-downgrade

# Generate a new migration after modifying models
make db-migrate MSG="Add new field to entities"

# Reset database (WARNING: deletes all data)
make db-reset

# Open SQLite shell to inspect database
make db-shell

# Show all available commands
make help
```

### Using Alembic Directly

```bash
source venv/bin/activate

# Apply migrations
alembic upgrade head

# Rollback one migration
alembic downgrade -1

# Show current revision
alembic current

# Show migration history
alembic history

# Generate new migration (auto-detect changes)
alembic revision --autogenerate -m "Description of changes"

# Generate empty migration (manual changes)
alembic revision -m "Description of changes"
```

## Development Workflow

### Adding New Models

1. Edit `src/ueba/db/models.py` to add/modify models
2. Generate migration: `make db-migrate MSG="Add new table"`
3. Review generated migration in `alembic/versions/`
4. Apply migration: `make db-upgrade`

### Testing Migrations Locally

```bash
# Start fresh
make db-reset

# Verify all tables exist
make db-shell
sqlite> .tables
sqlite> .schema entities
sqlite> .exit
```

### SQLite Development Tips

```bash
# View all tables
sqlite3 ueba.db ".tables"

# View schema for a table
sqlite3 ueba.db ".schema entities"

# Query data
sqlite3 ueba.db "SELECT * FROM entities LIMIT 10;"

# Use the shell interactively
make db-shell
```

## Field Mapping Configuration

The mapper service normalizes raw Wazuh alerts using YAML-driven field mappings. The
loader (`ueba.config.mapping_loader.load`) reads one or more YAML files and merges them
according to priority: `global` < `integration` < `emergency_override`. By default the
loader reads `config/mappings/default.yml`, but you can override the list of files by
setting the `UEBA_MAPPING_PATHS` environment variable to an `os.pathsep`-separated list
of paths.

Each mapping file supports the following top-level sections:

- `metadata.name` – friendly identifier for troubleshooting.
- `priority` – one of `global`, `integration`, or `emergency_override`.
- `excluded_entities` – optional list of entity values to ignore entirely. Supports exact
  matches (`"root"`, `"admin"`) and Unix-style wildcards (`"system_*"`, `"service_*"`).
  Excluded entities are never upserted by the mapper and are filtered out by the analyzer.
- `defaults` – canonical field definitions (entity_id, entity_type, severity, timestamp,
  and optional enrichment key/value pairs).
- `selectors` – optional overrides that match on `rule_id`, `group`, or custom key/value
  pairs. The loader automatically prefers rule matches, then group matches, and finally
  custom matches, falling back to defaults when nothing matches.
- `sources` – per-data-source overrides. Each source may define its own `defaults` and
  `selectors` block. When a selector lives under `sources.<name>` it implicitly matches
  only that source.

Example snippet:

```
metadata:
  name: default-wazuh
priority: global

# Optional: Exclude service accounts and system entities
excluded_entities:
  - root
  - admin
  - system_*
  - service_*

defaults:
  entity_id: agent.id
  entity_type: host
  severity: rule.level
  timestamp: "@timestamp"
  enrichment:
    agent_name: agent.name

sources:
  wazuh:
    defaults:
      entity_type: endpoint
    selectors:
      - name: auth-failure
        match:
          group: authentication_failed
        fields:
          entity_type: user
          entity_id: data.srcuser
```

A more complete, commented example lives at `config/mappings/example-with-exclusions.yml`.

To add a new mapping file, drop it in `config/mappings/` (or any accessible directory)
and set `UEBA_MAPPING_PATHS` to include its path. Files later in the list override fields
from earlier files according to their declared priority. Validation errors include the
source file and line number to simplify debugging.

## Mapper Service

The mapper service ingests raw alerts, applies YAML mappings, and persists entities plus
normalized events.

### CLI usage

```
python -m ueba.services.mapper.mapper_service \
  --input stdin \
  --source wazuh \
  --database-url sqlite:///./ueba.db \
  --mapping-paths config/mappings/default.yml
```

Input sources:

- `stdin` (default): newline-delimited JSON payloads.
- `file`: tail an on-disk file (`--file /path/to/alerts.jsonl`, optional `--follow`).
- `queue`: stubbed message queue. Provide a JSON array via STDIN.

The service accepts `--batch-size` (commit frequency) and `--log-level` for structured
logging. Idempotency is enforced using a `dedupe_hash`, ensuring retries do not create
duplicate rows.

Sample fixture alerts live at `tests/fixtures/sample_alerts.jsonl` for quick manual tests.

## Analyzer Service

The analyzer service consumes normalized events, groups them by entity plus UTC day, and
persists aggregate risk history to `entity_risk_history`. It is intentionally lightweight so
it can run via cron or as a long-running worker.

### CLI usage

```
python -m ueba.services.analyzer.analyzer_service --mode once
```

Common options:

- `--mode once|daemon` – Run once (cron-friendly) or loop with a polling interval
- `--since/--until` – ISO 8601 timestamps to override the default checkpoint window
- `--interval` – Polling interval (seconds) for daemon mode (default: 300)
- `--database-url` – Optional database override (defaults to `DATABASE_URL`)
- `--log-level` – Logging verbosity

Each run processes complete UTC-day windows and writes a JSON payload to `reason` with the
following structure:

```json
{
  "generator": "analyzer_service",
  "kind": "daily_rollup",
  "event_count": 12,
  "highest_severity": 9,
  "window_start": "2024-01-15T00:00:00+00:00",
  "window_end": "2024-01-16T00:00:00+00:00",
  "last_observed_at": "2024-01-15T14:30:00+00:00",
  "rules": {
    "triggered": ["high_event_volume"],
    "metadata": {"event_count": 12}
  },
  "baseline": {
    "avg": 32.5,
    "sigma": 8.2,
    "delta": 15.0,
    "is_anomalous": true
  }
}
```

This metadata allows downstream APIs to surface event counts, highest severity, baseline metrics,
and the last processed timestamp for each entity/day. The checkpoint for incremental runs is derived
from the latest `observed_at` value written by the analyzer.

### Baseline Risk Engine

The Phase 1 baseline risk engine computes an average and population standard deviation of the last
`UEBA_BASELINE_WINDOW_DAYS` windows for each entity to identify anomalies. Configure the engine via
environment variables:

- `UEBA_BASELINE_WINDOW_DAYS` – lookback period for baseline (default: 30 days)
- `UEBA_SIGMA_MULTIPLIER` – anomaly threshold multiplier (default: 3.0)
- `UEBA_ALERT_LOG_PATH` – path for newline-delimited JSON alert logs (default: `./ueba_alerts.log`)

Each anomaly log contains timestamp, entity ID, risk score, baseline statistics, delta from average,
and triggered rules. The analyzer CLI automatically picks up these env vars when running.

## UEBA Dashboard UI

A dark-mode, Bootswatch Darkly-themed web dashboard provides real-time visualization of entity risk scores,
baseline analysis, and triggering events. The dashboard requires Basic Auth credentials (from `UEBA_DASH_USERNAME`
and `UEBA_DASH_PASSWORD` environment variables) and includes session cookie management for seamless user experience.

### Features

- **Entity Roster**: Searchable list of entities with latest risk scores, delta from baseline, and triggered event counts
- **Detail Pane**: Shows selected entity's latest risk score, baseline comparison, triggering rules, and normalized events
- **Risk History Sparkline**: Chart.js-based sparkline visualization of risk history (last 100 days)
- **Event Details**: Expandable JSON view of normalized events with rule names and timestamps
- **Manual Refresh**: Button-triggered API refresh with last-refresh timestamp display
- **Login Form**: Simple login interface with session cookie storage (no hardcoded credentials in JS)
- **Dark Mode**: Bootswatch Darkly CSS for accessibility in low-light environments

### Running the Dashboard

**Prerequisites:**
- Environment variables configured: `UEBA_DASH_USERNAME`, `UEBA_DASH_PASSWORD`
- Database migrations applied: `make db-upgrade`
- Sample data in the database (from analyzer or mapper services)

**Start the dashboard:**

```bash
# Option 1: Using make target (recommended)
make run-dashboard

# Option 2: Direct uvicorn command
source venv/bin/activate
uvicorn ueba.api.main:app --reload --host 0.0.0.0

# Option 3: With specific port
source venv/bin/activate
uvicorn ueba.api.main:app --reload --host 0.0.0.0 --port 8000
```

The dashboard will be available at `http://localhost:8000/` (or the configured host:port).

### Configuration

Set these environment variables before running:

```bash
# Authentication credentials (required)
export UEBA_DASH_USERNAME=admin
export UEBA_DASH_PASSWORD=your_secure_password

# Database URL (optional, defaults to SQLite)
export DATABASE_URL=sqlite:///$(pwd)/ueba.db

# Baseline analysis settings (optional, used by API)
export UEBA_BASELINE_WINDOW_DAYS=30
export UEBA_SIGMA_MULTIPLIER=3.0
```

### API Endpoints

The dashboard consumes the following read-only API endpoints (all require Basic Auth):

- `GET /api/v1/entities` – Paginated roster of entities
- `GET /api/v1/entities/{entity_id}/history` – Risk history for an entity
- `GET /api/v1/entities/{entity_id}/events` – Recent normalized events
- `POST /login` – Create a session token for the dashboard

### Architecture

- **Frontend**: Jinja2 HTML template + vanilla JavaScript with Chart.js for visualizations
- **Styling**: Bootstrap 5 + Bootswatch Darkly theme + custom dark-mode CSS
- **Session Management**: Signed session cookies (24-hour TTL, stored in browser)
- **API Integration**: Fetch-based HTTP requests with Bearer token authentication

### Testing

Dashboard template and functionality tests are in `tests/test_dashboard_template.py`:

```bash
make test tests/test_dashboard_template.py
```

Key test coverage:
- Template renders at `/` with proper HTML structure
- CSS includes Bootswatch Darkly and dark-mode colors
- JavaScript initializes login modal and dashboard class
- Login endpoint validates credentials
- Static files are properly mounted
- All expected UI elements (search, refresh button, etc.) are present

## Phase 0 - Foundation

This is **Phase 0** of the UEBA system implementation. The current implementation includes:

✅ Core database tables (`entities`, `raw_alerts`, `normalized_events`, etc.) - Task 1/5  
✅ Foreign key relationships with appropriate delete behaviors  
✅ Indexes for efficient queries on `(entity_id, observed_at)`  
✅ JSON columns for flexible payload storage  
✅ Timestamp defaults and soft-delete support  
✅ Migration workflow with Alembic  
✅ SQLite support for local development  
✅ PostgreSQL support for production (optional)  
✅ YAML-driven field mapping system with priority-based configuration - Task 2/5  
✅ Mapper service with multi-source ingestion (STDIN, file, message queue stub) - Task 3/5  
✅ Entity upsert and normalized event persistence with idempotency guards  
✅ Structured logging and mapping metrics (latency, unmapped fields)  
✅ Unit tests with fixture alerts and SQLite test databases  
✅ Analyzer service with pluggable pipeline (feature extraction, rules, scoring) - Task 4/5  
✅ UTC-aligned daily rollup windows for entity risk history  
✅ Idempotent checkpoint mechanism for incremental processing  
✅ Cron-compatible CLI with daemon mode support  
✅ Comprehensive unit tests for analyzer repository, pipeline, and service  

Future phases will add additional tables and features through separate migrations.

## Contributing

When adding new database changes:

1. Always use migrations - never modify the database directly
2. Test migrations both upgrade and downgrade
3. Document any new tables or significant schema changes in this README
4. Use meaningful migration messages

## License

This project is part of the Wazuh Custom toolkit.
