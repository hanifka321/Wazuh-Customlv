# Wazuh-Customlv UEBA — SQLite Setup Guide

This guide walks through a complete end-to-end installation using only the built-in SQLite database. Follow the steps in order and you will have the mapper, analyzer, and FastAPI dashboard running on your workstation.

> **Tip:** Every command below assumes you are inside the project root (`/home/engine/project` or your cloned path).

---

## 1. Prerequisites

| Requirement | Notes |
|-------------|-------|
| Python 3.9+ | Verify with `python3 --version` |
| Git         | Used to clone/update the repo |
| SQLite      | Already bundled with Python, no extra action needed |
| Make        | Speeds up repetitive commands |

No PostgreSQL, Docker, or message queue is required for this workflow.

---

## 2. Prepare Environment Variables

1. Copy the example environment file:
   ```bash
   cp .env.example .env
   ```
2. Open `.env` and confirm (or add) a SQLite connection string that points to your repo path. Example:
   ```bash
   DATABASE_URL=sqlite:////home/you/path/to/repo/ueba.db
   ```
3. (Optional) Set dashboard credentials now so you do not forget later:
   ```bash
   echo "UEBA_DASH_USERNAME=admin" >> .env
   echo "UEBA_DASH_PASSWORD=change_me" >> .env
   ```

The services automatically read these values via `python-dotenv` when they start.

---

## 3. Create the Virtual Environment & Install Dependencies

Use the Makefile helpers to avoid manual pip commands:
```bash
make setup
```
This creates `venv/` and installs SQLAlchemy, Alembic, FastAPI, uvicorn, and all supporting libraries.

> **Verify:** Activate the virtual environment (`source venv/bin/activate`) and run `python -m pip list | grep SQLAlchemy` to confirm version `2.0.22` (or newer if future updates occur).

---

## 4. Create the SQLite Database Schema

Apply the Alembic migrations so the six core tables exist:
```bash
make db-upgrade
```

> **Verify:**
> ```bash
> sqlite3 ueba.db ".tables"
> ```
> You should see `entities`, `raw_alerts`, `normalized_events`, `entity_risk_history`, `tp_fp_feedback`, and `threshold_overrides` listed.

---

## 5. Run the Mapper Service (Ingest Sample Alerts)

Feed the provided Wazuh sample logs (`lgexamle.json`) through the mapper:
```bash
source venv/bin/activate
python -m ueba.services.mapper.mapper_service \
  --input file \
  --file lgexamle.json \
  --source wazuh \
  --database-url sqlite:///$(pwd)/ueba.db \
  --mapping-paths config/mappings/default.yml
```
What happens:
1. Each JSON line is parsed.
2. YAML mappings resolve the entity, severity, and enrichment fields.
3. Entities, raw alerts, and normalized events are written to SQLite.

> **Verify:** After the command finishes, run:
> ```bash
> sqlite3 ueba.db "SELECT COUNT(*) FROM normalized_events;"
> ```
> The count should match the number of ingested log lines (9 in the sample file).

---

## 6. Run the Analyzer Service

Process the normalized events into daily risk scores:
```bash
source venv/bin/activate
python -m ueba.services.analyzer.analyzer_service --mode once
```
The analyzer groups events per entity per UTC day, evaluates placeholder rules, calculates risk scores, and stores results in `entity_risk_history`.

> **Verify:**
> ```bash
> sqlite3 ueba.db "SELECT entity_id, risk_score, observed_at FROM entity_risk_history;"
> ```
> You should see at least one row per entity/day window.

If anomalies are detected, `ueba_alerts.log` appears in the project root with newline-delimited JSON entries.

---

## 7. Start the FastAPI Dashboard

Two helpful options:

### Option A – Makefile Helper (Recommended)
```bash
make run-dashboard
```
- Binds to `http://0.0.0.0:8000/` so you can access it from `http://localhost:8000/`.

### Option B – Manual uvicorn Command
```bash
source venv/bin/activate
uvicorn ueba.api.main:app --reload --host 0.0.0.0 --port 8000
```

Log in with the `UEBA_DASH_USERNAME` and `UEBA_DASH_PASSWORD` you stored earlier. The dashboard reads from the same SQLite file, so the entities and risk scores you created instantly appear.

---

## 8. Smoke Tests & Health Checks

1. **API Health Endpoint**
   ```bash
   curl -u "$UEBA_DASH_USERNAME:$UEBA_DASH_PASSWORD" http://localhost:8000/api/v1/health
   ```
   Expect `{ "status": "ok" }`.

2. **Entity Listing**
   ```bash
   curl -u "$UEBA_DASH_USERNAME:$UEBA_DASH_PASSWORD" http://localhost:8000/api/v1/entities?limit=5
   ```
   Confirms the API can read from SQLite and paginate results.

3. **Dashboard Page**
   Open `http://localhost:8000/` in a browser, log in, and verify:
   - Entity roster shows the ingested host `deb12` (based on the sample logs).
   - Risk history sparkline renders without errors (requires at least one analyzer run).

4. **Analyzer Alert Log**
   ```bash
   tail -n 5 ueba_alerts.log
   ```
   Each line is JSON containing `entity_id`, `risk_score`, and `triggered_rules`.

---

## 9. Resetting & Re-running

Need a clean slate? Use:
```bash
rm -f ueba.db ueba_alerts.log
make db-upgrade
```
Then repeat steps 5–8.

---

## 10. Troubleshooting Quick Hits

| Symptom | Fix |
|---------|-----|
| `sqlite3: command not found` | Install SQLite (`sudo apt install sqlite3`). |
| Mapper logs "Mapping file not found" | Confirm `config/mappings/default.yml` exists and the working directory is the repo root. |
| Analyzer reports "checkpoint newer than requested window" | Delete/rename `entity_risk_history` rows or pass `--since` with an older timestamp. |
| Dashboard returns HTTP 401 | Ensure `UEBA_DASH_USERNAME`/`UEBA_DASH_PASSWORD` exist in `.env` and you exported them in your shell (`source .env`). |
| `OperationalError: attempt to write a readonly database` | Make sure SQLite file is writable (not stored in a protected directory). |

You now have a functioning UEBA stack entirely on SQLite. Continue to the other documents in `/docs` for deeper architecture, customization, and process knowledge.
