# Quick Reference

A handy cheat sheet for the most common UEBA maintenance tasks, questions, and terminology.

---

## 1. Common Tasks

### Add a New Entity Type
1. **Decide the identifier** (hostnames, usernames, IPs, etc.).
2. **Update mappings** in `config/mappings/*.yml` so `entity_type` and `entity_id` resolve for that alert.
3. **Re-run the mapper** on representative data to populate the new entities.
4. **Verify** using:
   ```bash
   sqlite3 ueba.db "SELECT entity_type, COUNT(*) FROM entities GROUP BY entity_type;"
   ```

### Customize Analyzer Thresholds
1. Set environment variables (affects next analyzer run):
   ```bash
   export UEBA_BASELINE_WINDOW_DAYS=45
   export UEBA_SIGMA_MULTIPLIER=2.5
   ```
2. OR add entity-specific overrides in the `threshold_overrides` table via SQL or an admin API once available.
3. Rerun `python -m ueba.services.analyzer.analyzer_service --mode once` to apply.

### Add a New Risk Rule
1. Open `src/ueba/services/analyzer/pipeline.py`.
2. Create a new rule inside `PlaceholderRuleEvaluator.evaluate` or subclass `RuleEvaluator`.
3. Add logic based on `features` (event count, severity, etc.) or inspect the `events` list directly.
4. Wire the custom evaluator into `AnalyzerPipeline` (pass it when instantiating `AnalyzerService`).
5. Re-run analyzer and confirm new rule names appear in `entity_risk_history.reason -> rules.triggered`.

### Run the Dashboard Quickly
```bash
make run-dashboard
```
- Uses `uvicorn ueba.api.main:app --reload --host 0.0.0.0`.
- Requires `UEBA_DASH_USERNAME` and `UEBA_DASH_PASSWORD`.

### Reset the Environment
```bash
rm -f ueba.db ueba_alerts.log
make db-upgrade
```
This recreates the schema on SQLite. Re-ingest logs afterward.

---

## 2. FAQ

**Q: Do I need PostgreSQL?**  
A: No. SQLite is the default and works for single-node development. PostgreSQL is optional for scale.

**Q: Where do I change log mappings?**  
A: Edit YAML files under `config/mappings/` and/or provide your own via the `UEBA_MAPPING_PATHS` environment variable.

**Q: What creates `ueba_alerts.log`?**  
A: The analyzer’s `AlertLogger` writes a JSON line every time a window’s risk score exceeds the rolling baseline threshold.

**Q: How do I ingest a saved JSON file?**  
A: `python -m ueba.services.mapper.mapper_service --input file --file /path/to/file.jsonl --source <name>`.

**Q: The dashboard says 401 Unauthorized. What now?**  
A: Export `UEBA_DASH_USERNAME` and `UEBA_DASH_PASSWORD` (or store them in `.env`) before starting the API. Basic Auth is enforced for every route.

**Q: Analyzer reports "nothing to process". Why?**  
A: Either there are no normalized events with `entity_id`, or the latest checkpoint is newer than the requested window. Pass `--since` to backfill.

---

## 3. Glossary

| Term | Definition |
|------|------------|
| **Entity** | A unique thing you track (host, user, IP). Stored in the `entities` table. |
| **Raw Alert** | Unmodified JSON ingested from Wazuh or other sources. Stored in `raw_alerts` with `dedupe_hash`. |
| **Normalized Event** | Structured event referencing an entity and carrying normalized payload fields. Input to the analyzer. |
| **Entity Risk History** | Daily roll-up of risk scores per entity. Feeds the dashboard sparklines and alerts. |
| **Mapper** | CLI service that reads JSON logs, applies YAML mappings, and populates the database. |
| **Analyzer** | CLI service that groups events, evaluates rules, calculates risk scores, and detects anomalies. |
| **Baseline** | Rolling average + standard deviation of previous risk scores used to decide if today is unusual. |
| **Threshold Override** | Manual rule stored in `threshold_overrides` to raise/lower acceptable metrics for an entity or analyzer key. |
| **UEBA Mapping** | YAML instructions telling the mapper how to pull values (entity IDs, severity, enrichment) from nested JSON fields. |
| **Dedupe Hash** | SHA-256 checksum of the alert payload. Prevents double-ingesting the same alert. |

Pin or print this page so you have the essentials at your fingertips while working on the platform.
