# Wazuh-Customlv UEBA Documentation Hub

Welcome to the `/docs` workspace. Use the links below to navigate the guides that were written for different audiences (engineers, analysts, and stakeholders).

| Guide | Purpose |
|-------|---------|
| [Setup Guide (SQLite only)](setup-sqlite.md) | Step-by-step instructions to install dependencies, run migrations, ingest sample logs, execute the analyzer, and bring up the FastAPI dashboard without touching PostgreSQL. |
| [Code & Architecture Overview](code-overview.md) | High-level explanation of how mapper, analyzer, API, and dashboard pieces fit together, plus a map to every core module and configuration file. |
| [Log Format & Customization Guide](log-format-customization.md) | Deep dive into the JSON alert structure (`lgexamle.json`), how the mapper interprets it, and how to tailor YAML mappings for new data sources. Includes practical customization examples and troubleshooting tips. |
| [Non-Technical Intake Template](non-technical-template.md) | Plain-language prompt format for business users to describe what they want to monitor, which fields matter, and what counts as anomalous. Includes fill-in-the-blank template and real-world examples. |
| [Quick Reference](quick-reference.md) | Cheat sheet covering frequent tasks, FAQs, and a glossary of UEBA terminology. |

## Suggested Reading Order

1. **New developers** → Start with the [Setup Guide](setup-sqlite.md), then the [Code Overview](code-overview.md).
2. **Log / detection engineers** → Jump to the [Log Format & Customization Guide](log-format-customization.md) after setup.
3. **Analysts & requestors** → Use the [Non-Technical Intake Template](non-technical-template.md) to capture requirements.
4. **Everyone** → Keep the [Quick Reference](quick-reference.md) nearby while operating the stack.

Need more depth? The root-level `README.md`, `INTEGRATION_GUIDE_FRESH_GRADUATES.txt`, and in-code docstrings complement these guides with extra context.
