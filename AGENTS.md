# Repository Guidelines

## Project Structure & Module Organization
- `ingest_cves.py` handles CVE ingestion into PostgreSQL (`initial`, `incremental` modes).
- `settings.py` loads required settings from a local `.env` file.
- `db_schema.sql` defines ingestion tables (`cve`, `ingest_job_log`, `ingest_checkpoint`).
- `nvd_fetch.py` is a console query helper for keyword and CVSS filtering.
- `requirements.txt` lists Python dependencies.
- `README.md` documents setup and usage.
- There is no `tests/` directory yet; add one when introducing tests.

## Build, Test, and Development Commands
- Create and activate a virtual environment, then install deps:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.sample .env
```

- Apply schema:

```bash
psql -h <host> -p <port> -U <user> -d <db> -f db_schema.sql
```

- Run initial ingestion (published date lookback):

```bash
python3 ingest_cves.py --mode initial
```

- Run incremental ingestion (lastModified sync in 14-day chunks by default):

```bash
python3 ingest_cves.py --mode incremental
```

- Run the console query helper:

```bash
python3 nvd_fetch.py --product nginx --min-cvss 7.0
```

Use `--config` if your config file path is not `.env`.

## Coding Style & Naming Conventions
- Python 3.10+.
- Indentation: 4 spaces, no tabs.
- Prefer clear, descriptive names in `snake_case` for functions and variables.
- Type hints are already used; keep them consistent when adding functions.
- No formatter or linter is configured yet; keep code readable and PEP 8 aligned.

## Testing Guidelines
- There are currently no automated tests.
- If you add tests, place them under `tests/` and use `pytest`.
- Suggested naming: `tests/test_*.py`, with test functions named `test_*`.

## Commit & Pull Request Guidelines
- Commit history uses short, imperative subjects (e.g., “Add …”, “Initialize …”).
- Keep commits focused and describe the user-visible change.
- PRs should include a brief summary, verification steps (commands or example inputs), and linked issues when applicable.

## Security & Configuration Tips
- Store secrets in `.env` only; never commit real values.
- Keep `.env.sample` with placeholders only (e.g., `NVD_API_KEY=""`).
- Core runtime knobs are configurable in `.env`: `INITIAL_LOOKBACK_YEARS`, `INCREMENTAL_WINDOW_DAYS`, and DB connection values.
