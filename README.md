# SOAR ML MVP

This repository implements an MVP for a Security Orchestration, Automation, and Response (SOAR) system. It receives SIEM-style alerts, enriches them, uses machine learning to assess risk, selects YAML playbooks, and records analyst decisions.

## Scope

- Alert types: SSH brute force, RDP brute force, suspicious IP, malicious file hash
- Playbooks: `block_ip`, `create_ticket`, `notify_telegram`
- Dataset: CIC-IDS2017 (current explicit label mapping; UNSW-NB15 is not yet supported)
- Dashboard: intentionally out of scope
- IP blocking and ticket creation are local simulations; real Telegram messages require explicit opt-in

## Architecture

```text
SIEM
  -> POST /alerts (FastAPI)
  -> Enrichment (VirusTotal / AbuseIPDB / GeoIP)
  -> ML scoring (risk, label, SHAP features)
  -> YAML playbook selection
  -> Simulated actions and SQLite audit records
  -> Analyst approval for dangerous actions
  -> Feedback stored for retraining
```

The system is split into `api`, `enrichment`, `ml`, `playbooks`, `bot`, `data`, and `tests`. Redis and Celery are not used.

## ML training

Place the eight CIC-IDS2017 day CSV files in `data/raw/`. The loader uses the CIC `Label`
column with an explicit benign/attack label map and rejects unknown labels. The
synthetic dataset generator is for smoke testing only, not thesis evaluation.

For an immediate local validation run without downloading a dataset:

```powershell
python -m ml.create_demo_data
```

```powershell
python -m ml.eda
python -m ml.evaluate
```

Evaluation cleans the real dataset, uses a reproducible 100,000-row stratified sample
with an 80/20 split, and also measures a Mon-Wed train / Thu-Fri test split. It writes
the best model to `models/best_model.joblib`, metrics to `results/metrics.csv`, and
figures and baseline comparison into `results/`. Precision, recall, and F1 use malicious
as the positive class.

To inspect data interactively, open `ml/eda.ipynb`.

## Setup

Python 3.11 or newer is required.

```powershell
cd soar-ml
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
Copy-Item .env.example .env
```

No API keys are required for development. Missing enrichment keys activate mock enrichment.
Telegram delivery stays simulated unless it is explicitly enabled in `.env`.

## Run the API

After placing CIC-IDS2017 CSVs and evaluating a model:

```powershell
python -m ml.evaluate
uvicorn api.main:app --reload
```

Open `http://127.0.0.1:8000/docs` for Swagger UI. Send a test alert:

```powershell
curl.exe -X POST "http://127.0.0.1:8000/alerts" -H "Content-Type: application/json" -d "{\"alert_type\":\"suspicious IP\",\"source\":{\"ip\":\"198.51.100.10\"},\"destination_port\":3389,\"features\":{\"Duration\":2.0,\"Destination Port\":3389}}"
```

## Playbooks

The playbook engine loads YAML files from `playbooks/` and matches alert type, ML label,
and minimum risk. The bundled playbooks are `block_ip`, `create_ticket`, and
`notify_telegram`. Blocking is always simulated; notifications are simulated unless
Telegram is explicitly enabled. Ticket files are written under `data/tickets/`; pipeline and
action records are stored in `data/soar.db`.

### Telegram setup

Copy `.env.example` to `.env`, then set the bot token and destination chat ID. The
example file contains placeholders only and `.env` is ignored by Git.

```dotenv
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
SIMULATION_MODE=true
```

Only set `SIMULATION_MODE=false` when you intend to send real Telegram notifications.
Each message contains the alert type, risk, ML label, up to three SHAP features,
selected playbooks, and approval requirement. A five-second timeout and error fallback
keep Telegram failures from interrupting alert processing. IP blocking remains simulated.

For approval buttons, run the separate long-polling listener in another terminal:

```powershell
python -m bot.telegram_bot
```

The listener only accepts Approve/Reject callbacks from the configured
`TELEGRAM_CHAT_ID`. It requires `SIMULATION_MODE=false` and valid Telegram credentials.

## Human-in-the-loop

Alerts with risk of 70 or higher leave IP blocking as `pending_approval`; the system
does not execute the block until an analyst approves it.

```powershell
Invoke-RestMethod -Method Post `
  -Uri "http://127.0.0.1:8000/alerts/<alert-id>/approval" `
  -ContentType "application/json" `
  -Body '{"decision":"approve","analyst":"analyst1","comment":"Confirmed threat"}'
```

Use `"decision":"reject"` to reject a block. Decisions and analyst comments are stored
in SQLite for retraining; export feedback with `export_feedback_csv()` in
`playbooks.approval`.

## Tests

Run the complete local test suite:

```powershell
python -m pytest
```

Tests mock all external Telegram and enrichment HTTP requests. They do not send real
Telegram messages.

## Docker

Build and start the API with Docker Compose:

```powershell
Copy-Item .env.example .env
docker compose up --build
```

The API is available at `http://localhost:8000/docs`. The `data/` and `models/`
directories are mounted so records and trained models persist locally.

## End-to-end demo

The demo selects a true incident, a benign false-positive alert, and a borderline case
from CIC-IDS2017, sends them through the in-process API, and saves full pipeline output
to `results/demo_output.txt`. Telegram is forced to simulation mode during this demo.

```powershell
python -m scripts.demo
```

## Measured results

The latest real CIC-IDS2017 evaluation used 100,000 cleaned rows (80,000 train /
20,000 test). XGBoost led the random split with positive-class F1 `0.9977` and ROC-AUC
`0.99998`; on the day-based split its F1 was `0.6029`, showing substantial day-to-day
distribution shift. See `results/metrics.csv` and `results/SUMMARY.md` for full metrics
and limitations. Metrics and local triage timings are run-specific, not production SLAs.

## Project layout

```text
soar-ml/
├── api/           FastAPI application and HTTP schemas
├── enrichment/    external enrichment clients and mock fallbacks
├── ml/            data preparation, training, SHAP, and scoring
├── playbooks/     YAML playbooks and playbook engine
├── bot/           optional Telegram approval callback listener
├── scripts/       end-to-end CIC alert demo
├── data/          raw and processed datasets
├── tests/         pytest unit and integration tests
├── results/       measured metrics, figures, demo transcript, and summary
├── .env.example
├── .gitignore
└── requirements.txt
```

## Safety

IP blocking is always simulated. Real Telegram messages are sent only when
`SIMULATION_MODE=false` and both Telegram settings are present. Telegram API failures
fall back without stopping alert processing. No real IP blocking or other external
response action is performed.
