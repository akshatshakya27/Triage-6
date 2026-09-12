# Triage-6 — AI-Powered Network Security Intelligence Platform

A React and FastAPI prototype for detecting, classifying, scoring, explaining, and reviewing suspicious network activity. Triage-6 combines optional LightGBM inference, SHAP feature attribution, Mistral or IBM watsonx explanations, and analyst-reviewed report drafts in a dark cybersecurity dashboard.

## Product Vision

Help security analysts move from raw alerts to understandable evidence and informed defensive decisions. The platform brings model predictions, explanations, response guidance, and incident documentation into one workspace.

## Target Audience

- SOC analysts investigating network alerts.
- Security managers reviewing priorities and analyst decisions.
- Compliance teams preparing incident-report drafts.
- Students and hackathon teams demonstrating explainable threat detection.

This package is a local prototype, not a production SOC service or a guarantee of regulatory compliance.

## Core Features

| Feature | Implemented behavior |
| --- | --- |
| Detect | Predict Normal or Malicious from the trained model's highest-probability class. |
| Classify | Predict attack categories present in the model manifest. |
| Score risk | Show class confidence, aggregate malicious probability, and policy severity. |
| Explain | Display actual SHAP factors; optionally request Mistral or IBM narrative explanations. |
| Recommend | Present class-specific defensive guidance for analyst review; no automatic containment. |
| Visualize | Show alerts, class distributions, severity levels, evaluation metrics, and confusion matrices. |
| Review | Assign events and mark them new, investigating, resolved, or false positive. |
| Report | Generate editable Markdown reporting drafts with missing information marked. |
| Preserve history | Store events, CSV runs, report drafts, and activity in SQLite. |
| Retain original APIs | Keep alert, incident, and compliance CRUD APIs alongside the triage workflow. |

## Technology Stack

| Layer | Technology / responsibility |
| --- | --- |
| Frontend | React 19, Vite, Tailwind CSS, Lucide icons |
| Backend | Python, FastAPI, Uvicorn, Pydantic |
| Persistence | SQLAlchemy and SQLite |
| Classification | Optional native LightGBM multiclass model |
| Explainability | SHAP contributions for the predicted class |
| Narrative AI | Optional Mistral or IBM watsonx adapter through HTTPX |
| Event ingestion | Suricata EVE JSON/JSONL, REST ingestion, file feeder |
| Updates | WebSocket notifications and CSV progress polling |
| Packaging | Docker Compose and Nginx definitions |
| Verification | Pytest and frontend build checks |

Dependency files and `frontend/package-lock.json` define the package dependencies; the versions from the original backend-only README do not describe this updated application.

## Architecture Overview

The backend is a modular monolith: routers handle requests, services perform inference and explanation, models store records, and configuration supplies integration settings.

There are two distinct analysis paths:

- **CSV testing:** upload held-out records, extract the six training features, run LightGBM and SHAP, and compare predictions with labels used only for evaluation. An analyst may request a cloud explanation for an individual result.
- **Suricata EVE:** ingest network events, apply signature severity rules, and use ML only when model/extractor compatibility is validated. Eligible high-risk ML events with SHAP may request a configured narrative provider automatically.

React displays the results and supports analyst review. Report generation creates a draft; it does not submit reports or execute defensive actions.

## Prerequisites

- Python 3.12 is the verified development environment for the optional ML stack. An already working environment does not need to be recreated; newer Python installations may encounter dependency compatibility issues.
- Node.js 22.12+ or 24 for the supplied frontend.
- Internet access for dependency installation and optional cloud explanations.
- A trained model and matching manifest for ML testing. Model weights, datasets, and provider credentials are not bundled.

## Installation and Running Locally

Extract the project and open PowerShell in the **`triage-6` folder containing this README**. Run commands from the project root, not from `backend`.

Copy only the commands inside each code block, not the Markdown backticks. Run each command successfully before continuing.

### Terminal 1 — backend

For a new environment with Python 3.12 installed:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe scripts/setup_env.py
.\.venv\Scripts\python.exe -m uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000
```

If you already have a working `.venv`, skip the first command. If `py -3.12` reports no suitable runtime, run `py --list` to inspect installed versions. Install Python 3.12, or use `python -m venv .venv` with an appropriate installed interpreter. Do not continue with a nonexistent virtual environment.

The setup script creates `.env` with a generated secret and preserves an existing `.env`.

### Terminal 2 — frontend

Open another PowerShell window in the same project root:

```powershell
cd frontend
npm.cmd ci
npm.cmd run dev
```

- Dashboard: `http://localhost:3000`
- Swagger API documentation: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`

For Linux/macOS, create the environment with `python3 -m venv .venv`, use `.venv/bin/python` instead of the Windows interpreter path, and use `npm ci` / `npm run dev`.

### Updating an existing installation

Stop both servers, extract the updated package separately, and merge the updated source files into the project you actually run. Preserve your existing `model/lightgbm.txt`, `model/manifest.json`, `data/`, `.env`, `.venv`, and database. Install updated dependencies and restart both servers. See [CSV_TESTING.md](CSV_TESTING.md) for the CSV upgrade walkthrough.

## Choose Your Testing Mode

| Mode | Input | Requirements | What it demonstrates |
| --- | --- | --- | --- |
| Replay demo | Included synthetic EVE examples | Base dependencies | Dashboard, severity rules, review, and draft workflow |
| CSV testing | `UNSW_NB15_testing-set.csv` | ML dependencies, model, manifest | Predictions, SHAP, guidance, and measured sample evaluation |
| Import EVE | Suricata `eve.json` / JSONL | Base dependencies; validated model for ML | Network-event ingestion and signature triage; optional compatible ML |

**Import EVE is not the CSV upload screen.** Use **CSV testing** for UNSW-NB15 CSV files. Demo records are synthetic and cannot establish real detection accuracy.

## Enable LightGBM and SHAP

Install ML dependencies into the same backend environment:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-ml.txt
```

If you already trained successfully, keep your model files and skip retraining. Otherwise, place the separate training and testing CSVs in `data/`, then run:

```powershell
.\.venv\Scripts\python.exe scripts/train_model.py --csv ".\data\UNSW_NB15_training-set.csv" --test-csv ".\data\UNSW_NB15_testing-set.csv" --output model
```

Training writes `model/lightgbm.txt`, `model/manifest.json`, and measured `model/evaluation.json`. The protocol vocabulary is fitted on training data only; unseen test protocols use the manifest's recorded categorical unknown policy (`-1`). Missing or invalid numeric features are reported rather than silently padded.

Check the root `.env`:

```dotenv
MODEL_PATH=model/lightgbm.txt
MODEL_MANIFEST=model/manifest.json
HIGH_RISK_THRESHOLD=0.85
```

Restart the backend and check **Integrations** or **CSV testing** for readiness.

The feature contract is **`dur`, `proto`, `spkts`, `dpkts`, `sbytes`, `dbytes`**, in the model's recorded order and encoding. Native LightGBM text weights and their matching JSON manifest are required; an arbitrary pickle, joblib file, or full-feature model cannot be substituted. See [model/README.md](model/README.md).

**Keep `eve_compatible=false` until live feature compatibility has actually been validated.** CSV testing works with this flag false. UNSW-derived features and Suricata-derived fields are not automatically equivalent; incomplete EVE events stay unscored by ML. Flow reconstruction and cross-event correlation are not implemented.

## Test the Six Expected Outcomes

1. Open **CSV testing** and confirm **Model Ready**.
2. Choose **`UNSW_NB15_testing-set.csv`**, not the training CSV or features-list file.
3. Select **100 rows** with seed **42**, then click **Analyze CSV**.
4. Inspect detection, attack class, confidence, malicious probability, and severity.
5. In **Record predictions**, click a row's **↗ arrow** to open its detail drawer.
6. In **Evidence**, inspect SHAP factors; in **Response**, inspect defensive guidance.
7. Review class distributions, detection metrics, and confusion matrices. Use **Export evaluation** to download the run as JSON.

Uploads are limited to 50 MB and interactive runs to 1,000 sampled rows. The app samples uniformly across the uploaded file with a reproducible seed. Saved runs remain available after reload. Interrupted CSV runs retain partial results; upload again for a fresh run.

Labels such as `attack_cat` and `label` are evaluation-only, never model inputs. Invalid labels are disclosed and excluded from affected metrics. Files without labels still produce predictions but cannot produce ground-truth accuracy. Numeric feature errors are shown per row and excluded from metrics.

Sample accuracy can differ from full-file evaluation. A ten-row file containing only Normal records cannot measure attack recall; a missing denominator displays **—**. Use a larger held-out sample containing relevant classes to assess detection. Only classes actually trained in your model are supported; do not claim botnet detection from a model without that class.

### Understand the scores

| Display | Meaning |
| --- | --- |
| Predicted class | Highest-probability class, including Normal |
| Detection | Normal if the selected class is Normal; otherwise Malicious |
| Class confidence | Probability of the selected class; uncalibrated |
| Malicious probability | `1 - P(Normal)`; distinct from class confidence |
| CSV severity | Critical > 0.85; high ≥ 0.65; medium ≥ 0.40; otherwise low |
| Live priority | Maximum of available ML malicious probability and signature policy |
| SHAP | Contributions to the selected class's raw model output, not proof of causation |

A Normal prediction can coexist with a higher aggregate malicious probability because that probability sums multiple attack classes. These scores are not calibrated business-impact estimates. SHAP is computed for every scored CSV row; live EVE SHAP is restricted to high-risk ML events.

## Enable and Test Mistral AI

Mistral explains model evidence. It does not replace LightGBM, alter predictions, or execute responses.

Set these values in the root `.env`:

```dotenv
NARRATIVE_PROVIDER=mistral
MISTRAL_API_KEY=your-private-mistral-api-key
MISTRAL_MODEL_ID=mistral-large-latest
```

Use a model ID available to your account; the value above is the application's default. No additional Mistral Python SDK is required because the adapter uses HTTPX.

Restart the backend, then:

1. Complete a CSV run and open **Record predictions**.
2. Click the **↗ arrow at the far right of a completed row**.
3. Stay on the drawer's **Evidence** tab and scroll inside the drawer, below the SHAP section.
4. Click **Generate AI explanation**.
5. Check that the threat explanation shows **MISTRAL · VERIFY**.

The button requires a LightGBM result with SHAP evidence. If it is missing, verify those prerequisites and that you are running the updated frontend. An **EVIDENCE TEMPLATE** result alone does not confirm Mistral worked. Check the narrative status or error if generation fails; configuration presence does not prove account access.

CSV batches do not automatically call the cloud provider. Each explicit generation request sends approved prediction/SHAP evidence for one record. Raw CSV rows, evaluation labels, IP addresses, and packet payloads are excluded. Advice requires analyst verification; failures preserve the local explanation. Keep keys in the backend and replace any key exposed in a screenshot or repository.

### Narrative provider selection

| Value | Behavior |
| --- | --- |
| `mistral` | Use Mistral; fall back to a local template on failure |
| `watsonx` | Use IBM; requires IBM configuration and `WATSONX_ENABLED=true` |
| `template` | Disable external narrative calls |
| `auto` | Use IBM when enabled, otherwise templates; adding a Mistral key alone does not enable it |

## Enable IBM watsonx

Edit the root `.env` and restart:

```dotenv
NARRATIVE_PROVIDER=watsonx
WATSONX_ENABLED=true
WATSONX_API_KEY=your-ibm-api-key
WATSONX_PROJECT_ID=your-project-id
WATSONX_MODEL_ID=an-available-granite-model-id-in-your-project
WATSONX_URL=https://us-south.ml.cloud.ibm.com
```

Use your actual regional endpoint. Granite 3.0 availability is not assumed; choose an available supported model in your project. The adapter uses IBM IAM and the text generation endpoint with version `2024-05-31`.

Automatic generation is requested only for high-risk live ML events with successful SHAP evidence. CSV testing uses local explanations; an analyst can explicitly request one provider explanation from a scored record. Only fixed feature names, feature values, prediction, probability and attribution are sent to IBM; raw EVE text, signatures, packet payloads and IP addresses are excluded. Turning it on authorizes that configured evidence transfer. All secrets stay in the backend. If the service fails, the event retains its template explanation and shows an integration status. Generated text is untrusted advice requiring analyst review, not guaranteed fact or executed remediation.

## Continuous Suricata log ingestion

From the project root, in a third terminal:

```powershell
$env:TRIAGE_API_KEY="your-analyst-key-if-enabled"
.\.venv\Scripts\python.exe scripts/feed_eve.py "C:\path\to\eve.json" --follow
```

The feeder follows completed newline-delimited records, skips unsupported event types, persists a byte offset in `.triage-feed-checkpoint.json`, and restarts from zero when it detects rotation/truncation. API deduplication protects repeated records. A malformed/rejected event stops the feeder with its byte offset, preserving the checkpoint for correction. Use a separate `--checkpoint` per log source.

The feeder sends to localhost by default; pass `--url` for another backend. Suricata itself is not installed or launched by this package. Configure EVE alert/flow output in your existing Suricata installation. Flow records generally provide more model features than alert-only records.

## Access controls

Set distinct, random `ADMIN_API_KEY`, `ANALYST_API_KEY`, and `VIEWER_API_KEY` values in `.env` and restart. Open Integrations and enter a workspace key.

- Viewer: read-only API and event stream.
- Analyst: ingestion, decisions, reprocessing and draft generation.
- Administrator: analyst permissions plus deletion on the legacy CRUD endpoints.
- If all keys are blank: local development mode, not authentication.

Keys identify a role, not a named person. The assignment field is manually entered. This is not enterprise SSO, per-user auditing, or a tamper-evident log. WebSocket authentication uses an initial message, not a query string. The browser keeps the key in session storage; do not share it or expose the prototype publicly without production controls.

## API summary

All new routes are under `/api/v1/triage` and accept `X-API-Key` when enabled.

| Method / path | Purpose |
| --- | --- |
| GET `/system`, `/stats` | Integration readiness and observed workspace metrics |
| POST `/ingest` | `{ "events": [EVE objects] }`, max 100 records / 64 KiB per record |
| POST `/demo` | Explicit synthetic replay; disable via `DEMO_ENABLED=false` |
| GET `/events` | `q`, `severity`, `status`, `source`, `skip`, `limit` (max 200) |
| GET `/events/{id}` | Full evidence, including original JSON |
| PATCH `/events/{id}` | Analyst status and assignment |
| POST `/events/{id}/retry` | Reprocess an EVE event; CSV records require a new run |
| POST `/events/{id}/explain` | Explicit provider explanation for an eligible ML/SHAP record |
| POST `/csv-runs` | Multipart upload: `file`, `sample_size`, `seed` |
| GET `/csv-runs`, `/csv-runs/{id}` | Saved CSV runs and run details |
| POST `/events/{id}/report` | Persist and return a Markdown draft |
| GET `/reports`, `/reports/{id}/download` | Recent draft register and download |
| GET `/audit` | Latest 200 activity entries |
| WS `/ws/events` | Send `{ "api_key": "..." }` first; changed/heartbeat messages |

The original `/api/v1/alerts`, `/incidents`, and `/compliance` CRUD APIs are retained and protected by the same role dependency. The new frontend uses separate `triage_*` tables; old CRUD records do not automatically appear in the new queue. No existing records are migrated or deleted. To retain an old database, set `DATABASE_URL` deliberately and back it up first. New tables are created at startup.

## Reporting scope

The download is a **reporting worksheet/draft**, not an official completed form or a CERT-In compliance guarantee. It does not send email or submit a report. Organization/contact, actual time of noticing, impact, and actions taken cannot reliably be inferred from flow telemetry; blanks are marked REQUIRED. Recommendations are not recorded as completed actions. Synthetic drafts are prominently marked.

Consult current official directions and the responsible reporting team to determine reportability, deadlines and required fields. The app does not treat all high-risk alerts as reportable incidents or calculate a statutory deadline from the event timestamp.

## Docker

After creating `.env`:

```powershell
docker compose up --build
```

Frontend: http://localhost:3000 . Backend docs: http://localhost:8000/docs . Both ports bind to loopback by default. SQLite persists in a named Docker volume. Native local SQLite and Docker SQLite are separate databases. Model files mount read-only. The base image includes the non-ML stack; to include optional ML libraries use:

```powershell
docker compose build --build-arg INSTALL_ML=true backend
docker compose up
```

Docker definitions are supplied; Docker execution is not part of the verified test environment. Image pulls require internet access. TLS termination and encrypted disks/volumes must be configured for your actual deployment; the prototype does not claim encryption at rest or 99.5% uptime.

## Build and test

```powershell
cd frontend
npm.cmd run build
cd ..
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pytest -q tests
```

Tests use a temporary SQLite database and test keys, not your event store. See `VERIFICATION.md` for completed checks and remaining integration gates.

## Environment Variables

Use `.env.example` as the configuration reference. Restart the backend after editing `.env`.

| Variable | Purpose |
| --- | --- |
| `SECRET_KEY` | Required application setting; generated by setup. Role access uses API keys, not a JWT login flow. |
| `DATABASE_URL` | SQLAlchemy database URL; the example uses `sqlite:///./triage6.db`. |
| `ALLOWED_ORIGINS` | JSON array of allowed frontend origins. |
| `MODEL_PATH`, `MODEL_MANIFEST` | Matching native model and manifest paths. |
| `HIGH_RISK_THRESHOLD` | High-risk threshold used by the analysis workflow. |
| `NARRATIVE_PROVIDER` | `auto`, `template`, `mistral`, or `watsonx`. |
| `MISTRAL_API_KEY`, `MISTRAL_MODEL_ID` | Mistral credentials and account-supported model ID. |
| `WATSONX_ENABLED` | Enable IBM integration when selected. |
| `WATSONX_API_KEY`, `WATSONX_PROJECT_ID`, `WATSONX_MODEL_ID`, `WATSONX_URL` | IBM credentials, model, and regional endpoint. |
| `ADMIN_API_KEY`, `ANALYST_API_KEY`, `VIEWER_API_KEY` | Distinct role keys; all blank means local development mode. |
| `DEMO_ENABLED` | Allow or disable synthetic replay. |

Legacy settings remain in `backend/config.py`; toggling `AI_MODEL_ENABLED` alone does not supply weights or establish integration readiness.

## Project Structure

| Path | Purpose |
| --- | --- |
| `backend/main.py` | FastAPI entry point and router registration |
| `backend/config.py`, `backend/auth.py` | Settings and role access |
| `backend/database.py` | Database engine and sessions |
| `backend/models.py`, `backend/triage_models.py` | Original CRUD and triage storage models |
| `backend/routers/` | Original CRUD, event workflow, and CSV-run APIs |
| `backend/services/` | Features, inference, SHAP, CSV testing, and narrative adapters |
| `frontend/src/` | Dashboard, CSV testing, evidence drawer, styles, and API client |
| `model/` | Model contract documentation and locally supplied artifacts |
| `data/` | Locally supplied CSV datasets; create this directory as needed |
| `samples/` | Synthetic EVE examples |
| `scripts/setup_env.py` | Safe initial environment setup |
| `scripts/train_model.py` | Offline training and full test evaluation |
| `scripts/feed_eve.py` | Continuous EVE file ingestion |
| `tests/` | Backend verification |
| `requirements.txt` | Base backend dependencies |
| `requirements-ml.txt` | Optional ML stack |
| `requirements-dev.txt` | Test dependencies |
| `compose.yaml` | Container configuration |
| `CSV_TESTING.md` | Detailed CSV testing guide |
| `VERIFICATION.md` | Completed checks and integration limitations |

## Troubleshooting

| Problem | Fix |
| --- | --- |
| `.env` not found | Run `scripts/setup_env.py` through the project virtual environment from the root. |
| No suitable Python runtime | Run `py --list`; install the requested Python or use an appropriate installed interpreter. |
| Virtual-environment executable missing | Create `.venv` successfully before installing or running the backend. |
| PowerShell rejects backticks or `powershell` | Copy commands only; do not paste Markdown fences. |
| Dataset path not found | Create `data/` and copy both CSVs there, or use quoted absolute paths. |
| Missing features or unseen protocols in an older trainer | Update trainer and inference code together; retrain to record the unknown-category policy. Actual missing numeric features require correcting the input. |
| CSV model ready but EVE unavailable | Expected for an offline CSV model; leave compatibility disabled until validated. |
| No CSV testing menu | Restart the updated frontend and refresh; check the directory you are running. |
| Missing multipart dependency | Install the updated `requirements.txt` with the backend virtual environment. |
| AI button missing | Open a completed ML row with SHAP, then scroll in its Evidence drawer. |
| Provider generation fails | Check the narrative error, credentials, selected model, network access, and account permissions. |
| CSV run interrupted | Restart the backend and upload again; previous partial results remain available. |

## Development and Security

Keep routers, services, and storage responsibilities separate. Register new routers in `backend/main.py`, validate inputs, and add meaningful checks for changed behavior. Database schema changes need deliberate migration handling before production use.

Never commit credentials, private datasets, or local databases. Back up an existing database before changing its connection or deployment. Use HTTPS, appropriate request/rate limits, and stronger identity management for any deployment beyond local development. Role keys identify roles rather than individual people; activity history is not a tamper-evident audit system.

## Validation and Limitations

The package has passed 12 backend tests and desktop/mobile browser workflow checks using a temporary synthetic model. These verify software behavior, not detection quality on your dataset. No live Mistral or IBM account call was included in those checks. Docker definitions were supplied but were not runtime-tested in that environment.

Use the generated `evaluation.json` and CSV-run exports to report actual model results. PRD claims such as 90% accuracy, 73% faster triage, or 99.5% uptime are not demonstrated results of this package.

This is a single-process prototype with SQLite and in-process background work. Durable queues, distributed workers, load testing, tenant isolation, enterprise SSO, operational monitoring, backup/restore, and encryption/key management remain deployment work. Two identical canonical EVE records with the same source are deliberately deduplicated.

Without compatible trained weights, live events use explicitly labeled Suricata rules: IDS severity 1 → 0.95, 2 → 0.70, 3 → 0.35. These are policy values, not ML probabilities. No fake model scores or SHAP values are substituted.

## License

No project license is specified here. Add the license selected by the project owners before distributing the project under particular terms. Third-party dependencies retain their own licenses.

## Support

When reporting an issue, include the command, full error text, relevant screen, and environment versions. Remove API keys and other secrets first. Consult `CSV_TESTING.md`, `model/README.md`, and `VERIFICATION.md` for implementation-specific details.
