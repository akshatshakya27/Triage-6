# Verification record

Completed in the Linux build environment on 12 September 2026.

| Check | Result |
| --- | --- |
| React production build | Passed with Vite 7.3.6 and Tailwind 4 integration |
| Python source compilation | Passed |
| Backend workflow test | Passed: ingestion, six synthetic records, deduplication, missing-field rejection, review, reporting, stats, activity, reprocessing |
| Access controls | Passed: missing key rejected, viewer writes rejected, analyst writes allowed, legacy routes protected |
| WebSocket | Passed: authenticated change message and actual browser live connection |
| Missing model / features | Passed: explicit unavailable ML values; missing features remain missing |
| LightGBM + SHAP | Passed with a temporary synthetic multiclass model: prediction, high-score attribution, six feature contributions; fixture not bundled |
| Browser desktop | Passed at 1440 x 1100: demo replay, live updates, evidence drawer, analyst assignment, status save, report download, search and integration panels |
| Browser EVE import | Passed: JSONL upload and Suricata numeric timezone-offset timestamp display |
| Browser mobile | Passed at 390 x 844: responsive viewport, no page-level horizontal overflow; queue and nav intentionally scroll horizontally |
| JavaScript runtime | No uncaught page exceptions in the tested workflow |
| Visual inspection | Desktop and mobile screenshots inspected; copies in previews/ |
| Automated test suite | 3 passed; dependency deprecation warnings retained |

Dependencies exercised: Python 3.12, Node 24, LightGBM 4.7.0, SHAP 0.52.0. The browser harness used headless Chromium against the actual running Vite/FastAPI servers and an isolated temporary database. All synthetic test data was excluded from the shipped database (no database is shipped).

## Not established by these tests

- Live IBM inference: no customer API key, project or enabled model was supplied. Adapter and fallback are implemented, but no live IBM request was performed.
- Real intrusion detection quality: no user-trained artifact or labeled real network evaluation was supplied. The synthetic fixture only verifies adapter mechanics; it proves no cyberattack accuracy.
- Continuous Suricata deployment: the file feeder is included; no real sensor or packet capture was available here.
- Windows runtime: Windows commands are provided, but execution was verified on Linux with Python 3.12. Python 3.14 optional ML compatibility is not claimed.
- Docker runtime: Dockerfiles and Compose configuration were reviewed but not executed.
- PRD accuracy, latency, availability, throughput and improvement targets: no load test, baseline comparison or production pilot was conducted.

Screenshots show synthetic demo records. No pretrained threat detector, real credentials, secrets, node_modules, virtual environment, or test database is included.

## Mistral provider update

Added selectable Mistral/IBM/template routing. Mistral tests use HTTP mock responses (no real account or transmission): request schema and evidence-only payload, missing-key fallback, HTTP 429 fallback, and preservation of existing automatic IBM selection. Live Mistral account access is not verified. Preview screenshots predate this small integration-card update.

After the Mistral update: production build passed; 7 automated tests passed (including the existing LightGBM/SHAP and backend workflow tests). Test setup now initializes isolated configuration before importing any backend module.
