# Model integration contract

No trained weights were supplied. No pretrained model is bundled or simulated.

The backend accepts a LightGBM native text multiclass model (`lightgbm.txt`) and a JSON manifest (`manifest.json`). It does not load pickle or joblib files. The manifest must have:

```json
{
  "name": "Your validated flow model",
  "schema": "eve-flow-v1",
  "features": ["dur", "proto", "spkts", "dpkts", "sbytes", "dbytes"],
  "protocol_map": {"icmp": 0, "tcp": 1, "udp": 2},
  "classes": ["Normal", "Reconnaissance"],
  "eve_compatible": false,
  "validation": "Document feature alignment and held-out live-domain evaluation here."
}
```

The sample class order and protocol encoding above are illustrative: they must exactly match training. The model may have all nine UNSW attack classes plus Normal, but only actually trained classes are displayed. Manifest dimensions are checked against the model. Restart the backend after replacing model artifacts.

## Features

| Training feature | Runtime EVE extraction |
| --- | --- |
| dur | `flow.end - flow.start` in seconds |
| proto | lowercased `proto`, encoded with the training protocol map |
| spkts | `flow.pkts_toserver` |
| dpkts | `flow.pkts_toclient` |
| sbytes | `flow.bytes_toserver` |
| dbytes | `flow.bytes_toclient` |

These names alone do NOT establish equivalence with UNSW-NB15/Argus-derived fields. Validate direction, byte accounting, flow boundaries, sampling and units against the training pipeline. Do not silently pad the full UNSW feature schema with zeros. Alert records can lack complete flow features; the current prototype does not reconstruct missing flow history or correlate records into a feature window. Such events remain signature-triaged with an explicit ML-unavailable reason.

## Offline training

From the project root, using Python 3.12:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-ml.txt
.\.venv\Scripts\python.exe scripts/train_model.py --csv path/to/UNSW_NB15_training-set.csv --test-csv path/to/UNSW_NB15_testing-set.csv
```

This produces measured evaluation files and an experimental model, with `eve_compatible=false` by default. It is not used for EVE inference until compatibility has actually been established. For labeled flows produced by this exact EVE extractor, supply `--eve-validation-note "description of your extraction and held-out validation"` after doing that validation. This note is a user declaration, not automated evidence of accuracy.

Probabilities are uncalibrated. The scalar ML malicious score is `1 - P(Normal)`; the displayed class is the highest-probability class (which can still be Normal when aggregate attack probability is high). Triage priority is the maximum of that score and signature-based severity policy. SHAP explains the displayed class's raw output, not the aggregate malicious probability or business impact.

SHAP runs only when the ML malicious score exceeds the configured threshold. A lower score is not proof of safety. Threshold selection, calibration, domain drift checks, rare-class evaluation, and temporal testing remain necessary before a real deployment.
