"""Offline multiclass training with a training-only categorical protocol vocabulary."""
import argparse
import json
from pathlib import Path
import numpy as np
import pandas as pd
import lightgbm as lgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix

FEATURES = ['dur', 'proto', 'spkts', 'dpkts', 'sbytes', 'dbytes']

def read_dataset(path, label):
    # Do not accidentally interpret a protocol string as a pandas NA token.
    frame = pd.read_csv(path, keep_default_na=False)
    frame.columns = frame.columns.str.strip()
    required = FEATURES + [label]
    missing = [key for key in required if key not in frame]
    if missing:
        raise ValueError(f'{path.name}: missing columns: {", ".join(missing)}')
    if frame.empty:
        raise ValueError(f'{path.name}: no records found.')
    for key in ['proto', label]:
        frame[key] = frame[key].astype('string').str.strip()
        invalid = frame[key].isna() | frame[key].eq('')
        if invalid.any():
            rows = (np.flatnonzero(invalid.to_numpy())[:5] + 2).tolist()
            raise ValueError(f'{path.name}: {int(invalid.sum())} missing {key} values; CSV rows {rows}. Correct these values before training.')
    frame['proto'] = frame['proto'].str.lower()
    for key in FEATURES:
        if key == 'proto':
            continue
        numeric = pd.to_numeric(frame[key], errors='coerce')
        invalid = ~np.isfinite(numeric.to_numpy(dtype=float)) | (numeric.to_numpy(dtype=float) < 0)
        if invalid.any():
            rows = (np.flatnonzero(invalid)[:5] + 2).tolist()
            raise ValueError(f'{path.name}: {int(invalid.sum())} missing/invalid/non-finite/negative {key} values; CSV rows {rows}. No values were padded or rows dropped.')
        frame[key] = numeric
    return frame

def encode(frame, protocol_map):
    x = frame[FEATURES].copy()
    unseen = ~x['proto'].isin(protocol_map)
    counts = {str(k): int(v) for k, v in x.loc[unseen, 'proto'].value_counts().items()}
    # LightGBM treats -1 in a categorical feature as missing/unknown. It is
    # never interpreted as a packet count, zero padding, or a learned protocol.
    x['proto'] = x['proto'].map(protocol_map).fillna(-1).astype('int32')
    return x, counts

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--csv', required=True, type=Path)
    parser.add_argument('--test-csv', type=Path)
    parser.add_argument('--output', type=Path, default=Path('model'))
    parser.add_argument('--label', default='attack_cat')
    parser.add_argument('--eve-validation-note', default='', help='Provide only after validating training/runtime feature equivalence on labeled EVE flows.')
    args = parser.parse_args()
    try:
        frame = read_dataset(args.csv, args.label)
        if args.test_csv:
            if args.csv.resolve() == args.test_csv.resolve():
                raise ValueError('Training and testing paths must be different.')
            train, test = frame, read_dataset(args.test_csv, args.label)
        else:
            train, test = train_test_split(frame, test_size=.25, random_state=42, stratify=frame[args.label])
        classes = sorted(train[args.label].unique().tolist())
        if 'Normal' not in classes or len(classes) < 2:
            raise ValueError('Training labels must include Normal and at least one attack class.')
        unknown_labels = sorted(set(test[args.label]) - set(classes))
        if unknown_labels:
            raise ValueError('Test attack classes absent from training: ' + ', '.join(unknown_labels))
        protocol_map = {v: i for i, v in enumerate(sorted(train['proto'].unique().tolist()))}
        xtrain, _ = encode(train, protocol_map)
        xtest, unseen = encode(test, protocol_map)
        print(f'Training: {len(train):,} rows | Testing: {len(test):,} rows | Classes: {len(classes)}', flush=True)
        print(f'Protocol vocabulary: {len(protocol_map)} categories fitted on TRAINING ONLY.', flush=True)
        if unseen:
            print(f'Unseen test protocols: {unseen}. Retaining all rows using categorical unknown code -1.', flush=True)
        class_map = {c: i for i, c in enumerate(classes)}
        ytrain, ytest = train[args.label].map(class_map), test[args.label].map(class_map)
        model = lgb.LGBMClassifier(objective='multiclass', num_class=len(classes), n_estimators=250,
            learning_rate=.05, num_leaves=31, class_weight='balanced', random_state=42, n_jobs=2, verbosity=-1)
        model.fit(xtrain, ytrain, categorical_feature=['proto'])
        pred = model.predict(xtest)
        metrics = {'accuracy': float(accuracy_score(ytest, pred)),
            'classification_report': classification_report(ytest, pred, labels=list(range(len(classes))), target_names=classes, output_dict=True, zero_division=0),
            'confusion_matrix': confusion_matrix(ytest, pred, labels=list(range(len(classes)))).tolist(),
            'train_rows': len(train), 'test_rows': len(test), 'unseen_test_protocols': unseen,
            'unseen_test_protocol_rows': sum(unseen.values()), 'dropped_test_rows': 0,
            'split': 'separate test file' if args.test_csv else 'stratified random split; not temporal/deployment validation',
            'calibration': 'Not calibrated'}
        manifest = {'name': 'Offline LightGBM flow experiment', 'schema': 'eve-flow-v1', 'features': FEATURES,
            'protocol_map': protocol_map, 'categorical_features': ['proto'], 'unknown_protocol_policy': 'categorical_missing',
            'unknown_protocol_code': -1, 'classes': classes, 'eve_compatible': bool(args.eve_validation_note),
            'validation': args.eve_validation_note or 'NOT VALIDATED: align UNSW-NB15 and Suricata flow direction, byte accounting and duration. Live EVE scoring remains disabled.',
            'training_source': args.csv.name}
        args.output.mkdir(parents=True, exist_ok=True)
        model.booster_.save_model(str(args.output / 'lightgbm.txt'))
        (args.output / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
        (args.output / 'evaluation.json').write_text(json.dumps(metrics, indent=2), encoding='utf-8')
        print(f'Saved model, manifest and measured evaluation in {args.output}. Test accuracy: {metrics["accuracy"]:.4f}')
        print('EVE inference enabled by validation note:', manifest['eve_compatible'])
    except (ValueError, FileNotFoundError) as exc:
        raise SystemExit(str(exc)) from exc

if __name__ == '__main__':
    main()
