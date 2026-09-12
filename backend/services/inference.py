"""Shared model inference with separate CSV and live-EVE readiness gates."""
import json
from pathlib import Path
from threading import Lock
from backend.config import settings
from backend.services.features import FEATURES, extract

_lock = Lock()
_model = None
_manifest = None

def load(require_eve=True):
    global _model, _manifest
    with _lock:
        if _model is None:
            if not Path(settings.MODEL_PATH).is_file() or not Path(settings.MODEL_MANIFEST).is_file():
                raise ValueError('Model artifact or feature manifest is not installed.')
            import lightgbm as lgb
            m = json.loads(Path(settings.MODEL_MANIFEST).read_text(encoding='utf-8'))
            if m.get('features') != FEATURES or m.get('schema') != 'eve-flow-v1':
                raise ValueError('Model manifest must use the ordered eve-flow-v1 feature contract.')
            if 'Normal' not in m.get('classes', []) or not m.get('protocol_map'):
                raise ValueError('Manifest must supply classes including Normal and the training protocol_map.')
            model = lgb.Booster(model_file=settings.MODEL_PATH)
            if model.num_feature() != len(FEATURES) or model.num_model_per_iteration() != len(m['classes']):
                raise ValueError('Model dimensions disagree with manifest (multiclass model required).')
            _model, _manifest = model, m
        model, manifest = _model, _manifest
    # Check on EVERY call, even when a previous CSV request populated the cache.
    if require_eve and not manifest.get('eve_compatible', False):
        raise ValueError('CSV model is available, but live EVE feature compatibility has not been validated.')
    return model, manifest

def model_status(require_eve=True):
    try:
        _, m = load(require_eve=require_eve)
        return {'ready':True,'name':m.get('name','LightGBM'),'classes':m['classes'],'schema':m['schema'],
                'validation':m.get('validation','Not supplied'),'mode':'eve' if require_eve else 'csv',
                'training_source':m.get('training_source'),'features':FEATURES}
    except Exception as e:
        return {'ready':False,'reason':str(e)}

def recommendations(prediction):
    specific = {
        'normal': ['Continue routine monitoring; a Normal prediction is not proof that a record is safe.'],
        'dos': ['Check service availability and traffic volume against normal baselines.', 'Review rate limiting or upstream DDoS protection with the network owner before applying changes.'],
        'ddos': ['Check distributed traffic sources and service saturation.', 'Coordinate any filtering or traffic mitigation with your upstream provider and service owner.'],
        'reconnaissance': ['Correlate probing patterns with approved scanners and vulnerability assessments.', 'Review exposed services and access policies before deciding whether a source should be restricted.'],
        'exploits': ['Identify the affected service and verify relevant patch levels.', 'Review endpoint evidence for compromise and plan containment with the asset owner.'],
        'backdoor': ['Review unexpected remote access and persistence indicators.', 'Coordinate endpoint isolation and credential review if compromise is corroborated.'],
        'backdoors': ['Review unexpected remote access and persistence indicators.', 'Coordinate endpoint isolation and credential review if compromise is corroborated.'],
        'worms': ['Check related hosts for lateral spread.', 'Review segmentation and containment options with affected service owners.'],
        'shellcode': ['Review application and endpoint telemetry for suspected code execution.', 'Preserve evidence and check relevant exploit protections.'],
        'fuzzers': ['Check whether unusual request patterns belong to authorized testing.', 'Review application errors, input validation and exposed interfaces.'],
        'analysis': ['Correlate the suspected analysis activity with authorized testing.', 'Review surrounding sessions before escalating.'],
        'generic': ['Correlate this broad attack-class prediction with signatures and endpoint logs; it does not identify a specific exploit.'],
        'botnet': ['Review suspected command-and-control communication and related endpoint evidence.', 'Coordinate host containment only after corroborating the finding.']}
    return specific.get(str(prediction).lower(), ['Validate the event against related flow and endpoint logs.']) + [
        'Confirm affected assets and business impact; preserve evidence and timestamps.',
        'An authorized analyst must decide whether containment or external reporting is appropriate.']

def infer(event):
    return _infer(event, extract(event), require_eve=True, explain_all=False)

def infer_csv(values):
    # Explicit feature allowlist: labels, IDs and arbitrary CSV columns never reach the model.
    return _infer({}, {key: values.get(key) for key in FEATURES}, require_eve=False, explain_all=True)

def _infer(event, values, require_eve, explain_all):
    result = {'engine':'suricata-rules' if require_eve else 'unavailable','model_probability':None,'prediction':None,
              'class_confidence':None,'detection':None,'features':values,'shap':[],
              'shap_status':'Not computed: ML unavailable.','model_note':'','narrative_source':'template'}
    alert = event.get('alert') or {}
    priority = {1:.95,2:.70,3:.35}.get(alert.get('severity')) if event.get('event_type') == 'alert' else None
    result['priority_basis'] = 'Suricata signature severity policy; not an ML probability.' if priority is not None else 'No model score or signature severity available. Unscored does not mean benign.'
    try:
        model, manifest = load(require_eve=require_eve)
        missing = [key for key,value in values.items() if value is None]
        if missing:
            raise ValueError('Missing required features: '+', '.join(missing))
        unknown_protocol = values['proto'] not in manifest['protocol_map']
        supports_unknown = (manifest.get('unknown_protocol_policy') == 'categorical_missing'
                            and manifest.get('unknown_protocol_code') == -1
                            and 'proto' in manifest.get('categorical_features', []))
        if unknown_protocol and not supports_unknown:
            raise ValueError('Protocol was not represented in training: '+values['proto'])
        if unknown_protocol:
            result['protocol_note'] = 'Protocol absent from training; using categorical unknown (-1). This event is outside the learned protocol vocabulary.'
        import numpy as np
        row = np.array([[manifest['protocol_map'].get(values[k], -1) if k=='proto' else values[k] for k in FEATURES]],dtype=float)
        probs = np.asarray(model.predict(row, num_threads=2))[0]
        if probs.shape != (len(manifest['classes']),) or not np.isfinite(probs).all() or (probs<0).any() or (probs>1).any() or abs(float(probs.sum())-1)>0.01:
            raise ValueError('Model returned invalid probabilities.')
        idx = int(np.argmax(probs))
        probability = float(1-probs[manifest['classes'].index('Normal')])
        prediction=manifest['classes'][idx]
        result.update(engine='lightgbm',model_probability=probability,prediction=prediction,
            detection='Normal' if prediction=='Normal' else 'Malicious',class_confidence=float(probs[idx]),
            class_probabilities=dict(zip(manifest['classes'],map(float,probs))),model_name=manifest.get('name','LightGBM'),
            model_note='Uncalibrated model probabilities; deployment accuracy is not established by these scores.')
        if unknown_protocol:result['model_note'] += ' ' + result['protocol_note']
        priority = max(probability, priority or 0)
        result['priority_basis']=('Malicious probability (1 − P(Normal)) mapped to severity by policy; not business impact. Detection follows the highest-probability class.' if not require_eve else 'Maximum of model malicious probability and available Suricata signature policy; not business impact.')
        result['shap_status']='Below the configured ML explanation threshold.'
        if explain_all or probability > settings.HIGH_RISK_THRESHOLD:
            try:
                import shap
                explainer=shap.TreeExplainer(model)
                sv=explainer.shap_values(row)
                contrib=np.asarray(sv[idx])[0] if isinstance(sv,list) else np.asarray(sv)[0,:,idx]
                result['shap']=[{'feature':key,'value':values[key],'contribution':float(v)} for key,v in sorted(zip(FEATURES,contrib),key=lambda item:abs(item[1]),reverse=True)]
                result['shap_status']='Computed for '+prediction+' in raw model-output units; positive values push toward that class. Contributions are not causal evidence.'
            except Exception as e:
                result['shap_status']='SHAP unavailable: '+type(e).__name__
    except Exception as e:
        result['model_note']=str(e)
    result['priority']=priority
    result['severity']='info' if priority is None else 'critical' if priority>.85 else 'high' if priority>=.65 else 'medium' if priority>=.4 else 'low'
    if result['engine']=='lightgbm':
        result['summary']=f"The model predicts {result['prediction']} ({result['detection']}) with {result['class_confidence']:.1%} class confidence. Aggregate malicious probability is {result['model_probability']:.1%}. These are model estimates, not confirmation of an attack."
    else:result['summary']='This record has not been ML-classified. '+result['model_note']
    if alert:result['summary']+=' Suricata reported: '+str(alert.get('signature','no signature'))[:300]+'.'
    result['recommendations']=recommendations(result['prediction'])
    result['recommendation_source']='Curated class-based guidance; not executed.'
    return result
