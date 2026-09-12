"""Dataset inference. Labels are evaluated AFTER predictions and never sent to ML/LLMs."""
import csv
import hashlib
import io
import json
import math
import random
import time
from datetime import datetime
from collections import Counter
from backend.database import SessionLocal
from backend.triage_models import CsvRun, Event
from backend.services.features import FEATURES
from backend.services.inference import infer_csv, load

MAX_BYTES=50*1024*1024

def read_sample(content, limit, seed):
    if len(content)>MAX_BYTES:raise ValueError('CSV exceeds the 50 MB upload limit.')
    try:decoded=content.decode('utf-8-sig')
    except UnicodeDecodeError:raise ValueError('CSV must use UTF-8 encoding.')
    reader=csv.DictReader(io.StringIO(decoded,newline=''))
    if not reader.fieldnames:raise ValueError('CSV has no header row.')
    names=[key.strip() for key in reader.fieldnames]
    if len(names)!=len(set(names)):raise ValueError('CSV has duplicate column names.')
    reader.fieldnames=names
    missing=[key for key in FEATURES if key not in names]
    if missing:raise ValueError('Required feature columns missing: '+', '.join(missing))
    rng=random.Random(seed);sample=[];total=0
    # Reservoir sampling uses the whole file and does not use labels for selection.
    for row in reader:
        if None in row:raise ValueError(f'CSV record {total+1} has more fields than its header.')
        if any(value is None for value in row.values()):raise ValueError(f'CSV record {total+1} has too few fields.')
        total+=1
        item={'row':total,'values':{key:row[key] for key in FEATURES},
              'attack_cat':row.get('attack_cat','').strip(),'label':row.get('label','').strip()}
        if len(sample)<limit:sample.append(item)
        else:
            index=rng.randrange(total)
            if index<limit:sample[index]=item
    if not total:raise ValueError('CSV contains no data records.')
    sample.sort(key=lambda item:item['row'])
    return sample,total,{'file_sha256':hashlib.sha256(content).hexdigest(),
        'label_columns':[key for key in ['attack_cat','label'] if key in names],
        'sampling':'All rows' if total<=limit else f'Uniform reservoir sample, seed {seed}',
        'ignored_columns':[key for key in names if key not in FEATURES+['attack_cat','label']],
        'model_inputs':FEATURES}

def clean_features(values):
    result={}
    for key in FEATURES:
        value=values.get(key)
        if key=='proto':
            if value is None or not str(value).strip():raise ValueError('Missing proto')
            result[key]=str(value).strip().lower()
        else:
            try:value=float(value)
            except (TypeError,ValueError):raise ValueError('Missing or non-numeric '+key)
            if not math.isfinite(value) or value<0:raise ValueError('Invalid, non-finite or negative '+key)
            result[key]=value
    return result

def truth_for(item, classes):
    category=item.get('attack_cat','');binary=item.get('label','')
    canonical={str(c).lower():c for c in classes}
    actual=canonical.get(category.lower()) if category else None
    if category and actual is None:return {'class':None,'binary':None,'note':'Unsupported ground-truth attack_cat: '+category[:80]}
    derived=(0 if actual=='Normal' else 1) if actual is not None else None
    if binary:
        if binary not in ('0','1','0.0','1.0'):return {'class':None,'binary':None,'note':'Invalid binary ground-truth label'}
        explicit=int(float(binary))
        if derived is not None and explicit!=derived:return {'class':None,'binary':None,'note':'Conflicting attack_cat and label'}
        derived=explicit
    return {'class':actual,'binary':derived,'note':None}

def evaluate(results,classes):
    valid=[r for r in results if r.get('prediction') is not None and not r.get('error')]
    binary=[r for r in valid if r['truth']['binary'] is not None]
    labelled=[r for r in valid if r['truth']['class'] is not None]
    tn=fp=fn=tp=0
    for r in binary:
        pred=0 if r['prediction']=='Normal' else 1
        actual=r['truth']['binary']
        tn+=actual==0 and pred==0;fp+=actual==0 and pred==1;fn+=actual==1 and pred==0;tp+=actual==1 and pred==1
    def divide(x,y):return x/y if y else None
    precision=divide(tp,tp+fp);recall=divide(tp,tp+fn)
    confusion=[[0 for _ in classes] for _ in classes]
    for r in labelled:confusion[classes.index(r['truth']['class'])][classes.index(r['prediction'])]+=1
    per_class=[]
    for i,cls in enumerate(classes):
        support=sum(confusion[i]);predicted=sum(row[i] for row in confusion);correct=confusion[i][i]
        per_class.append({'class':cls,'support':support,'precision':divide(correct,predicted),
                          'recall':divide(correct,support),'f1':divide(2*correct,support+predicted)})
    return {'scored_rows':len(valid),'failed_rows':len(results)-len(valid),
        'binary_labelled_rows':len(binary),'class_labelled_rows':len(labelled),
        'missing_or_invalid_binary_labels':len(valid)-len(binary),
        'binary_accuracy':divide(tp+tn,len(binary)),'attack_precision':precision,'attack_recall':recall,
        'attack_f1':divide(2*tp,2*tp+fp+fn),'false_positive_rate':divide(fp,fp+tn),
        'binary_confusion':{'tn':tn,'fp':fp,'fn':fn,'tp':tp},
        'class_accuracy':divide(sum(r['prediction']==r['truth']['class'] for r in labelled),len(labelled)),
        'classes':classes,'confusion_matrix':confusion,'per_class':per_class,
        'predicted_counts':dict(Counter(r['prediction'] for r in valid)),
        'detection_counts':{'Normal':sum(r['prediction']=='Normal' for r in valid),'Malicious':sum(r['prediction']!='Normal' for r in valid)},
        'shap_explained_rows':sum(bool(r.get('has_shap')) for r in valid),
        'unknown_protocol_rows':sum(bool(r.get('unknown_protocol')) for r in valid),
        'scope':'Processed sampled rows only; failed rows are disclosed and excluded. No claim about the full file or live-network accuracy.'}

def process_run(run_id):
    with SessionLocal() as db:
        run=db.get(CsvRun,run_id)
        if not run:return
        try:
            model,manifest=load(require_eve=False)
            run.status='processing';db.commit()
            samples=json.loads(run.samples);results=[]
            for item in samples:
                started=time.perf_counter();truth=truth_for(item,manifest['classes'])
                try:
                    features=clean_features(item['values'])
                    analysis=infer_csv(features)
                    if analysis['engine']!='lightgbm':raise ValueError(analysis.get('model_note','ML inference unavailable'))
                    analysis['processing_ms']=round((time.perf_counter()-started)*1000,2)
                    analysis['narrative_status']='Local evidence template. Use Generate AI explanation for this record to request your selected provider.'
                    analysis['csv']={'run_id':run_id,'row':item['row'],'truth':truth,'evaluation_only':True}
                    raw={'event_type':'csv','timestamp_kind':'upload time; CSV has no observed network timestamp',
                         'csv_row':item['row'],'run_id':run_id,'csv_features':features,
                         'evaluation_labels':{'attack_cat':item.get('attack_cat'),'label':item.get('label')}}
                    # Run-specific identity preserves separate experiments without mutating past results.
                    event=Event(fingerprint=hashlib.sha256(f'{run_id}:{item["row"]}'.encode()).hexdigest(),
                        timestamp=datetime.utcnow().isoformat()+'Z',source='csv',event_type='csv',src_ip='',dest_ip='',
                        proto=features['proto'],title=f'CSV row {item["row"]}: {analysis["prediction"]}',
                        raw=json.dumps(raw),analysis=json.dumps(analysis),processing='complete',
                        severity=analysis['severity'],priority=analysis['priority'])
                    db.add(event);db.flush()
                    result={'row':item['row'],'event_id':event.id,'prediction':analysis['prediction'],
                        'detection':analysis['detection'],'class_confidence':analysis['class_confidence'],
                        'model_probability':analysis['model_probability'],'severity':analysis['severity'],
                        'has_shap':bool(analysis['shap']),'unknown_protocol':bool(analysis.get('protocol_note')),
                        'truth':truth,'error':None}
                except Exception as exc:
                    result={'row':item['row'],'event_id':None,'prediction':None,'truth':truth,'error':str(exc)[:500]}
                    run.failures+=1
                results.append(result);run.processed=len(results);run.results=json.dumps(results)
                run.metrics_json=json.dumps(evaluate(results,manifest['classes']));db.commit()
            run.status='complete' if not run.failures else 'complete_with_errors'
            db.commit()
        except Exception as exc:
            db.rollback();run=db.get(CsvRun,run_id);run.status='failed';run.error=str(exc)[:500];db.commit()
