import json
import hashlib
import uuid
from pathlib import Path
from fastapi import APIRouter, UploadFile, File, Form, BackgroundTasks, Depends, HTTPException
from backend.auth import authorize
from backend.config import settings
from backend.database import SessionLocal
from backend.triage_models import CsvRun, Audit
from backend.services.inference import load
from backend.services.csv_testing import read_sample, process_run, MAX_BYTES

router=APIRouter(dependencies=[Depends(authorize)])

def public(run,full=False):
    result={key:getattr(run,key) for key in ['id','created_at','updated_at','filename','status','total_rows','sample_rows','processed','failures','seed','error']}
    result['metadata']=json.loads(run.metadata_json);result['metrics']=json.loads(run.metrics_json)
    if full:result['results']=json.loads(run.results)
    return result

@router.post('/csv-runs',status_code=202)
def create_run(tasks:BackgroundTasks,file:UploadFile=File(...),sample_size:int=Form(100),seed:int=Form(42),role=Depends(authorize)):
    if not 1<=sample_size<=1000:raise HTTPException(422,'Choose between 1 and 1,000 rows per interactive run.')
    if not 0<=seed<=2147483647:raise HTTPException(422,'Seed must be between 0 and 2147483647.')
    try:
        try:model,manifest=load(require_eve=False)
        except Exception as exc:raise HTTPException(409,'CSV model unavailable: '+str(exc))
        content=file.file.read(MAX_BYTES+1)
        try:samples,total,metadata=read_sample(content,sample_size,seed)
        except Exception as exc:
            # Input problems return actionable validation errors, not an HTTP 500.
            raise HTTPException(422,str(exc)[:500])
        filename=Path((file.filename or 'dataset.csv').replace('\\','/')).name[:250]
        metadata.update({'model_name':manifest.get('name','LightGBM'),'model_classes':manifest['classes'],
            'model_sha256':hashlib.sha256(model.model_to_string().encode()).hexdigest(),
            'training_source':manifest.get('training_source'),
            'training_filename_match':filename==manifest.get('training_source'),
            'holdout_note':'Use a file not used to train or tune the model. Filenames alone cannot verify a held-out split.'})
        with SessionLocal() as db:
            if db.query(CsvRun).filter(CsvRun.status.in_(['queued','processing'])).count()>=2:
                raise HTTPException(409,'Two CSV runs are already active. Wait for a run to finish.')
            run=CsvRun(id=str(uuid.uuid4()),filename=filename,total_rows=total,sample_rows=len(samples),seed=seed,
                samples=json.dumps(samples),metadata_json=json.dumps(metadata))
            db.add(run);db.flush();db.add(Audit(actor=role,action='csv_run',detail=f'{run.id}: {len(samples)} sampled of {total} rows'));db.commit();db.refresh(run)
            result=public(run);tasks.add_task(process_run,run.id);return result
    finally:file.file.close()

@router.get('/csv-runs')
def list_runs():
    with SessionLocal() as db:return [public(run) for run in db.query(CsvRun).order_by(CsvRun.created_at.desc()).limit(50)]

@router.get('/csv-runs/{run_id}')
def get_run(run_id:str):
    with SessionLocal() as db:
        run=db.get(CsvRun,run_id)
        if not run:raise HTTPException(404,'CSV run not found.')
        return public(run,full=True)
