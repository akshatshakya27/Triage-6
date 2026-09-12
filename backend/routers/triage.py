import asyncio
import hashlib
import json
import time
from datetime import datetime
from typing import Literal
from pathlib import Path
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from backend.auth import authorize, role_for
from backend.config import settings
from backend.database import SessionLocal
from backend.triage_models import Event, Draft, Audit
from backend.services.inference import infer, model_status
from backend.services.narrative import explain, provider_status

router=APIRouter(dependencies=[Depends(authorize)])
ws_router=APIRouter()

def audit(db, actor, action, event_id=None, detail=''):
    db.add(Audit(actor=actor,action=action,event_id=event_id,detail=detail));db.commit()

def serialize(e):
    return {k:getattr(e,k) for k in ['id','timestamp','received_at','updated_at','source','event_type','src_ip','dest_ip','proto','title','status','assigned_to','severity','priority','processing','reviewed_at']} | {'analysis':json.loads(e.analysis or '{}')}

def process(event_id):
    with SessionLocal() as db:
        e=db.get(Event,event_id)
        if not e:return
        e.processing='processing';db.commit()
        started=time.perf_counter()
        try:
            analysis=infer(json.loads(e.raw))
            analysis['inference_ms']=round((time.perf_counter()-started)*1000,2)
            if analysis.get('model_probability') is not None and analysis['model_probability']>settings.HIGH_RISK_THRESHOLD and analysis.get('shap'):
                narrative,note,provider=explain(analysis)
                analysis['narrative_status']=note
                if narrative:
                    analysis['narrative']=narrative;analysis['narrative_source']=provider
            else:analysis['narrative_status']='Not requested: high-risk ML evidence with SHAP is required.'
            analysis['processing_ms']=round((time.perf_counter()-started)*1000,2)
            e.analysis=json.dumps(analysis);e.priority=analysis['priority'];e.severity=analysis['severity'];e.processing='complete'
        except Exception as exc:
            e.analysis=json.dumps({'error':'Processing failed: '+type(exc).__name__});e.processing='failed'
        db.commit()

class Ingest(BaseModel):
    events: list[dict] = Field(min_length=1,max_length=100)
    @field_validator('events')
    @classmethod
    def validate_events(cls,events):
        for e in events:
            if len(json.dumps(e))>65536:raise ValueError('Each event must be under 64 KiB.')
            if e.get('event_type') not in ('alert','flow','dns','http','tls','anomaly'):raise ValueError('Unsupported or missing EVE event_type.')
            if not isinstance(e.get('timestamp'),str):raise ValueError('EVE timestamp is required.')
            datetime.fromisoformat(e['timestamp'].replace('Z','+00:00'))
            for field in ['flow','alert']:
                if field in e and not isinstance(e[field],dict):raise ValueError(field+' must be an object')
        return events

def ingest(events, source, tasks, actor):
    ids=[];duplicates=0
    with SessionLocal() as db:
        for raw in events:
            record_source = 'demo' if raw.get('triage_demo') is True else source
            encoded=json.dumps(raw,sort_keys=True,separators=(',',':'))
            fingerprint=hashlib.sha256((record_source+encoded).encode()).hexdigest()
            existing=db.query(Event).filter_by(fingerprint=fingerprint).first()
            if existing:
                ids.append(existing.id);duplicates+=1;continue
            e=Event(fingerprint=fingerprint,raw=encoded,source=record_source,timestamp=raw['timestamp'],event_type=raw['event_type'],src_ip=str(raw.get('src_ip',''))[:80],dest_ip=str(raw.get('dest_ip',''))[:80],proto=str(raw.get('proto',''))[:20],title=str((raw.get('alert') or {}).get('signature') or f"{raw['event_type'].upper()} network event")[:300])
            db.add(e)
            try:db.commit();db.refresh(e)
            except IntegrityError:
                db.rollback();existing=db.query(Event).filter_by(fingerprint=fingerprint).one();ids.append(existing.id);duplicates+=1;continue
            ids.append(e.id);tasks.add_task(process,e.id)
        audit(db,actor,'ingest',detail=f'{len(events)-duplicates} new; {duplicates} duplicates; {source}')
    return {'ids':ids,'accepted':len(events)-duplicates,'duplicates':duplicates}

@router.get('/system')
def system():
    return {'name':'Triage-6','model':model_status(),'csv_model':model_status(require_eve=False),'narrative':provider_status(),'watsonx_enabled':settings.WATSONX_ENABLED,'watsonx_model':settings.WATSONX_MODEL_ID or None,'auth_enabled':bool(settings.ADMIN_API_KEY or settings.ANALYST_API_KEY or settings.VIEWER_API_KEY),'demo_enabled':settings.DEMO_ENABLED,'high_risk_threshold':settings.HIGH_RISK_THRESHOLD}

@router.post('/ingest',status_code=202)
def receive(payload:Ingest,tasks:BackgroundTasks,role=Depends(authorize)):
    return ingest(payload.events,'suricata',tasks,role)

@router.post('/demo',status_code=202)
def demo(tasks:BackgroundTasks,role=Depends(authorize)):
    if not settings.DEMO_ENABLED:raise HTTPException(403,'Demo replay is disabled.')
    path=Path(__file__).resolve().parents[2]/'samples'/'eve-demo.jsonl'
    events=[json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return ingest(events,'demo',tasks,role)

@router.get('/events')
def events(q:str='',severity:str='',status:str='',source:str='',skip:int=0,limit:int=50):
    if skip<0 or limit<1 or limit>200:raise HTTPException(422,'Use skip >= 0 and limit between 1 and 200.')
    with SessionLocal() as db:
        query=db.query(Event)
        if q:query=query.filter((Event.title.contains(q)) | (Event.src_ip.contains(q)) | (Event.dest_ip.contains(q)))
        if severity:query=query.filter(Event.severity==severity)
        if status:query=query.filter(Event.status==status)
        if source:query=query.filter(Event.source==source)
        total=query.count()
        return {'total':total,'items':[serialize(e) for e in query.order_by(Event.id.desc()).offset(skip).limit(limit)]}

@router.get('/events/{event_id}')
def event(event_id:int):
    with SessionLocal() as db:
        e=db.get(Event,event_id)
        if not e:raise HTTPException(404,'Event not found')
        return serialize(e)|{'raw':json.loads(e.raw)}

class Review(BaseModel):
    status: Literal['new','investigating','resolved','false_positive']
    assigned_to: str = Field(default='',max_length=100)

@router.patch('/events/{event_id}')
def review(event_id:int,payload:Review,role=Depends(authorize)):
    with SessionLocal() as db:
        e=db.get(Event,event_id)
        if not e:raise HTTPException(404,'Event not found')
        old=e.status;e.status=payload.status;e.assigned_to=payload.assigned_to
        if e.reviewed_at is None and e.status!='new':e.reviewed_at=datetime.utcnow()
        db.commit();audit(db,role,'review',event_id,old+' -> '+e.status)
        return serialize(e)

@router.post('/events/{event_id}/retry',status_code=202)
def retry(event_id:int,tasks:BackgroundTasks,role=Depends(authorize)):
    with SessionLocal() as db:
        e=db.get(Event,event_id)
        if not e:raise HTTPException(404,'Event not found')
        if e.source=='csv':raise HTTPException(409,'CSV runs are immutable experiments. Upload the CSV again for new predictions.')
        if e.processing in ('processing','queued','explaining'):raise HTTPException(409,'Event is already queued or processing.')
        e.processing='queued';db.commit();audit(db,role,'reprocess',event_id);tasks.add_task(process,event_id)
    return {'queued':event_id}

@router.get('/stats')
def stats():
    with SessionLocal() as db:
        total=db.query(Event).count()
        active=db.query(Event).filter(Event.status.in_(['new','investigating']))
        levels={s:n for s,n in db.query(Event.severity,func.count(Event.id)).group_by(Event.severity)}
        reviewed=db.query(Event).filter(Event.reviewed_at.isnot(None)).order_by(Event.id.desc()).limit(1000).all()
        durations=[max(0,(e.reviewed_at-e.received_at).total_seconds()) for e in reviewed]
        return {'total':total,'active':active.count(),'critical':active.filter(Event.severity=='critical').count(),'reports':db.query(Draft).count(),'levels':levels,'mean_first_review_seconds':sum(durations)/len(durations) if durations else None,'review_sample_size':len(durations),'demo_count':db.query(Event).filter_by(source='demo').count()}

class ReportFields(BaseModel):
    organization: str = Field(default='',max_length=200)
    contact: str = Field(default='',max_length=300)
    noticed_at: str = Field(default='',max_length=100)
    impact: str = Field(default='',max_length=3000)
    actions_taken: str = Field(default='',max_length=3000)

def clean(value):return str(value).replace('\r','').replace('\n',' ')

@router.post('/events/{event_id}/report')
def report(event_id:int,fields:ReportFields,role=Depends(authorize)):
    with SessionLocal() as db:
        e=db.get(Event,event_id)
        if not e:raise HTTPException(404,'Event not found')
        a=json.loads(e.analysis or '{}');raw=json.loads(e.raw)
        content=f'''# Triage-6 | Incident reporting draft

DRAFT — analyst review required. Not submitted to CERT-In. This is a supporting worksheet, not an official compliance certification.

## Organization and contact
Organization: {clean(fields.organization) or 'REQUIRED — organization name'}
Contact: {clean(fields.contact) or 'REQUIRED — authorized contact details'}
Incident noticed at (with timezone): {clean(fields.noticed_at) or 'REQUIRED — actual time incident was noticed; not inferred from alert time'}

## Recorded evidence
Event ID: {e.id}
Data source: {e.source} {'— SYNTHETIC DEMO; NOT A REAL INCIDENT' if e.source=='demo' else '— DATASET RECORD; NOT A VERIFIED LIVE INCIDENT' if e.source=='csv' else ''}
Recorded time: {clean(e.timestamp)} {'— upload time, not an observed network time' if e.source=='csv' else ''}
Source: {clean(e.src_ip)}:{raw.get('src_port','unknown')}
Destination: {clean(e.dest_ip)}:{raw.get('dest_port','unknown')}
Protocol: {clean(e.proto)}
Signature/title: {clean(e.title)}
Model classification: {clean(a.get('prediction') or 'Unavailable')}
ML malicious probability: {a.get('model_probability','Unavailable')}
Triage severity: {e.severity}
Status: {e.status}
Evidence SHA-256 (source-prefixed canonical event): {e.fingerprint}

## Analyst assessment
Impact: {clean(fields.impact) or 'REQUIRED — affected services, systems, and observed impact'}
Actions already taken: {clean(fields.actions_taken) or 'REQUIRED — document actual response actions; recommendations are not completed actions'}

## Automated explanation (verify)
{a.get('summary','Analysis pending.')}

## Suggested review steps (not executed)
'''+ '\n'.join('- '+clean(x) for x in a.get('recommendations',[]))+'''

## Before external submission
- Verify all evidence and complete missing fields, incident scope, and authorized contact information.
- Determine reportability and applicable deadlines with the responsible team. Do not use the event timestamp as a substitute for when the incident was noticed.
- Follow current CERT-In directions and the official incident reporting process: https://www.cert-in.org.in/Directions70B.jsp
- This application does not submit reports or certify regulatory compliance.
'''
        draft=Draft(event_id=e.id,markdown=content,fields=json.dumps(fields.model_dump()));db.add(draft);db.commit();db.refresh(draft);audit(db,role,'report_draft',e.id)
        return {'id':draft.id,'event_id':e.id,'markdown':content}

@router.get('/reports')
def reports():
    with SessionLocal() as db:return [{'id':r.id,'event_id':r.event_id,'created_at':r.created_at,'fields':json.loads(r.fields)} for r in db.query(Draft).order_by(Draft.id.desc()).limit(200)]

@router.get('/reports/{report_id}/download',response_class=PlainTextResponse)
def download(report_id:int):
    with SessionLocal() as db:
        r=db.get(Draft,report_id)
        if not r:raise HTTPException(404,'Report not found')
        return PlainTextResponse(r.markdown,media_type='text/markdown',headers={'Content-Disposition':f'attachment; filename="triage6-draft-{r.id}.md"'})

@router.get('/audit')
def audit_log():
    with SessionLocal() as db:return [{'id':a.id,'created_at':a.created_at,'actor':a.actor,'action':a.action,'event_id':a.event_id,'detail':a.detail} for a in db.query(Audit).order_by(Audit.id.desc()).limit(200)]

@ws_router.websocket('/ws/events')
async def live(ws:WebSocket):
    # Authenticate in first message, keeping keys out of query strings and server access logs.
    await ws.accept()
    try:
        message=await asyncio.wait_for(ws.receive_json(),timeout=10)
        role_for(message.get('api_key',''))
    except Exception:
        await ws.close(code=1008);return
    def revision():
        with SessionLocal() as db:
            last=db.query(func.max(Event.updated_at),func.count(Event.id)).one()
            return str(last)
    last=None
    try:
        while True:
            current=await asyncio.to_thread(revision)
            await ws.send_json({'type':'changed' if current!=last else 'heartbeat'})
            last=current
            await asyncio.sleep(1)
    except (WebSocketDisconnect,RuntimeError):pass

def generate_narrative(event_id):
    with SessionLocal() as db:
        e=db.get(Event,event_id)
        if not e:return
        analysis=json.loads(e.analysis or '{}')
        try:
            text,note,provider=explain(analysis)
            analysis['narrative_status']=note
            if text:analysis['narrative']=text;analysis['narrative_source']=provider
        except Exception as exc:
            analysis['narrative_status']='Generation failed ('+type(exc).__name__+'); local explanation retained.'
        e.analysis=json.dumps(analysis);e.processing='complete';db.commit()

@router.post('/events/{event_id}/explain',status_code=202)
def explain_event(event_id:int,tasks:BackgroundTasks,role=Depends(authorize)):
    with SessionLocal() as db:
        e=db.get(Event,event_id)
        if not e:raise HTTPException(404,'Event not found')
        a=json.loads(e.analysis or '{}')
        if e.processing in ('queued','processing','explaining'):raise HTTPException(409,'Event is busy.')
        if a.get('engine')!='lightgbm' or not a.get('shap'):raise HTTPException(409,'A model prediction and SHAP evidence are required.')
        status=provider_status()
        if status['provider']=='template' or not status['configured']:raise HTTPException(409,'Configure Mistral or IBM first. The local evidence explanation is already available.')
        e.processing='explaining';db.commit();audit(db,role,'request_explanation',e.id,status['provider'])
        tasks.add_task(generate_narrative,e.id)
    return {'queued':event_id}
