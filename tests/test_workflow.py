"""Runs only against an isolated temporary database, never the user's workspace."""
from fastapi.testclient import TestClient
from backend.main import app
from backend.services.features import extract

ADMIN={'X-API-Key':'test-admin'}
ANALYST={'X-API-Key':'test-analyst'}
VIEWER={'X-API-Key':'test-viewer'}
base='/api/v1/triage'

def test_workflow():
 with TestClient(app) as c:
    assert c.get(base+'/events').status_code==401
    assert c.post(base+'/demo',headers=VIEWER).status_code==403
    r=c.post(base+'/demo',headers=ANALYST);assert r.status_code==202,r.text
    assert r.json()['accepted']==6
    assert c.post(base+'/demo',headers=ADMIN).json()['duplicates']==6
    data=c.get(base+'/events',headers=VIEWER).json();assert data['total']==6
    assert all(e['source']=='demo' and e['analysis']['model_probability'] is None for e in data['items'])
    unscored=next(e for e in data['items'] if e['event_type']=='flow');assert unscored['priority'] is None
    event=next(e for e in data['items'] if e['severity']=='critical');eid=event['id']
    r=c.patch(f'{base}/events/{eid}',headers=ANALYST,json={'status':'investigating','assigned_to':'Test analyst'});assert r.status_code==200
    assert r.json()['reviewed_at']
    assert c.patch(f'{base}/events/{eid}',headers=ANALYST,json={'status':'invalid'}).status_code==422
    draft=c.post(f'{base}/events/{eid}/report',headers=ANALYST,json={}).json()
    text=c.get(f"{base}/reports/{draft['id']}/download",headers=VIEWER).text
    assert 'REQUIRED' in text and 'SYNTHETIC DEMO' in text and 'Not submitted' in text
    assert c.get(base+'/stats',headers=VIEWER).json()['review_sample_size']==1
    assert len(c.get(base+'/audit',headers=VIEWER).json())>=4
    assert c.post(base+'/ingest',headers=ANALYST,json={'events':[{'event_type':'flow'}]}).status_code==422
    assert c.get('/api/v1/alerts/').status_code==401  # old CRUD routes also protected
    with c.websocket_connect('/ws/events') as ws:
        ws.send_json({'api_key':'test-viewer'});assert ws.receive_json()['type']=='changed'
    assert c.post(f'{base}/events/{eid}/retry',headers=ANALYST).status_code==202

def test_features_do_not_invent_missing_values():
 values=extract({'proto':'TCP','flow':{'pkts_toserver':0}})
 assert values['spkts']==0 and values['dpkts'] is None and values['dur'] is None
