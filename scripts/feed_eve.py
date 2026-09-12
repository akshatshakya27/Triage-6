"""Read complete EVE lines, persist byte offset, retry failures, and follow rotation.
API key comes from TRIAGE_API_KEY; raw EVE payloads are never printed.
"""
import argparse, json, os, time, urllib.request, urllib.error
from pathlib import Path
p=argparse.ArgumentParser()
p.add_argument('path',type=Path);p.add_argument('--url',default='http://127.0.0.1:8000');p.add_argument('--follow',action='store_true');p.add_argument('--checkpoint',type=Path,default=Path('.triage-feed-checkpoint.json'))
a=p.parse_args();state={}
if a.checkpoint.exists():state=json.loads(a.checkpoint.read_text())
path=str(a.path.resolve());offset=state.get('offset',0) if state.get('path')==path else 0;old_identity=state.get('identity')
try:
 while True:
    try:stat=a.path.stat()
    except FileNotFoundError:
        if not a.follow:raise
        time.sleep(1);continue
    identity=f'{stat.st_dev}:{stat.st_ino}'
    if old_identity!=identity or stat.st_size<offset:offset=0
    old_identity=identity
    with a.path.open('rb') as f:
        f.seek(offset);line=f.readline();next_offset=f.tell()
    if not line or not line.endswith(b'\n'):
        if not a.follow:
            if line:print('Incomplete trailing line deferred. Add a newline to ingest it.')
            break
        time.sleep(.5);continue
    try:raw=json.loads(line)
    except (ValueError,UnicodeDecodeError):
        raise SystemExit(f'Invalid JSON at byte {offset}; checkpoint retained. Correct the log before retrying.')
    if raw.get('event_type') in ['alert','flow','dns','http','tls','anomaly']:
        req=urllib.request.Request(a.url.rstrip('/')+'/api/v1/triage/ingest',data=json.dumps({'events':[raw]}).encode(),headers={'Content-Type':'application/json','X-API-Key':os.getenv('TRIAGE_API_KEY','')},method='POST')
        try:
            with urllib.request.urlopen(req,timeout=25) as response:response.read()
        except urllib.error.HTTPError as e:
            if e.code<500:raise SystemExit(f'API rejected event at byte {offset}: HTTP {e.code}; checkpoint preserved.')
            print('Backend error; retrying without advancing checkpoint.');time.sleep(3);continue
        except (urllib.error.URLError,TimeoutError):
            print('Backend unavailable; retrying without advancing checkpoint.');time.sleep(3);continue
    offset=next_offset
    a.checkpoint.write_text(json.dumps({'path':path,'identity':identity,'offset':offset}))
    print(f'Processed through byte {offset}',flush=True)
except KeyboardInterrupt:print('\nStopped; checkpoint preserved.')
