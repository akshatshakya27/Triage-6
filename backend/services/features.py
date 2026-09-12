"""Explicit EVE flow schema. Never silently pad absent features with zeros."""
from datetime import datetime
import math

FEATURES = ['dur', 'proto', 'spkts', 'dpkts', 'sbytes', 'dbytes']

def extract(event):
    flow = event.get('flow') or {}
    values = {'proto': str(event['proto']).strip().lower() if event.get('proto') else None}
    for name, key in [('spkts','pkts_toserver'),('dpkts','pkts_toclient'),('sbytes','bytes_toserver'),('dbytes','bytes_toclient')]:
        value = flow.get(key)
        values[name] = float(value) if isinstance(value, (int,float)) and not isinstance(value,bool) and math.isfinite(value) and value >= 0 else None
    values['dur'] = None
    try:
        start = datetime.fromisoformat(flow['start'].replace('Z','+00:00'))
        end = datetime.fromisoformat(flow['end'].replace('Z','+00:00'))
        duration = (end-start).total_seconds()
        if duration >= 0:
            values['dur'] = duration
    except (KeyError, ValueError, TypeError):
        pass
    return values
