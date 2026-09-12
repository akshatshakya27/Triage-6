import secrets
from fastapi import Header, HTTPException, Request
from backend.config import settings

def role_for(token):
    keys = [(settings.ADMIN_API_KEY, 'admin'), (settings.ANALYST_API_KEY, 'analyst'), (settings.VIEWER_API_KEY, 'viewer')]
    if not any(k for k, _ in keys):
        return 'local'
    for key, role in keys:
        if key and token and secrets.compare_digest(token, key):
            return role
    raise HTTPException(401, 'A valid workspace API key is required.')

def authorize(request: Request, x_api_key: str = Header(default='')):
    role = role_for(x_api_key)
    if request.method not in ('GET', 'HEAD', 'OPTIONS') and role == 'viewer':
        raise HTTPException(403, 'Viewer access is read-only.')
    if request.method == 'DELETE' and role not in ('admin', 'local'):
        raise HTTPException(403, 'Administrator access is required for deletion.')
    return role
