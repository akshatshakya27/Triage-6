"""Run from any directory. Creates missing .env without overwriting existing values."""
from pathlib import Path
import secrets
root=Path(__file__).resolve().parents[1]
target=root/'.env'
if target.exists():
    text=target.read_text(encoding='utf-8')
    if 'replace-with-a-random-secret' in text:
        target.write_text(text.replace('replace-with-a-random-secret',secrets.token_urlsafe(48)),encoding='utf-8')
        print('Updated placeholder secret in existing .env.')
    else: print('.env already exists; preserved without changes.')
else:
    target.write_text((root/'.env.example').read_text().replace('replace-with-a-random-secret',secrets.token_urlsafe(48)),encoding='utf-8')
    print('Created project .env with a random secret.')
