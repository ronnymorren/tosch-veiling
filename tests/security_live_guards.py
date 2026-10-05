"""Three invalid requests, rejected before DB/email; no account or data mutation."""
import json
from pathlib import Path
import httpx

checks = []
with httpx.Client(timeout=20, trust_env=False) as client:
    for name, headers, expected in [
        ('same-origin-invalid-email', {'Origin':'https://veiling.tosch.nl','Content-Type':'application/json'}, 400),
        ('foreign-origin', {'Origin':'https://audit.example.test','Content-Type':'application/json'}, 403),
        ('simple-content-type', {'Origin':'https://veiling.tosch.nl','Content-Type':'text/plain'}, 415),
    ]:
        response = client.post('https://veiling.tosch.nl/api/auth/send-login-code',headers=headers,content='{}')
        checks.append({'check':name,'status':response.status_code,'expected':expected,
                       'passed':response.status_code==expected,'cache_control':response.headers.get('cache-control')})
out = Path(__file__).resolve().parents[1]/'docs'/'Security-2026-10-05'/'live-guards.json'
out.write_text(json.dumps({'checks':checks,'valid_email_supplied':False,'expected_data_mutations':0},indent=2),encoding='utf-8')
print(json.dumps(checks))
assert all(c['passed'] for c in checks)
