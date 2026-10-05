"""Bounded, anonymous, read-only production checks. Never stores response bodies."""
import json
from pathlib import Path
import socket
import ssl
import sys
import time
import httpx

out = Path(__file__).resolve().parents[1] / 'docs' / 'Security-2026-10-05'
out.mkdir(parents=True, exist_ok=True)
paths = ['/', '/.well-known/security.txt', '/robots.txt', '/.env', '/.git/HEAD',
         '/main.py', '/requirements.txt', '/veiling.db', '/test_credentials.py',
         '/static/%2e%2e%2f.env', '/docs', '/redoc', '/openapi.json',
         '/admin', '/admin/overzicht', '/admin/gebruikers', '/admin/audit',
         '/feedback', '/veilingen', '/veiling/1', '/api/auction/1',
         '/api/image-proxy?url=https%3A%2F%2Fexample.com%2F']
results = []
with httpx.Client(timeout=20, follow_redirects=False, trust_env=False) as client:
    for p in paths:
        with client.stream('GET', 'https://veiling.tosch.nl' + p) as r:
            item = {'path':p, 'status':r.status_code, 'headers': {k:v for k,v in r.headers.items()
                if k in ('content-type','location','strict-transport-security','content-security-policy',
                         'x-frame-options','x-content-type-options','cache-control','referrer-policy',
                         'permissions-policy','access-control-allow-origin','x-vercel-cache')}}
            if p == '/':
                import re
                body = r.read().decode(errors='replace')
                version = re.search(r'Tosch Veiling · (v[0-9.]+)', body)
                item['version'] = version[1] if version else None
            results.append(item)
        time.sleep(.15)
    r = client.get('http://veiling.tosch.nl/')
    results.append({'path':'http://veiling.tosch.nl/', 'status':r.status_code, 'location':r.headers.get('location')})
context = ssl.create_default_context()
with socket.create_connection(('veiling.tosch.nl',443),timeout=10) as raw:
    with context.wrap_socket(raw,server_hostname='veiling.tosch.nl') as secure:
        tls = {'protocol':secure.version(), 'cipher':secure.cipher()[0],
               'certificate_not_after':secure.getpeercert().get('notAfter'), 'hostname_verified':True}
report = {'target':'veiling.tosch.nl','client_date':'2026-10-05','authentication':'none',
          'mutating_requests':0,'checks':results,'tls':tls}
label = sys.argv[1] if len(sys.argv)>1 else 'before'
assert label in ('before','after')
(out / f'live-{label}.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,indent=2))
