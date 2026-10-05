"""Reproduce pre-fix races with forced interleaving in disposable local PostgreSQL."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
import os
from pathlib import Path
import subprocess
import sys
import threading
import types
from unittest.mock import patch, Mock
import test_extension as fixture

root=Path(__file__).resolve().parents[1]
source=subprocess.check_output(['git','show','29db7a6:main.py'],cwd=root,text=True,encoding='utf-8')
baseline=types.ModuleType('security_baseline'); baseline.__file__=str(root/'main.py')
sys.modules[baseline.__name__]=baseline
with patch('dotenv.load_dotenv',return_value=False),patch.dict(os.environ,{
    'DATABASE_URL':fixture.DSN,'SESSION_SECRET':fixture.main.SESSION_SECRET}):
    exec(compile(source,baseline.__file__,'exec'),baseline.__dict__)
baseline.nu=lambda:fixture.BASE
baseline.stuur_email=Mock()
connect=baseline.get_conn
email='audit@example.test'
with connect() as conn,conn.cursor() as cur:
    cur.execute("INSERT INTO users (email,naam,created_at) VALUES (%s,'Audit',%s) ON CONFLICT(email) DO NOTHING",(email,fixture.BASE.isoformat()))
conn.close()


def race(mode):
    with connect() as conn,conn.cursor() as cur:
        cur.execute('DELETE FROM email_verifications WHERE email=%s',(email,))
        if mode!='request':
            cur.execute('INSERT INTO email_verifications(email,auction_id,code,expires_at) VALUES(%s,0,%s,%s)',
                        (email,'123456',(fixture.BASE+timedelta(minutes=10)).isoformat()))
    conn.close()
    barrier=threading.Barrier(8)
    class Cursor:
        def __init__(self,cur): self.cur=cur; self.query=''
        def __getattr__(self,k): return getattr(self.cur,k)
        def execute(self,q,p=None): self.query=q; return self.cur.execute(q,p)
        def fetchone(self):
            row=self.cur.fetchone()
            gate=('SELECT COUNT(*) AS n FROM email_verifications' if mode=='request' else 'SELECT * FROM email_verifications')
            if gate in self.query: barrier.wait(timeout=10)
            return row
    get_cur=baseline.get_cur
    def call(_):
        fn=baseline.send_login_code if mode=='request' else baseline.verify_login_code
        data={'email':email,'code':'123456' if mode=='correct' else '654321','naam':'Audit'}
        try: return asyncio.run(fn(fixture.request(data))).status_code
        except baseline.HTTPException as e: return e.status_code
    with patch.object(baseline,'get_cur',side_effect=lambda c:Cursor(get_cur(c))),ThreadPoolExecutor(max_workers=8) as pool:
        statuses=list(pool.map(call,range(8)))
    with connect() as conn,conn.cursor() as cur:
        cur.execute('SELECT pogingen,used FROM email_verifications WHERE email=%s ORDER BY id',(email,))
        rows=cur.fetchall()
    conn.close()
    return {'requests':8,'successful_responses':statuses.count(200),'stored_attempts':[r[0] for r in rows]}


report={'baseline_commit':'29db7a6','scope':'disposable localhost PostgreSQL, synthetic data, no emails',
        'correct_code_replay':race('correct'),'wrong_attempt_lost_updates':race('wrong'),
        'code_request_limit_bypass':race('request')}
fake=Mock(); fake.__enter__=Mock(return_value=fake); fake.__exit__=Mock(return_value=False)
fake.read.return_value=b'<html><script>window.auditProbe=1</script></html>'
fake.headers={'Content-Type':'text/html'}
with patch.object(baseline,'is_admin',return_value=True),patch.object(baseline.urllib.request,'urlopen',return_value=fake) as network:
    response=asyncio.run(baseline.image_proxy('https://127.0.0.1/internal',fixture.request()))
    report['image_proxy']={'private_target_reached_fetch_boundary':network.called,
                           'returned_content_type':response.media_type,'status':response.status_code,
                           'network_was_mocked':True}
out=root/'docs'/'Security-2026-10-05'/'baseline-evidence.json'
out.write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps(report,indent=2))
