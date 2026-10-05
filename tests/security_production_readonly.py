"""Targeted read-only incident/configuration checks. Never imports the app or sends mail."""
import json
from pathlib import Path
import re
import sys
import psycopg2
from psycopg2.extras import RealDictCursor
from dotenv import dotenv_values

root=Path(__file__).resolve().parents[1]
config={**dotenv_values(root.parent.parent/'.env'),**dotenv_values(root/'.env')}
conn=psycopg2.connect(config['DATABASE_URL'],connect_timeout=10)
conn.set_session(readonly=True)
try:
    cur=conn.cursor(cursor_factory=RealDictCursor)
    cur.execute('SET LOCAL statement_timeout=10000')
    cur.execute('SHOW transaction_read_only')
    assert cur.fetchone()['transaction_read_only']=='on'
    cur.execute('''SELECT rolsuper,rolcreatedb,rolcreaterole,rolbypassrls,
        has_database_privilege(current_database(),'CREATE') AS can_create_schema,
        has_schema_privilege('public','CREATE') AS can_create_tables
        FROM pg_roles WHERE rolname=current_user''')
    permissions=dict(cur.fetchone())
    supplied_email='ganupam010+toschveiling@gmail.com'
    cur.execute('SELECT role,created_at FROM users WHERE email=%s',(supplied_email,))
    user=cur.fetchone()
    cur.execute('SELECT id,created_at,bericht FROM feedback WHERE email=%s',(supplied_email,))
    feedback=[{'id':r['id'],'created_at':r['created_at'],'length':len(r['bericht']),
               'html_tag_names':sorted(set(re.findall(r'<\s*([a-zA-Z][\w-]*)',r['bericht'])))} for r in cur.fetchall()]
    cur.execute('SELECT COUNT(*) AS n FROM bids WHERE email=%s',(supplied_email,))
    bids=cur.fetchone()['n']
    cur.execute('SELECT action,COUNT(*) AS n FROM admin_audit WHERE actor_email=%s GROUP BY action',(supplied_email,))
    actions=[dict(r) for r in cur.fetchall()]
    cur.execute("SELECT to_regclass('public.veiling_request_limits') IS NOT NULL AS present")
    rate_table=cur.fetchone()['present']
    cur.execute("SELECT COUNT(*) AS n FROM users WHERE naam ~* '<(script|img|svg)|onerror[[:space:]]*=|javascript:'")
    name_indicators=cur.fetchone()['n']
    report={'client_date':'2026-10-05','read_only':True,'database_tls':conn.info.ssl_in_use,
            'database_permissions':permissions,'reported_sender':{'account_exists':bool(user),
            'role':user['role'] if user else None,'created_at':user['created_at'] if user else None,
            'feedback':feedback,'bid_count':bids,'audit_actions':actions},
            'rate_limit_table_present':rate_table,'names_with_script_indicators':name_indicators,
            'limitations':'Targeted table check, not a review of Vercel access logs or all historical activity. HTML indicators are not proof of execution.'}
finally:
    conn.rollback(); conn.close()
label=sys.argv[1] if len(sys.argv)>1 else 'before'
assert label in ('before','after')
out=root/'docs'/'Security-2026-10-05'/f'production-readonly-{label}.json'
out.write_text(json.dumps(report,indent=2,default=str),encoding='utf-8')
print(json.dumps(report,indent=2,default=str))
