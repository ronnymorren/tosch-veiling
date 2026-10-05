"""Route and secret-pattern inventory. Only locations are written, never secret values."""
import ast
import json
from pathlib import Path
import re
import subprocess
from dotenv import dotenv_values
from urllib.parse import urlsplit, parse_qs

root=Path(__file__).resolve().parents[1]
out=root/'docs'/'Security-2026-10-05'
out.mkdir(parents=True,exist_ok=True)
patterns={
    'private_key':re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'provider_key':re.compile(r'\b(?:sk-ant-api\w*-|ghp_|github_pat_|sk-proj-)[A-Za-z0-9_-]{25,}'),
    'database_password':re.compile(r'postgres(?:ql)?://[^\s:@]+:[^\s@]{12,}@'),
    'literal_session_secret':re.compile(r"SESSION_SECRET\s*=\s*['\"][a-fA-F0-9]{32,}['\"]"),
}
objects=subprocess.check_output(['git','rev-list','--objects','--all'],cwd=root,text=True).splitlines()
findings=[]; scanned=0
for line in objects:
    oid,_,name=line.partition(' ')
    if not name or not (name.endswith(('.py','.md','.json','.toml','.txt','.yml','.yaml','.env')) or name=='.env'):
        continue
    kind=subprocess.check_output(['git','cat-file','-t',oid],cwd=root,text=True).strip()
    if kind!='blob': continue
    data=subprocess.check_output(['git','cat-file','blob',oid],cwd=root).decode(errors='replace')
    scanned+=1
    for rule,pattern in patterns.items():
        for match in pattern.finditer(data):
            findings.append({'rule':rule,'path':name,'blob':oid,'line':data.count('\n',0,match.start())+1})
tree=ast.parse((root/'main.py').read_text(encoding='utf-8'))
routes=[]
for node in tree.body:
    if not isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)): continue
    for deco in node.decorator_list:
        if isinstance(deco,ast.Call) and isinstance(deco.func,ast.Attribute) and getattr(deco.func.value,'id',None)=='app' and deco.args and isinstance(deco.args[0],ast.Constant):
            routes.append({'method':deco.func.attr,'path':deco.args[0].value,'handler':node.name,'line':node.lineno})
config={**dotenv_values(root.parent.parent/'.env'),**dotenv_values(root/'.env')}
secret=config.get('SESSION_SECRET') or ''
report={'git_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=root,text=True).strip(),
        'history_blobs_scanned':scanned,'secret_pattern_matches':findings,'routes':routes,
        'local_configuration':{'session_secret_at_least_32_chars':len(secret)>=32,
        'database_tls_required':parse_qs(urlsplit(config.get('DATABASE_URL') or '').query).get('sslmode',[''])[0] in ('require','verify-ca','verify-full')},
        'limitations':'Pattern scan, not proof that no secrets ever existed; local settings are not Vercel settings.'}
(out/'inventory.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
print(json.dumps({'blobs_scanned':scanned,'potential_secret_locations':findings,'routes':len(routes),'local_configuration':report['local_configuration']}))
