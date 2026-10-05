"""Local browser proof, with harmless JS markers and no real login or mail."""
import json
from pathlib import Path
import socket
import subprocess
import test_security as fixture
from fastapi.responses import HTMLResponse
from starlette.requests import Request
import uvicorn

main=fixture.main
root=Path(__file__).resolve().parents[1]


@main.app.get('/test/baseline-home')
def old_home():
    return HTMLResponse(subprocess.check_output(['git','show','29db7a6:templates/home.html'],cwd=root,text=True,encoding='utf-8'))


@main.app.get('/test/fixed-home')
async def fixed_home(request:Request):
    return await main.home(request)


@main.app.get('/test/{version}-admin')
def admin(version:str,request:Request):
    title="');window.auditProbe=1;//"
    auction=dict(id=1,title=title,image_url='',bid_count=0,current_price=100,start_price=100,
        min_increment=5,access_code='ABC123',end_time='2026-12-01T12:00:00',is_ended=False,
        require_email_verification=0,allowed_domains='')
    if version=='baseline':
        source=subprocess.check_output(['git','show','29db7a6:templates/admin_overzicht.html'],cwd=root,text=True,encoding='utf-8')
        template=main.jinja_env.from_string(source)
    else:
        template=main.jinja_env.get_template('admin_overzicht.html')
    return HTMLResponse(template.render(auctions=[auction],archief=[],request=request,
        user={'naam':'Audit'},is_admin=True,is_owner=True))


sock=socket.socket(); sock.bind(('127.0.0.1',0))
print(json.dumps({'port':sock.getsockname()[1]}),flush=True)
# Lifespan would try the DB; this offline fixture deliberately disables it.
uvicorn.Server(uvicorn.Config(main.app,log_level='error',lifespan='off')).run(sockets=[sock])
