"""Local-only browser fixture. Uses the disposable database from test_extension."""
from datetime import timedelta
import json
import socket
import test_extension as fixture
from fastapi.responses import RedirectResponse
import uvicorn

main = fixture.main
now = fixture.BASE
main.nu = lambda: now
main.mail_afloop = lambda *args: None
fixture.ExtensionTests().setUp()  # clear only disposable test DB
aid = fixture.ExtensionTests().auction(seconds=20)


@main.app.get('/test/login/{name}')
def login(name: str):
    response = RedirectResponse(f'/veiling/{aid}', status_code=303)
    response.set_cookie(main.USER_COOKIE, main.maak_user_token(name, name.lower() + '@example.test'))
    return response


@main.app.post('/test/clock/{seconds}')
def clock(seconds: float):
    global now
    now = fixture.BASE + timedelta(seconds=seconds)
    return {'ok': True}


sock = socket.socket()
sock.bind(('127.0.0.1', 0))
print(json.dumps({'port': sock.getsockname()[1], 'auction_id': aid}), flush=True)
uvicorn.Server(uvicorn.Config(main.app, log_level='error')).run(sockets=[sock])
