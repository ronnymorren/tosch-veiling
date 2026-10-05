"""Offline application security regression tests: no .env, live DB or email."""
import asyncio
import html
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import Mock, patch
from html.parser import HTMLParser

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
with patch('dotenv.load_dotenv', return_value=False), patch.dict(os.environ, {
    'SESSION_SECRET':'security-tests-only-never-production', 'DATABASE_URL':'',
    'LOGIN_DOMEINEN':'example.test,tosch.nl',  # test addresses; production default is tosch.nl
}), patch('psycopg2.connect', side_effect=RuntimeError('Offline tests: database disabled')):
    import main
from fastapi.testclient import TestClient
from starlette.requests import Request
import security


def req(path='/', method='GET', body=None, user=None, headers=None):
    hs = [(k.lower().encode(),v.encode()) for k,v in (headers or {}).items()]
    if user:
        hs.append((b'cookie',f'{main.USER_COOKIE}={main.maak_user_token(user[0],user[1])}'.encode()))
    async def receive(): return {'type':'http.request','body':json.dumps(body or {}).encode()}
    return Request({'type':'http','scheme':'https','server':('veiling.tosch.nl',443),
        'path':path,'query_string':b'','method':method,'headers':hs,'client':('127.0.0.1',1)},receive)


class Tags(HTMLParser):
    def __init__(self, text):
        super().__init__(); self.tags=[]; self.feed(text)
    def handle_starttag(self,tag,attrs): self.tags.append((tag,dict(attrs)))


class SecurityTests(unittest.TestCase):
    def test_feedback_text_is_not_html(self):
        payload='<b style="color:#c00">HTML-INJECTION-TEST</b><script>window.auditProbe=1</script>'
        item=dict(id=1,bericht=payload,naam=payload,datum='2026-10-05',status='open',
                  zelf_gestemd=False,stemmen=0,status_reden=payload,status_door=payload)
        text=main.jinja_env.get_template('feedback.html').render(items=[item],user={'naam':payload},is_admin=False,is_owner=False)
        self.assertNotIn(payload,text)
        self.assertIn('&lt;b style=',text)

    def test_winner_email_escapes_user_name_and_title(self):
        payload='<b data-audit="injected">Test</b>'
        with patch.object(main,'stuur_email') as mail:
            main.stuur_afloop_mail('test@example.test',payload,payload,100,True)
        body=mail.call_args.args[2]
        self.assertNotIn(payload,body)
        self.assertIn(html.escape(payload),body)

    def test_admin_title_not_interpolated_in_javascript(self):
        payload="');window.auditProbe=1;//"
        auction=dict(id=1,title=payload,image_url='',bid_count=0,description='',
            current_price=100,start_price=100,min_increment=5,access_code='ABC123',
            end_time='2026-12-01T12:00:00',is_ended=False,require_email_verification=0,allowed_domains='')
        page=main.jinja_env.get_template('admin_overzicht.html').render(
            auctions=[auction],archief=[auction],user={'naam':'Test'},is_owner=True,request=req())
        handlers=[attrs['onclick'] for tag,attrs in Tags(page).tags if 'onclick' in attrs]
        self.assertFalse(any(payload in handler for handler in handlers))

    def test_manager_email_not_interpolated_in_javascript(self):
        payload="x');window.auditProbe=1;//@example.test"
        page=main.jinja_env.get_template('admin_gebruikers.html').render(
            managers=[dict(email=payload,naam='Test',created_at='2026-10-05')],
            user={'naam':'Owner'},is_owner=True,request=req())
        handlers=[attrs['onclick'] for tag,attrs in Tags(page).tags if 'onclick' in attrs]
        self.assertFalse(any(payload in handler for handler in handlers))

    def test_redirect_rejects_external_and_backslash_paths(self):
        for url in ('https://example.test','//example.test','/\\example.test','/\n/example.test',
                    '/%5cexample.test','/%2fexample.test','javascript:alert(1)'):
            with self.subTest(url=url): self.assertEqual(main.valideer_next(url,'/veilingen'),'/veilingen')
        self.assertEqual(main.valideer_next('/veiling/123','/veilingen'),'/veiling/123')

    def test_home_uses_server_validated_redirect(self):
        source=(ROOT/'templates/home.html').read_text(encoding='utf-8')
        self.assertNotIn("params.get('next')",source)
        self.assertIn('next_url | tojson',source)

    def test_session_tampering_rejected(self):
        token=main.maak_user_token('Test','test@example.test')
        r=req(headers={'cookie':main.USER_COOKIE+'='+token[:-5]+'AAAAA'})
        self.assertIsNone(main.get_user(r))

    def test_unauthenticated_sensitive_endpoints(self):
        client=TestClient(main.app)
        for path in ('/api/auction/1','/api/image-proxy?url=https://example.test/'):
            self.assertIn(client.get(path).status_code,(401,403))

    def test_mutation_rejects_cross_origin(self):
        client=TestClient(main.app)
        conn=Mock(); cur=Mock(); cur.fetchone.return_value={'id':1}
        with patch.object(main,'get_conn',return_value=conn),patch.object(main,'get_cur',return_value=cur),patch.object(main,'stuur_email'):
            client.cookies.set(main.USER_COOKIE,main.maak_user_token('Test','test@example.test'))
            r=client.post('/api/feedback',json={'bericht':'test'},headers={'Origin':'https://evil.example'})
        self.assertEqual(r.status_code,403)
        cur.execute.assert_not_called()

    def test_mutation_rejects_simple_content_type(self):
        client=TestClient(main.app)
        r=client.post('/api/auth/verify-login-code',content='{}',headers={'Content-Type':'text/plain'})
        self.assertEqual(r.status_code,415)

    def test_profile_cookie_is_secure_on_https(self):
        with patch.object(main,'get_conn',return_value=Mock()),patch.object(main,'get_cur',return_value=Mock()):
            response=asyncio.run(main.update_naam(req('/api/profiel/naam','POST',{'naam':'Test'},('Test','test@example.test'))))
        self.assertIn('Secure',response.headers['set-cookie'])

    def test_dynamic_responses_not_publicly_cached(self):
        r=TestClient(main.app).get('/')
        self.assertIn('no-store',r.headers.get('cache-control',''))

    def test_invalid_json_shapes_and_oversized_body(self):
        client=TestClient(main.app)
        for body in ('[]','null','{"email":3}','{"email":', '{"code":"1234567"}'):
            r=client.post('/api/auth/verify-login-code',content=body,headers={'Content-Type':'application/json'})
            self.assertEqual(r.status_code,400)
        r=client.post('/api/auth/verify-login-code',content=b'a'*65537,headers={'Content-Type':'application/json'})
        self.assertEqual(r.status_code,413)

    def test_same_site_sibling_origin_is_rejected(self):
        client=TestClient(main.app)
        r=client.post('/api/auth/verify-login-code',json={},headers={'Origin':'https://other.tosch.nl','Sec-Fetch-Site':'same-site'})
        self.assertEqual(r.status_code,403)

    def test_unauthenticated_admin_writes_do_not_open_database(self):
        client=TestClient(main.app)
        with patch.object(main,'get_conn') as db:
            self.assertEqual(client.delete('/api/auction/999999').status_code,401)
        db.assert_not_called()

    def test_private_image_targets_are_rejected_even_for_admin(self):
        for ip in ('127.0.0.1','10.0.0.1','169.254.169.254','192.168.1.1','::1','fc00::1','::ffff:127.0.0.1'):
            with self.subTest(ip=ip),patch('security.socket.getaddrinfo',return_value=[(2,1,6,'',(ip,443))]):
                with self.assertRaises(main.HTTPException): security.image_target('https://image.example.test/',True)

    def test_mixed_public_private_dns_and_unsupported_urls(self):
        with patch('security.socket.getaddrinfo',return_value=[(2,1,6,'',('8.8.8.8',443)),(2,1,6,'',('127.0.0.1',443))]):
            with self.assertRaises(main.HTTPException): security.image_target('https://image.example.test/',True)
        for url in ('http://tse1.mm.bing.net/','file:///etc/passwd','https://user:pw@tse1.mm.bing.net/',
                    'https://tse1.mm.bing.net:22/','https://bing.net.evil.example/','https://evil.example/'):
            with self.subTest(url=url),self.assertRaises(main.HTTPException): security.image_target(url)

    def test_image_mime_is_derived_from_content(self):
        self.assertEqual(security.raster_type(b'\x89PNG\r\n\x1a\nrest'),'image/png')
        for content in (b'<html><script>window.auditProbe=1</script>',b'<svg onload="alert(1)">',b'not an image'):
            with self.assertRaises(main.HTTPException): security.raster_type(content)

    def test_money_requires_finite_bounded_cents(self):
        for value in ('NaN','Infinity',True,10000001,-1,'0.001',None):
            with self.subTest(value=value),self.assertRaises(main.HTTPException): security.money(value)
        self.assertEqual(security.money('10.25'),10.25)
        with self.assertRaises(main.HTTPException): security.money(0,positive=True)

    def test_expired_and_future_tokens_rejected(self):
        import time
        now=time.time()
        for timestamp in (now-main.USER_TTL-1,now+3600):
            with patch('main.time.time',return_value=timestamp): token=main.maak_user_token('Test','test@example.test')
            self.assertIsNone(main.get_user(req(headers={'cookie':main.USER_COOKIE+'='+token})))

    def test_image_fetch_pins_ip_and_refuses_redirect_to_private_network(self):
        response=Mock(status=302)
        response.getheader.return_value='https://127.0.0.1/private'
        conn=Mock(); conn.getresponse.return_value=response
        def resolve(host,*args,**kwargs):
            return [(2,1,6,'',('127.0.0.1' if host=='127.0.0.1' else '8.8.8.8',443))]
        with patch('security.socket.getaddrinfo',side_effect=resolve),patch('security.socket.create_connection') as connection,\
             patch('security.ssl.create_default_context'),patch('security.http.client.HTTPSConnection',return_value=conn):
            with self.assertRaises(main.HTTPException): security.fetch_image('https://image.example.test/',True)
            connection.assert_called_once_with(('8.8.8.8',443),timeout=8)

    def test_login_is_limited_to_allowed_domains(self):
        client=TestClient(main.app)
        with patch.object(main,'LOGIN_DOMEINEN',('tosch.nl',)),patch.object(main,'get_conn') as db,patch.object(main,'stuur_email') as mail:
            for path,body in (('/api/auth/send-login-code',{'email':'outsider@example.test'}),
                              ('/api/auth/verify-login-code',{'email':'outsider@example.test','code':'123456','naam':'X'})):
                self.assertEqual(client.post(path,json=body).status_code,403)
            # A session issued before the allowlist stops working immediately.
            old=main.maak_user_token('Outsider','outsider@example.test')
            self.assertIsNone(main.get_user(req(headers={'cookie':main.USER_COOKIE+'='+old})))
            staff=main.maak_user_token('Staff','staff@tosch.nl')
            self.assertEqual(main.get_user(req(headers={'cookie':main.USER_COOKIE+'='+staff}))['email'],'staff@tosch.nl')
        db.assert_not_called(); mail.assert_not_called()
        with patch.object(main,'LOGIN_DOMEINEN',('*',)): self.assertTrue(main.login_toegestaan('a@anything.example'))

    def test_plus_addresses_share_one_mailbox_limit(self):
        self.assertEqual(main.postvak('rm+1@tosch.nl'),'rm@tosch.nl')
        self.assertEqual(main.postvak('rm@tosch.nl'),'rm@tosch.nl')

    def test_deleting_missing_auction_never_touches_login_codes(self):
        client=TestClient(main.app)
        conn=Mock(); cur=Mock(); cur.fetchone.side_effect=[{'role':'manager'},None]
        with patch.object(main,'get_conn',return_value=conn),patch.object(main,'get_cur',return_value=cur):
            client.cookies.set(main.USER_COOKIE,main.maak_user_token('Manager','manager@example.test'))
            self.assertEqual(client.delete('/api/auction/0').status_code,404)
        statements=' '.join(str(call.args[0]) for call in cur.execute.call_args_list)
        self.assertNotIn('email_verifications',statements)
        self.assertNotIn('DELETE',statements)
        conn.commit.assert_not_called()

    def test_logout_only_by_same_origin_post(self):
        client=TestClient(main.app,follow_redirects=False)
        client.cookies.set(main.USER_COOKIE,main.maak_user_token('Test','test@example.test'))
        for path in ('/uitloggen','/admin/logout'):
            r=client.get(path)
            self.assertEqual(r.status_code,303)
            self.assertNotIn(main.USER_COOKIE+'=',r.headers.get('set-cookie',''))
        self.assertEqual(client.post('/uitloggen',headers={'Origin':'https://evil.example'}).status_code,403)
        r=client.post('/uitloggen')
        self.assertEqual(r.status_code,200)
        self.assertIn(main.USER_COOKIE+'=""',r.headers['set-cookie'])

    def test_archive_images_load_through_proxy(self):
        auction=dict(id=1,title='Test',image_url='https://veiling.tosch.nl/uitloggen',bid_count=0,description='',
            current_price=100,start_price=100,min_increment=5,access_code='ABC123',
            end_time='2026-12-01T12:00:00',is_ended=True,require_email_verification=0,allowed_domains='')
        page=main.jinja_env.get_template('admin_overzicht.html').render(
            auctions=[],archief=[auction],user={'naam':'Test'},is_owner=True,request=req())
        sources=[attrs.get('src','') for tag,attrs in Tags(page).tags if tag=='img' and 'ov-img' in attrs.get('class','')]
        self.assertTrue(sources)
        self.assertTrue(all(src.startswith('/api/image-proxy?url=') for src in sources))

    def test_closed_auction_stays_closed_when_clock_repeats_an_hour(self):
        from datetime import datetime
        row=dict(notified=1,status='active',end_time='2026-10-25T02:30:00')
        self.assertTrue(main.is_afgelopen(row,datetime(2026,10,25,2,10)))
        row['notified']=0
        self.assertFalse(main.is_afgelopen(row,datetime(2026,10,25,2,10)))
        self.assertTrue(main.is_afgelopen(row,datetime(2026,10,25,2,30)))

    def test_image_fetch_rejects_html_and_oversized_response(self):
        for content,status in ((b'<html>bad</html>',400),(b'\x89PNG\r\n\x1a\n'+b'x'*security.MAX_IMAGE_BYTES,413)):
            response=Mock(status=200); response.read.return_value=content
            conn=Mock(); conn.getresponse.return_value=response
            with patch('security.socket.getaddrinfo',return_value=[(2,1,6,'',('8.8.8.8',443))]),\
                 patch('security.socket.create_connection'),patch('security.ssl.create_default_context'),\
                 patch('security.http.client.HTTPSConnection',return_value=conn):
                with self.assertRaises(main.HTTPException) as error: security.fetch_image('https://image.example.test/',True)
                self.assertEqual(error.exception.status_code,status)
                response.read.assert_called_once_with(security.MAX_IMAGE_BYTES+1)


if __name__=='__main__': unittest.main(verbosity=2)
