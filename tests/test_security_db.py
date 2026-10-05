"""Real PostgreSQL abuse/concurrency tests, only the disposable local test DB."""
import asyncio
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta
import json
import threading
import unittest
from unittest.mock import patch
import test_extension as fixture
from fastapi.testclient import TestClient

main=fixture.main


def invoke(fn, data, user='alice@example.test'):
    try:
        result=asyncio.run(fn(fixture.request(data,user)))
        return result.status_code,json.loads(result.body)
    except main.HTTPException as exc:
        return exc.status_code,exc.detail


class AuthSecurityTests(unittest.TestCase):
    def setUp(self):
        patch.object(main.time,'time',return_value=1800000000).start()
        with fixture.connect() as conn, conn.cursor() as cur:
            cur.execute('TRUNCATE email_verifications, veiling_request_limits, feedback_votes, feedback, admin_audit RESTART IDENTITY CASCADE')
            cur.execute("DELETE FROM users WHERE email LIKE '%%@example.test'")
        conn.close()
        self.mail=patch.object(main,'stuur_email').start()
        self.addCleanup(patch.stopall)

    def code(self,email='alice@example.test',value='123456'):
        with fixture.connect() as conn, conn.cursor() as cur:
            cur.execute("INSERT INTO email_verifications (email,auction_id,code,expires_at) VALUES (%s,0,%s,%s)",
                        (email,main.code_digest(email,value),(fixture.BASE+timedelta(minutes=10)).isoformat()))
        conn.close()

    def parallel(self,fn,n=8):
        barrier=threading.Barrier(n)
        def job(_): barrier.wait(); return fn()
        with ThreadPoolExecutor(max_workers=n) as pool: return list(pool.map(job,range(n)))

    def test_parallel_code_requests_respect_limit(self):
        results=self.parallel(lambda:invoke(main.send_login_code,{'email':'alice@example.test'}))
        self.assertEqual(sum(status==200 for status,_ in results),3)
        self.assertEqual(sum(status==429 for status,_ in results),5)
        self.assertEqual(self.mail.call_count,3)
        with fixture.connect() as conn, conn.cursor() as cur:
            cur.execute('SELECT code,used FROM email_verifications ORDER BY id')
            rows=cur.fetchall()
        conn.close()
        self.assertTrue(all(len(code)==64 for code,_ in rows))
        self.assertEqual(sum(used==0 for _,used in rows),1)

    def test_parallel_wrong_guesses_are_counted_without_lost_updates(self):
        self.code()
        results=self.parallel(lambda:invoke(main.verify_login_code,{'email':'alice@example.test','code':'654321','naam':'Alice'}))
        self.assertTrue(all(status==400 for status,_ in results))
        with fixture.connect() as conn, conn.cursor() as cur:
            cur.execute('SELECT pogingen,used FROM email_verifications')
            self.assertEqual(cur.fetchone(),(5,1))
        conn.close()
        self.assertEqual(invoke(main.verify_login_code,{'email':'alice@example.test','code':'123456','naam':'Alice'})[0],400)

    def test_valid_code_can_be_consumed_only_once_concurrently(self):
        self.code()
        results=self.parallel(lambda:invoke(main.verify_login_code,{'email':'alice@example.test','code':'123456','naam':'Alice'}))
        self.assertEqual(sum(status==200 for status,_ in results),1)
        self.assertEqual(sum(status==400 for status,_ in results),7)

    def test_new_code_invalidates_old_code(self):
        self.code()
        self.assertEqual(invoke(main.send_login_code,{'email':'alice@example.test'})[0],200)
        self.assertEqual(invoke(main.verify_login_code,{'email':'alice@example.test','code':'123456','naam':'Alice'})[0],400)

    def test_ip_limit_covers_many_distinct_addresses(self):
        for i in range(main.LOGIN_MAX_CODES_PER_IP):
            self.assertEqual(invoke(main.send_login_code,{'email':f'person{i}@example.test'})[0],200)
        self.assertEqual(invoke(main.send_login_code,{'email':'excess@example.test'})[0],429)
        self.assertEqual(self.mail.call_count,main.LOGIN_MAX_CODES_PER_IP)

    def test_feedback_rate_limit_is_atomic(self):
        results=self.parallel(lambda:invoke(main.api_feedback,{'bericht':'Test feedback'}))
        self.assertEqual(sum(status==200 for status,_ in results),5)
        self.assertEqual(sum(status==429 for status,_ in results),3)
        self.assertEqual(self.mail.call_count,5)

    def test_login_mail_escapes_existing_name_and_hides_provider_errors(self):
        payload='<b data-audit="probe">Test</b>'
        with fixture.connect() as conn, conn.cursor() as cur:
            cur.execute('INSERT INTO users (email,naam,created_at) VALUES (%s,%s,%s)',('alice@example.test',payload,fixture.BASE.isoformat()))
        conn.close()
        self.assertEqual(invoke(main.send_login_code,{'email':'alice@example.test'})[0],200)
        self.assertNotIn(payload,self.mail.call_args.args[2])
        self.assertIn('&lt;b',self.mail.call_args.args[2])
        self.mail.side_effect=RuntimeError('provider-internal-sensitive-value')
        status,detail=invoke(main.send_login_code,{'email':'alice@example.test'})
        self.assertEqual(status,503)
        self.assertNotIn('sensitive',detail)

    def test_role_boundaries_and_database_role_revocation(self):
        with fixture.connect() as conn, conn.cursor() as cur:
            cur.execute('INSERT INTO users (email,naam,created_at,role) VALUES (%s,%s,%s,%s)',
                        ('alice@example.test','Alice',fixture.BASE.isoformat(),'participant'))
        conn.close()
        client=TestClient(main.app,follow_redirects=False)
        client.cookies.set(main.USER_COOKIE,main.maak_user_token('Alice','alice@example.test'))
        self.assertEqual(client.get('/admin/gebruikers').status_code,303)
        self.assertEqual(client.delete('/api/auction/999999').status_code,403)
        with fixture.connect() as conn, conn.cursor() as cur:
            cur.execute("UPDATE users SET role='manager' WHERE email='alice@example.test'")
        conn.close()
        self.assertEqual(client.get('/admin').status_code,200)
        self.assertEqual(client.get('/admin/gebruikers').status_code,303)
        self.assertEqual(client.post('/api/admin/gebruikers',json={'email':'new@example.test','naam':'New'}).status_code,403)
        with fixture.connect() as conn, conn.cursor() as cur:
            cur.execute("UPDATE users SET role='participant' WHERE email='alice@example.test'")
        conn.close()
        self.assertEqual(client.get('/admin').status_code,303)

    def manager(self):
        with fixture.connect() as conn, conn.cursor() as cur:
            cur.execute('INSERT INTO users (email,naam,created_at,role) VALUES (%s,%s,%s,%s)',
                        ('alice@example.test','Alice',fixture.BASE.isoformat(),'manager'))
        conn.close()
        client=TestClient(main.app,follow_redirects=False)
        client.cookies.set(main.USER_COOKIE,main.maak_user_token('Alice','alice@example.test'))
        return client

    def audit(self):
        with fixture.connect() as conn, conn.cursor() as cur:
            cur.execute('SELECT action,target,actor_email FROM admin_audit ORDER BY id')
            rows=cur.fetchall()
        conn.close()
        return rows

    def test_plus_addresses_cannot_bypass_the_mailbox_limit(self):
        for i in range(main.LOGIN_MAX_CODES):
            self.assertEqual(invoke(main.send_login_code,{'email':f'alice+{i}@example.test'})[0],200)
        self.assertEqual(invoke(main.send_login_code,{'email':'alice+x@example.test'})[0],429)
        self.assertEqual(invoke(main.send_login_code,{'email':'alice@example.test'})[0],429)
        self.assertEqual(self.mail.call_count,main.LOGIN_MAX_CODES)

    def test_deleting_auction_zero_keeps_login_codes_and_limits(self):
        client=self.manager()
        self.code()
        self.assertEqual(client.delete('/api/auction/0').status_code,404)
        self.assertEqual(client.delete('/api/auction/999999').status_code,404)
        with fixture.connect() as conn, conn.cursor() as cur:
            cur.execute('SELECT COUNT(*) FROM email_verifications WHERE auction_id=0')
            self.assertEqual(cur.fetchone()[0],1)
        conn.close()
        self.assertEqual(invoke(main.verify_login_code,{'email':'alice@example.test','code':'123456','naam':'Alice'})[0],200)

    def test_manager_bid_removal_and_archiving_are_audited(self):
        client=self.manager()
        aid=fixture.ExtensionTests().auction(seconds=60)
        self.assertEqual(fixture.bid(aid,email='bob@example.test')[0],200)
        with fixture.connect() as conn, conn.cursor() as cur:
            cur.execute('SELECT id FROM bids WHERE auction_id=%s',(aid,))
            bid_id=cur.fetchone()[0]
        conn.close()
        self.assertEqual(client.delete(f'/api/bid/{bid_id}').status_code,200)
        self.assertEqual(client.post(f'/api/auction/{aid}/archive').status_code,200)
        self.assertEqual(client.post(f'/api/auction/{aid}/unarchive').status_code,200)
        self.assertEqual(client.post('/api/auction/999999/archive').status_code,404)
        self.assertEqual(client.post('/api/auction/999999/unarchive').status_code,404)
        rows=self.audit()
        self.assertEqual([r[0] for r in rows],['bod_verwijderd','veiling_gearchiveerd','veiling_hersteld'])
        self.assertIn('bob@example.test',rows[0][1])
        self.assertIn(f'veiling #{aid}',rows[0][1])
        self.assertTrue(all(r[2]=='alice@example.test' for r in rows))

    def test_archived_or_closed_auction_refuses_bids(self):
        archived=fixture.ExtensionTests().auction(seconds=60)
        closed=fixture.ExtensionTests().auction(seconds=60)
        with fixture.connect() as conn, conn.cursor() as cur:
            cur.execute('UPDATE auctions SET archived=1 WHERE id=%s',(archived,))
            cur.execute('UPDATE auctions SET notified=1 WHERE id=%s',(closed,))  # clock repeats an hour after closing
        conn.close()
        self.assertEqual(fixture.bid(archived)[0],400)
        self.assertEqual(fixture.bid(closed)[0],400)
        request=fixture.request()
        self.assertEqual(json.loads(asyncio.run(main.get_auction(closed,request)).body)['status'],'ended')

    def test_bid_ceiling_blocks_lockout_bids(self):
        aid=fixture.ExtensionTests().auction(seconds=60)  # start 100, step 5
        self.assertEqual(fixture.bid(aid,10000000)[0],400)
        self.assertEqual(fixture.bid(aid,1100.01)[0],400)
        self.assertEqual(fixture.bid(aid,1100)[0],200)       # first bid: max(10 x 100, 100 + 1000)
        self.assertEqual(fixture.bid(aid,11050.01)[0],400)   # next minimum 1105: max(11050, 2105)
        self.assertEqual(fixture.bid(aid,1105)[0],200)

    def test_same_display_name_does_not_make_other_bidder_winner(self):
        aid=fixture.ExtensionTests().auction(seconds=3)
        fixture.bid(aid,email='alice@example.test')
        request=fixture.request(email='bob@example.test')
        request._cookies={main.USER_COOKIE:main.maak_user_token('alice','bob@example.test')}
        response=asyncio.run(main.get_auction(aid,request))
        data=json.loads(response.body)
        self.assertFalse(data['leading_is_you'])
        self.assertNotIn('email',data['bids'][0])
        self.assertNotIn('ip_address',data['bids'][0])

    def test_decimal_bid_steps_and_domain_isolation(self):
        aid=fixture.ExtensionTests().auction(seconds=60)
        with fixture.connect() as conn,conn.cursor() as cur:
            cur.execute('UPDATE auctions SET start_price=.1,current_price=.1,min_increment=.2 WHERE id=%s',(aid,))
        conn.close()
        self.assertEqual(fixture.bid(aid,.1)[0],200)
        self.assertEqual(fixture.bid(aid,.3)[0],200)
        restricted=fixture.ExtensionTests().auction(seconds=60,domains='corp.example')
        client=TestClient(main.app)
        client.cookies.set(main.USER_COOKIE,main.maak_user_token('Alice','alice@example.test'))
        self.assertEqual(client.get(f'/api/auction/{restricted}').status_code,403)
        self.assertEqual(client.get(f'/veiling/{restricted}').status_code,403)
        self.assertEqual(client.post('/api/bid',json={'auction_id':restricted,'amount':100}).status_code,403)
        client.cookies.set(main.USER_COOKIE,main.maak_user_token('Alice','alice@corp.example'))
        self.assertEqual(client.get(f'/api/auction/{restricted}').status_code,200)


if __name__=='__main__': unittest.main(verbosity=2)
