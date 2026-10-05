"""Integration tests against disposable PostgreSQL on localhost:55439.

No .env files, production database or outbound email are used.
Run: .venv/Scripts/python.exe tests/test_extension.py
"""
import asyncio
import json
import os
from pathlib import Path
import sys
import threading
import time
import unittest
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from unittest.mock import patch

import psycopg2
from psycopg2 import sql
from starlette.requests import Request

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
os.chdir(ROOT)
DB_NAME = 'veiling_extension_test'
DSN = f'host=127.0.0.1 port=55439 user=postgres dbname={DB_NAME} connect_timeout=5'
admin = psycopg2.connect('host=127.0.0.1 port=55439 user=postgres dbname=postgres connect_timeout=5')
admin.autocommit = True
with admin.cursor() as cur:
    cur.execute('SELECT 1 FROM pg_database WHERE datname=%s', (DB_NAME,))
    if not cur.fetchone():
        cur.execute(sql.SQL('CREATE DATABASE {}').format(sql.Identifier(DB_NAME)))
admin.close()
with patch('dotenv.load_dotenv', return_value=False), patch.dict(os.environ, {
    'DATABASE_URL': DSN, 'SESSION_SECRET': 'only-for-local-auction-tests',
    'LOGIN_DOMEINEN': 'example.test,corp.example,tosch.nl',  # test addresses; production default is tosch.nl
}):
    import main

# Even an accidental mail attempt fails locally; no live SMTP is reachable here.
main.stuur_email = unittest.mock.Mock(side_effect=AssertionError('No outbound email in tests'))
clock = threading.local()
BASE = datetime(2026, 9, 28, 12, 0, 0)
real_nu = main.nu
main.nu = lambda: getattr(clock, 'now', BASE)
connect = main.get_conn


def request(body=None, email='alice@example.test'):
    async def receive():
        return {'type': 'http.request', 'body': json.dumps(body or {}).encode()}
    token = main.maak_user_token(email.split('@')[0], email)
    return Request({'type': 'http', 'method': 'POST', 'path': '/api/bid',
                    'headers': [(b'cookie', f'tosch_user={token}'.encode())],
                    'client': ('127.0.0.1', 1234)}, receive)


def bid(aid, amount=100, now=BASE, email='alice@example.test'):
    clock.now = now
    try:
        response = asyncio.run(main.place_bid(request({'auction_id': aid, 'amount': amount}, email)))
        return response.status_code, json.loads(response.body)
    except main.HTTPException as e:
        return e.status_code, e.detail


def poll(aid, now=BASE):
    clock.now = now
    response = asyncio.run(main.get_auction(aid, request(), zichtbaar=1))
    assert response.headers['cache-control'] == 'no-store'
    return json.loads(response.body)


def sweep(now):
    clock.now = now
    conn = connect()
    try:
        main.verstuur_afloopmails(main.get_cur(conn), conn)
    finally:
        conn.close()


class ExtensionTests(unittest.TestCase):
    def setUp(self):
        clock.now = BASE
        with connect() as conn, conn.cursor() as cur:
            cur.execute('TRUNCATE bids, auction_presence, auctions RESTART IDENTITY CASCADE')
        conn.close()
        self.mail = patch.object(main, 'mail_afloop').start()
        self.addCleanup(patch.stopall)

    def auction(self, seconds=3, status='active', domains=''):
        with connect() as conn, conn.cursor() as cur:
            cur.execute('''INSERT INTO auctions
                (title, start_price, current_price, min_increment, end_time, access_code, status, allowed_domains, created_at)
                VALUES ('Test auction',100,100,5,%s,%s,%s,%s,%s) RETURNING id''',
                ((BASE + timedelta(seconds=seconds)).isoformat(), str(time.monotonic_ns()), status, domains,
                 (BASE - timedelta(days=1)).isoformat()))
            aid = cur.fetchone()[0]
        conn.close()
        return aid

    def state(self, aid):
        conn = connect()
        try:
            cur = main.get_cur(conn)
            cur.execute('SELECT * FROM auctions WHERE id=%s', (aid,))
            row = dict(cur.fetchone())
            cur.execute('SELECT * FROM bids WHERE auction_id=%s ORDER BY id', (aid,))
            return row, cur.fetchall()
        finally:
            conn.close()

    def test_boundary_matrix(self):
        for remaining in (30, 5.000001, 5, 4.999999, 3, .000001, 0, -.000001):
            with self.subTest(remaining=remaining):
                aid = self.auction(remaining)
                status, data = bid(aid)
                row, bids = self.state(aid)
                if remaining <= 0:
                    self.assertEqual(status, 400)
                    self.assertEqual(bids, [])
                else:
                    self.assertEqual(status, 200)
                    extended = remaining <= 5
                    self.assertEqual(data['extended'], extended)
                    expected = BASE + timedelta(seconds=10 if extended else remaining)
                    self.assertEqual(datetime.fromisoformat(row['end_time']), expected)
                    self.assertEqual(datetime.fromisoformat(data['end_time']).utcoffset(), timedelta(hours=2))
                    self.assertEqual(len(bids), 1)
                    self.assertEqual(bids[0]['timestamp'], BASE.isoformat())

    def test_repeat_extension_and_no_extension_outside_window(self):
        aid = self.auction()
        self.assertTrue(bid(aid)[1]['extended'])  # end: t+10
        self.assertFalse(bid(aid, 105, BASE + timedelta(seconds=1))[1]['extended'])
        self.assertTrue(bid(aid, 110, BASE + timedelta(seconds=6))[1]['extended'])  # end: t+16
        self.assertTrue(bid(aid, 115, BASE + timedelta(seconds=11))[1]['extended'])  # end: t+21
        self.assertEqual(self.state(aid)[0]['end_time'], (BASE + timedelta(seconds=21)).isoformat())
        self.assertEqual(bid(aid, 120, BASE + timedelta(seconds=21))[0], 400)

    def test_invalid_bids_never_extend(self):
        aid = self.auction()
        for amount in (99, -1, 'NaN', 'Infinity', '-Infinity', 'invalid', None):
            self.assertEqual(bid(aid, amount)[0], 400)
        self.assertEqual(self.state(aid)[1], [])
        self.assertEqual(self.state(aid)[0]['end_time'], (BASE + timedelta(seconds=3)).isoformat())

    def test_ended_and_forbidden_bids_never_extend(self):
        self.assertEqual(bid(self.auction(status='ended'))[0], 400)
        self.assertEqual(bid(self.auction(domains='tosch.nl'))[0], 403)
        self.assertEqual(bid(999999)[0], 404)

    def test_concurrent_equal_bids_only_one_accepted(self):
        aid = self.auction()
        barrier = threading.Barrier(6)
        def place():
            barrier.wait()
            return bid(aid)[0]
        with ThreadPoolExecutor(max_workers=6) as pool:
            results = list(pool.map(lambda _: place(), range(6)))
        self.assertEqual(results.count(200), 1)
        self.assertEqual(results.count(400), 5)
        self.assertEqual(len(self.state(aid)[1]), 1)
        self.assertEqual(self.state(aid)[0]['end_time'], (BASE + timedelta(seconds=10)).isoformat())

    def test_transaction_failure_rolls_back_bid_and_extension(self):
        aid = self.auction()
        with connect() as conn, conn.cursor() as cur:
            cur.execute('''CREATE OR REPLACE FUNCTION reject_test_update() RETURNS trigger AS $$
                BEGIN RAISE EXCEPTION 'forced test failure'; END; $$ LANGUAGE plpgsql;
                CREATE TRIGGER reject_test_update BEFORE UPDATE ON auctions
                FOR EACH ROW EXECUTE FUNCTION reject_test_update();''')
        conn.close()
        try:
            with self.assertRaises(psycopg2.Error):
                bid(aid)
            row, bids = self.state(aid)
            self.assertEqual(bids, [])
            self.assertEqual(row['end_time'], (BASE + timedelta(seconds=3)).isoformat())
        finally:
            with connect() as conn, conn.cursor() as cur:
                cur.execute('DROP TRIGGER reject_test_update ON auctions; DROP FUNCTION reject_test_update()')
            conn.close()

    def race_with_uncommitted_bid(self, reader):
        aid = self.auction()
        ready, release = threading.Event(), threading.Event()
        class HeldCommit:
            def __init__(self): self.conn = connect()
            def __getattr__(self, attr): return getattr(self.conn, attr)
            def commit(self):
                ready.set()
                if not release.wait(10): raise AssertionError('Test commit timeout')
                self.conn.commit()
        def factory():
            return HeldCommit() if threading.current_thread().name.endswith('_0') else connect()
        with patch.object(main, 'get_conn', side_effect=factory), ThreadPoolExecutor(max_workers=2) as pool:
            writer = pool.submit(bid, aid)
            self.assertTrue(ready.wait(5))
            observer = pool.submit(reader, aid, BASE + timedelta(seconds=4))
            try:
                # Ensure the reader actually reached the DB row-lock, not merely a slow thread.
                waiting = False
                for _ in range(100):
                    with connect() as conn, conn.cursor() as cur:
                        cur.execute("SELECT 1 FROM pg_stat_activity WHERE datname=%s AND wait_event_type='Lock'", (DB_NAME,))
                        waiting = bool(cur.fetchone())
                    conn.close()
                    if waiting: break
                    time.sleep(.02)
                self.assertTrue(waiting, 'Reader must wait for the bid transaction')
                self.assertFalse(observer.done())
            finally:
                release.set()
            self.assertEqual(writer.result(timeout=5)[0], 200)
            result = observer.result(timeout=5)
        self.assertEqual(self.state(aid)[0]['notified'], 0)
        self.mail.assert_not_called()
        return result

    def test_poll_waits_for_bid_and_sees_extended_deadline(self):
        data = self.race_with_uncommitted_bid(poll)
        self.assertEqual(data['status'], 'active')
        self.assertIsNone(data['winner'])
        self.assertEqual(len(data['bids']), 1)
        self.assertEqual(datetime.fromisoformat(data['end_time']).replace(tzinfo=None), BASE + timedelta(seconds=10))

    def test_sweep_rechecks_stale_candidate_after_waiting_for_bid(self):
        self.race_with_uncommitted_bid(lambda aid, now: sweep(now))

    def test_mail_only_once_after_final_deadline(self):
        aid = self.auction()
        bid(aid)
        self.assertEqual(poll(aid, BASE + timedelta(seconds=4))['status'], 'active')
        self.mail.assert_not_called()
        data = poll(aid, BASE + timedelta(seconds=10))
        self.assertEqual(data['status'], 'ended')
        self.assertEqual(data['winner'], 'alice')
        poll(aid, BASE + timedelta(seconds=11))
        sweep(BASE + timedelta(seconds=11))
        self.mail.assert_called_once()

    def test_competing_final_polls_claim_mail_once(self):
        aid = self.auction()
        bid(aid)
        with ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(lambda _: poll(aid, BASE + timedelta(seconds=11)), range(4)))
        self.assertTrue(all(r['status'] == 'ended' for r in results))
        self.mail.assert_called_once()

    def test_overview_poll_does_not_remove_existing_presence(self):
        aid = self.auction(60)
        poll(aid)
        response = asyncio.run(main.get_auction(aid, request()))
        self.assertEqual(json.loads(response.body)['kijkers'], 1)

    def test_explicit_timezone_summer_and_winter(self):
        for now, hours in ((BASE, 2), (datetime(2026, 12, 1, 12), 1)):
            payload = main.tijd_payload(now.isoformat(), now)
            for field in ('end_time', 'server_time'):
                self.assertEqual(datetime.fromisoformat(payload[field]).utcoffset(), timedelta(hours=hours))


if __name__ == '__main__':
    unittest.main(verbosity=2)
