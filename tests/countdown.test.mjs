import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import test from 'node:test';
import assert from 'node:assert/strict';

const template = readFileSync(new URL('../templates/auction.html', import.meta.url), 'utf8');
const source = template.match(/<script>([\s\S]*?)<\/script>/)[1]
  .replace('{{ auction_id }}', '1')
  .replace('{{ mijn_naam | tojson }}', '"Alice"')
  .replace('{{ mijn_email | tojson }}', '"alice@example.test"');
const baseline = Date.parse('2026-09-28T12:00:00+02:00');
function snapshot(seconds, endSeconds, extra = {}) {
  return {server_time: new Date(baseline + seconds * 1000).toISOString(),
    end_time: new Date(baseline + endSeconds * 1000).toISOString(),
    status: 'active', current_price: 100, min_increment: 5, start_price: 100, bids: [], ...extra};
}
function screen() {
  const elements = new Map(), intervals = new Map();
  let tick = 1000, sequence = 0;
  const element = id => {
    if (!elements.has(id)) elements.set(id, {textContent: '', innerHTML: '', style: {},
      classList: {add(){}, remove(){}}, disabled: false});
    return elements.get(id);
  };
  const sandbox = {
    document: {getElementById: element, hidden: false, addEventListener(){}},
    window: {addEventListener(){}, location: {}}, performance: {now: () => tick},
    setInterval: (fn, ms) => { const id = ++sequence; intervals.set(id, {fn, ms}); return id; },
    clearInterval: id => intervals.delete(id), setTimeout: () => ++sequence, clearTimeout(){},
    fetch: () => { throw Error('Unexpected request'); }, Intl, Date, console,
  };
  const context = vm.createContext(sandbox);
  vm.runInContext(source, context);
  return {element, intervals, sandbox, context,
    run: code => vm.runInContext(code, context),
    data: data => { context.data = data; }, advance: ms => { tick += ms; }};
}

test('server clock is authoritative, regardless of local system date', () => {
  const s = screen(); s.data(snapshot(0, 3));
  s.run('updateTijd(data, performance.now()); looptijdMs=86400000; updateCountdown()');
  assert.equal(s.element('countdownDisplay').textContent, '00:03');
  s.advance(2001); s.run('updateCountdown()');
  assert.equal(s.element('countdownDisplay').textContent, '00:01');
});

test('zero waits for confirmation and a late extension resumes countdown', () => {
  const s = screen(); s.data(snapshot(0, 3));
  s.run('updateTijd(data, performance.now()); looptijdMs=86400000; startCountdown()');
  s.advance(3000); s.run('updateCountdown()');
  assert.equal(s.element('countdownDisplay').textContent, 'Controle…');
  assert.equal(s.intervals.size, 1);
  s.data(snapshot(3, 12));
  s.run('updateTijd(data, performance.now()); updateCountdown()');
  assert.equal(s.element('countdownDisplay').textContent, '00:09');
  assert.equal(s.element('verlengMelding').style.display, 'block');
  assert.match(s.element('eindigOp').textContent, /12:00:12/);
});

test('stale poll cannot undo a confirmed extension', () => {
  const s = screen(); s.data(snapshot(2, 12));
  assert.equal(s.run('updateTijd(data, performance.now())'), true);
  s.data(snapshot(1, 3));
  assert.equal(s.run('updateTijd(data, performance.now())'), false);
  assert.equal(s.run('+endTime'), baseline + 12000);
  // Even a different instance with a later clock may not shorten the deadline.
  s.data(snapshot(4, 3));
  assert.equal(s.run('updateTijd(data, performance.now())'), false);
});

test('repeated extensions update all screens from server state', () => {
  const a = screen(), b = screen();
  for (const data of [snapshot(0, 3), snapshot(2, 12), snapshot(8, 18)]) {
    for (const s of [a,b]) {
      s.data(data); s.run('updateTijd(data, performance.now()); looptijdMs=86400000; updateCountdown()');
    }
    assert.equal(a.element('countdownDisplay').textContent, b.element('countdownDisplay').textContent);
    assert.equal(a.element('eindigOp').textContent, b.element('eindigOp').textContent);
  }
  assert.equal(a.element('countdownDisplay').textContent, '00:10');
});

test('poll requests do not overlap; stale final result is ignored', async () => {
  const s = screen(); s.data(snapshot(0, 3));
  s.run('updateTijd(data, performance.now()); looptijdMs=86400000');
  let resolve, calls = 0;
  s.sandbox.fetch = () => { calls++; return new Promise(r => resolve = r); };
  const first = s.run('peilVeiling()');
  await s.run('peilVeiling()');
  assert.equal(calls, 1);
  // Bid response arrives while the old poll is pending.
  s.data(snapshot(2, 12)); s.run('updateTijd(data, performance.now())');
  resolve({ok: true, json: async () => snapshot(1, 3, {status: 'ended', winner: 'Bob'})});
  await first;
  assert.equal(s.run('+endTime'), baseline + 12000);
  assert.notEqual(s.element('biedFormWrap').style.display, 'none');
});

test('server-confirmed ending stops countdown and hides bidding', () => {
  const s = screen(); s.data(snapshot(0, 3));
  s.run('updateTijd(data, performance.now()); looptijdMs=86400000; startCountdown(); toonAfgelopen(null, 100, false)');
  assert.equal(s.element('countdownDisplay').textContent, 'Afgelopen');
  assert.equal(s.element('biedFormWrap').style.display, 'none');
  assert.equal(s.intervals.size, 0);
});

test('late bid response cannot overwrite a server-confirmed final countdown', () => {
  const s = screen(); s.data(snapshot(11, 10, {status:'ended'}));
  s.run('auctionData=data; updateTijd(data, performance.now()); toonAfgelopen(null,100,false); updateCountdown()');
  assert.equal(s.element('countdownDisplay').textContent, 'Afgelopen');
});

test('bid confirmation uses submitted amount even if polling changes the stepper', async () => {
  const s = screen(); s.data(snapshot(0, 3));
  s.run('updateTijd(data, performance.now()); looptijdMs=86400000; currentBedrag=100; pollBezig=true');
  let resolve;
  s.sandbox.fetch = () => new Promise(r => resolve = r);
  const pending = s.run('bied()');
  s.run('currentBedrag=110');
  resolve({ok: true, status: 200, json: async () => snapshot(2,12,{amount:100,extended:true})});
  await pending;
  assert.match(s.element('biedSuccess').textContent, /100,00/);
  assert.equal(s.run('+endTime'), baseline + 12000);
  assert.equal(s.element('bodBtn').disabled, false);
});
