// Real Chrome + real FastAPI/PostgreSQL, only local fictional auction data.
import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {createInterface} from 'node:readline';
import assert from 'node:assert/strict';
import {fileURLToPath} from 'node:url';
const root = fileURLToPath(new URL('../', import.meta.url));
const fixture = spawn(path.join(root,'.venv/Scripts/python.exe'), ['tests/serve_fixture.py'],
  {cwd:root, windowsHide:true, stdio:['pipe','pipe','inherit']});
const lines = createInterface({input:fixture.stdout});
const [line] = await once(lines,'line');
const {port, auction_id} = JSON.parse(line);
const base = `http://127.0.0.1:${port}`;
const profile = await fs.mkdtemp(path.join(os.tmpdir(),'veiling-extension-browser-'));
const browser = spawn('C:/Program Files/Google/Chrome/Application/chrome.exe',
  ['--headless=new','--no-first-run','--disable-background-networking','--remote-debugging-port=0',
   '--user-data-dir='+profile,'about:blank'], {windowsHide:true, stdio:'ignore'});
const sockets = [], failures = [];
async function connect(url) {
  const ws = new WebSocket(url); sockets.push(ws); await once(ws,'open');
  let seq=0; const pending=new Map();
  ws.onmessage=e=>{ const m=JSON.parse(e.data);
    if(m.id){const p=pending.get(m.id);pending.delete(m.id);m.error?p.reject(Error(m.error.message)):p.resolve(m.result);}
    else if(m.method==='Runtime.exceptionThrown') failures.push(m.params.exceptionDetails.text);
  };
  return (method,params={})=>new Promise((resolve,reject)=>{const id=++seq;pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params}));});
}
try {
  let debugPort;
  for(let i=0;i<100;i++) {try {debugPort=(await fs.readFile(path.join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0];break;}catch{await new Promise(r=>setTimeout(r,100));}}
  assert(debugPort,'Chrome did not start');
  const version=await (await fetch(`http://127.0.0.1:${debugPort}/json/version`)).json();
  const control=await connect(version.webSocketDebuggerUrl);
  async function page(name, mobile=false) {
    const {browserContextId}=await control('Target.createBrowserContext');
    const {targetId}=await control('Target.createTarget',{url:'about:blank',browserContextId});
    const call=await connect(`ws://127.0.0.1:${debugPort}/devtools/page/${targetId}`);
    await call('Runtime.enable');
    await call('Emulation.setDeviceMetricsOverride',{width:mobile?390:1440,height:mobile?844:1000,deviceScaleFactor:1,mobile});
    await call('Emulation.setTimezoneOverride',{timezoneId:mobile?'America/New_York':'Europe/Amsterdam'});
    const run=async expression=>{const r=await call('Runtime.evaluate',{expression,awaitPromise:true,returnByValue:true});if(r.exceptionDetails)throw Error(r.exceptionDetails.text);return r.result.value;};
    const wait=async expr=>{for(let i=0;i<100;i++){if(await run(expr))return;await new Promise(r=>setTimeout(r,100));}throw Error('Timeout: '+expr);};
    await call('Page.navigate',{url:base+'/test/login/'+name});
    await wait('typeof auctionData !== "undefined" && auctionData !== null');
    return {call,run,wait};
  }
  const a=await page('Alice'), b=await page('Bob',true);
  const setTime=async seconds=>{const r=await fetch(base+'/test/clock/'+seconds,{method:'POST'});assert(r.ok);};
  await setTime(17); // first bid with 3s remaining -> end t+27
  await a.run('bied()');
  await b.run('peilVeiling(true)');
  await b.wait('auctionData.current_price===100 && auctionData.bids.length===1');
  assert.equal(await a.run('+endTime'),await b.run('+endTime'));
  assert.match(await b.run('document.getElementById("verlengMelding").textContent'),/verlengd/);
  assert.equal(await a.run('document.getElementById("eindigOp").textContent'),await b.run('document.getElementById("eindigOp").textContent'));
  await setTime(23); // second bid with 4s remaining -> end t+33
  await b.run('bied()');
  await a.run('peilVeiling(true)');
  await a.wait('auctionData.current_price===105');
  assert.equal(await a.run('+endTime'),await b.run('+endTime'));
  assert.equal(await b.run('document.documentElement.scrollWidth <= innerWidth'),true,'mobile overflow');
  for(const [name,p] of [['desktop',a],['mobile',b]]) {
    const {data}=await p.call('Page.captureScreenshot',{format:'png',captureBeyondViewport:true});
    await fs.writeFile(path.join(profile,name+'.png'),Buffer.from(data,'base64'));
  }
  // Overview must keep updating and must not erase this bidder's presence.
  await b.call('Page.navigate',{url:base+'/veilingen'});
  await b.wait('document.querySelector("[data-endtime]") !== null');
  await setTime(29);
  await a.run('bied()'); // t+39
  await b.run('updateTimers()');
  await b.wait('document.querySelector("[data-endtime]").dataset.endtime.includes("12:00:39")');
  await setTime(39);
  await a.run('peilVeiling(true)');
  await a.wait('document.getElementById("countdownDisplay").textContent === "Afgelopen"');
  const late=await a.run(`fetch('/api/bid',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({auction_id:${auction_id},amount:120})}).then(r=>r.status)`);
  assert.equal(late,400);
  assert.deepEqual(failures,[]);
  console.log(JSON.stringify({passed:true,checks:['two browsers','repeated extensions','different timezones','mobile layout','overview refresh','confirmed winner','late bid refused'],screenshots:profile}));
} finally {
  for(const ws of sockets) ws.close();
  browser.kill(); fixture.kill(); lines.close();
}
