import fs from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import {spawn} from 'node:child_process';
import {once} from 'node:events';
import {createInterface} from 'node:readline';
import {fileURLToPath} from 'node:url';
import assert from 'node:assert/strict';
const root=fileURLToPath(new URL('../',import.meta.url));
const fixture=spawn(path.join(root,'.venv/Scripts/python.exe'),['tests/serve_security_fixture.py'],{cwd:root,windowsHide:true,stdio:['pipe','pipe','inherit']});
const lines=createInterface({input:fixture.stdout});
const [first]=await once(lines,'line'); const {port}=JSON.parse(first);
const base=`http://127.0.0.1:${port}`;
const profile=await fs.mkdtemp(path.join(os.tmpdir(),'veiling-security-browser-'));
const browser=spawn('C:/Program Files/Google/Chrome/Application/chrome.exe',['--headless=new','--no-first-run',
  '--disable-background-networking','--remote-debugging-port=0','--user-data-dir='+profile,'about:blank'],{windowsHide:true,stdio:'ignore'});
let ws;
try {
  let debugPort;
  for(let i=0;i<100;i++){try {debugPort=(await fs.readFile(path.join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0];break;}catch{await new Promise(r=>setTimeout(r,100));}}
  assert(debugPort);
  const tab=await (await fetch(`http://127.0.0.1:${debugPort}/json/new?about:blank`,{method:'PUT'})).json();
  ws=new WebSocket(tab.webSocketDebuggerUrl); await once(ws,'open');
  let sequence=0; const pending=new Map();
  ws.onmessage=e=>{const m=JSON.parse(e.data);if(m.id){const p=pending.get(m.id);pending.delete(m.id);m.error?p.reject(Error(m.error.message)):p.resolve(m.result);}};
  const call=(method,params={})=>new Promise((resolve,reject)=>{const id=++sequence;pending.set(id,{resolve,reject});ws.send(JSON.stringify({id,method,params}));});
  const run=async expression=>{const r=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(r.exceptionDetails)throw Error(r.exceptionDetails.exception?.description||r.exceptionDetails.text);return r.result.value;};
  const wait=async expr=>{for(let i=0;i<100;i++){if(await run(expr))return;await new Promise(r=>setTimeout(r,50));}throw Error('Timeout '+expr);};
  async function navigate(url,ready){await call('Page.navigate',{url});await wait(`location.href===${JSON.stringify(url)} && document.readyState==='complete' && (${ready})`);}
  const payload='javascript:window.auditProbe=1;void(0)';
  const results={baseline_commit:'29db7a6',scope:'localhost Chrome, mocked verification response, no real authentication'};
  await navigate(base+'/test/baseline-home?next='+encodeURIComponent(payload),"typeof controleerCode==='function'");
  await run(`window.fetch=async()=>({ok:true,json:async()=>({ok:true})});document.getElementById('loginEmail').value='audit@example.test';document.getElementById('loginCode').value='123456';controleerCode()`);
  await wait('window.auditProbe===1');
  results.before_login_javascript_executed=true;
  await navigate(base+'/test/fixed-home?next='+encodeURIComponent(payload),"typeof controleerCode==='function'");
  assert.equal(await run('nextUrl'),'/veilingen');
  assert.notEqual(await run('window.auditProbe'),1);
  results.after_login_redirect='/veilingen';
  await navigate(base+'/test/baseline-admin',"typeof verwijder==='function'");
  assert.equal(await run(`document.querySelector('[onclick^="verwijder("]').click(); window.auditProbe===1`),true);
  results.before_admin_title_javascript_executed=true;
  await navigate(base+'/test/fixed-admin',"typeof verwijder==='function'");
  assert.equal(await run(`document.querySelector('[onclick^="verwijder("]').click(); window.auditProbe===1`),false);
  results.after_admin_title_javascript_executed=false;
  results.passed=true;
  await fs.writeFile(path.join(root,'docs/Security-2026-10-05/browser-security.json'),JSON.stringify(results,null,2));
  console.log(JSON.stringify(results));
} finally {
  ws?.close();browser.kill();fixture.kill();lines.close();
}
