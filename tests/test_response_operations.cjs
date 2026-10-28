const fs = require('fs'), vm = require('vm'), assert = require('assert');
class Element {
  constructor() {this.children=[]; this.value=''; this.textContent=''; this.listeners={}; this.classList={add(){},remove(){}};}
  append(...items) {for (const item of items) this.children.push(...(item.fragment ? item.children : [item]));}
  replaceChildren(...items) {this.children=[]; this.append(...items);}
  addEventListener(event, fn) {this.listeners[event]=fn;}
}
const elements = new Map();
const el = id => {if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id);};
let requests=[], queue={response_actions: []}, failCreate=false;
const catalog = [
  {action:'COLLECT_FILE', label:'Collect file', target_kind:'file', description:'Collect exact path.'},
  {action:'KILL_PROCESS', label:'Terminate process', target_kind:'process', description:'Verified identity.'}
];
const context = vm.createContext({
  document:{addEventListener:(e, fn)=>fn(), getElementById:el, createElement:()=>new Element(), createDocumentFragment:()=>Object.assign(new Element(),{fragment:true})},
  AbortController, setTimeout, clearTimeout, setInterval:()=>{},
  prompt:()=> 'Analyst reviewed', confirm:()=>true,
  fetch:async (url, options={})=> {
    requests.push({url, options});
    let status=200, payload=queue;
    if (url.endsWith('/catalog')) payload={actions:catalog};
    else if (options.method==='POST') {
      payload=failCreate ? {detail:'an equivalent response is already pending or in flight'} : {response_id:'manual-1'};
      status=failCreate ? 409 : 201;
    }
    return {ok:status<400,status,json:async()=>payload};
  }
});
vm.runInContext(fs.readFileSync('static/app.js','utf8').split('// RESPONSE ACTIONS PANEL')[1],context);
(async()=>{
  await new Promise(r=>setImmediate(r));
  assert.equal(el('response-create').disabled,false);
  assert.equal(el('response-file-label').hidden,false);
  el('response-alert').value='alert-1'; el('response-reason').value='Collect evidence'; el('response-file').value='/tmp/evidence';
  await el('response-create-form').listeners.submit({preventDefault(){}});
  const created=requests.find(r=>r.url==='/api/response-actions' && r.options.method==='POST');
  assert.deepEqual(JSON.parse(created.options.body),{alert_id:'alert-1',action:'COLLECT_FILE',reason:'Collect evidence',target:{path:'/tmp/evidence'}});
  assert.match(el('response-create-status').textContent,/Staged for approval/);
  failCreate=true;
  await el('response-create-form').listeners.submit({preventDefault(){}});
  assert.match(el('response-create-status').textContent,/already pending/);
  el('response-action').value='KILL_PROCESS'; el('response-action').listeners.change();
  assert.equal(el('response-file-label').hidden,true);
  assert.match(el('response-action-help').textContent,/retained process identity/);
  queue={response_actions:[{response_id:'r1',action:'KILL_PROCESS',lifecycle_state:'AUTHORIZED',command_id:'c1',command_lifecycle_state:'INDETERMINATE',target:{pid:4,start_time_ticks:'18446744073709551615',boot_id:'boot_abc'},receipts:[{payload:{result_id:'receipt-1',outcome:'indeterminate',execution:{stage:'completion',action_initiated:true,completion_observed:false,native_error:5}}}]}],next_offset:200};
  await el('response-refresh').listeners.click();
  let row=el('response-body').children[0];
  assert.match(row.children[6].textContent,/uncertain outcome/);
  assert.equal(row.children[8].children.length,0);
  assert.match(row.children[1].children[1].textContent,/18446744073709551615/);
  const evidence=row.children[6].children[0];
  assert.ok(evidence.children.some(child=>/completion observed: false/.test(child.textContent)));
  assert.equal(el('response-next').disabled,false);
  await el('response-next').listeners.click();
  assert.ok(requests.some(r=>r.url==='/api/response-actions?offset=200'));
  el('response-filter-state').value='PENDING'; el('response-filter-host').value='host-1';
  await el('response-apply').listeners.click();
  assert.equal(requests.at(-1).url,'/api/response-actions?state=PENDING&host_id=host-1');
  queue={response_actions:[{response_id:'r2',action:'ISOLATE_HOST',lifecycle_state:'AUTHORIZED',command_id:'c2',command_lifecycle_state:'AUTHORIZED'}]};
  failCreate=false;
  await el('response-refresh').listeners.click();
  row=el('response-body').children[0];
  assert.equal(row.children[8].children[0].textContent,'Cancel queued command');
  await row.children[8].children[0].listeners.click();
  assert.ok(requests.some(r=>r.url==='/api/response-actions/r2/cancel' && JSON.parse(r.options.body).reason==='Analyst reviewed'));
  el('detail-id').textContent='alert-from-detail';
  el('detail-respond').listeners.click();
  assert.equal(el('response-alert').value,'alert-from-detail');
  assert.equal(el('response-request').open,true);
  console.log('PASS: catalog, guided requests, duplicate errors, exact ticks, uncertain evidence, paging, filtering, cancellation and alert navigation');
})().catch(e=>{console.error(e);process.exitCode=1;});
