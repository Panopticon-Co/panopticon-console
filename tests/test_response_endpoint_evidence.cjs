const fs = require('fs'), vm = require('vm'), assert = require('assert');
class Element {
  constructor(){this.children=[];this.value='';this.textContent='';this.listeners={};this.classList={add(){},remove(){}};}
  append(...items){for(const item of items)this.children.push(...(item.fragment?item.children:[item]));}
  replaceChildren(...items){this.children=[];this.append(...items);}
  addEventListener(event,fn){this.listeners[event]=fn;}
  set innerHTML(value){throw Error('Evidence must render as text');}
}
const elements=new Map(), el=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
const flatten=e=>[e.textContent,...e.children.map(flatten)].join(' ');
const find=(e,label)=>e.textContent===label?e:e.children.map(c=>find(c,label)).find(Boolean);
const action={response_id:'r1',command_id:'cmd-1',alert_id:'a1',action:'KILL_PROCESS',lifecycle_state:'AUTHORIZED',command_lifecycle_state:'AUTHORIZED',
  endpoint_evidence:[{record_id:'record-1',linkage:'mismatch',mismatches:['correlation_id'],sha256:'abc123',captured_at:'old-capture',received_at:'new-receipt',reported:{action:'KILL_PROCESS',outcome:'rejected',dry_run:true,executed:true,mode:'pidfd',affected:1,target:{pid:42,start_time_ticks:'18446744073709551615'},reason:'dry_run',detail:'<img src=x onerror=alert(1)>'}}]};
const context=vm.createContext({document:{addEventListener:(e,fn)=>fn(),getElementById:el,createElement:()=>new Element(),createDocumentFragment:()=>Object.assign(new Element(),{fragment:true})},AbortController,setTimeout,clearTimeout,setInterval:()=>{},fetch:async url=>({ok:true,status:200,json:async()=>url.endsWith('/catalog')?{actions:[],analyst:{permissions:[]},preflight_supported:true}:url.endsWith('/preflight')?{checks:[],readiness:{contact_state:'recent',execution_mode:'unknown',sensor_report:{captured_at:'old-capture',received_at:'new-receipt',freshness:'unverified',response_providers:[{name:'command_channel',state:'running',capabilities:['response.collect_process_info']}]}}}:{response_actions:[action]}})});
vm.runInContext(fs.readFileSync('static/app.js','utf8').split('// RESPONSE ACTIONS PANEL')[1],context);
(async()=>{
 await new Promise(r=>setImmediate(r));
 const body=el('response-body'), output=flatten(body);
 assert.match(output,/DRY RUN/);
 assert.match(output,/does not establish that a containment action occurred/);
 assert.match(output,/correlation_id/);
 assert.match(output,/18446744073709551615/);
 assert.match(output,/<img src=x onerror=alert\(1\)>/);
 assert.match(output,/abc123/);
 assert.match(output,/no outcome reported yet/);
 assert.doesNotMatch(output,/Agent reported SUCCEEDED/);
 await find(body,'Review readiness').listeners.click();
 const reviewed=flatten(body);
 assert.match(reviewed,/freshness: unverified/);
 assert.match(reviewed,/response.collect_process_info/);
 assert.match(reviewed,/Current enforcement mode and action support still require endpoint verification/);
 console.log('PASS: Linux evidence preserves dry-run, mismatch, full-precision identity and stale-report caveats as text');
})().catch(e=>{console.error(e);process.exitCode=1;});
