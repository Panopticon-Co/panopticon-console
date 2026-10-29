const fs=require('fs'),vm=require('vm'),assert=require('assert');
class Element {
 constructor(){this.children=[];this.value='';this.textContent='';this.listeners={};this.classList={add(){},remove(){}};}
 append(...items){for(const item of items)this.children.push(...(item.fragment?item.children:[item]));}
 replaceChildren(...items){this.children=[];this.append(...items);}
 addEventListener(event,fn){this.listeners[event]=fn;}
 set innerHTML(value){throw Error('Runtime policy must render as text');}
}
const flat=e=>[e.textContent,...e.children.map(flat)].join(' ');
const elements=new Map(),el=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
let state='recent',platform='windows';
const action={response_id:'r1',command_id:'c1',action:'ISOLATE_HOST',lifecycle_state:'AUTHORIZED',command_lifecycle_state:'AUTHORIZED',dispatch_blocker:'Endpoint is in dry-run mode'};
const context=vm.createContext({document:{addEventListener:(e,fn)=>fn(),getElementById:el,createElement:()=>new Element(),createDocumentFragment:()=>Object.assign(new Element(),{fragment:true})},AbortController,setTimeout,clearTimeout,setInterval:()=>{},fetch:async url=>({ok:true,status:200,json:async()=>url.endsWith('/catalog')?{actions:[],analyst:{permissions:[]},preflight_supported:true}:url.endsWith('/preflight')?{checks:[{state:'block',detail:'Changing action cannot execute'}],readiness:{execution_mode:state==='recent'?'dry_run':'unknown',runtime_profile:{state,observed_at:'observed-time',report:{platform,mode:'dry_run',allowed_actions:['COLLECT_PROCESS_INFO'],implemented_actions:['COLLECT_PROCESS_INFO','ISOLATE_HOST'],require_boot_binding:true,require_signature:true,boot_id:'<untrusted-boot>'}}}}:{response_actions:[action]}})});
vm.runInContext(fs.readFileSync('static/app.js','utf8').split('// RESPONSE ACTIONS PANEL')[1],context);
(async()=>{
 await new Promise(r=>setImmediate(r));
 const row=el('response-body').children[0],audit=row.children[7];
 assert.match(flat(row),/Further delivery held by endpoint policy/);
 const review=audit.children.find(c=>c.textContent==='Review readiness');
 await review.listeners.click();
 let output=flat(audit);
 assert.match(output,/Runtime policy: recent/);assert.match(output,/Platform: windows/);
 assert.match(output,/Permitted actions: COLLECT_PROCESS_INFO/);
 assert.match(output,/Boot binding required: yes.*command signatures required: yes/);
 assert.match(output,/<untrusted-boot>/);
 state='stale';platform='linux';await review.listeners.click();output=flat(audit);
 assert.match(output,/Runtime policy: stale/);assert.match(output,/Platform: linux/);
 assert.match(output,/Current endpoint policy is unknown/);
 console.log('PASS: current/stale native policy, permitted actions, identity requirements and held delivery are visible');
})().catch(e=>{console.error(e);process.exitCode=1;});
