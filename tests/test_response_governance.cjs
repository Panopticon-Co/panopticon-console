const fs=require('fs'),vm=require('vm'),assert=require('assert');
class Element {
  constructor(){this.children=[];this.value='';this.textContent='';this.listeners={};this.classList={add(){},remove(){}};}
  append(...items){for(const item of items)this.children.push(...(item.fragment?item.children:[item]));}
  replaceChildren(...items){this.children=[];this.append(...items);}
  addEventListener(e,fn){this.listeners[e]=fn;}
}
const source=fs.readFileSync('static/app.js','utf8').split('// RESPONSE ACTIONS PANEL')[1];
async function harness(role,permissions){
  const elements=new Map(),el=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
  const requests=[];
  let offline=false;
  const action={response_id:'r1',alert_id:'alert-1',action:'ISOLATE_HOST',lifecycle_state:'PENDING',requested_by:'analyst:alice',decision_audit:[{event:'staged',actor:'analyst:alice',detail:{reason:'Contain'},occurred_at:'2026-10-29T00:00:00Z'}],evidence_truncated:true};
  const context=vm.createContext({document:{addEventListener:(e,fn)=>fn(),getElementById:el,createElement:()=>new Element(),createDocumentFragment:()=>Object.assign(new Element(),{fragment:true})},AbortController,setTimeout,clearTimeout,setInterval:()=>{},fetch:async(url,options={})=>{
    requests.push({url,options});
    if(options.method==='POST'&&offline)throw Error('connection lost');
    return {ok:true,status:200,json:async()=>url.endsWith('/catalog')?{actions:[{action:'ISOLATE_HOST',label:'Isolate',target_kind:'host',description:'Contain host'}],analyst:{analyst_id:'alice',role,permissions,separate_approver_required:true}}:options.method==='POST'?{response_id:'created'}:{response_actions:[action]}};
  }});
  vm.runInContext(source,context);
  await new Promise(r=>setImmediate(r));
  return {el,requests,setOffline:value=>offline=value};
}
(async()=>{
  let h=await harness('viewer',[]);
  assert.equal(h.el('response-create').disabled,true);
  assert.equal(h.el('response-body').children[0].children[8].children.length,0);
  assert.equal(h.el('incident-set-resolved').disabled,true);
  const audit=h.el('response-body').children[0].children[7];
  assert.ok(audit.children.some(el=>el.textContent==='History preview is limited. Export the complete case.'));
  assert.equal(audit.children.find(child=>child.href).href,'/api/response-actions/r1/export');
  assert.equal(audit.children[1].children[0].textContent,'1 decision events');
  h.el('response-alert').value='alert-1'; h.el('response-reason').value='review';
  await h.el('response-create-form').listeners.submit({preventDefault(){}});
  assert.equal(h.requests.filter(r=>r.options.method==='POST').length,0);
  h=await harness('approver',['response:decide','incident:write']);
  assert.equal(h.el('response-create').disabled,true);
  const controls=h.el('response-body').children[0].children[8].children;
  assert.equal(controls.length,2);
  assert.equal(controls[0].disabled,true,'separate approver cannot approve own request');
  assert.equal(h.el('incident-set-resolved').disabled,false);
  h=await harness('responder',['response:request','incident:write']);
  h.el('response-alert').value='alert-1'; h.el('response-reason').value='review';
  h.setOffline(true);
  for(let i=0;i<2;i++)await h.el('response-create-form').listeners.submit({preventDefault(){}});
  const posted=()=>h.requests.filter(r=>r.options.method==='POST').map(r=>JSON.parse(r.options.body));
  assert.equal(posted()[0].request_id,posted()[1].request_id,'network retry retains identity');
  h.el('response-reason').value='Changed intent';
  await h.el('response-create-form').listeners.submit({preventDefault(){}});
  assert.notEqual(posted()[1].request_id,posted()[2].request_id,'changed intent gets a new identity');
  h.el('response-filter-command').value='INDETERMINATE';
  await h.el('response-apply').listeners.click();
  assert.equal(h.requests.at(-1).url,'/api/response-actions?command_state=INDETERMINATE');
  console.log('PASS: viewer/requester/approver controls, separate approval, safe retries, outcome filters and decision exports');
})().catch(e=>{console.error(e);process.exitCode=1;});
