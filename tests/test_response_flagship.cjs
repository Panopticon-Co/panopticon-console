const fs=require('fs'),vm=require('vm'),assert=require('assert');
class Element {
  constructor(){this.children=[];this.value='';this.textContent='';this.listeners={};this.classList={add(){},remove(){}};}
  append(...items){for(const item of items)this.children.push(...(item.fragment?item.children:[item]));}
  replaceChildren(...items){this.children=[];this.append(...items);}
  addEventListener(e,fn){this.listeners[e]=fn;}
}
const elements=new Map(),el=id=>{if(!elements.has(id))elements.set(id,new Element());return elements.get(id);};
const requests=[];
let blocked=true;
const action={response_id:'r1',alert_id:'alert-1',action:'ISOLATE_HOST',lifecycle_state:'PENDING'};
const catalog={actions:[{action:'COLLECT_NETWORK_CONNECTIONS',label:'Collect network',target_kind:'host',description:'Collect connections'}],analyst:{analyst_id:'alice',role:'analyst',permissions:['response:request','response:decide']},command_authority:{state:'ready',key_id:'abc123'},max_campaign_actions:25,preflight_supported:true};
const context=vm.createContext({document:{addEventListener:(e,fn)=>fn(),getElementById:el,createElement:()=>new Element(),createDocumentFragment:()=>Object.assign(new Element(),{fragment:true})},AbortController,setTimeout,clearTimeout,setInterval:()=>{},prompt:()=> 'APPROVE ISOLATE_HOST alert-1',confirm:()=>true,fetch:async(url,options={})=>{
  requests.push({url,options}); let payload;
  if(url.endsWith('/catalog'))payload=catalog;
  else if(url.endsWith('/preflight'))payload={allowed_to_authorize:!blocked,checks:[{state:blocked?'block':'warning',detail:blocked?'Signing authority unavailable':'Capabilities not reported'}],host_id:'host-1',target:{},readiness:{contact_state:'stale',execution_mode:'unknown'}};
  else if(url==='/api/response-campaigns'&&options.method==='POST'){
    const body=JSON.parse(options.body);
    payload={campaign_id:body.campaign_id,created_count:1,failed_count:1,items:[{alert_id:'alert-1',action:'COLLECT_NETWORK_CONNECTIONS',response_id:'staged-1'},{alert_id:'missing-alert',action:'COLLECT_NETWORK_CONNECTIONS',error:'No enrolled endpoint'}]};
  }else if(url==='/api/response-campaigns')payload={campaigns:[]};
  else if(options.method==='POST')payload={authorized:true};
  else payload={response_actions:[action]};
  return {ok:true,status:200,json:async()=>payload};
}});
vm.runInContext(fs.readFileSync('static/app.js','utf8').split('// RESPONSE ACTIONS PANEL')[1],context);
(async()=>{
  await new Promise(r=>setImmediate(r));
  assert.match(el('response-authority').textContent,/ready.*abc123/);
  assert.equal(el('response-campaign-create').disabled,false);
  let row=el('response-body').children[0];
  await row.children[8].children[0].listeners.click();
  assert.match(el('response-status').textContent,/Approval blocked: Signing authority unavailable/);
  assert.equal(requests.filter(r=>r.url.endsWith('/authorize')).length,0);
  const audit=row.children[7],review=audit.children.find(c=>c.textContent==='Review readiness');
  await review.listeners.click();
  assert.match(audit.children.at(-1).children[0].children[1].textContent,/stale.*unknown/);
  blocked=false;
  await row.children[8].children[0].listeners.click();
  assert.ok(requests.some(r=>r.url.endsWith('/authorize')&&r.options.method==='POST'));
  el('response-campaign-alerts').value='alert-1\nmissing-alert';el('response-campaign-reason').value='Investigate incident';
  await el('response-campaign-form').listeners.submit({preventDefault(){}});
  assert.match(el('response-campaign-status').textContent,/1 staged.*1 refused/);
  const posts=()=>requests.filter(r=>r.url==='/api/response-campaigns'&&r.options.method==='POST').map(r=>JSON.parse(r.options.body));
  assert.equal(posts()[0].items.length,2);
  assert.deepEqual(posts()[0].items[0],{alert_id:'alert-1',action:'COLLECT_NETWORK_CONNECTIONS',reason:'Investigate incident',target:{}});
  await el('response-campaign-form').listeners.submit({preventDefault(){}});
  assert.equal(posts()[0].campaign_id,posts()[1].campaign_id);
  el('response-campaign-new').listeners.click();
  await el('response-campaign-form').listeners.submit({preventDefault(){}});
  assert.notEqual(posts()[1].campaign_id,posts()[2].campaign_id);
  const before=posts().length;el('response-campaign-alerts').value='alert-1\nalert-1';
  await el('response-campaign-form').listeners.submit({preventDefault(){}});
  assert.match(el('response-campaign-status').textContent,/Duplicate alert IDs/);
  assert.equal(posts().length,before);
  console.log('PASS: authority readiness, advisory review, blocked approval and bounded retry-safe campaign staging');
})().catch(e=>{console.error(e);process.exitCode=1;});
