const fs = require('fs'), vm = require('vm'), assert = require('assert');
class Element {
 constructor() { this.children=[]; this.value=''; this.textContent=''; this.listeners={}; this.classList={add(){},remove(){}}; }
 append(...items) { for(const item of items) this.children.push(...(item.fragment ? item.children : [item])); }
 replaceChildren(...items) {this.children=[]; this.append(...items);}
 addEventListener(event, fn) {this.listeners[event]=fn;}
 showModal(){this.open=true;} close(){this.open=false;}
}
const elements = new Map(); const el = id => {if(!elements.has(id)) elements.set(id,new Element()); return elements.get(id);};
let payload = Array.from({length:30},(_,i)=>({alert_id:String(i),rule_id:'DET-'+i,title:'Alert '+i,severity:i%2?'high':'medium',timestamp:new Date(1700000000000+i*1000).toISOString(),evidence:{'process.name':'whoami.exe','process.command_line':'whoami /priv'}}));
payload.push(payload[0]); let fail=false;
const context = vm.createContext({document:{addEventListener:(event,fn)=>fn(),getElementById:el,createElement:()=>new Element(),createDocumentFragment:()=>Object.assign(new Element(),{fragment:true}),querySelectorAll:()=>[]},AbortController,setTimeout,clearTimeout,setInterval:()=>{},fetch:async()=>{if(fail) throw Error('offline'); return {ok:true,json:async()=>payload};}});
vm.runInContext(fs.readFileSync('static/app.js','utf8').split('// DASHBOARD INITIALIZATION')[1],context);
(async()=>{
 await new Promise(r=>setImmediate(r));
 assert.equal(el('count-total').textContent,'30'); assert.equal(el('alerts-body').children.length,25);
 el('next').listeners.click(); assert.equal(el('alerts-body').children.length,5);
 el('severity').value='High'; el('severity').listeners.change(); assert.equal(el('alerts-body').children.length,15);
 el('search').value='no match'; el('search').listeners.input(); assert.equal(el('alerts-table').hidden,true);
 el('clear').listeners.click(); assert.equal(el('alerts-body').children.length,25);
 el('search').value='HIGH   WHOAMI'; el('search').listeners.input(); assert.equal(el('alerts-body').children.length,15);
 await el('refresh').listeners.click(); assert.equal(el('alerts-body').children.length,15);
 el('search').value='severity'; el('search').listeners.input(); assert.equal(el('alerts-table').hidden,true);
 payload=[
   {alert_id:'critical-1',severity:'critical',title:'PowerShell detection',evidence:{}},
   {alert_id:'high-1',severity:'high',title:'Critical text in a high alert',evidence:{message:'critical powershell'}}
 ];
 el('search').value='CRITICAL'; el('search').listeners.input();
 await el('refresh').listeners.click();
 assert.equal(el('alerts-body').children.length,1);
 assert.equal(el('alerts-body').children[0].children[0].children[0].textContent,'critical');
 el('search').value='critical powershell'; el('search').listeners.input(); assert.equal(el('alerts-body').children.length,1);
 el('severity').value='High'; el('severity').listeners.change(); assert.equal(el('alerts-table').hidden,true);
 el('clear').listeners.click(); assert.equal(el('alerts-body').children.length,2);
 payload=[{alert_id:'path',title:'Path test',severity:'low',evidence:{'process.command_line':String.raw`C:\Windows\System32\whoami.exe /priv`}}];
 el('search').value=String.raw`C:\Windows\System32`; el('search').listeners.input();
 await el('refresh').listeners.click(); assert.equal(el('alerts-body').children.length,1);
 el('search').value='process path'; el('search').listeners.input(); assert.equal(el('alerts-body').children.length,1);
 el('clear').listeners.click();
 payload=[{alert_id:'xss',title:'<img src=x onerror=alert(1)>',severity:'unexpected',evidence:{'process.command_line':'<script>bad()</script>'}}];
 await el('refresh').listeners.click(); assert.equal(el('count-total').textContent,'1');
 el('alerts-body').children[0].children[1].children[0].listeners.click(); assert.equal(el('detail').open,true); assert.equal(el('detail-title').textContent,payload[0].title); assert.equal(el('evidence').children[0].children[1].textContent,'<script>bad()</script>');
 fail=true; await el('refresh').listeners.click(); assert.equal(el('status').className,'error'); assert.equal(el('count-total').textContent,'1');
 fail=false; payload=[]; await el('refresh').listeners.click(); assert.equal(el('count-total').textContent,'0'); assert.equal(el('empty').hidden,false);
 console.log('PASS: deduplication, pagination, filters, search, details, literal evidence, failure retention, recovery and empty state');
})().catch(e=>{console.error(e);process.exitCode=1;});
