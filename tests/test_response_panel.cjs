const fs = require('fs'), vm = require('vm'), assert = require('assert');
class Element {
 constructor() { this.children=[]; this.value=''; this.textContent=''; this.hidden=false; this.listeners={}; this.classList={add(){},remove(){}}; }
 append(...items) { for(const item of items) this.children.push(...(item.fragment ? item.children : [item])); }
 replaceChildren(...items) {this.children=[]; this.append(...items);}
 addEventListener(event, fn) {this.listeners[event]=fn;}
}
const elements = new Map(); const el = id => {if(!elements.has(id)) elements.set(id,new Element()); return elements.get(id);};
let status = 200, payload = { response_actions: [] }, offline = false;
const context = vm.createContext({
  document: { addEventListener:(event,fn)=>fn(), getElementById: el, createElement: () => new Element(), createDocumentFragment: () => Object.assign(new Element(), { fragment: true }) },
  AbortController, setTimeout, clearTimeout, setInterval: () => {},
  fetch: async () => { if (offline) throw Error('offline'); return { ok: status < 400, status, json: async () => payload }; }
});
// Only the RESPONSE ACTIONS PANEL section is executed here -- it registers
// its own, separate DOMContentLoaded handler and does not depend on the
// dashboard section above it in app.js.
vm.runInContext(fs.readFileSync('static/app.js', 'utf8').split('// RESPONSE ACTIONS PANEL')[1], context);

(async () => {
  await new Promise(r => setImmediate(r));
  assert.equal(el('response-table').hidden, true, 'no rows yet -> table hidden');
  assert.equal(el('response-empty').hidden, false);
  assert.equal(el('response-empty-title').textContent, 'No response actions yet');

  payload = { response_actions: [
    { response_id: 'r1', lifecycle_state: 'PENDING', action: 'ISOLATE_HOST', tier: 'ANALYST_APPROVAL', alert_id: 'ALT-1', created_at: '2026-01-01T00:00:00Z', decided_reason: 'direct mapping' },
  ] };
  await el('response-refresh').listeners.click();
  assert.equal(el('response-table').hidden, false);
  assert.equal(el('response-empty').hidden, true);
  assert.equal(el('response-body').children.length, 1);
  assert.equal(el('response-body').children[0].children[0].textContent, 'PENDING');
  // Read-only: no authorize/reject control exists anywhere in the rendered row.
  assert.equal(el('response-body').children[0].children.length, 6);

  status = 503; payload = { error: 'Manager connection not configured (--manager-url / PANOPTICON_MANAGER_TOKEN)' };
  await el('response-refresh').listeners.click();
  assert.equal(el('response-table').hidden, true);
  assert.equal(el('response-empty-title').textContent, 'Response actions unavailable');
  assert.equal(el('response-empty-description').textContent, payload.error);

  offline = true;
  await el('response-refresh').listeners.click();
  assert.equal(el('response-status').textContent, 'Cannot reach the console server');

  console.log('PASS: response actions panel renders, reports unavailable/offline states, and offers no authorize/reject control');
})().catch(e => { console.error(e); process.exitCode = 1; });
