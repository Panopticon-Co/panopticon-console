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
  // Pending actions expose analyst decision controls in the final cell.
  assert.equal(el('response-body').children[0].children.length, 9);
  assert.equal(el('response-body').children[0].children[8].children.length, 2);
  assert.equal(el('response-body').children[0].children[6].textContent, 'No command issued');

  // Decided actions: no approve/reject, command state and audit trail rendered
  // from Manager's fields, and success is only claimed for SUCCEEDED.
  payload = { response_actions: [
    { response_id: 'r2', lifecycle_state: 'AUTHORIZED', action: 'KILL_PROCESS', tier: 'ANALYST_APPROVAL', alert_id: 'ALT-2', command_id: 'resp-r2', command_state: 'SUCCEEDED',
      target: { host_id: 'WS-1', target_pid: 4242 },
      audit: [ { audit_id: 'a1', command_id: 'resp-r2', event: 'authorized', actor: 'analyst:alice', detail: '<b>ok</b>', occurred_at: '2026-01-01T00:00:01Z' },
               { audit_id: 'a2', command_id: 'resp-r2', event: 'result_received', actor: 'agent:WS-1', detail: 'succeeded', occurred_at: '2026-01-01T00:00:05Z' } ] },
    { response_id: 'r3', lifecycle_state: 'AUTHORIZED', action: 'ISOLATE_HOST', tier: 'ANALYST_APPROVAL', alert_id: 'ALT-3', command_id: 'resp-r3', command_state: 'DISPATCHED', audit: [] },
    { response_id: 'r4', lifecycle_state: 'REJECTED', action: 'QUARANTINE_FILE', tier: 'ANALYST_APPROVAL', alert_id: 'ALT-4', decided_reason: 'behavioral alert' },
  ] };
  await el('response-refresh').listeners.click();
  const rows = el('response-body').children;
  assert.equal(rows.length, 3);
  for (const row of rows) assert.equal(row.children[8].children.length, 0, 'no decision buttons unless PENDING');
  assert.match(rows[0].children[6].textContent, /^Agent reported SUCCEEDED for KILL_PROCESS \(host WS-1 · pid 4242\) · command resp-r2$/);
  assert.equal(rows[0].children[1].children[1].textContent, 'host WS-1 · pid 4242');
  const audit = rows[0].children[7].children[0];
  assert.equal(audit.children[0].textContent, '2 audit events');
  assert.equal(audit.children[1].children.length, 2);
  assert.match(audit.children[1].children[0].textContent, /authorized · by analyst:alice · <b>ok<\/b>$/);
  assert.match(rows[1].children[6].textContent, /is DISPATCHED · no outcome reported yet$/);
  assert.doesNotMatch(rows[1].children[6].textContent, /succeed|neutrali|block/i);
  assert.equal(rows[2].children[6].textContent, 'No command issued');
  assert.equal(rows[2].children[7].children[0].textContent, 'No audit events');
  // Unchanged payload -> rows are not rebuilt (an expanded audit trail survives polling).
  const before = el('response-body').children[0];
  await el('response-refresh').listeners.click();
  assert.equal(el('response-body').children[0], before);

  status = 503; payload = { error: 'Manager connection not configured (--manager-url / PANOPTICON_MANAGER_TOKEN)' };
  await el('response-refresh').listeners.click();
  assert.equal(el('response-table').hidden, true);
  assert.equal(el('response-empty-title').textContent, 'Response actions unavailable');
  assert.equal(el('response-empty-description').textContent, payload.error);

  offline = true;
  await el('response-refresh').listeners.click();
  assert.equal(el('response-status').textContent, 'Cannot reach the console server');

  console.log('PASS: response actions panel renders, reports unavailable/offline states, exposes decision controls only on PENDING, and renders command state and audit trails');
})().catch(e => { console.error(e); process.exitCode = 1; });
