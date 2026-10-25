// Alert feed in Manager mode: source badges, incident links, source filter,
// the active-source indicator and the alert detail's confidence / matched
// conditions / recommendation sections.
const fs = require('fs'), vm = require('vm'), assert = require('assert');
class Element {
  constructor() { this.children = []; this.value = ''; this.textContent = ''; this.className = ''; this.listeners = {}; this.classList = { add() {}, remove() {} }; }
  append(...items) { for (const item of items) this.children.push(...(item.fragment ? item.children : [item])); }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  addEventListener(event, fn) { this.listeners[event] = fn; }
  showModal() { this.open = true; } close() { this.open = false; }
}
const elements = new Map(); const el = (id) => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
const allText = (e) => [e.textContent, ...e.children.map(allText)].filter(Boolean).join(' | ');

const ALERTS = [
  { alert_id: 'A1', rule_id: 'DET-PROC-011', title: 'Obfuscated script', severity: 'high', level: 11, timestamp: '2026-10-25T08:00:00Z', detection_source: 'rule', confidence: 0.8, host_id: 'WS-1', agent_id: 'agent-1',
    evidence: { 'process.name': 'powershell.exe', matched_conditions: ['process.command_line contains -enc', '<script>x</script>'] },
    active_response: { action: 'TERMINATE_PROCESS', host_id: 'WS-1', target_pid: 4242, target_guid: null, target_start_time_ticks: '133000000000', target_file: null, reason: 'obfuscated script' } },
  { alert_id: 'A2', rule_id: 'BEH-BEACON', title: 'Beacon', severity: 'medium', timestamp: '2026-10-25T08:01:00Z', detection_source: 'behavioral', evidence: {} },
  { alert_id: 'A3', rule_id: 'STATE-1', title: 'Sequence', severity: 'low', timestamp: '2026-10-25T08:02:00Z', detection_source: 'stateful', evidence: {} },
  { alert_id: 'INC-1-R1', rule_id: 'PROV-CAMPAIGN', title: '[INCIDENT] chain', severity: 'critical', timestamp: '2026-10-25T08:03:00Z', detection_source: 'correlation', incident_id: 'INC-1', evidence: {} },
  { alert_id: 'A5', rule_id: 'OLD', title: 'Legacy line', severity: 'low', timestamp: '2026-10-25T07:00:00Z', evidence: {} },
];
const urls = []; let sourceHeader = 'manager';
const context = vm.createContext({
  document: { addEventListener: (e, fn) => fn(), getElementById: el, createElement: () => new Element(), createDocumentFragment: () => Object.assign(new Element(), { fragment: true }), querySelectorAll: () => [] },
  AbortController, setTimeout, clearTimeout, setInterval: () => {},
  fetch: async (url) => { urls.push(url); return { ok: true, status: 200, headers: { get: (h) => (h === 'X-Panopticon-Alert-Source' ? sourceHeader : null) }, json: async () => (url.startsWith('/api/alerts') ? ALERTS : {}) }; },
});
const incidentsOpened = [];
context.PanopticonConsole = { openIncident: (id) => incidentsOpened.push(id) };
// Only the dashboard section: stop before the response panel so the
// incidents view does not replace the openIncident hook above.
vm.runInContext(fs.readFileSync('static/app.js', 'utf8').split('// DASHBOARD INITIALIZATION')[1].split('// RESPONSE ACTIONS PANEL')[0], context);

(async () => {
  await new Promise((r) => setImmediate(r));
  assert.equal(urls[0], '/api/alerts');
  assert.equal(el('data-source').textContent, 'Alert source: Manager API (proxied by this console)');
  const rows = el('alerts-body').children;
  assert.equal(rows.length, 5);
  // Columns: severity, detection, source, process, type, MITRE, time.
  assert.equal(rows[0].children.length, 7);
  const badges = rows.map((r) => r.children[2].children[0]);
  assert.deepEqual(badges.map((b) => b.textContent), ['correlation', 'stateful', 'behavioral', 'rule', 'unknown']);
  assert.deepEqual(badges.map((b) => b.className), ['src src-correlation', 'src src-stateful', 'src src-behavioral', 'src src-rule', 'src src-unknown']);
  // Incident alerts carry a link to their incident; the others do not.
  const incidentLink = rows[0].children[1].children[2];
  assert.equal(incidentLink.textContent, 'Incident INC-1');
  incidentLink.listeners.click();
  assert.deepEqual(incidentsOpened, ['INC-1']);
  assert.equal(rows[3].children[1].children.length, 2);

  // Source filter.
  el('source').value = 'behavioral'; el('source').listeners.change();
  assert.equal(el('alerts-body').children.length, 1);
  assert.equal(el('alerts-body').children[0].children[1].children[0].textContent, 'Beacon');
  el('clear').listeners.click(); assert.equal(el('source').value, ''); assert.equal(el('alerts-body').children.length, 5);

  // Manager mode asks for a bounded page on later polls.
  await el('refresh').listeners.click();
  assert.equal(urls[urls.length - 1], '/api/alerts?limit=500');

  // Detail: confidence label, matched conditions, evidence without duplicates, recommendation.
  el('alerts-body').children[3].children[1].children[0].listeners.click();
  assert.equal(el('detail').open, true);
  assert.match(allText(el('detail-meta')), /rule confidence \(prior, not calibrated\) \| 0\.80/);
  assert.match(allText(el('detail-meta')), /Agent \| agent-1/);
  assert.equal(el('detail-source').textContent, 'rule');
  assert.deepEqual(el('detail-conditions').children.map((c) => c.textContent), ALERTS[0].evidence.matched_conditions);
  assert.ok(!allText(el('evidence')).includes('matched_conditions'));
  const rec = allText(el('detail-response'));
  assert.match(rec, /action \| TERMINATE_PROCESS/);
  assert.match(rec, /target_start_time_ticks \| 133000000000/);
  assert.ok(!rec.includes('target_guid'), 'null recommendation fields are omitted');
  assert.match(rec, /Recommendation only: the detection engine does not execute it/);
  assert.doesNotMatch(rec, /neutrali|blocked|terminated/i);
  el('alerts-body').children[1].children[1].children[0].listeners.click();
  assert.equal(el('detail-response').children[0].textContent, 'No response recommended by this detection.');
  assert.equal(el('detail-conditions').children[0].textContent, 'No matched conditions were supplied.');

  // File mode indicator.
  sourceHeader = 'file';
  await el('refresh').listeners.click();
  assert.equal(el('data-source').textContent, 'Alert source: engine alert file (--alerts-file)');
  console.log('PASS: source badges, incident links, source filter, active-source indicator, bounded manager polling, detail confidence/conditions/recommendation');
})().catch((e) => { console.error(e); process.exitCode = 1; });
