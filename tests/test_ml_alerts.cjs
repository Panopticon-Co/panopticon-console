// The engine's optional ML stage in the alert feed: an "ml" source badge and
// filter, a score chip on annotated rule alerts, an "ML triage" section in the
// detail view, and no chip or section on alerts the model did not score.
const fs = require('fs'), vm = require('vm'), assert = require('assert');
class Element {
  constructor() { this.children = []; this.value = ''; this.textContent = ''; this.className = ''; this.listeners = {}; this.hidden = false; this.classList = { add() {}, remove() {} }; }
  append(...items) { for (const item of items) this.children.push(...(item.fragment ? item.children : [item])); }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  addEventListener(event, fn) { this.listeners[event] = fn; }
  showModal() { this.open = true; } close() { this.open = false; }
}
const elements = new Map(); const el = (id) => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
const allText = (e) => [e.textContent, ...e.children.map(allText)].filter(Boolean).join(' | ');
const ML = { model_id: 'panopticon-process-start', model_version: 'v7_lgb_no_stats-a4f71136', artifact_sha256: 'abc123', featurizer_version: 5, mode: 'active', raw_score: 3.97, band: 'alert', thresholds: { alert: 3.4809, high: 4.2005 } };
const ALERTS = [
  { alert_id: 'ML-1', rule_id: 'ML-PROC-001', title: 'ML triage: process start resembles abuse seen in training', severity: 'medium', level: 7, timestamp: '2026-10-25T08:02:00Z', detection_source: 'ml', confidence: 0.3, evidence: { 'process.name': 'powershell.exe' }, active_response: null, tags: ['ml', 'process'], ml: ML },
  { alert_id: 'A1', rule_id: 'DET-PROC-011', title: 'Obfuscated script', severity: 'high', level: 11, timestamp: '2026-10-25T08:01:00Z', detection_source: 'rule', confidence: 0.8, evidence: { 'process.name': 'powershell.exe' }, ml: ML },
  { alert_id: 'A2', rule_id: 'DET-PROC-008', title: 'whoami /priv', severity: 'medium', level: 10, timestamp: '2026-10-25T08:00:00Z', detection_source: 'rule', confidence: 0.6, evidence: {} },
];
const context = vm.createContext({
  document: { addEventListener: (e, fn) => fn(), getElementById: el, createElement: () => new Element(), createDocumentFragment: () => Object.assign(new Element(), { fragment: true }), querySelectorAll: () => [] },
  AbortController, setTimeout, clearTimeout, setInterval: () => {},
  fetch: async () => ({ ok: true, status: 200, headers: { get: () => 'file' }, json: async () => ALERTS }),
});
context.PanopticonConsole = {};
vm.runInContext(fs.readFileSync('static/app.js', 'utf8').split('// DASHBOARD INITIALIZATION')[1].split('// RESPONSE ACTIONS PANEL')[0], context);

(async () => {
  await new Promise((r) => setImmediate(r));
  const rows = el('alerts-body').children;
  assert.equal(rows.length, 3);
  const badges = rows.map((r) => r.children[2].children[0]);
  assert.deepEqual(badges.map((b) => b.textContent), ['ml', 'rule', 'rule']);
  assert.equal(badges[0].className, 'src src-ml');
  // Rule alert scored by the model: a chip with score and band. ML alert itself and unscored rule: none.
  const chips = rows.map((r) => r.children[1].children.find((c) => String(c.className).startsWith('ml-chip')));
  assert.equal(chips[0], undefined);
  assert.equal(chips[1].textContent, 'ML 3.97 · alert');
  assert.equal(chips[1].className, 'ml-chip ml-alert');
  assert.equal(chips[2], undefined);

  // Source filter.
  el('source').value = 'ml'; el('source').listeners.change();
  assert.equal(el('alerts-body').children.length, 1);
  el('clear').listeners.click();

  // Detail: ML section with model identity and the triage disclaimer.
  rows[0].children[1].children[0].listeners.click();
  assert.equal(el('detail-ml').hidden, false);
  const detail = allText(el('detail-ml'));
  for (const s of ['3.97', 'alert 3.4809 · high 4.2005', 'v7_lgb_no_stats-a4f71136', 'abc123', 'not a verdict']) assert.ok(detail.includes(s), s);
  assert.ok(allText(el('detail-meta')).includes('model marker (fixed, not a probability)'));
  assert.ok(allText(el('detail-response')).includes('No response recommended'));
  // An unscored alert hides the section (absence is "not scored", never "benign").
  rows[2].children[1].children[0].listeners.click();
  assert.equal(el('detail-ml').hidden, true);
  assert.equal(el('detail-ml').children.length, 0);
  assert.ok(allText(el('detail-meta')).includes('rule confidence (prior, not calibrated)'));
  console.log('ok test_ml_alerts');
})().catch((e) => { console.error(e); process.exit(1); });
