// Incidents view + pipeline status tiles, against a URL-routed mocked fetch.
// Runs everything after the RESPONSE ACTIONS PANEL marker: the shared render
// helpers, the response panel, the incidents view and the status tiles.
const fs = require('fs'), vm = require('vm'), assert = require('assert');
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.value = ''; this.textContent = ''; this.hidden = false; this.disabled = false; this.className = ''; this.listeners = {}; }
  append(...items) { for (const item of items) this.children.push(...(item.fragment ? item.children : [item])); }
  replaceChildren(...items) { this.children = []; this.append(...items); }
  addEventListener(event, fn) { this.listeners[event] = fn; }
  showModal() { this.open = true; } close() { this.open = false; if (this.listeners.close) this.listeners.close(); }
}
const elements = new Map(); const el = (id) => { if (!elements.has(id)) elements.set(id, new Element('#' + id)); return elements.get(id); };
// Depth-first text of a rendered subtree, for assertions on nested lists.
const allText = (e) => [e.textContent, ...e.children.map(allText)].filter(Boolean).join(' | ');

const XSS = '<img src=x onerror=alert(1)>';
const SUMMARY = { incident_id: 'INC-abc', host_id: 'WS-1', status: 'open', severity: 'critical', level: 14, score: 7.25, confidence: 0.6,
  tactics: ['Execution', 'Command and Control'], stage_count: 2, root_process: 'winword.exe', revision: 2, first_seen: '2026-10-25T08:00:00Z', last_seen: '2026-10-25T08:05:00Z', alert_count: 3 };
const EVIDENCE = {
  incident_id: 'INC-abc', revision: 2, attack_chain: 'DET-PROC-011 (Execution) -> DET-NET-002 (Command and Control)', stage_count: 2,
  stages: [
    { time: '2026-10-25T08:00:00Z', rule_id: 'DET-PROC-011', rule_name: 'Obfuscated script', tactic: 'Execution', technique: 'T1059.001', process: 'powershell.exe', pid: 4242, event_id: 'e1', alert_id: 'ALT-1' },
    { time: '2026-10-25T08:05:00Z', rule_id: 'DET-NET-002', rule_name: XSS, tactic: 'Command and Control', technique: 'T1071', process: 'powershell.exe', pid: 4242, event_id: 'e2', alert_id: null },
  ],
  tactics_covered: ['Execution', 'Command and Control'], root_cause_process: 'winword.exe', root_pid: 100, root_inferred: true,
  process_lineage: 'explorer.exe -> winword.exe -> cmd.exe -> powershell.exe', provenance_origin: 'winword.exe', processes_in_scope: 3,
  causal_path: ['2026-10-25T08:00:00+00:00 winword.exe[100] -[spawned]-> cmd.exe[200]', '2026-10-25T08:00:01+00:00 cmd.exe[200] -[spawned]-> ' + XSS],
  incident_score: 7.25,
  score_breakdown: { stage_severity: { weight: 4.5, max_stage_level: 14 }, tactic_breadth: { weight: 1.5, tactics: 2 }, context: { weight: 1.25, factors: { external_network: 0.75, initial_access_vector: 0.5 } }, total: 7.25 },
  why: ['highest stage level 14/16', '2 ATT&CK tactic(s): Execution, Command and Control'],
};
let incidentStatus = 'open';
const detail = () => ({
  incident: Object.assign({}, SUMMARY, { status: incidentStatus, evidence: EVIDENCE }),
  alerts: [
    { alert_id: 'ALT-1', rule_id: 'DET-PROC-011', severity: 'high', detection_source: 'rule', incident_id: 'INC-abc', alert: { alert_id: 'ALT-1', title: 'Obfuscated script', severity: 'high', timestamp: '2026-10-25T08:00:00Z', evidence: {} } },
    { alert_id: 'INC-abc-R2', rule_id: 'PROV-CAMPAIGN', severity: 'critical', detection_source: 'correlation', incident_id: 'INC-abc', alert: { alert_id: 'INC-abc-R2', title: XSS } },
  ],
  response_actions: [{ response_id: 'r1', action: 'KILL_PROCESS', lifecycle_state: 'PENDING', alert_id: 'INC-abc-R2' }],
  audit: incidentStatus === 'open'
    ? [{ audit_id: 'ia1', event: 'opened', actor: 'system:detection', occurred_at: '2026-10-25T08:05:00Z' }]
    : [{ audit_id: 'ia1', event: 'opened', actor: 'system:detection', occurred_at: '2026-10-25T08:05:00Z' }, { audit_id: 'ia2', event: 'status_changed', actor: 'analyst:alice', from_status: 'open', to_status: incidentStatus, note: 'confirmed', occurred_at: '2026-10-25T08:10:00Z' }],
});
const STATUS = { events: { pending: 4, claimed: 1, done: 120, failed: 2 }, alerts: 9, incidents_open: 1, response_actions: { PENDING: 3, AUTHORIZED: 1 }, agents_enrolled: 2, last_event_at: '2026-10-25T08:05:00Z' };

let configured = true; const posts = [];
const reply = (status, body) => ({ ok: status < 400, status, json: async () => body });
const NOT_CONFIGURED = { error: 'Manager connection not configured (--manager-url / PANOPTICON_MANAGER_TOKEN)' };
async function fetch(url, opts = {}) {
  if (!configured) return reply(503, NOT_CONFIGURED);
  if (opts.method === 'POST') {
    posts.push({ url, body: JSON.parse(opts.body) });
    incidentStatus = JSON.parse(opts.body).status;
    return reply(200, { incident_id: 'INC-abc', status: incidentStatus });
  }
  if (url === '/api/incidents') return reply(200, { incidents: [Object.assign({}, SUMMARY, { status: incidentStatus })] });
  if (url === '/api/incidents/INC-abc') return reply(200, detail());
  if (url === '/api/status') return reply(200, STATUS);
  if (url === '/api/response-actions') return reply(200, { response_actions: [] });
  return reply(404, { detail: 'not found' });
}
const opened = [];
const context = vm.createContext({
  document: { addEventListener: (event, fn) => fn(), getElementById: el, createElement: (tag) => new Element(tag), createDocumentFragment: () => Object.assign(new Element('frag'), { fragment: true }) },
  AbortController, setTimeout, clearTimeout, setInterval: () => {}, fetch,
});
context.PanopticonConsole = { openAlert: (a) => opened.push(a) };
vm.runInContext(fs.readFileSync('static/app.js', 'utf8').split('// RESPONSE ACTIONS PANEL')[1], context);
const settle = () => new Promise((r) => setImmediate(r));

(async () => {
  await settle(); await settle();
  // -- list ---------------------------------------------------------------
  assert.equal(el('incidents-table').hidden, false);
  const row = el('incidents-body').children[0];
  assert.equal(row.children.length, 8);
  assert.equal(row.children[0].children[0].textContent, 'critical · L14');
  assert.equal(row.children[1].children[0].textContent, 'INC-abc');
  assert.equal(row.children[2].textContent, '7.25');
  assert.equal(row.children[3].textContent, 'Execution, Command and Control');
  assert.equal(row.children[4].textContent, '2');
  assert.equal(row.children[5].textContent, 'winword.exe');
  assert.equal(row.children[6].children[0].textContent, 'open');

  // -- detail -------------------------------------------------------------
  await row.children[1].children[0].listeners.click();
  assert.equal(el('incident-detail').open, true);
  assert.equal(el('incident-title').textContent, 'Incident INC-abc');
  const meta = allText(el('incident-meta'));
  assert.match(meta, /rule confidence \(prior, not calibrated\) \| 0\.60/);
  assert.match(meta, /winword\.exe\[100\] \(inferred: creation not observed\)/);
  const stages = el('incident-stages').children;
  assert.equal(stages.length, 2);
  assert.equal(stages[0].children[2].textContent, 'Execution / T1059.001');
  assert.equal(stages[0].children[3].textContent, 'powershell.exe[4242]');
  assert.equal(stages[0].children[4].children[0].textContent, 'ALT-1');
  stages[0].children[4].children[0].listeners.click();
  assert.equal(opened[0].title, 'Obfuscated script', 'linked stage alert opens the alert detail');
  assert.equal(opened[0].detection_source, 'rule');
  assert.equal(stages[1].children[4].children[0].textContent, '— (repeat suppressed)');
  assert.equal(stages[1].children[1].children[1].textContent, XSS, 'untrusted strings are kept literal in textContent');
  // Lineage renders as a nested tree, root first, leaf last.
  let level = el('incident-lineage').children[0], names = [];
  while (level) { const li = level.children[0]; names.push(li.children[0].textContent); level = li.children[1]; }
  assert.deepEqual(names, ['explorer.exe', 'winword.exe', 'cmd.exe', 'powershell.exe']);
  assert.equal(el('incident-causal').children.length, 2);
  assert.ok(el('incident-causal').children[1].textContent.endsWith(XSS));
  const score = el('incident-score').children[0].children;
  assert.equal(score[0].textContent, 'stage severity: +4.500 (max stage level 14)');
  assert.equal(score[2].children[0].children.map((c) => c.textContent).join('; '), 'external network: +0.750; initial access vector: +0.500');
  assert.equal(score[3].textContent, 'total: 7.250');
  assert.deepEqual(el('incident-why').children.map((c) => c.textContent), EVIDENCE.why);
  assert.equal(el('incident-alerts').children.length, 2);
  assert.equal(el('incident-alerts').children[1].children[0].textContent, XSS);
  assert.equal(el('incident-alerts').children[1].children[2].textContent, 'correlation');
  assert.match(allText(el('incident-responses')), /KILL_PROCESS · PENDING \| No command issued/);
  assert.match(allText(el('incident-audit')), /opened · by system:detection/);
  assert.equal(el('incident-set-investigating').disabled, false);

  // -- status change ------------------------------------------------------
  el('incident-note').value = '  confirmed  ';
  await el('incident-set-resolved').listeners.click();
  await settle();
  assert.deepEqual(posts[0], { url: '/api/incidents/INC-abc/status', body: { status: 'resolved', note: 'confirmed' } });
  assert.equal(el('incident-message').textContent, 'Status set to Resolved · recorded by Manager');
  assert.equal(el('incident-note').value, '');
  assert.equal(el('incident-set-resolved').disabled, true, 'current status button is disabled');
  assert.equal(el('incident-set-false_positive').disabled, false);
  assert.match(allText(el('incident-audit')), /status_changed · by analyst:alice · open → resolved · confirmed/);
  // Without a note, only the status is sent.
  await el('incident-set-investigating').listeners.click();
  assert.deepEqual(posts[1].body, { status: 'investigating' });

  // An open dialog is refreshed in place on poll, and only when data changed.
  const stagesBefore = el('incident-stages').children[0];
  el('incident-note').value = 'typing…';
  await el('incidents-refresh').listeners.click();
  assert.equal(el('incident-stages').children[0], stagesBefore, 'unchanged detail is not re-rendered');
  assert.equal(el('incident-note').value, 'typing…', 'polling never clears the analyst note');

  // -- status tiles -------------------------------------------------------
  assert.equal(el('pipeline-tiles').hidden, false);
  assert.equal(el('pipeline-unavailable').hidden, true);
  assert.equal(el('status-events-pending').textContent, '4');
  assert.equal(el('status-events-pending-sub').textContent, '1 claimed by the worker');
  assert.equal(el('status-events-done').textContent, '120');
  assert.equal(el('status-events-failed').textContent, '2');
  assert.equal(el('status-incidents-open').textContent, '1');
  assert.equal(el('status-pending-approvals').textContent, '3');
  assert.notEqual(el('status-last-event').textContent, 'No events yet');
  assert.match(el('status-last-event-sub').textContent, /^2 agents enrolled · 9 alerts stored$/);
  assert.doesNotMatch(el('health-note').textContent, /Collector health is not reported/);

  // -- not configured (file mode) ------------------------------------------
  configured = false;
  el('incident-detail').close();
  await el('incidents-refresh').listeners.click();
  assert.equal(el('incidents-table').hidden, true);
  assert.equal(el('incidents-empty-title').textContent, 'Incidents unavailable');
  assert.equal(el('incidents-empty-description').textContent, NOT_CONFIGURED.error);
  // Re-run the status section to observe its 503 handling.
  vm.runInContext(fs.readFileSync('static/app.js', 'utf8').split('// PIPELINE STATUS')[1], context);
  await settle(); await settle();
  assert.equal(el('pipeline-tiles').hidden, true);
  assert.equal(el('pipeline-unavailable').textContent, 'Pipeline status is not reported: no Manager is configured.');
  assert.equal(el('health-note').textContent, 'Collector health is not reported by this console.');

  console.log('PASS: incident list and detail (stages, linked/suppressed alerts, lineage tree, causal path, score, why, members, responses, audit), status changes with note, in-place refresh, status tiles, 503 states');
})().catch((e) => { console.error(e); process.exitCode = 1; });
