// Automated-response rendering: policy mode, simulation preview and verified
// execution stay distinct, and only verified success reads as contained.
const fs = require('fs'), vm = require('vm'), assert = require('assert');
const context = vm.createContext({ document: { addEventListener() {}, createElement: () => ({ append() {} }) } });
vm.runInContext(fs.readFileSync('static/app.js', 'utf8').split('// RESPONSE ACTIONS PANEL')[1] + '\nthis.R = PanopticonRender;', context);
const R = context.R;

const simulated = {
  action: 'KILL_PROCESS', lifecycle_state: 'PENDING', response_status: 'awaiting_approval',
  policy_decision: { policy_id: 'contain-reverse-shell', mode: 'approval', global_mode: 'enforce', simulation_status: 'simulated',
    simulation: { would: 'terminate process pid=42 (start_time_ticks=7) on host LAB-1', host_effect: 'none' } },
  execution: { kind: 'simulated', outcome: null, verified: false },
};
assert.deepStrictEqual(JSON.parse(JSON.stringify(R.automationLines(simulated))), [
  'Response status: Awaiting approval',
  'Policy contain-reverse-shell · Approval required · response mode enforce',
  'Simulated (no host effect): would terminate process pid=42 (start_time_ticks=7) on host LAB-1',
]);

const contained = { ...simulated, response_status: 'contained', execution: { kind: 'endpoint', outcome: 'succeeded', verified: true } };
assert.ok(R.automationLines(contained).includes('Executed on endpoint · succeeded · verified'));
assert.strictEqual(R.responseStatusLabel('contained'), 'Contained (verified on endpoint)');
assert.strictEqual(R.responseStatusLabel('containment_unverified'), 'Containment reported, unverified');
assert.strictEqual(R.responseStatusLabel('simulated_containment'), 'Simulated containment (no host action)');
assert.strictEqual(R.responseStatusLabel('resolved'), 'Manually resolved');
assert.strictEqual(R.responseStatusLabel(undefined), null);

// Older Managers send none of these fields: nothing is rendered or inferred.
assert.deepStrictEqual(JSON.parse(JSON.stringify(R.automationLines({ action: 'KILL_PROCESS', lifecycle_state: "AUTHORIZED" }))), []);
console.log('response automation rendering ok');
