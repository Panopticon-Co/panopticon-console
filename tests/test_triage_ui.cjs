"use strict";
const assert = require("node:assert/strict"), fs = require("node:fs"), vm = require("node:vm");
class Element {
  constructor(tag) { this.tag = tag; this.children = []; this.listeners = {}; this.value = ""; this.hidden = false; }
  set textContent(value) { this.text = String(value); this.children = []; }
  get textContent() { return this.text || ""; }
  set innerHTML(_) { throw Error("Never render triage using HTML"); }
  append(...items) { this.children.push(...items.filter(i => !this.children.includes(i))); }
  replaceChildren(...items) { this.children = items; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  setAttribute(name, value) { this[name] = value; }
}
const elements = new Map(), el = id => { if (!elements.has(id)) elements.set(id, new Element("div")); return elements.get(id); };
const listeners = {}, calls = [], cases = [];
let identity = {analyst_id: "administrator", identity_version: "identity-1", permissions: ["triage:manage"]};
let reject = false;
const policy = {schema_version: "1", rule_id: "RULE-1", version: 4, enabled: true, budget: {}, entries: [
  {action: "COLLECT_PROCESS_INFO", asset_class: "standard", decision: "auto_dispatch", file_paths: []},
  {action: "COLLECT_NETWORK_CONNECTIONS", asset_class: "standard", decision: "auto_dispatch", file_paths: []},
  {action: "COLLECT_FILE", asset_class: "standard", decision: "require_approval", file_paths: []},
]};
const context = vm.createContext({
  document: {getElementById: el, createElement: tag => new Element(tag), addEventListener(name, fn) {
    if (name === "DOMContentLoaded") fn(); else listeners[name] = fn;
  }}, window: {PanopticonEvidence: {openCase: async id => cases.push(id)}},
  AbortController, setTimeout, clearTimeout, crypto: {randomUUID: () => "retry-id"},
  fetch: async (path, options) => {
    calls.push({path, options});
    assert.equal(options.credentials, "same-origin");
    assert.equal(options.headers.Authorization, undefined);
    let value = {};
    if (path.endsWith("/session")) value = identity;
    else {
      assert.equal(options.headers["X-Panopticon-Evidence-Identity"], identity.identity_version);
      if (path.endsWith("/policies") && !options.body) value = {policies: [policy], configured_rules: ["RULE-1"], assets: []};
      if (path.includes("/runs?")) value = {runs: [{alert_id: "<img src=x>", host_id: "host-1", rule_id: "RULE-1",
        policy_version: 4, items: [{action: "COLLECT_PROCESS_INFO", decision: "auto_dispatch", reason: "policy_auto_collection",
          response_id: "actual-collection-response", reserved_bytes: 1048576, live_blocker: "triage_runtime_policy_changed"}]}], next_offset: null};
    }
    return {ok: !(reject && options.body), status: reject ? 409 : 200, json: async () => reject && options.body ? {detail: "Policy revision changed"} : value};
  }
});
vm.runInContext(fs.readFileSync("static/triage.js", "utf8"), context);
const all = root => [root, ...root.children.flatMap(all)];
(async () => {
  await el("triage-refresh").listeners.click();
  assert.equal(el("triage-admin").hidden, false);
  const form = all(el("triage-admin")).find(n => n.tag === "form");
  await form.listeners.submit({preventDefault() {}});
  const sent = calls.find(c => c.path.endsWith("/policies") && c.options.body);
  const body = JSON.parse(sent.options.body);
  assert.equal(body.expected_version, 4); assert.equal(body.policy.version, 5);
  assert.equal(body.policy.entries.length, 9);
  assert.ok(body.policy.entries.filter(e => e.asset_class !== "standard").every(e => e.decision === "require_approval"));
  assert.ok(body.policy.entries.every(e => !["KILL_PROCESS", "ISOLATE_HOST", "QUARANTINE_FILE"].includes(e.action)));
  reject = true;
  await form.listeners.submit({preventDefault() {}});
  assert.match(el("triage-message").textContent, /revision changed/); reject = false;
  listeners["panopticon-identity-changed"]({detail: {identity_version: "identity-2"}});
  assert.equal(el("triage-admin").children.length, 0);
  identity = {analyst_id: "operator", identity_version: "identity-2", permissions: ["response:request", "response:decide", "artifact:read"]};
  await el("triage-refresh").listeners.click();
  const rendered = all(el("triage-runs"));
  assert.ok(rendered.some(n => n.textContent === "<img src=x>"));
  assert.ok(rendered.some(n => /triage_runtime_policy_changed/.test(n.textContent)));
  await rendered.find(n => n.textContent === "Review case and evidence").listeners.click();
  assert.deepEqual(cases, ["actual-collection-response"]);
  rendered.find(n => n.tag === "input").value = "Analyst stopped investigation";
  await rendered.find(n => n.textContent === "Stop remaining collections").listeners.click();
  assert.ok(calls.some(c => c.path === "/api/evidence/triage/runs/%3Cimg%20src%3Dx%3E/cancel"));
  listeners["panopticon-identity-changed"]({detail: null});
  assert.equal(el("triage-runs").children.length, 0);
  console.log("Triage UI: versioned collection-only policies, stale-save refusal, literal rendering, individual identity, case links and cancellation passed");
})().catch(error => {console.error(error); process.exitCode = 1;});
