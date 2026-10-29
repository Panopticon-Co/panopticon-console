"use strict";
const assert = require("node:assert/strict"), fs = require("node:fs"), vm = require("node:vm");
class Element {
  constructor() { this.children = []; this.listeners = {}; this.hidden = false; this.disabled = false; this.value = ""; this._text = ""; }
  set textContent(value) { this._text = String(value); this.children = []; }
  get textContent() { return this._text; }
  set innerHTML(_) { throw Error("Evidence must never enter innerHTML"); }
  append(...items) { this.children.push(...items); }
  replaceChildren(...items) { this.children = [...items]; this._text = ""; }
  addEventListener(name, fn) { this.listeners[name] = fn; }
  showModal() { this.open = true; } close() { this.open = false; }
  click() {} remove() {}
}
const elements = new Map(), el = id => { if (!elements.has(id)) elements.set(id, new Element()); return elements.get(id); };
const item = {artifact_id: "art_" + "a".repeat(64), kind: "process_snapshot", content_bytes: 20, sha256: "b".repeat(64),
              signing: {trust_status: "active_key", key_version: 1}};
let identity = {signed_in: true, analyst_id: "reader", role: "analyst", identity_version: "a".repeat(22)};
let record = {response_id: "r1", alert_id: "alert-1", host_id: "host-1", agent_id: "agent-1", command_id: "command-1",
              command: {correlation_id: "correlation-1"}, artifact_access: "granted", artifacts: [item]};
let error = null, deferred = null, clearCount = 0, exportCount = 0;
const calls = [];
const verified = {content: '{"command_line":"<img src=x onerror=alert(1)>"}',
                  packageValue: {manifest: {authorization: {signature: "signature"}}, content_base64: "e30="},
                  trusted: {key_version: 1, trust_status: "active_key"}};
const window = {};
const context = vm.createContext({
  document: {getElementById: el, addEventListener: (_, fn) => fn(), createElement: () => new Element(), body: new Element()},
  window, AbortController, setTimeout, clearTimeout, Blob,
  URL: {createObjectURL() {exportCount++; return "blob:test";}, revokeObjectURL() {}},
  PanopticonArtifactDownload: {createDownloader: () => ({
    clear() {clearCount++;},
    async collect(selected, artifactId, operation, progress) {
      assert.equal(selected.response_id, "r1"); assert.equal(selected.correlation_id, "correlation-1");
      progress(20, 20, "Verifying evidence");
      if (deferred) await deferred;
      if (error) throw error;
      return verified;
    }
  })},
  fetch: async (path, options = {}) => {
    calls.push({path, options});
    if (path.endsWith("/logout")) return {ok: true, status: 200, json: async () => ({signed_in: false})};
    if (path.endsWith("/session")) return {ok: true, status: 200, json: async () => identity};
    if (path.includes("/cases/")) {
      assert.equal(options.headers["X-Panopticon-Evidence-Identity"], identity.identity_version);
      return {ok: true, status: 200, json: async () => ({response_action: record})};
    }
    if (path.includes("/custody?")) return {ok: true, status: 200, json: async () => ({events: [
      {occurred_at: "time", event: "artifact_viewed", actor: "analyst:reader", detail: {literal: "<script>"}}
    ], next_after: 1})};
    throw Error("Unexpected route " + path);
  }
});
vm.runInContext(fs.readFileSync("static/evidence.js", "utf8"), context);
const tick = () => new Promise(resolve => setImmediate(resolve));
const card = () => el("evidence-items").children[0];
const button = label => card().children.find(child => child.textContent === label);
(async () => {
  await tick();
  await window.PanopticonEvidence.openCase("r1");
  assert.equal(el("evidence-dialog").open, true);
  assert.equal(el("evidence-items").children.length, 1);
  await button("Verify and view").listeners.click();
  assert.equal(el("evidence-content").textContent, verified.content);
  assert.match(el("evidence-message").textContent, /Signature and SHA-256 verified/);
  assert.match(el("evidence-custody").children[1].children[0].textContent, /artifact_viewed.*<script>/);
  await button("Download signed bundle").listeners.click(); assert.equal(exportCount, 1);

  error = Error("Mandatory custody audit unavailable");
  await button("Verify and view").listeners.click();
  assert.equal(el("evidence-content").textContent, "");
  await button("Download signed bundle").listeners.click(); assert.equal(exportCount, 1);
  assert.match(el("evidence-message").textContent, /audit unavailable/); error = null;

  let release;
  deferred = new Promise(resolve => {release = resolve;});
  const pending = button("Verify and view").listeners.click();
  el("evidence-close").listeners.click(); release(); await pending; deferred = null;
  assert.equal(el("evidence-content").textContent, ""); assert.equal(el("evidence-dialog").open, false);

  record = {...record, artifact_access: "requires_case_endpoint_grant"};
  await window.PanopticonEvidence.openCase("r1");
  assert.equal(el("evidence-items").children.length, 0);
  assert.match(el("evidence-message").textContent, /administrator must grant/);
  record = {...record, artifact_access: "granted", artifacts: [{...item,
    signing: {trust_status: "compromised_key", key_version: 1, compromise_reason: "Key stolen"}}]};
  await window.PanopticonEvidence.openCase("r1");
  assert.equal(button("Verify and view").disabled, true);
  assert.equal(button("Download signed bundle").disabled, true);
  assert.equal(button("Review custody").disabled, false);
  assert.ok(card().children.some(child => /Key stolen/.test(child.textContent)));

  el("evidence-token").value = "individual_credential_never_store";
  await el("evidence-login-form").listeners.submit({preventDefault() {}});
  assert.equal(el("evidence-token").value, "");
  assert.ok(calls.some(c => c.path === "/api/evidence/session" && c.options.method === "POST"));
  await el("evidence-logout").listeners.click();
  assert.equal(el("evidence-content").textContent, "");
  assert.equal(el("evidence-items").children.length, 0);
  assert.ok(clearCount >= 5);
  console.log("Evidence UI: literal safe rendering, case grants, compromised flags, no unaudited display/export, stale-view refusal and sign-out clearing passed");
})().catch(error => {console.error(error); process.exitCode = 1;});
