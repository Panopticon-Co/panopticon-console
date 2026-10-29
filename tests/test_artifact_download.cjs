"use strict";
const assert = require("node:assert/strict");
const {webcrypto: crypto} = require("node:crypto");
if (!globalThis.crypto?.subtle) Object.defineProperty(globalThis, "crypto", {value: crypto});
const verifier = require("../static/artifact-verifier.js");
const {createDownloader} = require("../static/artifact-download.js");
const canonical = value => JSON.stringify(value, (_, item) => item && typeof item === "object" && !Array.isArray(item)
  ? Object.fromEntries(Object.keys(item).sort().map(k => [k, item[k]])) : item);
const sha = async bytes => Buffer.from(await crypto.subtle.digest("SHA-256", bytes)).toString("hex");
const failure = (status, message) => Object.assign(Error(message), {status});

async function fixture(seed = 0) {
  const keys = await crypto.subtle.generateKey({name: "ECDSA", namedCurve: "P-256"}, true, ["sign", "verify"]);
  const point = Buffer.from(await crypto.subtle.exportKey("raw", keys.publicKey));
  const content = Buffer.from(JSON.stringify({processes: [], note: "x".repeat(140000), seed}));
  const selected = {response_id: "response-1", alert_id: "alert-1", agent_id: "agent-1", host_id: "host-1",
                    command_id: "command-1", correlation_id: "correlation-1"};
  const manifest = {schema_version: "2", artifact_id: "art_" + await sha(content), agent_id: selected.agent_id,
    host_id: selected.host_id, command_id: selected.command_id, correlation_id: selected.correlation_id,
    kind: "process_snapshot", media_type: "application/json", content_bytes: content.length, sha256: await sha(content),
    produced_at_unix: 1793232000, authorization: {algorithm: "ES256", key_id: (await sha(point)).slice(0, 16),
                                              signature: Buffer.alloc(64).toString("base64")}};
  manifest.authorization.signature = Buffer.from(await crypto.subtle.sign({name: "ECDSA", hash: "SHA-256"},
    keys.privateKey, verifier.signingInput(manifest))).toString("base64");
  const context = {schema_version: "1", artifact_id: manifest.artifact_id, manifest,
    manifest_sha256: await sha(Buffer.from(canonical(manifest))), chunk_bytes: 65536,
    trusted: {...selected, artifact_id: manifest.artifact_id, key_id: manifest.authorization.key_id, key_version: 1,
              public_key: point.toString("base64"), trust_status: "active_key"}};
  const state = {identity: "a".repeat(22), calls: [], chunks: [], receipts: new Map(), failOffset: null,
                 loseReceipt: false, corrupt: false, revokeAt: null, compromiseAfter: false, contexts: 0};
  const request = async (path, options = {}) => {
    state.calls.push({path, options});
    if (path === "/api/evidence/session") return {signed_in: true, analyst_id: "reader", identity_version: state.identity};
    if (options.headers?.["X-Panopticon-Evidence-Identity"] !== state.identity) throw failure(409, "Identity changed");
    if (path.endsWith("/context")) {
      state.contexts++;
      const result = structuredClone(context);
      if (state.compromiseAfter && state.contexts > 1) result.trusted.trust_status = "compromised_key";
      return result;
    }
    if (path.includes("/chunks?")) {
      const offset = Number(new URL("http://console" + path).searchParams.get("offset"));
      state.chunks.push(offset);
      if (state.revokeAt === offset) throw failure(403, "Scope revoked");
      if (state.failOffset === offset) { state.failOffset = null; throw Error("Network interrupted"); }
      const part = content.subarray(offset, offset + 65536), next = offset + part.length;
      const result = {schema_version: "1", artifact_id: manifest.artifact_id, manifest_sha256: context.manifest_sha256,
        offset, content_bytes: part.length, sha256: await sha(part), content_base64: part.toString("base64"),
        next_offset: next, complete: next === content.length};
      if (state.corrupt) result.sha256 = "0".repeat(64);
      return result;
    }
    if (path.endsWith("/view")) {
      const body = JSON.parse(options.body);
      const result = {schema_version: "1", artifact_id: manifest.artifact_id,
                     manifest_sha256: context.manifest_sha256, operation: body.operation, recorded: true};
      if (state.receipts.has(body.request_id)) assert.deepEqual(state.receipts.get(body.request_id), result);
      state.receipts.set(body.request_id, result);
      if (state.loseReceipt) { state.loseReceipt = false; throw Error("Receipt acknowledgement lost"); }
      return result;
    }
    throw Error("Unexpected route " + path);
  };
  return {selected, manifest, context, content, state, request};
}

(async () => {
  let f = await fixture();
  let downloader = createDownloader({request: f.request, verifier, crypto});
  f.state.failOffset = 65536;
  await assert.rejects(downloader.collect(f.selected, f.manifest.artifact_id, "view"), /interrupted/);
  assert.equal(f.state.receipts.size, 0);
  let result = await downloader.collect(f.selected, f.manifest.artifact_id, "view");
  assert.equal(result.content, f.content.toString());
  assert.deepEqual(f.state.chunks, [0, 65536, 65536, 131072]);
  assert.equal(f.state.receipts.size, 1);

  f = await fixture(); downloader = createDownloader({request: f.request, verifier, crypto});
  f.state.loseReceipt = true;
  await assert.rejects(downloader.collect(f.selected, f.manifest.artifact_id, "download"), /lost/);
  const frames = f.state.chunks.length;
  await downloader.collect(f.selected, f.manifest.artifact_id, "download");
  assert.equal(f.state.chunks.length, frames);
  assert.equal(f.state.receipts.size, 1, "lost receipt retry must reuse the acknowledgement identity");

  for (const scenario of ["hash", "scope", "compromise", "case", "signature", "identity"] ) {
    f = await fixture();
    let originalRequest = f.request;
    const selected = {...f.selected};
    if (scenario === "hash") f.state.corrupt = true;
    if (scenario === "scope") f.state.revokeAt = 65536;
    if (scenario === "compromise") f.state.compromiseAfter = true;
    if (scenario === "case") selected.response_id = "other-case";
    if (scenario === "signature") {
      f.context.manifest.authorization.signature = Buffer.alloc(64).toString("base64");
      f.context.manifest_sha256 = await sha(Buffer.from(canonical(f.context.manifest)));
    }
    if (scenario === "identity") originalRequest = async (path, options) => {
      const value = await f.request(path, options);
      if (path.includes("/chunks?")) f.state.identity = "b".repeat(22);
      return value;
    };
    downloader = createDownloader({request: originalRequest, verifier, crypto});
    await assert.rejects(downloader.collect(selected, f.manifest.artifact_id, "view"), undefined, scenario);
    assert.equal(f.state.receipts.size, 0, scenario + " must not acknowledge or expose evidence");
  }
  f = await fixture();
  let release;
  downloader = createDownloader({request: async (path, options) => {
    if (path.includes("/chunks?")) await new Promise(resolve => {release = resolve;});
    return f.request(path, options);
  }, verifier, crypto});
  const pending = downloader.collect(f.selected, f.manifest.artifact_id, "view");
  while (!release) await new Promise(resolve => setImmediate(resolve));
  downloader.clear(); release();
  await assert.rejects(pending, /identity or case changed/);
  assert.equal(f.state.receipts.size, 0);
  const fixtures = await Promise.all([1, 2, 3, 4, 5].map(seed => fixture(seed)));
  downloader = createDownloader({request: async (path, options) => {
    const target = path.endsWith("/session") ? fixtures[0]
      : fixtures.find(value => path.includes(value.manifest.artifact_id));
    assert.ok(target); return target.request(path, options);
  }, verifier, crypto});
  for (const value of fixtures) {
    value.state.failOffset = 65536;
    await assert.rejects(downloader.collect(value.selected, value.manifest.artifact_id, "view"), /interrupted/);
  }
  await downloader.collect(fixtures[0].selected, fixtures[0].manifest.artifact_id, "view");
  assert.equal(fixtures[0].state.chunks[2], 0, "oldest partial must be evicted at the four-artifact budget");
  console.log("Evidence downloads: real signatures, bounded resume, lost receipts, revocation, compromise, case/identity and stale-view refusal passed");
})().catch(error => {console.error(error); process.exitCode = 1;});
