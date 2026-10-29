"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const {webcrypto} = require("node:crypto");
if (!globalThis.crypto?.subtle) Object.defineProperty(globalThis, "crypto", {value: webcrypto});
const verifier = require("../static/artifact-verifier.js");
const contracts = process.env.PANOPTICON_CONTRACTS_DIR || "../panopticon-contracts";
const vector = JSON.parse(fs.readFileSync(path.join(contracts, "fixtures/artifacts/signing-v2.json"), "utf8"));
const manifest = vector.manifest;
const trusted = {artifact_id: manifest.artifact_id, agent_id: manifest.agent_id, host_id: manifest.host_id,
  command_id: manifest.command_id, correlation_id: manifest.correlation_id,
  key_id: manifest.authorization.key_id, key_version: 1, public_key: vector.public_key, trust_status: "active_key"};
const pkg = {manifest, content_base64: vector.content_base64, signing_key: {public_key: "ignored-upload-key"}};
(async () => {
  assert.deepEqual(Buffer.from(verifier.signingInput(manifest)), Buffer.from(vector.signing_input_base64, "base64"));
  const result = await verifier.verifyPackage(pkg, trusted);
  assert.equal(result.verified, true);
  assert.deepEqual(Buffer.from(result.content), Buffer.from(vector.content_base64, "base64"));
  assert.equal((await verifier.verifyPackage(pkg, {...trusted, trust_status: "retired_key"})).verified, true);
  for (const field of ["artifact_id", "agent_id", "host_id", "command_id", "correlation_id", "key_id"]) {
    await assert.rejects(verifier.verifyPackage(pkg, {...trusted, [field]: "different"}));
  }
  await assert.rejects(verifier.verifyPackage(pkg, {...trusted, trust_status: "compromised_key"}));
  await assert.rejects(verifier.verifyPackage(pkg, {...trusted, public_key: "untrusted"}));
  await assert.rejects(verifier.verifyPackage({...pkg, content_base64: Buffer.from("{}").toString("base64")}, trusted));
  const changed = structuredClone(pkg);
  changed.manifest.produced_at_unix++;
  await assert.rejects(verifier.verifyPackage(changed, trusted), /signature/);
  const forged = structuredClone(pkg);
  forged.manifest.authorization.signature = Buffer.alloc(64).toString("base64");
  await assert.rejects(verifier.verifyPackage(forged, trusted), /signature/);
  assert.throws(() => verifier.signingInput({...manifest, content_bytes: true}));
  assert.throws(() => verifier.signingInput({...manifest, extra: "not allowed"}));
  console.log("Signed artifact: central byte vector, signature, hash, trusted identity and compromise refusal passed");
})().catch(error => {console.error(error); process.exitCode = 1;});
