/* Verify exact signed evidence against separately trusted enrollment history. */
"use strict";
(function (root) {
  const encoder = new TextEncoder();
  const fields = ["schema_version", "artifact_id", "agent_id", "host_id", "command_id",
    "correlation_id", "kind", "media_type", "content_bytes", "sha256", "produced_at_unix"];
  const numeric = new Set(["content_bytes", "produced_at_unix"]);
  const hex = bytes => Array.from(bytes, byte => byte.toString(16).padStart(2, "0")).join("");
  function closed(value, keys) {
    if (!value || typeof value !== "object" || Array.isArray(value) ||
        Object.keys(value).sort().join(",") !== [...keys].sort().join(",")) {
      throw Error("Invalid closed evidence manifest");
    }
  }
  function bounded(value, maximum) {
    if (typeof value !== "string" || !value.length || [...value].length > maximum ||
        /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/u.test(value)) {
      throw Error("Invalid evidence identity text");
    }
  }
  function decode(value, maximum) {
    if (typeof value !== "string" || !value.length || value.length > Math.ceil(maximum / 3) * 4 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
      throw Error("Invalid bounded evidence encoding");
    }
    const raw = atob(value);
    if (raw.length > maximum || btoa(raw) !== value) throw Error("Noncanonical evidence encoding");
    return Uint8Array.from(raw, character => character.charCodeAt(0));
  }
  function signingInput(manifest) {
    closed(manifest, [...fields, "authorization"]);
    closed(manifest.authorization, ["algorithm", "key_id", "signature"]);
    if (manifest.schema_version !== "2" || manifest.media_type !== "application/json" ||
        !["process_snapshot", "network_snapshot", "file_metadata", "execution_report"].includes(manifest.kind) ||
        !/^art_[0-9a-f]{64}$/.test(manifest.artifact_id) || !/^[0-9a-f]{64}$/.test(manifest.sha256) ||
        manifest.authorization.algorithm !== "ES256" || !/^[0-9a-f]{16}$/.test(manifest.authorization.key_id)) {
      throw Error("Unsupported signed evidence manifest");
    }
    for (const name of numeric) {
      if (!Number.isSafeInteger(manifest[name]) || manifest[name] < (name === "content_bytes" ? 1 : 0) ||
          manifest[name] > (name === "content_bytes" ? 1048576 : 253402300799)) {
        throw Error("Invalid evidence size or timestamp");
      }
    }
    for (const name of ["agent_id", "host_id", "command_id", "correlation_id"]) {
      bounded(manifest[name], name === "host_id" ? 256 : 128);
    }
    let input = "panopticon-response-artifact-auth/2\n";
    for (const name of [...fields, "algorithm", "key_id"]) {
      const value = String(name === "algorithm" || name === "key_id" ? manifest.authorization[name] : manifest[name]);
      input += name + ":" + encoder.encode(value).length + ":" + value + "\n";
    }
    return encoder.encode(input);
  }
  async function verifyPackage(packageValue, trusted) {
    // The caller must obtain trusted key/context from a separately authenticated
    // case-scoped lookup. The package's signing_key cannot authorize itself.
    closed(packageValue, ["manifest", "content_base64", "signing_key"]);
    if (!trusted || !["active_key", "retired_key"].includes(trusted.trust_status) ||
        !Number.isSafeInteger(trusted.key_version) || trusted.key_version < 1) {
      throw Error("Evidence signing identity is untrusted or compromised");
    }
    const manifest = packageValue.manifest;
    const input = signingInput(manifest);
    if (manifest.artifact_id !== trusted.artifact_id || manifest.agent_id !== trusted.agent_id ||
        manifest.host_id !== trusted.host_id || manifest.command_id !== trusted.command_id ||
        manifest.correlation_id !== trusted.correlation_id || manifest.authorization.key_id !== trusted.key_id) {
      throw Error("Evidence does not belong to the selected case and endpoint");
    }
    const subtle = root.crypto?.subtle;
    if (!subtle) throw Error("Secure evidence verification is unavailable in this browser");
    const point = decode(trusted.public_key, 65);
    if (point.length !== 65 || point[0] !== 4 ||
        hex(new Uint8Array(await subtle.digest("SHA-256", point))).slice(0, 16) !== trusted.key_id) {
      throw Error("Evidence signing key disagrees with trusted enrollment history");
    }
    const signature = decode(manifest.authorization.signature, 64);
    if (signature.length !== 64) throw Error("Invalid evidence signature length");
    const key = await subtle.importKey("raw", point, {name: "ECDSA", namedCurve: "P-256"}, false, ["verify"]);
    if (!await subtle.verify({name: "ECDSA", hash: "SHA-256"}, key, signature, input)) {
      throw Error("Evidence manifest signature failed verification");
    }
    const content = decode(packageValue.content_base64, 1048576);
    if (content.length !== manifest.content_bytes ||
        hex(new Uint8Array(await subtle.digest("SHA-256", content))) !== manifest.sha256) {
      throw Error("Evidence content hash or size failed verification");
    }
    return {manifest, content, verified: true, key_version: trusted.key_version};
  }
  const api = {signingInput, verifyPackage};
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.PanopticonArtifactVerifier = api;
})(globalThis);
