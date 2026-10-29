/* Bounded resumable signed evidence retrieval; no content is exposed before audit. */
"use strict";
(function (root) {
  const hex = bytes => Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
  const canonical = value => JSON.stringify(value, function (key, item) {
    if (item && typeof item === "object" && !Array.isArray(item)) {
      return Object.fromEntries(Object.keys(item).sort().map(name => [name, item[name]]));
    }
    return item;
  });
  function fatal(message) { const error = Error(message); error.discard = true; return error; }
  function decode(value, maximum) {
    if (typeof value !== "string" || value.length > Math.ceil(maximum / 3) * 4 ||
        !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
      throw fatal("Invalid evidence frame encoding");
    }
    const raw = atob(value);
    if (!raw.length || raw.length > maximum || btoa(raw) !== value) throw fatal("Invalid evidence frame size");
    return Uint8Array.from(raw, c => c.charCodeAt(0));
  }
  function encode(bytes) {
    let output = "";
    for (let offset = 0; offset < bytes.length; offset += 32768) {
      output += String.fromCharCode(...bytes.subarray(offset, offset + 32768));
    }
    return btoa(output);
  }
  function createDownloader({request, verifier = root.PanopticonArtifactVerifier, crypto = root.crypto}) {
    const partials = new Map();
    let epoch = 0, owner = null;
    const clear = () => { epoch++; partials.clear(); owner = null; };
    const sha = async bytes => hex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
    async function collect(selected, artifactId, operation, progress = () => {}) {
      const generation = epoch;
      const guard = () => { if (generation !== epoch) throw fatal("Evidence identity or case changed"); };
      let cacheKey;
      try {
        if (!verifier || !crypto?.subtle || !["view", "download"].includes(operation) ||
            !/^art_[0-9a-f]{64}$/.test(artifactId)) throw fatal("Secure evidence verification unavailable");
        const identity = await request("/api/evidence/session"); guard();
        if (identity.signed_in !== true || typeof identity.analyst_id !== "string" ||
            !/^[A-Za-z0-9_-]{22}$/.test(identity.identity_version)) throw fatal("Evidence identity is unavailable");
        const identityKey = identity.analyst_id + ":" + identity.identity_version;
        if (owner !== null && owner !== identityKey) partials.clear();
        owner = identityKey;
        const headers = {"X-Panopticon-Evidence-Identity": identity.identity_version};
        const call = async (path, options = {}) => {
          guard();
          const value = await request(path, {...options, headers: {...headers, ...options.headers}});
          guard(); return value;
        };
        const base = "/api/evidence/artifacts/" + artifactId;
        async function context() {
          const value = await call(base + "/context");
          const trusted = value.trusted, manifest = value.manifest;
          if (value.schema_version !== "1" || value.artifact_id !== artifactId || value.chunk_bytes !== 65536 ||
              !trusted || !manifest || !["active_key", "retired_key"].includes(trusted.trust_status)) {
            throw fatal("Evidence signer is compromised, unsigned or unavailable");
          }
          // Validate the closed signed manifest before considering a size or key from it.
          verifier.signingInput(manifest);
          for (const key of ["response_id", "alert_id", "agent_id", "host_id", "command_id", "correlation_id"]) {
            if (typeof selected[key] !== "string" || !selected[key] || trusted[key] !== selected[key]) {
              throw fatal("Evidence belongs to another case or endpoint");
            }
          }
          if (trusted.artifact_id !== artifactId || manifest.artifact_id !== artifactId ||
              !/^[0-9a-f]{64}$/.test(value.manifest_sha256) ||
              await sha(new TextEncoder().encode(canonical(manifest))) !== value.manifest_sha256) {
            throw fatal("Evidence manifest binding failed");
          }
          guard(); return value;
        }
        let current = await context();
        const binding = value => canonical({digest: value.manifest_sha256, key: value.trusted.public_key,
                                            key_id: value.trusted.key_id, version: value.trusted.key_version});
        cacheKey = canonical({owner: identityKey, case: selected.response_id, artifactId});
        let entry = partials.get(cacheKey);
        if (entry && entry.binding !== binding(current)) { partials.delete(cacheKey); entry = null; }
        if (!entry) {
          if (partials.size >= 4) partials.delete(partials.keys().next().value);
          entry = {binding: binding(current), parts: [], received: 0, requests: {}};
          partials.set(cacheKey, entry);
        }
        const total = current.manifest.content_bytes;
        progress(entry.received, total, "Receiving signed evidence");
        while (entry.received < total) {
          const frame = await call(base + "/chunks?offset=" + entry.received +
                                   "&manifest_sha256=" + current.manifest_sha256);
          if (!frame || Object.keys(frame).sort().join(",") !== ["schema_version", "artifact_id",
              "manifest_sha256", "offset", "content_bytes", "sha256", "content_base64", "next_offset", "complete"].sort().join(",") ||
              frame.schema_version !== "1" || frame.artifact_id !== artifactId ||
              frame.manifest_sha256 !== current.manifest_sha256 || frame.offset !== entry.received ||
              !Number.isSafeInteger(frame.content_bytes) || !Number.isSafeInteger(frame.next_offset)) {
            throw fatal("Evidence frame identity or offset failed");
          }
          const bytes = decode(frame.content_base64, 65536), expected = Math.min(65536, total - entry.received);
          if (bytes.length !== expected || frame.content_bytes !== expected ||
              frame.next_offset !== entry.received + expected ||
              typeof frame.complete !== "boolean" || frame.complete !== (frame.next_offset === total) ||
              await sha(bytes) !== frame.sha256) throw fatal("Evidence frame hash or size failed");
          guard(); entry.parts.push(bytes); entry.received += bytes.length;
          progress(entry.received, total, "Receiving signed evidence");
        }
        // Re-read live scope/key state after a reconnect or a long transfer.
        const fresh = await context();
        if (binding(current) !== binding(fresh)) throw fatal("Evidence signing history changed during download");
        current = fresh;
        const bytes = new Uint8Array(total);
        let offset = 0;
        for (const part of entry.parts) { bytes.set(part, offset); offset += part.length; }
        const packageValue = {manifest: current.manifest, content_base64: encode(bytes), signing_key: current.trusted};
        let verified;
        try { verified = await verifier.verifyPackage(packageValue, current.trusted); }
        catch (error) { error.discard = true; throw error; }
        guard();
        if (!verified.verified) throw fatal("Evidence was not verified");
        // Reject invalid JSON/text before recording the acknowledgement or exposing it.
        let text;
        try { text = new TextDecoder("utf-8", {fatal: true}).decode(verified.content); JSON.parse(text); }
        catch (error) { error.discard = true; throw error; }
        if (!entry.requests[operation]) entry.requests[operation] = "view-" + crypto.randomUUID();
        progress(total, total, "Recording analyst custody acknowledgement");
        const receipt = await call(base + "/view", {method: "POST", body: JSON.stringify({schema_version: "1",
          request_id: entry.requests[operation], manifest_sha256: current.manifest_sha256, operation}),
          headers: {"Content-Type": "application/json"}});
        if (receipt.recorded !== true || receipt.schema_version !== "1" || receipt.artifact_id !== artifactId ||
            receipt.manifest_sha256 !== current.manifest_sha256 || receipt.operation !== operation) {
          throw fatal("Evidence custody acknowledgement failed");
        }
        guard(); partials.delete(cacheKey);
        return {packageValue, content: text, manifest: current.manifest, trusted: current.trusted};
      } catch (error) {
        if (error.discard || [401, 403, 409, 410, 422, 503].includes(error.status)) {
          partials.clear(); owner = null;
        }
        throw error;
      }
    }
    return {collect, clear};
  }
  const api = {createDownloader};
  if (typeof module !== "undefined" && module.exports) module.exports = api;
  else root.PanopticonArtifactDownload = api;
})(globalThis);
