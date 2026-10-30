/* Individual evidence identity and verified, case-bound investigation views. */
"use strict";
document.addEventListener("DOMContentLoaded", () => {
  const $ = id => document.getElementById(id);
  if (!$("evidence-login-form")) return;
  const node = (tag, value) => { const el = document.createElement(tag); if (value !== undefined) el.textContent = String(value); return el; };
  let identity = null, selected = null, flight = null, generation = 0;
  async function request(path, options = {}) {
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 8000);
    const cancel = () => controller.abort();
    const external = flight?.signal;
    external?.addEventListener("abort", cancel, {once: true});
    if (external?.aborted) controller.abort();
    try {
      const response = await fetch(path, {cache: "no-store", credentials: "same-origin", ...options,
                                         signal: controller.signal});
      const value = await response.json();
      if (!response.ok) {
        const error = Error(value.detail || value.error || "Evidence request failed");
        error.status = response.status; throw error;
      }
      return value;
    } finally { clearTimeout(timeout); external?.removeEventListener("abort", cancel); }
  }
  const downloader = PanopticonArtifactDownload.createDownloader({request});
  function clearSensitive() {
    generation++; flight?.abort(); flight = null; selected = null; downloader.clear();
    $("evidence-content").textContent = ""; $("evidence-items").replaceChildren();
    $("evidence-custody").replaceChildren(); $("evidence-message").textContent = "";
  }
  function showIdentity(value) {
    identity = value;
    if (typeof CustomEvent === "function" && document.dispatchEvent) {
      document.dispatchEvent(new CustomEvent("panopticon-identity-changed", {detail: value}));
    }
    $("evidence-session-status").textContent = value
      ? "Evidence identity: " + value.analyst_id + " · " + value.role + " · case and endpoint grants required"
      : "Sign in with your individual analyst credential to inspect investigation evidence.";
    $("evidence-logout").hidden = !value;
  }
  async function session() {
    const value = await request("/api/evidence/session");
    if (identity && identity.identity_version !== value.identity_version) {
      if (selected || flight) clearSensitive(); else downloader.clear();
    }
    showIdentity(value); return value;
  }
  const headers = () => ({"X-Panopticon-Evidence-Identity": identity?.identity_version || ""});
  $("evidence-login-form").addEventListener("submit", async event => {
    event.preventDefault();
    const token = $("evidence-token").value; $("evidence-token").value = "";
    clearSensitive(); showIdentity(null); $("evidence-login").disabled = true;
    try { showIdentity(await request("/api/evidence/session", {method: "POST",
      headers: {"Content-Type": "application/json"}, body: JSON.stringify({access_token: token})})); }
    catch (error) { $("evidence-session-status").textContent = error.message; }
    finally { $("evidence-login").disabled = false; }
  });
  $("evidence-logout").addEventListener("click", async () => {
    clearSensitive(); showIdentity(null);
    try { await request("/api/evidence/session/logout", {method: "POST"}); }
    catch { $("evidence-session-status").textContent = "Sign-out could not be confirmed. Retry sign out or close this Console session.";
      $("evidence-logout").hidden = false; }
  });
  $("evidence-close").addEventListener("click", () => { clearSensitive(); $("evidence-dialog").close(); });
  $("evidence-dialog").addEventListener("cancel", () => clearSensitive());
  $("evidence-cancel").addEventListener("click", () => {
    flight?.abort(); $("evidence-message").textContent = "Transfer paused. Retry to resume verified frames in this browser session.";
  });
  async function custody(artifactId) {
    $("evidence-custody").replaceChildren(); let after = 0; const current = generation;
    const title = node("h3", "Chain of custody"), list = node("ol"), more = node("button", "Load custody events");
    $("evidence-custody").append(title, list, more);
    async function load() {
      more.disabled = true;
      try {
        await session();
        if (current !== generation) return;
        const value = await request("/api/evidence/artifacts/" + artifactId + "/custody?limit=100&after=" + after,
                                    {headers: headers()});
        if (current !== generation) return;
        for (const entry of value.events || []) list.append(node("li", [entry.occurred_at, entry.event,
          entry.actor, JSON.stringify(entry.detail)].join(" · ")));
        after = value.next_after;
        more.hidden = !Array.isArray(value.events) || value.events.length < 100;
        more.textContent = "Load more custody events";
      } catch (error) {
        if (current !== generation) return;
        if ([401, 403, 409, 410].includes(error.status)) clearSensitive();
        if (error.status === 401) showIdentity(null);
        $("evidence-message").textContent = error.message;
      }
      finally { more.disabled = false; }
    }
    more.addEventListener("click", load); await load();
  }
  async function inspect(item, operation, button) {
    if (flight || !selected) return;
    const current = generation, record = selected;
    flight = new AbortController(); button.disabled = true; $("evidence-cancel").hidden = false;
    $("evidence-content").textContent = "";
    try {
      const value = await downloader.collect(record, item.artifact_id, operation, (received, total, message) => {
        $("evidence-message").textContent = message + " · " + received.toLocaleString() + " / " + total.toLocaleString() + " bytes";
      });
      if (current !== generation) return;
      if (operation === "download") {
        const blob = new Blob([JSON.stringify(value.packageValue, null, 2)], {type: "application/json"});
        const url = URL.createObjectURL(blob), link = node("a"); link.href = url;
        link.download = item.artifact_id + ".signed.json"; document.body.append(link); link.click(); link.remove();
        setTimeout(() => URL.revokeObjectURL(url), 1000);
      } else { $("evidence-content").textContent = value.content; }
      $("evidence-message").textContent = "Signature and SHA-256 verified · key version " + value.trusted.key_version +
        " · " + value.trusted.trust_status + " · analyst custody recorded";
      await custody(item.artifact_id);
    } catch (error) {
      if (current !== generation) return;
      $("evidence-content").textContent = "";
      $("evidence-message").textContent = error.name === "AbortError"
        ? "Transfer paused. Retry to resume in this session." : error.message;
      if ([401, 403, 409, 410].includes(error.status)) { downloader.clear(); $("evidence-items").replaceChildren(); }
      if (error.status === 401) showIdentity(null);
    } finally { if (current === generation) { flight = null; button.disabled = false; $("evidence-cancel").hidden = true; } }
  }
  async function openCase(responseId) {
    clearSensitive();
    $("evidence-title").textContent = "Investigation evidence";
    $("evidence-dialog").showModal();
    const current = generation;
    try {
      await session();
      const value = await request("/api/evidence/cases/" + encodeURIComponent(responseId), {headers: headers()});
      if (current !== generation) return;
      const record = value.response_action;
      if (!record || record.response_id !== responseId) throw Error("Case identity did not match");
      selected = {response_id: responseId, alert_id: record.alert_id, host_id: record.host_id,
                  agent_id: record.agent_id, command_id: record.command_id,
                  correlation_id: record.command?.correlation_id};
      $("evidence-title").textContent = "Evidence · " + record.alert_id + " · " + record.host_id;
      if (record.artifact_access !== "granted") {
        $("evidence-message").textContent = "An evidence administrator must grant access to this case and endpoint."; return;
      }
      if (!record.artifacts?.length) $("evidence-message").textContent = "No investigation artifacts have been retained for this response yet.";
      for (const item of record.artifacts || []) {
        const card = node("li"), signing = item.signing || {};
        card.append(node("strong", item.kind), node("p", item.content_bytes + " bytes · " + signing.trust_status +
          " · key version " + (signing.key_version || "unverified")), node("p", "SHA-256: " + item.sha256));
        if (signing.trust_status === "compromised_key") card.append(node("p", "Signing key flagged: " + signing.compromise_reason +
          ". Evidence is retained; content access is blocked."));
        for (const [label, operation] of [["Verify and view", "view"], ["Download signed bundle", "download"]]) {
          const button = node("button", label); button.type = "button";
          button.disabled = !["active_key", "retired_key"].includes(signing.trust_status);
          button.addEventListener("click", () => inspect(item, operation, button)); card.append(button);
        }
        const trail = node("button", "Review custody"); trail.type = "button";
        trail.addEventListener("click", () => custody(item.artifact_id)); card.append(trail);
        $("evidence-items").append(card);
      }
    } catch (error) {
      if (current !== generation) return;
      $("evidence-message").textContent = error.status === 401
        ? "Sign in using the Evidence identity form in Response actions, then reopen this case." : error.message;
      if (error.status === 401) showIdentity(null);
    }
  }
  window.PanopticonEvidence = {openCase};
  session().catch(() => showIdentity(null));
});
