/* Collection-only triage through an individual browser identity. Manager is authoritative. */
"use strict";
document.addEventListener("DOMContentLoaded", () => {
  const $ = id => document.getElementById(id);
  if (!$("triage-panel")) return;
  const node = (tag, text) => { const value = document.createElement(tag); if (text !== undefined) value.textContent = String(text); return value; };
  const actions = ["COLLECT_PROCESS_INFO", "COLLECT_NETWORK_CONNECTIONS", "COLLECT_FILE"];
  const names = ["Process context", "Network connections", "File metadata and hash"];
  const defaults = {reserved_bytes_per_action: 1048576, max_actions_per_alert: 3, max_bytes_per_alert: 3145728,
    endpoint_window_seconds: 900, max_actions_per_endpoint_window: 12, max_bytes_per_endpoint_window: 12582912,
    max_active_per_endpoint: 3, workflow_ttl_seconds: 300};
  let identity = null, generation = 0, offset = 0;
  const message = text => { $("triage-message").textContent = text; };
  function clear() { generation++; identity = null; offset = 0; $("triage-admin").replaceChildren();
    $("triage-admin").hidden = true; $("triage-runs").replaceChildren(); $("triage-more").hidden = true; }
  async function request(path, body) {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch(path, {credentials: "same-origin", cache: "no-store", signal: controller.signal,
        headers: {"Content-Type": "application/json", "X-Panopticon-Evidence-Identity": identity?.identity_version || ""},
        ...(body ? {method: "POST", body: JSON.stringify(body)} : {})});
      const value = await response.json();
      if (!response.ok) throw Error(value.detail || value.error || "Triage request refused");
      return value;
    } finally { clearTimeout(timer); }
  }
  function field(form, label, input) { const wrapper = node("label", label); wrapper.append(input); form.append(wrapper); return input; }
  function select(values, current) { const el = node("select"); for (const [value, label] of values) {
    const option = node("option", label); option.value = value; el.append(option); } el.value = current; return el; }
  function input(type, value) { const el = node("input"); el.type = type; el.value = value; return el; }
  function button(label, handler) { const el = node("button", label); el.type = "button";
    el.addEventListener("click", async () => { el.disabled = true; try { await handler(); }
      catch (error) { message(error.message); } finally { el.disabled = false; } }); return el; }

  function editor(data) {
    const root = $("triage-admin"); root.hidden = false; root.replaceChildren();
    root.append(node("h3", "Rule collection policy"), node("p", "Changes create a new policy revision. Queued work under an older revision cannot execute. File collection remains metadata/hash only."));
    const form = node("form"); form.className = "response-form";
    const rule = field(form, "Detection rule ID", input("text", "")); rule.required = true; rule.maxLength = 128;
    const choices = node("datalist"); choices.id = "triage-rules"; rule.setAttribute("list", choices.id);
    for (const policy of data.policies) { const option = node("option"); option.value = policy.rule_id; choices.append(option); }
    form.append(choices);
    const enabled = field(form, "Enable automatic triage for this rule", input("checkbox", ""));
    const decisions = actions.map((action, i) => field(form, names[i] + " · standard endpoints", select([
      ["skip", "Skip"], ["require_approval", "Require analyst approval"], ["auto_dispatch", "Collect automatically"],
    ], action === "COLLECT_FILE" ? "require_approval" : "auto_dispatch")));
    const filePaths = Object.fromEntries(["windows", "linux"].map(platform => {
      const paths = field(form, "Exact " + platform + " file paths · one per line, at most 16 combined", node("textarea"));
      paths.maxLength = 66000; return [platform, paths];
    }));
    form.append(node("p", "Critical and unclassified endpoints always require approval. Automatic file collection requires an exact allowlist; wildcards are refused."));
    const bounds = [
      ["max_actions_per_alert", "Collections per alert", 1, 3],
      ["max_bytes_per_alert", "Reserved bytes per alert", 1048576, 3145728],
      ["endpoint_window_seconds", "Endpoint budget window (seconds)", 60, 86400],
      ["max_actions_per_endpoint_window", "Collections per endpoint window", 1, 64],
      ["max_bytes_per_endpoint_window", "Reserved bytes per endpoint window", 1048576, 67108864],
      ["max_active_per_endpoint", "Active collections per endpoint", 1, 8],
      ["workflow_ttl_seconds", "Workflow deadline (seconds)", 30, 900],
    ];
    const budgets = Object.fromEntries(bounds.map(([key, label, min, max]) => {
      const el = field(form, label, input("number", defaults[key])); el.min = min; el.max = max; el.step = 1; el.required = true; return [key, el];
    }));
    let selected = null, expected = 0;
    const load = () => {
      selected = data.policies.find(p => p.rule_id === rule.value) || null;
      expected = data.configured_rules.includes(rule.value) ? selected.version : 0;
      enabled.checked = selected?.enabled || false;
      for (let i = 0; i < actions.length; i++) decisions[i].value = selected?.entries.find(e => e.action === actions[i] && e.asset_class === "standard")?.decision || (i === 2 ? "require_approval" : "auto_dispatch");
      const file = selected?.entries.find(e => e.action === "COLLECT_FILE" && e.asset_class === "standard");
      for (const [platform, paths] of Object.entries(filePaths)) paths.value = (file?.file_paths || []).filter(p => p.platform === platform).map(p => p.path).join("\n");
      for (const [key, el] of Object.entries(budgets)) el.value = selected?.budget[key] ?? defaults[key];
    };
    rule.addEventListener("change", load);
    if (data.policies.length) { rule.value = data.policies[0].rule_id; load(); }
    const save = node("button", "Save policy revision"); save.type = "submit"; form.append(save);
    form.addEventListener("submit", async event => {
      event.preventDefault(); save.disabled = true; const current = generation;
      try {
        const entries = [];
        for (const asset of ["standard", "critical", "unknown"]) for (let i = 0; i < actions.length; i++) {
          const previous = selected?.entries.find(e => e.action === actions[i] && e.asset_class === asset);
          const decision = asset === "standard" ? decisions[i].value : previous?.decision === "skip" ? "skip" : "require_approval";
          let file_paths = [];
          if (asset === "standard" && i === 2 && decision === "auto_dispatch") {
            file_paths = Object.entries(filePaths).flatMap(([platform, paths]) => paths.value.split(/\r?\n/).filter(Boolean).map(path => ({platform, path})));
            if (!file_paths.length || file_paths.length > 16) throw Error("Supply 1–16 exact approved file paths.");
          }
          entries.push({action: actions[i], asset_class: asset, decision, file_paths});
        }
        const policy = {schema_version: "1", rule_id: rule.value, version: expected + 1, enabled: enabled.checked,
          entries, budget: {reserved_bytes_per_action: 1048576, ...Object.fromEntries(Object.entries(budgets).map(([key, el]) => [key, Number(el.value)]))}};
        await request("/api/evidence/triage/policies", {request_id: crypto.randomUUID(), expected_version: expected, policy});
        if (current === generation) { await refresh(); message("Policy revision saved. Future detections use the new revision."); }
      } catch (error) { if (current === generation) message(error.message); } finally { save.disabled = false; }
    });
    root.append(form, node("h3", "Authoritative asset classification"));
    for (const asset of data.assets) {
      const row = node("div"); row.className = "response-form"; row.append(node("strong", asset.host_id));
      const classification = select([["unknown", "Unclassified · approval required"], ["critical", "Critical · approval required"], ["standard", "Standard · policy may automate"]], asset.asset_class);
      classification.setAttribute("aria-label", "Classification for " + asset.host_id);
      const reason = input("text", ""); reason.placeholder = "Reason for classification"; reason.maxLength = 512;
      reason.setAttribute("aria-label", "Classification reason for " + asset.host_id);
      row.append(classification, reason, button("Save classification", async () => {
        if (!reason.value.trim()) throw Error("Explain this asset classification.");
        const current = generation;
        await request("/api/evidence/triage/assets", {request_id: crypto.randomUUID(), expected_version: asset.version,
          host_id: asset.host_id, asset_class: classification.value, reason: reason.value});
        if (current === generation) { await refresh(); message("Asset classification saved; older queued triage is blocked."); }
      })); root.append(row);
    }
  }

  async function loadRuns() {
    const current = generation, value = await request("/api/evidence/triage/runs?limit=50&offset=" + offset);
    if (current !== generation) return;
    for (const run of value.runs) {
      const card = node("section"); card.append(node("h3", run.alert_id), node("p", [run.rule_id,
        "policy revision " + run.policy_version, run.host_id, run.asset_class, "deadline " + run.deadline,
        run.cancelled_at ? "Cancelled: " + run.cancelled_at : ""].filter(Boolean).join(" · ")));
      const list = node("ul");
      for (const item of run.items) {
        const li = node("li", [item.action, item.command_state || item.lifecycle_state || item.decision,
          item.reason, item.live_blocker || "", "reserved " + item.reserved_bytes + " bytes"].filter(Boolean).join(" · "));
        if (item.response_id) li.append(button("Review case and evidence", () => window.PanopticonEvidence.openCase(item.response_id)));
        card.append(list); list.append(li);
      }
      if (!run.cancelled_at && identity.permissions.includes("response:decide")) {
        const reason = input("text", ""); reason.placeholder = "Reason for stopping queued work"; reason.maxLength = 512;
        reason.setAttribute("aria-label", "Cancellation reason for " + run.alert_id);
        card.append(reason, button("Stop remaining collections", async () => {
          if (!reason.value.trim()) throw Error("Explain why triage should stop.");
          const active = generation;
          const result = await request("/api/evidence/triage/runs/" + encodeURIComponent(run.alert_id) + "/cancel", {reason: reason.value});
          if (active === generation) { await refresh(); message(result.notice); }
        }));
      }
      $("triage-runs").append(card);
    }
    offset = value.next_offset; $("triage-more").hidden = offset === null;
    if (!value.runs.length && !$("triage-runs").children.length) $("triage-runs").append(node("p", "No automated triage runs yet. New detections appear after a rule policy is configured."));
  }
  async function refresh() {
    clear(); const current = generation;
    try {
      const session = await request("/api/evidence/session"); if (current !== generation) return; identity = session;
      if (identity.permissions.includes("triage:manage")) {
        const data = await request("/api/evidence/triage/policies"); if (current === generation) editor(data);
      }
      if (identity.permissions.some(p => ["response:request", "response:decide"].includes(p))) await loadRuns();
      if (current === generation) message("Triage loaded for " + identity.analyst_id + ". New detections follow configured policy; collected evidence still requires case and endpoint grants.");
    } catch (error) { if (current === generation) { clear(); message(error.message); } }
  }
  document.addEventListener("panopticon-identity-changed", event => {
    if (event.detail?.identity_version !== identity?.identity_version) { clear(); message("Identity changed. Refresh triage to load your permissions."); }
  });
  $("triage-refresh").addEventListener("click", refresh);
  $("triage-more").addEventListener("click", async () => { try { await loadRuns(); } catch (error) { clear(); message(error.message); } });
});
