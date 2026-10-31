"use strict";

// Single source of truth: semantic color tokens use hex values only.
// Components consume CSS variables; severity meanings stay consistent across palettes.
(() => {
  const STORAGE_KEY = "panopticon.theme.v1";
  const modes = {
    dark: {
      bg: "#0B1016", panel: "#111B25", sidebar: "#0E161F",
      control: "#192634", border: "#526477", text: "#E8EEF5",
      muted: "#A2B2C3", heading: "#182330", hover: "#1A2836",
      evidence: "#0B131C", overlay: "#02070CBF",
      critical: "#FF8298", "critical-bg": "#3B2431",
      high: "#FFB37A", "high-bg": "#382D23",
      medium: "#EAD374", "medium-bg": "#323120",
      low: "#8ECBFF", "low-bg": "#1F3349", ok: "#5BE0A6",
      unknown: "#B5C2CF", "unknown-bg": "#27333E"
    },
    light: {
      bg: "#F3F6FA", panel: "#FFFFFF", sidebar: "#EAF0F6",
      control: "#F6F8FB", border: "#78899B", text: "#182635",
      muted: "#4C6074", heading: "#EAF0F6", hover: "#EDF2F7",
      evidence: "#F3F6FA", overlay: "#18263580",
      critical: "#A51D3B", "critical-bg": "#FFE5EB",
      high: "#93420B", "high-bg": "#FFF0E2",
      medium: "#715500", "medium-bg": "#FFF5CC",
      low: "#165A96", "low-bg": "#E4F1FF", ok: "#0F7A4D",
      unknown: "#46586B", "unknown-bg": "#E8EEF4"
    }
  };
  const palettes = {
    emerald: { label: "Emerald", dark: ["#63E3BE", "#1C3533", "#284B40"], light: ["#09674F", "#DDF4EA", "#C2EBD9"] },
    ocean: { label: "Ocean", dark: ["#80C7FF", "#19334B", "#244967"], light: ["#155F9A", "#E0EFFF", "#C7E1F8"] },
    violet: { label: "Violet", dark: ["#C7ADFF", "#322846", "#493660"], light: ["#6940AC", "#EEE5FF", "#E0D1FA"] },
    amber: { label: "Amber", dark: ["#F5CC76", "#3A3020", "#51432A"], light: ["#805300", "#FFF0D2", "#F5DDAA"] }
  };
  const system = window.matchMedia("(prefers-color-scheme: dark)");
  const root = document.documentElement;
  const validate = (value) => ({
    mode: ["dark", "light", "system"].includes(value?.mode) ? value.mode : "system",
    palette: Object.hasOwn(palettes, value?.palette) ? value.palette : "emerald"
  });
  function read() {
    try { return validate(JSON.parse(localStorage.getItem(STORAGE_KEY))); }
    catch { return validate(null); }
  }
  let preference = read();
  function apply() {
    const resolved = preference.mode === "system" ? (system.matches ? "dark" : "light") : preference.mode;
    const [accent, active, flash] = palettes[preference.palette][resolved];
    for (const [key, value] of Object.entries({ ...modes[resolved], accent, active, flash })) {
      root.style.setProperty("--" + key, value);
    }
    root.style.colorScheme = resolved;
    root.dataset.theme = resolved;
    root.dataset.palette = preference.palette;
    const modeControl = document.getElementById("theme-mode");
    const paletteControl = document.getElementById("theme-palette");
    if (modeControl) modeControl.value = preference.mode;
    if (paletteControl) paletteControl.value = preference.palette;
    const status = document.getElementById("theme-status");
    if (status) status.textContent = `${palettes[preference.palette].label} · ${resolved}${preference.mode === "system" ? " (system)" : ""}`;
  }
  function setPreference(update) {
    preference = validate({ ...preference, ...update });
    try { localStorage.setItem(STORAGE_KEY, JSON.stringify(preference)); } catch { /* Session still works when storage is blocked. */ }
    apply();
  }
  apply(); // Head script applies saved colors before the page is rendered.
  system.addEventListener("change", () => { if (preference.mode === "system") apply(); });
  window.addEventListener("storage", (event) => {
    if (event.key === STORAGE_KEY || event.key === null) { preference = read(); apply(); }
  });
  document.addEventListener("DOMContentLoaded", () => {
    const paletteControl = document.getElementById("theme-palette");
    for (const [value, { label }] of Object.entries(palettes)) {
      const option = document.createElement("option"); option.value = value; option.textContent = label;
      paletteControl.append(option);
    }
    document.getElementById("theme-mode").addEventListener("change", (event) => setPreference({ mode: event.target.value }));
    paletteControl.addEventListener("change", (event) => setPreference({ palette: event.target.value }));
    apply();
  });
})();


// DASHBOARD INITIALIZATION
document.addEventListener("DOMContentLoaded", () => {
"use strict";
// Evidence is untrusted: all alert values use textContent, never HTML.
const POLL_INTERVAL_MS = 3000, PAGE_SIZE = 25, MANAGER_ALERT_LIMIT = 200;
const $ = (id) => document.getElementById(id);
const FAMILIES = ["process", "network", "file", "registry", "image_load"];
const SOURCES = ["rule", "stateful", "behavioral", "correlation", "ml"];
const RESPONSE_FIELDS = ["action", "host_id", "target_pid", "target_guid", "target_start_time_ticks", "target_file", "reason"];
let alerts = [], page = 1, lastPayload = null, busy = false, hasLoaded = false, alertSource = null;
let seenIds = new Set();
const registry = globalThis.PanopticonConsole || (globalThis.PanopticonConsole = {});
function text(v) { return v == null ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v); }
function node(tag, value, cls) { const el = document.createElement(tag); if (value !== undefined) el.textContent = text(value); if (cls) el.className = cls; return el; }
function dedupe(items) { const ids = new Set(); return items.filter((a) => { if (!a || typeof a !== "object" || Array.isArray(a)) return false; if (a.alert_id == null || a.alert_id === "") return true; const id = String(a.alert_id); if (ids.has(id)) return false; ids.add(id); return true; }); }
function severityOf(a) { const s = String(a.severity || "").toLowerCase(); return ["critical", "high", "medium", "low"].includes(s) ? s : "unknown"; }
function sourceOf(a) { const s = String(a.detection_source || "").toLowerCase(); return SOURCES.includes(s) ? s : "unknown"; }
function evidenceOf(a) { return a.evidence && typeof a.evidence === "object" ? a.evidence : {}; }
// Search actual values, not JSON syntax (which doubles Windows backslashes).
// Each word may match a different field, e.g. "high powershell".
function searchableText(value) {
  if (value == null) return "";
  if (Array.isArray(value)) return value.map(searchableText).join(" ");
  if (typeof value === "object") return Object.values(value).map(searchableText).join(" ");
  return String(value).toLowerCase();
}
function matchesSearch(alert, query) {
  const haystack = searchableText(alert) + " " + familyOf(alert).replace("_", " ") + " " + timeOf(alert.timestamp).toLowerCase();
  return query.split(/\s+/).filter(Boolean).every((term) => {
    // Severity words describe the alert, even if another severity appears in evidence.
    if (["critical", "high", "medium", "low", "unknown"].includes(term)) {
      return severityOf(alert) === term;
    }
    return haystack.includes(term);
  });
}
function familyOf(a) { const tags = Array.isArray(a.tags) ? a.tags.map((t) => String(t).toLowerCase()) : []; for (const f of FAMILIES) if (tags.includes(f)) return f; const keys = Object.keys(evidenceOf(a)); if (keys.some((k) => k.startsWith("image."))) return "image_load"; for (const f of ["registry", "network", "file"]) if (keys.some((k) => k.startsWith(f + "."))) return f; return "process"; }
function timeOf(v) { const d = new Date(v); return v && Number.isFinite(d.getTime()) ? d.toLocaleString() : text(v); }
function badge(a) { return node("span", severityOf(a) + (Number.isFinite(a.level) ? ` · L${a.level}` : ""), "sev sev-" + severityOf(a)); }
function sourceBadge(a) { const s = sourceOf(a); return node("span", s === "ml" ? "ML" : s, "src src-" + s); }
// The engine's optional ML stage: a score from a supervised model, shown as a
// triage aid. An alert without an `ml` block was not scored -- never "benign".
function mlOf(a) { return a.ml && typeof a.ml === "object" && !Array.isArray(a.ml) ? a.ml : null; }
function mlScore(ml) { return Number.isFinite(ml.raw_score) ? ml.raw_score.toFixed(2) : text(ml.raw_score); }
function mlChip(a) { const ml = mlOf(a); if (!ml || sourceOf(a) === "ml") return null; return node("span", "ML " + mlScore(ml) + (ml.band ? " · " + ml.band : " · below threshold"), "ml-chip" + (ml.band ? " ml-" + ml.band : "")); }
function pair(parent, key, value) { const group = node("div"); group.append(node("dt", key), node("dd", text(value))); parent.append(group); }
function incidentButton(id) { const link = node("button", "Incident " + text(id), "incident-link"); link.type = "button"; link.addEventListener("click", () => { if (typeof registry.openIncident === "function") registry.openIncident(String(id)); }); return link; }
function showDetail(a) {
  const ev = evidenceOf(a);
  $("detail-title").textContent = text(a.title || a.rule_id || "Untitled alert"); const sev = badge(a); $("detail-severity").textContent = sev.textContent; $("detail-severity").className = sev.className;
  const src = sourceBadge(a); $("detail-source").textContent = src.textContent; $("detail-source").className = src.className;
  $("detail-meta").replaceChildren();
  for (const [key, value] of [["Rule", a.rule_id], ["Detected at", timeOf(a.timestamp)], ["Telemetry", familyOf(a).replace("_", " ")], ["MITRE technique", a.mitre_technique], ["MITRE tactic", a.mitre_tactic], ["Process", ev["process.name"]], ["Host", a.host_id], ["Agent", a.agent_id], [sourceOf(a) === "ml" ? "model marker (fixed, not a probability)" : "rule confidence (prior, not calibrated)", Number.isFinite(a.confidence) ? a.confidence.toFixed(2) : a.confidence]]) pair($("detail-meta"), key, value);
  $("detail-incident").replaceChildren(); if (a.incident_id) $("detail-incident").append(incidentButton(a.incident_id));
  const ml = mlOf(a); $("detail-ml").replaceChildren(); $("detail-ml-title").hidden = $("detail-ml").hidden = !ml;
  if (ml) {
    const thresholds = ml.thresholds && typeof ml.thresholds === "object" ? ml.thresholds : {};
    for (const [key, value] of [["Score (raw margin)", mlScore(ml)], ["Band", ml.band || "below threshold"], ["Thresholds", `alert ${text(thresholds.alert)} · high ${text(thresholds.high)}`], ["Mode", ml.mode], ["Model", ml.model_version], ["Artifact SHA-256", ml.artifact_sha256], ["Featurizer", ml.featurizer_version]]) pair($("detail-ml"), key, value);
    $("detail-ml").append(node("p", "A triage aid from a supervised model with known limitations, not a verdict. It never changes a rule's level and never recommends a response.", "note"));
  }
  if (a.description) $("detail-description").textContent = text(a.description); else $("detail-description").textContent = "";
  const conditions = Array.isArray(ev.matched_conditions) ? ev.matched_conditions : ev.matched_conditions == null ? [] : [ev.matched_conditions];
  $("detail-conditions").replaceChildren(); if (!conditions.length) $("detail-conditions").append(node("li", "No matched conditions were supplied.")); for (const c of conditions) $("detail-conditions").append(node("li", text(c), "mono"));
  $("evidence").replaceChildren(); const entries = Object.entries(ev).filter(([key]) => key !== "matched_conditions"); if (!entries.length) $("evidence").append(node("p", "No evidence fields were supplied.")); for (const [key, value] of entries) pair($("evidence"), key, value);
  $("detail-response").replaceChildren(); const rec = a.active_response && typeof a.active_response === "object" ? a.active_response : null;
  if (!rec) $("detail-response").append(node("p", "No response recommended by this detection."));
  else { for (const key of RESPONSE_FIELDS) if (rec[key] != null) pair($("detail-response"), key, rec[key]); $("detail-response").append(node("p", "Recommendation only: the detection engine does not execute it. Its approval and command state are listed under Response actions.", "note")); }
  $("detail-id").textContent = text(a.alert_id); if (!$("detail").open) $("detail").showModal();
}
registry.openAlert = showDetail;
function rowFor(a, isNew) {
  const row = node("tr", undefined, isNew ? "new-row" : ""), sev = node("td"), detection = node("td"), source = node("td"); sev.append(badge(a)); const open = node("button", a.title || a.rule_id || "Untitled alert", "alert-link"); open.type = "button"; open.addEventListener("click", () => showDetail(a)); detection.append(open, node("span", text(a.rule_id), "subline")); const chip = mlChip(a); if (chip) detection.append(chip); if (a.incident_id) detection.append(incidentButton(a.incident_id)); source.append(sourceBadge(a)); row.append(sev, detection, source, node("td", text(a.host_id), "mono"), node("td", text(evidenceOf(a)["process.name"]), "mono"), node("td", familyOf(a).replace("_", " "), "family"), node("td", text(a.mitre_technique), "mono"), node("td", timeOf(a.timestamp), "when")); return row;
}
function render(flash = false) {
  $("count-total").textContent = alerts.length.toLocaleString(); for (const s of ["critical", "high", "medium", "low"]) $("count-" + s).textContent = alerts.filter((a) => severityOf(a) === s).length.toLocaleString();
  const query = $("search").value.trim().toLowerCase(), severity = $("severity").value.toLowerCase(), family = $("family").value, source = $("source").value;
  const filtered = alerts.filter((a) => (!severity || severityOf(a) === severity) && (!family || familyOf(a) === family) && (!source || sourceOf(a) === source) && matchesSearch(a, query));
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE)); page = Math.max(1, Math.min(page, pages)); const start = (page - 1) * PAGE_SIZE, fragment = document.createDocumentFragment();
  for (const a of filtered.slice(start, start + PAGE_SIZE)) fragment.append(rowFor(a, flash && a.alert_id != null && !seenIds.has(String(a.alert_id)))); $("alerts-body").replaceChildren(fragment); $("alerts-table").hidden = !filtered.length; $("empty").hidden = !!filtered.length;
  $("empty-title").textContent = alerts.length ? "No matching alerts" : "No alerts received yet"; $("empty-description").textContent = alerts.length ? "Try a different search or clear your filters." : "Alerts appear when the running detection engine finds a match. Collector health is not available here.";
  $("result-count").textContent = filtered.length ? `${start + 1}–${Math.min(start + PAGE_SIZE, filtered.length)} of ${filtered.length.toLocaleString()} matching alerts · ${alerts.length.toLocaleString()} total` : `0 matching alerts · ${alerts.length.toLocaleString()} total`;
  $("page-label").textContent = `Page ${page} of ${pages}`; $("previous").disabled = page <= 1; $("next").disabled = page >= pages;
}
function showSource(response) {
  const header = response && response.headers && typeof response.headers.get === "function" ? response.headers.get("X-Panopticon-Alert-Source") : null;
  alertSource = header === "manager" || header === "file" ? header : null;
  $("data-source").textContent = alertSource === "manager" ? "Alert source: Manager API (proxied by this console)" : alertSource === "file" ? "Alert source: engine alert file (--alerts-file)" : "Alert source: not reported";
}
async function poll() {
  if (busy) return; busy = true; $("refresh").disabled = true; const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 8000);
  try { const url = alertSource === "manager" ? "/api/alerts?limit=" + MANAGER_ALERT_LIMIT : "/api/alerts"; const response = await fetch(url, {cache: "no-store", signal: controller.signal}); showSource(response); if (!response.ok) throw new Error(`HTTP ${response.status}`); const raw = await response.json(); if (!Array.isArray(raw)) throw new Error("Invalid alert feed"); const payload = JSON.stringify(raw);
    if (payload !== lastPayload) { alerts = dedupe(raw).reverse().sort((a, b) => (Date.parse(b.timestamp) || 0) - (Date.parse(a.timestamp) || 0)); render(hasLoaded); seenIds = new Set(alerts.filter((a) => a.alert_id != null).map((a) => String(a.alert_id))); lastPayload = payload; }
    hasLoaded = true; $("status").textContent = "● Alert feed connected"; $("status").className = ""; $("last-updated").textContent = "Updated " + new Date().toLocaleTimeString();
  } catch (error) { $("status").textContent = "● Alert feed unavailable"; $("status").className = "error"; if (!hasLoaded) { $("empty-title").textContent = "Cannot reach the alert feed"; $("empty-description").textContent = "Check that the console server is running. Retrying automatically."; } else $("last-updated").textContent = "Showing last received alerts · retrying";
  } finally { clearTimeout(timeout); busy = false; $("refresh").disabled = false; }
}
for (const id of ["search", "severity", "family", "source"]) $(id).addEventListener(id === "search" ? "input" : "change", () => { page = 1; if (hasLoaded) render(); });
$("clear").addEventListener("click", () => { for (const id of ["search", "severity", "family", "source"]) $(id).value = ""; page = 1; if (hasLoaded) render(); });
$("previous").addEventListener("click", () => { page--; render(); }); $("next").addEventListener("click", () => { page++; render(); }); $("refresh").addEventListener("click", poll); $("close-detail").addEventListener("click", () => $("detail").close());
document.querySelectorAll("nav a").forEach((link) => link.addEventListener("click", () => { document.querySelectorAll("nav a").forEach((item) => item.classList.remove("active")); link.classList.add("active"); }));
poll(); setInterval(poll, POLL_INTERVAL_MS);

});


// RESPONSE ACTIONS PANEL
// Shared, pure render helpers for the response panel and the incidents view.
// Every string they produce is derived from Manager's fields; nothing here
// claims an action took effect unless the agent reported SUCCEEDED.
const PanopticonRender = (() => {
  "use strict";
  function text(v) { return v == null ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v); }
  function node(tag, value, cls) { const el = document.createElement(tag); if (value !== undefined) el.textContent = text(value); if (cls) el.className = cls; return el; }
  function timeOf(v) { const d = new Date(v); return v && Number.isFinite(d.getTime()) ? d.toLocaleString() : text(v); }
  function commandOf(action) { return action && action.command && typeof action.command === "object" ? action.command : {}; }
  function commandIdOf(action) { return action.command_id ?? commandOf(action).command_id ?? null; }
  function commandStateOf(action) { const c = commandOf(action); return action.command_state ?? action.command_lifecycle_state ?? c.lifecycle_state ?? c.state ?? null; }
  function targetSummary(target) {
    if (!target || typeof target !== "object") return "";
    const parts = [];
    if (target.host_id != null) parts.push("host " + target.host_id);
    const pid = target.target_pid ?? target.pid; if (pid != null) parts.push("pid " + pid);
    const file = target.target_file ?? target.file ?? target.path; if (file != null) parts.push("file " + file);
    if (target.start_time_ticks != null) parts.push("creation ticks " + target.start_time_ticks);
    if (target.boot_id != null) parts.push("boot " + target.boot_id);
    return parts.join(" · ");
  }
  function commandSummary(action) {
    const id = commandIdOf(action), state = commandStateOf(action), verb = commandOf(action).action ?? action.command_action ?? action.action ?? "command";
    const target = targetSummary(action.target);
    if (!id) return "No command issued";
    if (!state) return `Command ${id} · state not reported`;
    switch (String(state).toUpperCase()) {
      case "SUCCEEDED": return `Agent reported SUCCEEDED for ${verb}${target ? " (" + target + ")" : ""} · command ${id}`;
      case "FAILED": return `Agent reported FAILED for ${verb} · command ${id}`;
      case "REJECTED": return `Agent rejected ${verb} · command ${id}`;
      case "EXPIRED": return `Command ${id} (${verb}) expired · no outcome`;
      case "CANCELLED": return `Command ${id} (${verb}) cancelled before dispatch`;
      case "INDETERMINATE": return `Agent reported an uncertain outcome for ${verb} · review execution evidence · command ${id}`;
      default: return `Command ${id} (${verb}) is ${state} · no outcome reported yet`;
    }
  }
  function auditLine(entry) {
    if (!entry || typeof entry !== "object") return text(entry);
    const when = entry.occurred_at ?? entry.created_at ?? entry.at ?? entry.timestamp;
    const event = entry.event ?? entry.action ?? entry.type;
    const actor = entry.actor ?? entry.analyst_id;
    const change = entry.from_status != null || entry.to_status != null ? `${text(entry.from_status)} → ${text(entry.to_status)}` : entry.status;
    const detail = entry.detail ?? entry.note ?? entry.reason;
    return [timeOf(when), text(event), actor == null ? null : "by " + actor, change == null ? null : String(change), detail == null || detail === "" ? null : text(detail)].filter((p) => p != null).join(" · ");
  }
  function auditList(entries, emptyText) {
    const list = node("ol", undefined, "audit");
    const items = Array.isArray(entries) ? entries : [];
    if (!items.length) { list.append(node("li", emptyText || "No audit events recorded.")); return list; }
    for (const entry of items) list.append(node("li", auditLine(entry)));
    return list;
  }
  return { text, node, timeOf, commandSummary, commandStateOf, targetSummary, auditLine, auditList };
})();

// All browser calls are same-origin Console routes. The analyst credential
// stays server-side; app.py attaches it when proxying decisions to Manager.
document.addEventListener("DOMContentLoaded", () => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const { text, node, commandSummary, commandStateOf, targetSummary, auditList } = PanopticonRender;
  let lastPayload = null;
  let offset = 0, nextOffset = null, catalog = [];
  let analyst = null, retryRequest = null;
  let maxCampaignActions = 0, campaignRetry = null, preflightEnabled = false;
  let queueFilters = {state: "", host: "", command: ""};
  const can = permission => !!analyst && Array.isArray(analyst.permissions) && analyst.permissions.includes(permission);
  async function fetchPreflight(action) {
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch("/api/response-actions/" + encodeURIComponent(action.response_id) + "/preflight", {cache: "no-store", signal: controller.signal});
      const payload = await response.json();
      if (!response.ok) throw new Error(text(payload.detail || payload.error || "Readiness review unavailable"));
      return payload;
    } finally {clearTimeout(timer);}
  }
  async function reviewReadiness(action, button, container) {
    button.disabled = true;
    try {
      const payload = await fetchPreflight(action), details = node("details"); details.open = true;
      details.append(node("summary", "Readiness review"));
      const readiness = payload.readiness || {};
      details.append(node("p", "Endpoint: " + text(payload.host_id) + " · last response contact: " + text(readiness.contact_state) + " · execution mode: " + text(readiness.execution_mode)));
      const runtime = readiness.runtime_profile;
      if (runtime) {
        details.append(node("p", "Runtime policy: " + text(runtime.state) + " · received " + text(runtime.observed_at)));
        if (runtime.report) {
          const policy = runtime.report;
          details.append(node("p", "Platform: " + text(policy.platform) + " · last reported mode: " + text(policy.mode)));
          details.append(node("p", "Permitted actions: " + ((policy.allowed_actions || []).join(", ") || "none")));
          details.append(node("p", "Implemented actions: " + ((policy.implemented_actions || []).join(", ") || "none")));
          details.append(node("p", "Boot binding required: " + (policy.require_boot_binding ? "yes" : "no") + " · command signatures required: " + (policy.require_signature ? "yes" : "no")));
          details.append(node("p", "Reported boot: " + text(policy.boot_id)));
        }
        if (runtime.state !== "recent") details.append(node("p", "Current endpoint policy is unknown. A stale or missing report does not establish action support."));
        else details.append(node("p", "This is the endpoint's recently reported policy. Each native action still verifies its target and local safety requirements."));
      }
      const report = readiness.sensor_report;
      if (report) {
        details.append(node("p", "Linux sensor report · captured " + text(report.captured_at) + " · received " + text(report.received_at) + " · freshness: " + text(report.freshness)));
        const providers = node("ul");
        for (const provider of report.response_providers || []) {
          providers.append(node("li", text(provider.name) + " · " + text(provider.state) + " · " + text(provider.reason) + " · reported policy capabilities: " + (provider.capabilities || []).join(", ")));
        }
        details.append(providers, node("p", "Reported capabilities describe the retained snapshot. Current enforcement mode and action support still require endpoint verification."));
      }
      details.append(node("p", "Target: " + (targetSummary(payload.target) || "host-wide action")));
      const checks = node("ul");
      for (const check of payload.checks || []) checks.append(node("li", check.state + " · " + check.detail));
      details.append(checks, node("p", "This is an advisory review. Manager rechecks authorization; the endpoint enforces native safety."));
      container.replaceChildren(details);
    } catch (error) {container.replaceChildren(node("p", "Review failed: " + error.message));}
    finally {button.disabled = !preflightEnabled;}
  }
  function decisionCell(action) {
    const cell = node("td");
    if (!can("response:decide")) return cell;
    if (commandStateOf(action) === "AUTHORIZED") {
      const cancel = node("button", "Cancel queued command"); cancel.type = "button";
      cancel.addEventListener("click", () => decide(action, "cancel", cancel));
      cell.append(cancel); return cell;
    }
    if (action.lifecycle_state !== "PENDING") return cell;
    const approve = node("button", "Approve");
    const reject = node("button", "Reject");
    approve.type = reject.type = "button";
    const selfApproval = analyst.separate_approver_required && action.requested_by === "analyst:" + analyst.analyst_id;
    approve.disabled = selfApproval;
    if (selfApproval) approve.title = "A different analyst must approve this request.";
    approve.addEventListener("click", () => decide(action, "authorize", approve));
    reject.addEventListener("click", () => decide(action, "reject", reject));
    cell.append(approve, reject);
    return cell;
  }
  function auditCell(action) {
    const cell = node("td");
    const entries = Array.isArray(action.audit) ? action.audit : [];
    if (!entries.length) cell.append(node("span", "No audit events", "subline"));
    else {
      const details = node("details"), summary = node("summary", `${entries.length} audit event${entries.length === 1 ? "" : "s"}`);
      details.append(summary, auditList(entries)); cell.append(details);
    }
    if (Array.isArray(action.decision_audit) && action.decision_audit.length) {
      const details = node("details");
      details.append(node("summary", action.decision_audit.length + " decision events"), auditList(action.decision_audit));
      cell.append(details);
    }
    if (action.evidence_truncated) cell.append(node("p", "History preview is limited. Export the complete case."));
    const download = node("a", "Export case JSON", "subline");
    download.href = "/api/response-actions/" + encodeURIComponent(action.response_id) + "/export";
    download.download = "response-evidence.json"; cell.append(download);
    const artifacts = node("button", "Investigation evidence"); artifacts.type = "button";
    artifacts.addEventListener("click", () => window.PanopticonEvidence?.openCase(action.response_id));
    cell.append(artifacts);
    const review = node("button", "Review readiness"), preview = node("div");
    review.type = "button"; review.disabled = !preflightEnabled;
    review.addEventListener("click", () => reviewReadiness(action, review, preview));
    cell.append(review, preview);
    return cell;
  }
  function rowFor(action) {
    const row = node("tr"), actionCell = node("td");
    actionCell.append(node("span", action.action));
    if (action.host_id || action.agent_id) actionCell.append(node("span", [action.host_id, action.agent_id].filter(Boolean).join(" · "), "subline"));
    const target = targetSummary(action.target); if (target) actionCell.append(node("span", target, "subline"));
    if (action.requested_by) actionCell.append(node("span", "Requested by " + action.requested_by + " · " + action.request_reason, "subline"));
    const commandCell = node("td", commandSummary(action), "command-state");
    if (action.dispatch_blocker) commandCell.append(node("p", "Further delivery held by endpoint policy: " + text(action.dispatch_blocker)));
    if ((action.results || []).length || (action.receipts || []).length || (action.endpoint_evidence || []).length) {
      const details = node("details"); details.append(node("summary", "Execution evidence"));
      for (const result of action.results || []) details.append(node("p", result.outcome + " · " + text(result.detail) + " · received " + text(result.received_at)));
      for (const receipt of action.receipts || []) {
        const payload = receipt.payload || {};
        details.append(node("p", "Retained receipt " + text(payload.result_id) + " · " + text(payload.outcome) + " · " + text(payload.detail)));
        if (payload.execution) {
          const e = payload.execution;
          details.append(node("p", `Stage: ${e.stage} · action initiated: ${e.action_initiated} · completion observed: ${e.completion_observed} · native error: ${text(e.native_error)}`));
        }
      }
      for (const item of action.endpoint_evidence || []) {
        const report = item.reported || {}, section = node("details");
        section.append(node("summary", (report.dry_run ? "DRY RUN · " : "Endpoint report · ") + text(report.action) + " · " + text(report.outcome)));
        section.append(node("p", "Command linkage: " + text(item.linkage) + ((item.mismatches || []).length ? " · disagreements: " + item.mismatches.join(", ") : "")));
        section.append(node("p", "Captured " + text(item.captured_at) + " · received " + text(item.received_at) + " · record " + text(item.record_id)));
        if (report.dry_run) section.append(node("p", "Dry run: this report does not establish that a containment action occurred."));
        section.append(node("p", "Sensor fields · executed: " + text(report.executed) + " · native method: " + text(report.mode) + " · affected: " + text(report.affected)));
        section.append(node("p", "Reported target: " + (targetSummary(report.target || {}) || text(report.path) || "host-wide action")));
        section.append(node("p", "Reason: " + text(report.reason) + " · " + text(report.detail)));
        section.append(node("p", "Retained record SHA-256: " + text(item.sha256)));
        details.append(section);
      }
      details.append(node("p", "Endpoint telemetry is retained separately from command receipts. A report with mismatched identity is evidence to investigate; it does not establish command completion."));
      details.append(node("p", "Retained receipts may arrive after expiry or a terminal outcome. They do not change the command state."));
      commandCell.append(details);
    }
    const state = commandStateOf(action); if (state) commandCell.className += " cmd-" + String(state).toLowerCase();
    row.append(node("td", action.lifecycle_state), actionCell, node("td", action.tier), node("td", action.alert_id), node("td", action.created_at), node("td", action.decided_reason), commandCell, auditCell(action), decisionCell(action));
    return row;
  }
  async function decide(action, operation, button) {
    if (!can("response:decide")) return;
    if (button) button.disabled = true;
    if (operation === "authorize") {
      if (preflightEnabled) {
        try {
          const preview = await fetchPreflight(action);
          if (!preview.allowed_to_authorize) throw new Error((preview.checks || []).filter(c => c.state === "block").map(c => c.detail).join(" ") || "Authorization is blocked.");
        } catch (error) {
          $("response-status").textContent = "Approval blocked: " + error.message;
          if (button) button.disabled = false; return;
        }
      }
      const destructive = ["KILL_PROCESS", "ISOLATE_HOST", "QUARANTINE_FILE", "RELEASE_HOST_ISOLATION"].includes(action.action);
      if (destructive) {
        const expected = "APPROVE " + action.action + " " + action.alert_id;
        const typed = typeof globalThis.prompt === "function" ? globalThis.prompt("Type exactly: " + expected) : null;
        if (typed !== expected) { if (button) button.disabled = false; return; }
      } else if (typeof globalThis.confirm === "function" && !globalThis.confirm("Approve " + action.action + " for " + action.alert_id + "?")) {
        if (button) button.disabled = false; return;
      }
    }
    let body;
    if (operation === "reject" || operation === "cancel") {
      const reason = typeof globalThis.prompt === "function" ? globalThis.prompt("Reason for " + operation + ":", "Analyst reviewed") : null;
      if (!reason || !reason.trim()) { if (button) button.disabled = false; return; }
      body = JSON.stringify({reason: reason.trim()});
    }
    try {
      const response = await fetch("/api/response-actions/" + encodeURIComponent(action.response_id) + "/" + operation, {
        method: "POST", headers: {"Content-Type": "application/json"}, body, cache: "no-store"
      });
      const result = await response.json().catch(() => ({}));
      if (!response.ok || result.authorized === false) throw new Error(text(result.reason || result.detail || result.error || "Manager returned HTTP " + response.status));
      $("response-status").textContent = "Decision recorded · refreshing…";
      await pollResponseActions();
    } catch (error) {
      $("response-status").textContent = "Decision failed: " + error.message;
      if (button) button.disabled = false;
    }
  }
  async function pollResponseActions() {
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 8000);
    try {
      const filters = [];
      if (queueFilters.state) filters.push("state=" + encodeURIComponent(queueFilters.state));
      if (queueFilters.host) filters.push("host_id=" + encodeURIComponent(queueFilters.host));
      if (queueFilters.command) filters.push("command_state=" + encodeURIComponent(queueFilters.command));
      if (offset) filters.push("offset=" + offset);
      const response = await fetch("/api/response-actions" + (filters.length ? "?" + filters.join("&") : ""), { cache: "no-store", signal: controller.signal });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        lastPayload = null;
        $("response-table").hidden = true; $("response-empty").hidden = false;
        $("response-empty-title").textContent = response.status === 503 ? "Response actions unavailable" : "Cannot load response actions";
        $("response-empty-description").textContent = text(payload.error || payload.detail || "Manager did not return response actions.");
        $("response-status").textContent = "Not connected";
        return;
      }
      const actions = Array.isArray(payload.response_actions) ? payload.response_actions : [];
      nextOffset = payload.next_offset ?? null;
      $("response-next").disabled = nextOffset === null; $("response-prev").disabled = offset === 0;
      // Re-render only when the queue changed, so an expanded audit trail or a
      // button mid-decision is not wiped by the 3-second poll.
      const serialized = JSON.stringify([analyst, actions]);
      if (serialized !== lastPayload) {
        const fragment = document.createDocumentFragment();
        for (const action of actions) fragment.append(rowFor(action));
        $("response-body").replaceChildren(fragment);
        lastPayload = serialized;
      }
      $("response-table").hidden = !actions.length;
      $("response-empty").hidden = !!actions.length;
      $("response-empty-title").textContent = "No response actions yet";
      $("response-empty-description").textContent = "Response actions appear here when a detection recommends one.";
      $("response-status").textContent = "Connected · updated " + new Date().toLocaleTimeString();
    } catch {
      $("response-status").textContent = "Cannot reach the console server";
    } finally { clearTimeout(timeout); }
  }
  $("response-refresh").addEventListener("click", pollResponseActions);
  const respondFromAlert = $("detail-respond");
  if (respondFromAlert) respondFromAlert.addEventListener("click", () => {
    $("response-alert").value = $("detail-id").textContent;
    if (typeof $("detail").close === "function") $("detail").close();
    $("response-request").open = true;
    if (typeof $("response").scrollIntoView === "function") $("response").scrollIntoView({behavior: "smooth"});
    if (typeof $("response-action").focus === "function") $("response-action").focus();
  });
  $("response-apply").addEventListener("click", () => {
    queueFilters = {state: $("response-filter-state").value, host: $("response-filter-host").value.trim(), command: $("response-filter-command").value};
    offset = 0; return pollResponseActions();
  });
  $("response-next").addEventListener("click", () => {if (nextOffset !== null) {offset = nextOffset; return pollResponseActions();}});
  $("response-prev").addEventListener("click", () => {offset = Math.max(0, offset - 200); return pollResponseActions();});
  function updateActionHelp() {
    const item = catalog.find(a => a.action === $("response-action").value);
    $("response-file-label").hidden = !item || item.target_kind !== "file";
    $("response-file").required = !!item && item.target_kind === "file";
    $("response-action-help").textContent = item ? item.description + " All manual requests await explicit approval." + (item.target_kind === "process" ? " The target is derived from the alert's retained process identity." : "") : "Choose an available action.";
  }
  $("response-action").addEventListener("change", updateActionHelp);
  $("response-create-form").addEventListener("submit", async event => {
    event.preventDefault(); const button = $("response-create"); button.disabled = true;
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 15000);
    try {
      if (!can("response:request")) throw new Error("Your analyst role cannot request responses.");
      const item = catalog.find(a => a.action === $("response-action").value);
      if (!item) throw new Error("Select an action.");
      const request = {alert_id: $("response-alert").value.trim(), action: item.action, reason: $("response-reason").value.trim(), target: item.target_kind === "file" ? {path: $("response-file").value} : {}};
      if (!request.alert_id || !request.reason) throw new Error("Alert ID and reason are required.");
      const intent = JSON.stringify(request);
      if (!retryRequest || retryRequest.intent !== intent) retryRequest = {intent, id: globalThis.crypto?.randomUUID?.() || "ui-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2)};
      request.request_id = retryRequest.id;
      const response = await fetch("/api/response-actions", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify(request), signal: controller.signal});
      const result = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(text(result.detail || result.error || "Manager returned HTTP " + response.status));
      $("response-create-status").textContent = (result.replayed ? "Original request recovered · " : "Staged for approval · ") + result.response_id;
      retryRequest = null;
      offset = 0; await pollResponseActions();
    } catch (error) {$("response-create-status").textContent = "Request failed: " + error.message;}
    finally {clearTimeout(timer); button.disabled = !catalog.length || !can("response:request");}
  });
  function updateCampaignHelp() {
    const item = catalog.find(a => a.action === $("response-campaign-action").value);
    $("response-campaign-file-label").hidden = !item || item.target_kind !== "file";
    $("response-campaign-file").required = !!item && item.target_kind === "file";
  }
  function campaignReport(report) {
    const item = node("li");
    item.append(node("strong", `${report.campaign_id} · ${report.created_count} staged · ${report.failed_count} refused${report.replayed ? " · recovered report" : ""}`));
    const list = node("ol");
    for (const entry of report.items || []) list.append(node("li", entry.alert_id + " · " + entry.action + " · " + (entry.response_id ? "Staged request: " + entry.response_id + " (current state is in the queue)" : text(entry.error))));
    item.append(list); return item;
  }
  async function loadCampaigns() {
    if (!maxCampaignActions) return;
    try {
      const response = await fetch("/api/response-campaigns", {cache: "no-store"});
      const payload = await response.json();
      if (!response.ok) throw new Error(text(payload.detail || payload.error || "Campaign reports unavailable"));
      $("response-campaign-reports").replaceChildren(...(payload.campaigns || []).map(campaignReport));
    } catch (error) {$("response-campaign-status").textContent = error.message;}
  }
  $("response-campaign-action").addEventListener("change", updateCampaignHelp);
  $("response-campaign-new").addEventListener("click", () => {campaignRetry = null; $("response-campaign-status").textContent = "A new campaign will be staged on the next submission.";});
  $("response-campaign-form").addEventListener("submit", async event => {
    event.preventDefault(); const button = $("response-campaign-create"); button.disabled = true;
    const controller = new AbortController(), timer = setTimeout(() => controller.abort(), 15000);
    try {
      if (!can("response:request") || !maxCampaignActions) throw new Error("Your connection cannot stage campaigns.");
      const alerts = $("response-campaign-alerts").value.split(/\r?\n/).map(s => s.trim()).filter(Boolean);
      if (!alerts.length || alerts.length > maxCampaignActions) throw new Error("Enter 1 to " + maxCampaignActions + " alert IDs.");
      if (new Set(alerts).size !== alerts.length) throw new Error("Duplicate alert IDs are not allowed.");
      const item = catalog.find(a => a.action === $("response-campaign-action").value), reason = $("response-campaign-reason").value.trim();
      if (!item || !reason) throw new Error("An action and reason are required.");
      const items = alerts.map(alert_id => ({alert_id, action: item.action, reason, target: item.target_kind === "file" ? {path: $("response-campaign-file").value} : {}}));
      const intent = JSON.stringify(items);
      if (!campaignRetry || campaignRetry.intent !== intent) campaignRetry = {intent, id: globalThis.crypto?.randomUUID?.() || "campaign-" + Date.now().toString(36) + "-" + Math.random().toString(36).slice(2)};
      const response = await fetch("/api/response-campaigns", {method: "POST", headers: {"Content-Type": "application/json"}, body: JSON.stringify({campaign_id: campaignRetry.id, items}), signal: controller.signal});
      const report = await response.json();
      if (!response.ok) throw new Error(text(report.detail || report.error || "Campaign staging failed"));
      $("response-campaign-status").textContent = `${report.created_count} staged for individual approval · ${report.failed_count} refused${report.replayed ? " · original report recovered" : ""}`;
      $("response-campaign-reports").replaceChildren(campaignReport(report));
      offset = 0; await pollResponseActions();
    } catch (error) {$("response-campaign-status").textContent = "Campaign failed: " + error.message;}
    finally {clearTimeout(timer); button.disabled = !maxCampaignActions || !can("response:request");}
  });
  async function loadCatalog() {
    try {
      const response = await fetch("/api/response-actions/catalog", {cache: "no-store"});
      const payload = await response.json();
      if (!response.ok || !Array.isArray(payload.actions)) throw new Error("Action catalog unavailable; check Manager connection.");
      analyst = payload.analyst || null;
      maxCampaignActions = Number.isInteger(payload.max_campaign_actions) ? Math.min(25, payload.max_campaign_actions) : 0;
      preflightEnabled = payload.preflight_supported === true;
      const authority = payload.command_authority;
      $("response-authority").textContent = authority ? "Command signing: " + authority.state + (authority.key_id ? " · key " + authority.key_id : "") + ". Use readiness review for current endpoint details." : "Command signing readiness is not reported by this Manager.";
      $("response-campaign-create").disabled = !maxCampaignActions || !can("response:request");
      $("response-campaign-status").textContent = maxCampaignActions ? "Stage up to " + maxCampaignActions + " requests. Every action requires individual approval." : "Campaign staging requires the updated Manager.";
      for (const id of ["incident-set-investigating", "incident-set-resolved", "incident-set-false_positive"]) {
        const control = $(id); if (control) control.disabled = !can("incident:write");
      }
      if (respondFromAlert) respondFromAlert.disabled = !can("response:request");
      $("response-identity").textContent = analyst ? "Console identity: " + analyst.analyst_id + " · " + analyst.role + (analyst.separate_approver_required ? " · independent approval required" : "") : "Analyst permissions unavailable — update the Manager connection.";
      catalog = payload.actions; $("response-action").replaceChildren();
      for (const item of catalog) {const option = node("option", item.label); option.value = item.action; $("response-action").append(option);}
      $("response-campaign-action").replaceChildren();
      for (const item of catalog) {const option = node("option", item.label); option.value = item.action; $("response-campaign-action").append(option);}
      if (catalog.length) $("response-action").value = catalog.some(a => a.action === "COLLECT_NETWORK_CONNECTIONS") ? "COLLECT_NETWORK_CONNECTIONS" : catalog[0].action;
      $("response-campaign-action").value = $("response-action").value; updateCampaignHelp();
      $("response-create").disabled = !catalog.length || !can("response:request");
      if (!can("response:request")) $("response-create-status").textContent = "Your role permits viewing or reviewing responses; request creation is unavailable.";
      updateActionHelp(); lastPayload = null; await pollResponseActions(); await loadCampaigns();
    } catch (error) {
      analyst = null;
      $("response-create").disabled = true;
      $("response-campaign-create").disabled = true;
      $("response-create-status").textContent = error.message;
      $("response-identity").textContent = "Analyst permissions unavailable";
    }
  }
  loadCatalog();
  pollResponseActions();
  setInterval(pollResponseActions, 3000);
});


// INCIDENTS VIEW
// Lists Manager's incidents and renders one incident's evidence: the stage
// timeline, process lineage, causal path, score breakdown and reasons, member
// alerts, related response actions and the incident audit trail. Status
// changes are relayed through this console's same-origin route.
document.addEventListener("DOMContentLoaded", () => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const { text, node, timeOf, commandSummary, auditList } = PanopticonRender;
  const STATUSES = { investigating: "Investigating", resolved: "Resolved", false_positive: "False positive" };
  const SOURCES = ["rule", "stateful", "behavioral", "correlation", "ml"];
  const registry = globalThis.PanopticonConsole || (globalThis.PanopticonConsole = {});
  let lastList = null, currentId = null, lastDetail = null, currentDetail = null, posting = false;

  function sevOf(s) { const v = String(s || "").toLowerCase(); return ["critical", "high", "medium", "low"].includes(v) ? v : "unknown"; }
  function sevBadge(severity, level) { return node("span", sevOf(severity) + (Number.isFinite(level) ? ` · L${level}` : ""), "sev sev-" + sevOf(severity)); }
  function srcBadge(source) { const s = SOURCES.includes(String(source || "").toLowerCase()) ? String(source).toLowerCase() : "unknown"; return node("span", s === "ml" ? "ML" : s, "src src-" + s); }
  function statusBadge(status) { return node("span", status == null ? "—" : String(status).replace("_", " "), "status-badge status-" + String(status || "unknown").replace(/[^a-z_]/g, "")); }
  function num(v, digits) { return Number.isFinite(v) ? v.toFixed(digits) : text(v); }
  function list(v) { return Array.isArray(v) ? v.map(text).join(", ") : text(v); }
  function pair(parent, key, value) { const group = node("div"); group.append(node("dt", key), node("dd", text(value))); parent.append(group); }
  function normalizeAlert(row) {
    if (!row || typeof row !== "object") return null;
    const stored = row.alert && typeof row.alert === "object" ? row.alert : null;
    if (!stored) return row;
    const merged = Object.assign({}, stored);
    for (const key of ["alert_id", "rule_id", "level", "severity", "host_id", "event_id", "mitre_tactic", "mitre_technique"]) if (merged[key] == null && row[key] != null) merged[key] = row[key];
    for (const key of ["detection_source", "incident_id", "agent_id"]) if (row[key] != null) merged[key] = row[key];
    if (merged.timestamp == null) merged.timestamp = row.alert_timestamp;
    return merged;
  }

  function incidentRow(inc) {
    const row = node("tr"), sev = node("td"), id = node("td"), status = node("td");
    sev.append(sevBadge(inc.severity, inc.level));
    const open = node("button", inc.incident_id, "alert-link mono"); open.type = "button";
    open.addEventListener("click", () => openIncident(String(inc.incident_id)));
    id.append(open, node("span", "host " + text(inc.host_id) + " · revision " + text(inc.revision), "subline"));
    status.append(statusBadge(inc.status));
    row.append(sev, id, node("td", num(inc.score, 2), "mono"), node("td", list(inc.tactics)), node("td", text(inc.stage_count)), node("td", text(inc.root_process), "mono"), status, node("td", timeOf(inc.last_seen), "when"));
    return row;
  }

  async function pollIncidents() {
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch("/api/incidents", { cache: "no-store", signal: controller.signal });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        lastList = null;
        $("incidents-table").hidden = true; $("incidents-empty").hidden = false;
        $("incidents-empty-title").textContent = response.status === 503 ? "Incidents unavailable" : "Cannot load incidents";
        $("incidents-empty-description").textContent = text(payload.error || payload.detail || "Manager did not return incidents.");
        $("incidents-status").textContent = "Not connected";
        return;
      }
      const incidents = Array.isArray(payload.incidents) ? payload.incidents : [];
      const serialized = JSON.stringify(incidents);
      if (serialized !== lastList) {
        const fragment = document.createDocumentFragment();
        for (const inc of incidents) if (inc && typeof inc === "object") fragment.append(incidentRow(inc));
        $("incidents-body").replaceChildren(fragment);
        lastList = serialized;
      }
      $("incidents-table").hidden = !incidents.length; $("incidents-empty").hidden = !!incidents.length;
      $("incidents-empty-title").textContent = "No incidents yet";
      $("incidents-empty-description").textContent = "An incident opens when causally connected detections span at least two tactics.";
      $("incidents-status").textContent = `${incidents.length} incident${incidents.length === 1 ? "" : "s"} · updated ${new Date().toLocaleTimeString()}`;
      // Keep an open incident current, without touching the analyst's note.
      if (currentId && $("incident-detail").open && !posting) await loadDetail();
    } catch {
      $("incidents-status").textContent = "Cannot reach the console server";
    } finally { clearTimeout(timeout); }
  }

  function lineageTree(lineage) {
    const names = Array.isArray(lineage) ? lineage.map(text) : typeof lineage === "string" ? lineage.split(/\s*->\s*/).filter(Boolean) : [];
    if (!names.length || (names.length === 1 && /^unknown$/i.test(names[0]))) return node("p", "Process lineage not available.");
    const root = node("ul", undefined, "tree");
    let parent = root;
    names.forEach((name, i) => {
      const item = node("li"); item.append(node("span", name, i === names.length - 1 ? "mono tree-leaf" : "mono"));
      parent.append(item);
      if (i < names.length - 1) { const child = node("ul", undefined, "tree"); item.append(child); parent = child; }
    });
    return root;
  }

  function scoreList(breakdown) {
    const ul = node("ul", undefined, "score");
    if (!breakdown || typeof breakdown !== "object") { ul.append(node("li", "No score breakdown supplied.")); return ul; }
    for (const [key, value] of Object.entries(breakdown)) {
      if (key === "total") continue;
      const label = key.replace(/_/g, " ");
      if (value && typeof value === "object" && !Array.isArray(value)) {
        const details = Object.entries(value).filter(([k]) => k !== "weight" && k !== "factors").map(([k, v]) => `${k.replace(/_/g, " ")} ${text(v)}`);
        const item = node("li", `${label}: +${num(value.weight, 3)}${details.length ? " (" + details.join(", ") + ")" : ""}`);
        if (value.factors && typeof value.factors === "object") {
          const factors = Object.entries(value.factors), sub = node("ul");
          if (!factors.length) sub.append(node("li", "no context factors matched"));
          for (const [factor, weight] of factors) sub.append(node("li", `${factor.replace(/_/g, " ")}: +${num(weight, 3)}`));
          item.append(sub);
        }
        ul.append(item);
      } else ul.append(node("li", `${label}: ${text(value)}`));
    }
    if ("total" in breakdown) ul.append(node("li", "total: " + num(breakdown.total, 3), "score-total"));
    return ul;
  }

  function stageRow(stage, alertsById) {
    const row = node("tr"), rule = node("td"), linked = node("td");
    rule.append(node("span", stage.rule_id, "mono"), node("span", text(stage.rule_name), "subline"));
    if (stage.alert_id == null) linked.append(node("span", "— (repeat suppressed)", "subline"));
    else {
      const alert = alertsById.get(String(stage.alert_id));
      const btn = node("button", stage.alert_id, "alert-link mono"); btn.type = "button";
      btn.disabled = !alert;
      btn.addEventListener("click", () => { if (alert && typeof registry.openAlert === "function") registry.openAlert(alert); });
      linked.append(btn);
    }
    const proc = text(stage.process) + (stage.pid != null ? `[${stage.pid}]` : "");
    row.append(node("td", timeOf(stage.time), "when"), rule, node("td", `${text(stage.tactic)} / ${text(stage.technique)}`), node("td", proc, "mono"), linked);
    return row;
  }

  function memberAlertItem(alert) {
    const li = node("li"), btn = node("button", alert.title || alert.rule_id || alert.alert_id, "alert-link"); btn.type = "button";
    btn.addEventListener("click", () => { if (typeof registry.openAlert === "function") registry.openAlert(alert); });
    li.append(btn, node("span", " "), srcBadge(alert.detection_source), node("span", " "), node("span", sevOf(alert.severity), "sev sev-" + sevOf(alert.severity)), node("span", `${text(alert.alert_id)} · ${timeOf(alert.timestamp)}`, "subline"));
    return li;
  }

  function responseItem(action) {
    const li = node("li");
    li.append(node("strong", `${text(action.action)} · ${text(action.lifecycle_state)}`), node("span", commandSummary(action), "subline"));
    if (action.decided_reason) li.append(node("span", "Reason: " + text(action.decided_reason), "subline"));
    if (Array.isArray(action.audit) && action.audit.length) li.append(auditList(action.audit));
    return li;
  }

  function renderDetail(payload) {
    const inc = payload.incident && typeof payload.incident === "object" ? payload.incident : {};
    const ev = inc.evidence && typeof inc.evidence === "object" ? inc.evidence : {};
    currentDetail = inc;
    $("incident-title").textContent = "Incident " + text(inc.incident_id ?? currentId);
    const sev = sevBadge(inc.severity, inc.level); $("incident-severity").textContent = sev.textContent; $("incident-severity").className = sev.className;
    $("incident-chain").textContent = ev.attack_chain ? text(ev.attack_chain) : "";
    $("incident-meta").replaceChildren();
    const root = text(ev.root_cause_process ?? inc.root_process) + (ev.root_pid != null ? `[${ev.root_pid}]` : "") + (ev.root_inferred ? " (inferred: creation not observed)" : "");
    for (const [key, value] of [["Status", text(inc.status).replace("_", " ")], ["Host", inc.host_id], ["Score", num(ev.incident_score ?? inc.score, 3)], ["rule confidence (prior, not calibrated)", num(inc.confidence, 2)], ["Revision", ev.revision ?? inc.revision], ["Stages", ev.stage_count ?? inc.stage_count], ["Tactics", list(ev.tactics_covered ?? inc.tactics)], ["Member alerts", inc.alert_count], ["First seen", timeOf(inc.first_seen)], ["Last seen", timeOf(inc.last_seen)], ["Root cause process", root], ["Provenance origin", ev.provenance_origin], ["Processes in scope", ev.processes_in_scope]]) pair($("incident-meta"), key, value);

    const alerts = (Array.isArray(payload.alerts) ? payload.alerts : []).map(normalizeAlert).filter(Boolean);
    const alertsById = new Map(alerts.filter((a) => a.alert_id != null).map((a) => [String(a.alert_id), a]));
    const stages = Array.isArray(ev.stages) ? ev.stages : [];
    const stageFragment = document.createDocumentFragment();
    for (const stage of stages) if (stage && typeof stage === "object") stageFragment.append(stageRow(stage, alertsById));
    $("incident-stages").replaceChildren(stageFragment);
    $("incident-stages-empty").hidden = !!stages.length;

    $("incident-lineage").replaceChildren(lineageTree(ev.process_lineage));
    const causal = Array.isArray(ev.causal_path) ? ev.causal_path : [];
    $("incident-causal").replaceChildren(); if (!causal.length) $("incident-causal").append(node("li", "No causal path supplied.")); for (const line of causal) $("incident-causal").append(node("li", text(line), "mono"));
    $("incident-score").replaceChildren(scoreList(ev.score_breakdown));
    const why = Array.isArray(ev.why) ? ev.why : [];
    $("incident-why").replaceChildren(); if (!why.length) $("incident-why").append(node("li", "No reasons supplied.")); for (const reason of why) $("incident-why").append(node("li", text(reason)));

    $("incident-alerts").replaceChildren(); if (!alerts.length) $("incident-alerts").append(node("li", "No member alerts returned.")); for (const a of alerts) $("incident-alerts").append(memberAlertItem(a));
    const actions = Array.isArray(payload.response_actions) ? payload.response_actions : [];
    $("incident-responses").replaceChildren(); if (!actions.length) $("incident-responses").append(node("li", "No response actions for this incident.")); for (const action of actions) if (action && typeof action === "object") $("incident-responses").append(responseItem(action));
    $("incident-audit").replaceChildren(auditList(payload.audit, "No incident audit events recorded."));
    for (const status of Object.keys(STATUSES)) $("incident-set-" + status).disabled = posting || inc.status === status;
  }

  async function loadDetail() {
    const id = currentId; if (!id) return false;
    try {
      const response = await fetch("/api/incidents/" + encodeURIComponent(id), { cache: "no-store" });
      const payload = await response.json().catch(() => ({}));
      if (id !== currentId) return false;
      if (!response.ok) { $("incident-message").textContent = "Cannot load incident: " + text(payload.error || payload.detail || "HTTP " + response.status); return false; }
      const serialized = JSON.stringify(payload);
      if (serialized !== lastDetail) { renderDetail(payload); lastDetail = serialized; }
      return true;
    } catch {
      $("incident-message").textContent = "Cannot reach the console server";
      return false;
    }
  }

  async function openIncident(id) {
    if (currentId !== id) { $("incident-note").value = ""; $("incident-message").textContent = ""; }
    currentId = id; lastDetail = null;
    await loadDetail();
    if (!$("incident-detail").open) $("incident-detail").showModal();
  }

  async function setStatus(status) {
    if (!currentId || posting) return;
    posting = true;
    for (const s of Object.keys(STATUSES)) $("incident-set-" + s).disabled = true;
    const note = String($("incident-note").value || "").trim();
    try {
      const response = await fetch("/api/incidents/" + encodeURIComponent(currentId) + "/status", {
        method: "POST", headers: { "Content-Type": "application/json" }, cache: "no-store",
        body: JSON.stringify(note ? { status, note } : { status })
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) throw new Error(text(payload.error || payload.detail || "HTTP " + response.status));
      $("incident-message").textContent = `Status set to ${STATUSES[status]} · recorded by Manager`;
      $("incident-note").value = "";
    } catch (error) {
      $("incident-message").textContent = "Status change failed: " + error.message;
    } finally {
      posting = false; lastDetail = null;
      await loadDetail();
      if (currentDetail) for (const s of Object.keys(STATUSES)) $("incident-set-" + s).disabled = currentDetail.status === s;
      lastList = null; pollIncidents();
    }
  }

  registry.openIncident = openIncident;
  for (const status of Object.keys(STATUSES)) $("incident-set-" + status).addEventListener("click", () => setStatus(status));
  $("close-incident").addEventListener("click", () => { $("incident-detail").close(); });
  $("incident-detail").addEventListener("close", () => { currentId = null; lastDetail = null; currentDetail = null; });
  $("incidents-refresh").addEventListener("click", pollIncidents);
  pollIncidents();
  setInterval(pollIncidents, 3000);
});


// PIPELINE STATUS
// Overview tiles from Manager's GET /api/v1/status. When it is unavailable the
// tiles stay hidden and the sidebar keeps saying collector health is not
// reported -- the console never invents a health signal.
document.addEventListener("DOMContentLoaded", () => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const { text, timeOf } = PanopticonRender;
  const NOT_REPORTED = "Collector health is not reported by this console.";
  function count(v) { return Number.isFinite(v) ? v.toLocaleString() : "—"; }
  function setTile(id, value, sub) { $(id).textContent = value; if (sub !== undefined) $(id + "-sub").textContent = sub; }
  function render(status) {
    // Legacy events and the Windows agent's canonical records are two queues
    // feeding the same detection worker; the tiles count both.
    const queues = [status.events, status.endpoint_records].filter((q) => q && typeof q === "object");
    const events = {};
    for (const key of ["pending", "claimed", "done", "failed"]) {
      const values = queues.map((q) => q[key]).filter(Number.isFinite);
      events[key] = values.length ? values.reduce((x, y) => x + y, 0) : undefined;
    }
    const lastSeen = [status.last_event_at, status.last_record_at].filter(Boolean).sort().pop();
    const worker = status.detection_worker && typeof status.detection_worker === "object" ? status.detection_worker : null;
    const actions = status.response_actions && typeof status.response_actions === "object" ? status.response_actions : {};
    setTile("status-events-pending", count(events.pending), Number.isFinite(events.claimed) ? `${events.claimed.toLocaleString()} claimed by the worker` : "");
    setTile("status-events-done", count(events.done));
    setTile("status-events-failed", count(events.failed));
    setTile("status-incidents-open", count(status.incidents_open));
    setTile("status-pending-approvals", count(Number.isFinite(actions.PENDING) ? actions.PENDING : 0));
    setTile("status-last-event", lastSeen ? timeOf(lastSeen) : "No events yet", Number.isFinite(status.agents_enrolled) ? `${status.agents_enrolled.toLocaleString()} agent${status.agents_enrolled === 1 ? "" : "s"} enrolled · ${count(status.alerts)} alerts stored` : "");
    $("pipeline-tiles").hidden = false; $("pipeline-unavailable").hidden = true;
    const workerNote = !worker ? "" : worker.alive ? " Detection worker running." : ` Detection worker NOT running: ${worker.fatal_error ? text(worker.fatal_error) : "no heartbeat"}.`;
    $("health-note").textContent = "Pipeline status from Manager: event queue and incident counts. Not per-collector health." + workerNote;
  }
  async function pollStatus() {
    const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 8000);
    try {
      const response = await fetch("/api/status", { cache: "no-store", signal: controller.signal });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok || !payload || typeof payload !== "object" || Array.isArray(payload)) {
        $("pipeline-tiles").hidden = true; $("pipeline-unavailable").hidden = false;
        $("pipeline-unavailable").textContent = response.status === 503 ? "Pipeline status is not reported: no Manager is configured." : "Pipeline status unavailable: " + text(payload && (payload.error || payload.detail) || "HTTP " + response.status);
        $("health-note").textContent = NOT_REPORTED;
        return;
      }
      render(payload);
    } catch {
      $("pipeline-tiles").hidden = true; $("pipeline-unavailable").hidden = false;
      $("pipeline-unavailable").textContent = "Pipeline status unavailable: cannot reach the console server.";
      $("health-note").textContent = NOT_REPORTED;
    } finally { clearTimeout(timeout); }
  }
  pollStatus();
  setInterval(pollStatus, 3000);
});
