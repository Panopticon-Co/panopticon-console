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
      low: "#8ECBFF", "low-bg": "#1F3349",
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
      low: "#165A96", "low-bg": "#E4F1FF",
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
const POLL_INTERVAL_MS = 3000, PAGE_SIZE = 25;
const $ = (id) => document.getElementById(id);
const FAMILIES = ["process", "network", "file", "registry", "image_load"];
let alerts = [], page = 1, lastPayload = null, busy = false, hasLoaded = false;
let seenIds = new Set();
function text(v) { return v == null ? "—" : typeof v === "object" ? JSON.stringify(v) : String(v); }
function node(tag, value, cls) { const el = document.createElement(tag); if (value !== undefined) el.textContent = text(value); if (cls) el.className = cls; return el; }
function dedupe(items) { const ids = new Set(); return items.filter((a) => { if (!a || typeof a !== "object" || Array.isArray(a)) return false; if (a.alert_id == null || a.alert_id === "") return true; const id = String(a.alert_id); if (ids.has(id)) return false; ids.add(id); return true; }); }
function severityOf(a) { const s = String(a.severity || "").toLowerCase(); return ["critical", "high", "medium", "low"].includes(s) ? s : "unknown"; }
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
function pair(parent, key, value) { const group = node("div"); group.append(node("dt", key), node("dd", text(value))); parent.append(group); }
function showDetail(a) {
  $("detail-title").textContent = text(a.title || a.rule_id || "Untitled alert"); const sev = badge(a); $("detail-severity").textContent = sev.textContent; $("detail-severity").className = sev.className;
  $("detail-meta").replaceChildren(); for (const [key, value] of [["Rule", a.rule_id], ["Detected at", timeOf(a.timestamp)], ["Telemetry", familyOf(a).replace("_", " ")], ["MITRE technique", a.mitre_technique], ["MITRE tactic", a.mitre_tactic], ["Process", evidenceOf(a)["process.name"]]]) pair($("detail-meta"), key, value);
  $("evidence").replaceChildren(); const entries = Object.entries(evidenceOf(a)); if (!entries.length) $("evidence").append(node("p", "No evidence fields were supplied.")); for (const [key, value] of entries) pair($("evidence"), key, value); $("detail-id").textContent = text(a.alert_id); $("detail").showModal();
}
function rowFor(a, isNew) {
  const row = node("tr", undefined, isNew ? "new-row" : ""), sev = node("td"), detection = node("td"); sev.append(badge(a)); const open = node("button", a.title || a.rule_id || "Untitled alert", "alert-link"); open.type = "button"; open.addEventListener("click", () => showDetail(a)); detection.append(open, node("span", text(a.rule_id), "subline")); row.append(sev, detection, node("td", text(evidenceOf(a)["process.name"]), "mono"), node("td", familyOf(a).replace("_", " "), "family"), node("td", text(a.mitre_technique), "mono"), node("td", timeOf(a.timestamp), "when")); return row;
}
function render(flash = false) {
  $("count-total").textContent = alerts.length.toLocaleString(); for (const s of ["critical", "high", "medium", "low"]) $("count-" + s).textContent = alerts.filter((a) => severityOf(a) === s).length.toLocaleString();
  const query = $("search").value.trim().toLowerCase(), severity = $("severity").value.toLowerCase(), family = $("family").value;
  const filtered = alerts.filter((a) => (!severity || severityOf(a) === severity) && (!family || familyOf(a) === family) && matchesSearch(a, query));
  const pages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE)); page = Math.max(1, Math.min(page, pages)); const start = (page - 1) * PAGE_SIZE, fragment = document.createDocumentFragment();
  for (const a of filtered.slice(start, start + PAGE_SIZE)) fragment.append(rowFor(a, flash && a.alert_id != null && !seenIds.has(String(a.alert_id)))); $("alerts-body").replaceChildren(fragment); $("alerts-table").hidden = !filtered.length; $("empty").hidden = !!filtered.length;
  $("empty-title").textContent = alerts.length ? "No matching alerts" : "No alerts received yet"; $("empty-description").textContent = alerts.length ? "Try a different search or clear your filters." : "Alerts appear when the running detection engine finds a match. Collector health is not available here.";
  $("result-count").textContent = filtered.length ? `${start + 1}–${Math.min(start + PAGE_SIZE, filtered.length)} of ${filtered.length.toLocaleString()} matching alerts · ${alerts.length.toLocaleString()} total` : `0 matching alerts · ${alerts.length.toLocaleString()} total`;
  $("page-label").textContent = `Page ${page} of ${pages}`; $("previous").disabled = page <= 1; $("next").disabled = page >= pages;
}
async function poll() {
  if (busy) return; busy = true; $("refresh").disabled = true; const controller = new AbortController(), timeout = setTimeout(() => controller.abort(), 8000);
  try { const response = await fetch("/api/alerts", {cache: "no-store", signal: controller.signal}); if (!response.ok) throw new Error(`HTTP ${response.status}`); const raw = await response.json(); if (!Array.isArray(raw)) throw new Error("Invalid alert feed"); const payload = JSON.stringify(raw);
    if (payload !== lastPayload) { alerts = dedupe(raw).reverse().sort((a, b) => (Date.parse(b.timestamp) || 0) - (Date.parse(a.timestamp) || 0)); render(hasLoaded); seenIds = new Set(alerts.filter((a) => a.alert_id != null).map((a) => String(a.alert_id))); lastPayload = payload; }
    hasLoaded = true; $("status").textContent = "● Alert feed connected"; $("status").className = ""; $("last-updated").textContent = "Updated " + new Date().toLocaleTimeString();
  } catch (error) { $("status").textContent = "● Alert feed unavailable"; $("status").className = "error"; if (!hasLoaded) { $("empty-title").textContent = "Cannot reach the alert feed"; $("empty-description").textContent = "Check that the console server is running. Retrying automatically."; } else $("last-updated").textContent = "Showing last received alerts · retrying";
  } finally { clearTimeout(timeout); busy = false; $("refresh").disabled = false; }
}
for (const id of ["search", "severity", "family"]) $(id).addEventListener(id === "search" ? "input" : "change", () => { page = 1; if (hasLoaded) render(); });
$("clear").addEventListener("click", () => { for (const id of ["search", "severity", "family"]) $(id).value = ""; page = 1; if (hasLoaded) render(); });
$("previous").addEventListener("click", () => { page--; render(); }); $("next").addEventListener("click", () => { page++; render(); }); $("refresh").addEventListener("click", poll); $("close-detail").addEventListener("click", () => $("detail").close());
document.querySelectorAll("nav a").forEach((link) => link.addEventListener("click", () => { document.querySelectorAll("nav a").forEach((item) => item.classList.remove("active")); link.classList.add("active"); }));
poll(); setInterval(poll, POLL_INTERVAL_MS);

});
