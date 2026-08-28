"use strict";
// Panopticon Console V1 - client.
//
// Polls /api/alerts and renders the table. Every value that reaches the DOM is
// written through textContent / createTextNode, never innerHTML, because alert
// evidence carries attacker-influenced strings (process command lines). Do not
// reintroduce string-built HTML here.

const POLL_INTERVAL_MS = 3000;

const tbody = document.getElementById("alerts-body");
const table = document.getElementById("alerts-table");
const empty = document.getElementById("empty");
const statusEl = document.getElementById("status");

// alert_id values already rendered. Used to (a) drop duplicate lines the engine
// may re-append on a restart / retry, and (b) decide which rows are genuinely
// new and should flash. A count-based check was fragile across file rewrites.
let seenIds = new Set();

function dedupe(alerts) {
  const out = [];
  const ids = new Set();
  for (const a of alerts) {
    const id = a && a.alert_id;
    if (id === undefined || id === null || id === "") {
      out.push(a); // no id to dedupe on; show it
      continue;
    }
    if (ids.has(String(id))) continue; // duplicate within this payload
    ids.add(String(id));
    out.push(a);
  }
  return out;
}

function sevClass(sev) {
  const s = String(sev || "").toLowerCase();
  return "sev sev-" + (["critical", "high", "medium", "low"].includes(s) ? s : "low");
}

function cell(text, className) {
  const td = document.createElement("td");
  td.textContent = text === undefined || text === null ? "" : String(text);
  if (className) td.className = className;
  return td;
}

function mitreText(a) {
  const parts = [];
  if (a.mitre_technique) parts.push(String(a.mitre_technique));
  if (a.mitre_tactic) parts.push(String(a.mitre_tactic));
  return parts.join(" · ");
}

function severityCell(a) {
  const td = document.createElement("td");
  const span = document.createElement("span");
  span.className = sevClass(a.severity);
  const level = Number.isFinite(a.level) ? ` L${a.level}` : "";
  span.textContent = `${String(a.severity || "?")}${level}`;
  td.appendChild(span);
  return td;
}

function evidenceCell(a) {
  const td = document.createElement("td");
  const wrap = document.createElement("div");
  wrap.className = "evidence";
  const ev = a.evidence && typeof a.evidence === "object" ? a.evidence : {};
  const keys = Object.keys(ev);
  if (keys.length === 0) {
    wrap.textContent = "(none)";
  } else {
    for (const k of keys) {
      const line = document.createElement("div");
      const key = document.createElement("span");
      key.className = "k";
      key.textContent = `${k}: `;
      line.appendChild(key);
      let v = ev[k];
      if (typeof v === "object") v = JSON.stringify(v);
      line.appendChild(document.createTextNode(String(v)));
      wrap.appendChild(line);
    }
  }
  td.appendChild(wrap);
  return td;
}

function rowFor(a, isNew) {
  const tr = document.createElement("tr");
  if (isNew) tr.className = "new-row";
  tr.appendChild(cell(a.timestamp, "when"));
  tr.appendChild(cell(a.rule_id, "rule"));
  tr.appendChild(severityCell(a));
  tr.appendChild(cell(mitreText(a)));
  tr.appendChild(cell(a.title));
  tr.appendChild(evidenceCell(a));
  return tr;
}

function render(rawAlerts) {
  const alerts = Array.isArray(rawAlerts) ? dedupe(rawAlerts) : [];
  if (alerts.length === 0) {
    table.hidden = true;
    empty.hidden = false;
    seenIds = new Set();
    return;
  }
  table.hidden = false;
  empty.hidden = true;

  // A row flashes if its alert_id was not present on the previous poll.
  const nextSeen = new Set();
  const frag = document.createDocumentFragment();
  for (const a of alerts) {
    const id = a && a.alert_id != null ? String(a.alert_id) : null;
    const isNew = id === null ? true : !seenIds.has(id);
    if (id !== null) nextSeen.add(id);
    frag.appendChild(rowFor(a, isNew));
  }
  const ordered = Array.from(frag.children).reverse(); // newest first
  tbody.replaceChildren(...ordered);
  seenIds = nextSeen;
}

async function poll() {
  try {
    const res = await fetch("/api/alerts", { cache: "no-store" });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    const alerts = await res.json();
    render(alerts);
    const n = Array.isArray(alerts) ? dedupe(alerts).length : 0;
    statusEl.textContent = `${n} alert(s) — updated ${new Date().toLocaleTimeString()}`;
  } catch (e) {
    statusEl.textContent = "connection lost, retrying…";
  }
}

poll();
setInterval(poll, POLL_INTERVAL_MS);
