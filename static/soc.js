"use strict";
// SOC views layered on top of app.js: hash navigation, live overview, agents,
// event stream, attack graph, response summary/audit and service health.
// Everything rendered here comes from the console's same-origin /api routes
// (Manager data, proxied server-side). Nothing is synthesized: a value the
// Manager does not report is shown as "not reported", never filled in.
(() => {
  if (typeof document === "undefined" || typeof document.querySelector !== "function") return;
  const $ = (id) => document.getElementById(id);
  const SVG_NS = "http://www.w3.org/2000/svg";
  const SEV_RANK = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  const VIEWS = ["overview", "agents", "events", "investigations", "graph", "response", "health"];
  const ALIASES = { alerts: "investigations", incidents: "investigations" };
  const MAX_EVENTS = 3000;

  const state = {
    events: [], eventIds: new Set(), cursor: null, paused: false, newIds: new Set(),
    alerts: new Map(), incidents: [], agents: null, status: null, health: null,
    audit: [], auditAfter: 0, auditError: null, responses: [],
    graphHost: null, graphFocus: null, graphSelected: null, graphKnown: new Set(),
  };

  // -- helpers ----------------------------------------------------------------
  function el(tag, attrs, ...children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === "class") e.className = v; else if (k.startsWith("on")) e.addEventListener(k.slice(2), v); else e.setAttribute(k, v === true ? "" : String(v));
    }
    for (const c of children.flat()) if (c != null && c !== "") e.append(c instanceof Node ? c : document.createTextNode(String(c)));
    return e;
  }
  function svg(tag, attrs) { const e = document.createElementNS(SVG_NS, tag); for (const [k, v] of Object.entries(attrs || {})) if (v != null) e.setAttribute(k, String(v)); return e; }
  const txt = (v) => (v == null || v === "" ? "—" : String(v));
  const sev = (s) => { const v = String(s || "").toLowerCase(); return v in SEV_RANK ? v : "info"; };
  function ago(ts) {
    if (!ts) return "never";
    const ms = Date.now() - new Date(ts).getTime();
    if (!Number.isFinite(ms)) return txt(ts);
    if (ms < 0) return "just now";
    const s = Math.round(ms / 1000);
    if (s < 60) return s + "s ago"; if (s < 3600) return Math.round(s / 60) + "m ago";
    if (s < 86400) return Math.round(s / 3600) + "h ago"; return Math.round(s / 86400) + "d ago";
  }
  const clock = (ts) => { const d = new Date(ts); return ts && Number.isFinite(d.getTime()) ? d.toLocaleTimeString() : txt(ts); };
  const chip = (label, tone) => el("span", { class: "chip chip-" + tone }, label);
  const sevChip = (s) => chip(sev(s), "sev-" + sev(s));
  async function getJSON(path) {
    const r = await fetch(path, { cache: "no-store" });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw Object.assign(new Error(body.error || body.detail || "HTTP " + r.status), { status: r.status });
    return body;
  }
  function eventSummary(e) {
    const p = e.process || {};
    switch (e.category) {
      case "network": { const n = e.network || {}; return `${txt(p.name)} → ${n.destination_hostname || n.destination_ip || "?"}:${txt(n.destination_port)} ${n.protocol || ""}`; }
      case "file": return `${txt(p.name)} ${txt((e.file || {}).operation)} ${txt((e.file || {}).path)}`;
      case "registry": return `${txt(p.name)} ${txt((e.registry || {}).operation)} ${txt((e.registry || {}).key_path)}`;
      case "dns": return `${txt(p.name)} resolved ${txt((e.dns || {}).query_name)}`;
      case "process": return e.type === "stop" ? `${txt(p.name)}[${txt(p.pid)}] exited` : `${txt(p.parent_name)}[${txt(p.parent_pid)}] → ${txt(p.name)}[${txt(p.pid)}] ${p.command_line || ""}`;
      default: return `${txt(p.name)}[${txt(p.pid)}] ${e.category}`;
    }
  }

  // -- navigation -------------------------------------------------------------
  function route() {
    const raw = (location.hash || "#overview").slice(1).split("?")[0];
    const view = ALIASES[raw] || (VIEWS.includes(raw) ? raw : "overview");
    for (const s of document.querySelectorAll("[data-view]")) s.hidden = !s.dataset.view.split(" ").includes(view);
    for (const a of document.querySelectorAll("nav a[data-nav]")) a.classList.toggle("active", a.dataset.nav === view);
    document.body.dataset.view = view;
    if (view === "graph") {
      const params = new URLSearchParams((location.hash.split("?")[1]) || "");
      const key = params.toString();
      if (key && key !== state.graphLink) {
        state.graphLink = key;
        if (params.get("incident")) { openGraphForIncident(params.get("incident")); return; }
        if (params.get("alert")) { const a = state.alerts.get(params.get("alert")); if (a) { openGraphForAlert(a); return; } state.graphLink = null; }
        if (params.get("host")) { openGraph(params.get("host"), null); return; }
      }
      renderGraph();
    }
    if (raw === "alerts" || raw === "incidents") { const t = $(raw); if (t && t.scrollIntoView) t.scrollIntoView(); } else window.scrollTo(0, 0);
  }
  function go(view) { if (location.hash === "#" + view) route(); else location.hash = view; }

  function setLive(ok, message) {
    const pill = $("soc-live");
    if (!pill) return;
    pill.className = "live-pill " + (ok ? "on" : "off");
    pill.textContent = ok ? "LIVE" : "OFFLINE";
    pill.title = message || "";
  }

  // -- polling ------------------------------------------------------------------
  async function pollEvents() {
    if (state.paused) return;
    try {
      const q = state.cursor ? `?after_event=${state.cursor.after_event}&after_record=${state.cursor.after_record}&limit=200` : "?limit=200";
      const body = await getJSON("/api/events" + q);
      state.cursor = body.cursor;
      const fresh = (body.events || []).filter((e) => !state.eventIds.has(e.kind + ":" + e.event_id));
      for (const e of fresh) state.eventIds.add(e.kind + ":" + e.event_id);
      const first = state.events.length === 0;
      state.events = fresh.concat(state.events).sort(newestFirst).slice(0, MAX_EVENTS);
      state.newIds = first ? new Set() : new Set(fresh.map((e) => e.kind + ":" + e.event_id));
      setLive(true, "Event stream connected · polling every 2 s");
      renderEvents(); renderOverview();
      if (fresh.length) linkAlerts();
      if (fresh.length && document.body.dataset.view === "graph") renderGraph();
    } catch (err) {
      setLive(false, err.message);
      const n = $("events-unavailable"); if (n) { n.hidden = false; n.textContent = "Event stream not available: " + err.message; }
    }
  }
  function newestFirst(a, b) { return (b.ingested_at || "").localeCompare(a.ingested_at || "") || (b.timestamp || "").localeCompare(a.timestamp || "") || b.cursor - a.cursor; }
  async function pollSlow() {
    await Promise.all([
      getJSON("/api/status").then((b) => { state.status = b; }, () => { state.status = null; }),
      getJSON("/api/health").then((b) => { state.health = b; }, () => { state.health = null; }),
      getJSON("/api/agents").then((b) => { state.agents = b; }, (e) => { state.agents = { error: e.message }; }),
      getJSON("/api/alerts?limit=200").then((b) => { if (Array.isArray(b)) for (const a of b) if (a && a.alert_id) state.alerts.set(String(a.alert_id), a); }, () => {}),
      getJSON("/api/incidents?limit=50").then((b) => { state.incidents = Array.isArray(b.incidents) ? b.incidents : []; }, () => {}),
      getJSON("/api/response-audit?limit=200&after=" + state.auditAfter).then((b) => {
        const rows = Array.isArray(b.events) ? b.events : [];
        state.audit = state.audit.concat(rows).slice(-500);
        if (Number.isFinite(b.next_after)) state.auditAfter = b.next_after;
        state.auditError = null;
      }, (e) => { state.auditError = e.message; }),
    ]);
    linkAlerts();
    renderOverview(); renderAgents(); renderHealth(); renderResponseSummary(); renderEvents();
    if (document.body.dataset.view === "graph") { if (state.graphLink) renderGraph(); else route(); }
  }
  // Detection runs after ingest, so an event is often loaded before its alert
  // exists. Re-attach alerts by the event_id the engine recorded on them.
  function linkAlerts() {
    const byEvent = new Map();
    for (const a of state.alerts.values()) if (a.event_id) { if (!byEvent.has(a.event_id)) byEvent.set(a.event_id, []); byEvent.get(a.event_id).push({ alert_id: a.alert_id, rule_id: a.rule_id, severity: a.severity }); }
    for (const e of state.events) {
      const extra = (byEvent.get(e.event_id) || []).filter((a) => !e.alerts.some((x) => x.alert_id === a.alert_id));
      if (!extra.length) continue;
      e.alerts = e.alerts.concat(extra);
      e.severity = e.alerts.reduce((m, a) => (SEV_RANK[sev(a.severity)] > SEV_RANK[m] ? sev(a.severity) : m), "info");
    }
  }

  // -- overview -----------------------------------------------------------------
  function tile(label, value, sub, tone, onclick) {
    return el("article", { class: "tile" + (tone ? " tone-" + tone : "") + (onclick ? " clickable" : ""), onclick, tabindex: onclick ? 0 : null },
      el("span", { class: "tile-label" }, label), el("strong", {}, value), el("small", {}, sub || ""));
  }
  function eventsPerMinute() {
    const cutoff = Date.now() - 60000;
    return state.events.filter((e) => new Date(e.ingested_at).getTime() >= cutoff).length;
  }
  function renderOverview() {
    const box = $("soc-tiles"); if (!box) return;
    const st = state.status, h = state.health, ag = state.agents;
    const m = h && h.manager;
    const ready = m && m.readyz;
    const managerUp = m && m.healthz && m.healthz.status === "ok";
    const dbReady = ready && ready.status === "ready";
    const agents = ag && Array.isArray(ag.agents) ? ag.agents : [];
    const online = agents.filter((a) => a.status === "online").length;
    const sources = ag && Array.isArray(ag.unenrolled_sources) ? ag.unenrolled_sources : [];
    const liveSources = sources.filter((a) => a.status === "online").length;
    const ev = st ? st.events || {} : {}, rec = st ? st.endpoint_records || {} : {};
    const sum = (o) => Object.values(o).reduce((a, b) => a + b, 0);
    const pending = st ? (st.response_actions || {}).PENDING || 0 : null;
    const worker = st && st.detection_worker;
    if (!changed(box, [st, h && { m: h.manager && [h.manager.healthz.status, h.manager.readyz.status, Math.round(h.manager.healthz.latency_ms / 5)] }, ag, eventsPerMinute()])) { renderStory(); renderMiniFeed(); renderTopAlerts(); return; }
    box.replaceChildren(
      tile("Manager API", h ? (m ? (managerUp ? "Healthy" : "Down") : "Not configured") : "—", m ? (managerUp ? `${m.healthz.latency_ms} ms round trip` : txt(m.healthz.reason)) : "", m ? (managerUp ? "ok" : "bad") : "warn", () => go("health")),
      tile("Database", ready ? (dbReady ? "Connected" : "Not ready") : "—", st ? `${(sum(ev) + sum(rec)).toLocaleString()} telemetry rows stored` : ready ? txt(ready.reason) : "not reported", ready ? (dbReady ? "ok" : "bad") : "warn", () => go("health")),
      tile("Detection engine", worker ? (worker.alive ? "Running" : "Stopped") : "—", st ? `${(ev.done || 0) + (rec.done || 0)} analysed · ${(ev.pending || 0) + (rec.pending || 0)} queued` : "not reported", worker ? (worker.alive ? "ok" : "bad") : "warn", () => go("health")),
      tile("Agents online", ag && !ag.error ? `${online} / ${agents.length}` : "—", sources.length ? `+ ${sources.length} unenrolled source${sources.length > 1 ? "s" : ""} (${liveSources} active)` : "enrolled agents", online || liveSources ? "ok" : "warn", () => go("agents")),
      tile("Event rate", `${eventsPerMinute()}/min`, "ingested in the last 60 s", null, () => go("events")),
      tile("Alerts", st ? st.alerts.toLocaleString() : "—", st ? `${st.incidents_open} open incident${st.incidents_open === 1 ? "" : "s"}` : "", st && st.alerts ? "high" : null, () => go("investigations")),
      tile("Pending approvals", pending == null ? "—" : String(pending), "response actions awaiting an analyst", pending ? "medium" : null, () => go("response")),
    );
    renderStory(); renderMiniFeed(); renderTopAlerts();
  }
  function changed(box, value) { const sig = JSON.stringify(value); if (box.dataset.sig === sig) return false; box.dataset.sig = sig; return true; }
  function renderStory() {
    const box = $("soc-story"); if (!box) return;
    const inc = state.incidents[0];
    if (!changed(box, [inc, Math.floor(Date.now() / 30000)])) return;
    if (!inc) { box.replaceChildren(el("p", { class: "muted" }, "No incident reconstructed yet. When the detection engine links alerts causally, the attack story appears here.")); return; }
    const tactics = Array.isArray(inc.tactics) ? inc.tactics : [];
    box.replaceChildren(
      el("div", { class: "story-head" }, sevChip(inc.severity), el("strong", {}, "Incident " + txt(inc.incident_id)), el("span", { class: "muted" }, `${txt(inc.host_id)} · ${txt(inc.status).replace("_", " ")} · ${txt(inc.stage_count)} stages · last seen ${ago(inc.last_seen)}`)),
      el("ol", { class: "story-chain" }, (tactics.length ? tactics : ["tactics not reported"]).map((t) => el("li", {}, t))),
      inc.root_process ? el("p", { class: "mono" }, "Root process: " + inc.root_process) : null,
      el("div", { class: "story-actions" },
        el("button", { type: "button", class: "primary", onclick: () => openGraphForIncident(String(inc.incident_id)) }, "Open attack graph"),
        el("button", { type: "button", onclick: () => { const r = globalThis.PanopticonConsole; if (r && r.openIncident) r.openIncident(String(inc.incident_id)); } }, "Incident details")),
    );
  }
  function renderMiniFeed() {
    const box = $("soc-minifeed"); if (!box) return;
    const rows = state.events.slice(0, 9);
    if (!changed(box, rows.map((e) => [e.event_id, e.severity, state.newIds.has(e.kind + ":" + e.event_id)]))) return;
    box.replaceChildren(...(rows.length ? rows.map((e) => eventRow(e, true)) : [el("li", { class: "muted" }, "Waiting for telemetry…")]));
  }
  function renderTopAlerts() {
    const box = $("soc-topalerts"); if (!box) return;
    const list = [...state.alerts.values()].sort((a, b) => (SEV_RANK[sev(b.severity)] - SEV_RANK[sev(a.severity)]) || String(b.timestamp || "").localeCompare(String(a.timestamp || ""))).slice(0, 6);
    if (!changed(box, [list.map((a) => a.alert_id), Math.floor(Date.now() / 30000)])) return;
    box.replaceChildren(...(list.length ? list.map((a) => el("li", { class: "clickable", onclick: () => openAlertById(a.alert_id), tabindex: 0 }, sevChip(a.severity), " ", el("strong", {}, txt(a.title || a.rule_id)), el("span", { class: "subline" }, `${txt(a.host_id)} · ${txt((a.evidence || {})["process.name"])} · ${txt(a.mitre_technique)} · ${ago(a.timestamp)}`))) : [el("li", { class: "muted" }, "No alerts yet.")]));
  }

  // -- agents ---------------------------------------------------------------------
  function statusChip(s) { return chip(String(s || "unknown").replace("_", " "), { online: "ok", stale: "warn", offline: "bad", revoked: "bad", never_seen: "muted" }[s] || "muted"); }
  function agentRow(a, enrolled) {
    return el("tr", {},
      el("td", {}, statusChip(a.status)),
      el("td", {}, el("strong", {}, txt(a.hostname || a.host_id)), el("div", { class: "subline mono" }, `${txt(a.agent_id)} · host ${txt(a.host_id)}`)),
      el("td", {}, txt(a.os)),
      el("td", {}, enrolled ? clock(a.enrolled_at) : chip("not enrolled", "warn")),
      el("td", { title: txt(a.last_seen) }, ago(a.last_seen)),
      el("td", {}, `${(a.event_count || 0).toLocaleString()} events` + (a.record_count ? ` · ${a.record_count.toLocaleString()} records` : "")),
      el("td", {}, txt(a.last_category)),
      el("td", {}, enrolled ? (a.response_channel ? chip("response enabled", "bad") : chip("telemetry only", "muted")) : chip("replay / unauthenticated", "warn")),
      el("td", { class: "actions" }, el("button", { type: "button", onclick: () => { state.eventHost = a.host_id; renderEvents(); go("events"); } }, "Events"),
        el("button", { type: "button", onclick: () => openGraph(a.host_id, null) }, "Graph")),
    );
  }
  function renderAgents() {
    const body = $("agents-body"); if (!body) return;
    const ag = state.agents;
    if (!ag || ag.error) { body.replaceChildren(el("tr", {}, el("td", { colspan: 9, class: "muted" }, ag ? "Agent inventory not available: " + ag.error : "Loading…"))); return; }
    const rows = ag.agents.map((a) => agentRow(a, true)).concat(ag.unenrolled_sources.map((a) => agentRow(a, false)));
    body.replaceChildren(...(rows.length ? rows : [el("tr", {}, el("td", { colspan: 9, class: "muted" }, "No agent has enrolled or sent telemetry yet."))]));
    const t = ag.thresholds_seconds || {};
    $("agents-note").textContent = `Online = telemetry ingested within ${t.online} s; stale = within ${t.stale} s. Connectivity is measured from ingested telemetry, separately from Manager service health. "Unenrolled" sources sent telemetry without an enrolled identity (for example the offline replay tool).`;
  }

  // -- event stream -------------------------------------------------------------------
  function eventRow(e, compact) {
    const key = e.kind + ":" + e.event_id;
    const open = () => { $("ev-raw-title").textContent = `${e.category} · ${e.event_id}`; $("ev-raw").textContent = JSON.stringify(e.raw, null, 2); $("ev-raw-dialog").showModal(); };
    if (compact) return el("li", { class: state.newIds.has(key) ? "flash" : "" }, el("span", { class: "mono muted" }, clock(e.timestamp)), sevChip(e.severity), el("strong", {}, e.category), el("span", { class: "mono ellipsis" }, `${txt(e.host_id)} · ${eventSummary(e)}`));
    return el("tr", { class: (state.newIds.has(key) ? "flash " : "") + "sev-row-" + sev(e.severity), onclick: open, tabindex: 0 },
      el("td", { class: "mono", title: "ingested " + txt(e.ingested_at) }, clock(e.timestamp)),
      el("td", {}, sevChip(e.severity)),
      el("td", {}, txt(e.host_id)),
      el("td", {}, el("strong", {}, e.category), el("div", { class: "subline" }, `${txt(e.type)} · ${txt(e.source)}`)),
      el("td", { class: "mono wrap" }, eventSummary(e)),
      el("td", {}, e.alerts && e.alerts.length ? e.alerts.map((a) => el("div", { class: "mono" }, a.rule_id)) : el("span", { class: "muted" }, txt(e.detect_state))),
    );
  }
  function filteredEvents() {
    const host = $("ev-host").value, cat = $("ev-category").value, sv = $("ev-severity").value;
    const terms = $("ev-search").value.toLowerCase().split(/\s+/).filter(Boolean);
    return state.events.filter((e) => (!host || e.host_id === host) && (!cat || e.category === cat)
      && (!sv || (sv === "alerted" ? e.severity !== "info" : e.severity === sv))
      && (!terms.length || terms.every((t) => JSON.stringify(e.raw).toLowerCase().includes(t))));
  }
  function syncSelect(id, values, allLabel) {
    const s = $(id), cur = s.value;
    const want = [""].concat([...values].sort());
    if ([...s.options].map((o) => o.value).join("|") !== want.join("|")) {
      s.replaceChildren(...want.map((v) => el("option", { value: v }, v || allLabel)));
      s.value = want.includes(cur) ? cur : "";
    }
  }
  function renderEvents() {
    const body = $("events-body"); if (!body) return;
    $("events-unavailable").hidden = true;
    syncSelect("ev-host", new Set(state.events.map((e) => e.host_id)), "All hosts");
    if (state.eventHost) { $("ev-host").value = state.eventHost; state.eventHost = null; }
    syncSelect("ev-category", new Set(state.events.map((e) => e.category)), "All types");
    const rows = filteredEvents();
    body.replaceChildren(...rows.slice(0, 300).map((e) => eventRow(e, false)));
    $("events-count").textContent = `${rows.length.toLocaleString()} of ${state.events.length.toLocaleString()} loaded events` + (rows.length > 300 ? " · showing newest 300" : "") + (state.paused ? " · stream paused" : "");
    $("events-empty").hidden = rows.length > 0;
  }

  // -- attack / provenance graph ----------------------------------------------------------
  // Process nodes are process incarnations keyed by (host, pid, start time). A
  // child's parent is the newest observed start of its parent pid at or before
  // the child's start -- the same (host_id, pid) + time resolution the engine's
  // ProcessRegistry uses (entity_id is not joinable across families).
  function buildGraph(host) {
    const evs = state.events.filter((e) => e.host_id === host).slice().sort((a, b) => (a.timestamp || "").localeCompare(b.timestamp || ""));
    const nodes = new Map(), edges = [], starts = new Map();
    const t = (ts) => new Date(ts).getTime();
    function resolve(pid, at) { let best = null; for (const n of starts.get(pid) || []) if (n.start <= at && (!best || n.start > best.start)) best = n; return best; }
    function proc(pid, name, at, kind) {
      const n = resolve(pid, at);
      if (n) return n;
      const key = `${host}|${pid}|unobserved`;
      if (!nodes.has(key)) nodes.set(key, { key, type: "process", pid, name: name || "pid " + pid, start: -Infinity, observed: false, inferred: kind, events: [], alerts: [] });
      const u = nodes.get(key); if (!u.name || u.name.startsWith("pid ")) u.name = name || u.name;
      return u;
    }
    for (const e of evs) {
      const p = e.process || {};
      if (p.pid == null) continue;
      const at = t(e.timestamp);
      if (e.category === "process" && e.type === "start") {
        if (!starts.has(p.pid)) starts.set(p.pid, []);
        const list = starts.get(p.pid);
        let n = list.find((x) => x.start === at);
        if (!n) {
          n = { key: `${host}|${p.pid}|${e.timestamp}`, type: "process", pid: p.pid, name: p.name, start: at, observed: true, events: [], alerts: [] };
          if (p.parent_pid != null) {
            const parent = resolve(p.parent_pid, at) || proc(p.parent_pid, p.parent_name, at, "parent");
            edges.push({ from: parent.key, to: n.key, kind: "spawn" });
          }
          list.push(n); nodes.set(n.key, n);
        }
        // ETW and Sysmon both report one creation; keep the richest fields.
        n.name = n.name || p.name; n.executable = n.executable || p.executable; n.command_line = n.command_line || p.command_line;
        n.user = n.user || e.user; n.timestamp = n.timestamp || e.timestamp; n.parent = n.parent || `${txt(p.parent_name)}[${txt(p.parent_pid)}]`;
        n.sources = [...new Set([...(n.sources || []), e.source].filter(Boolean))];
        n.events.push(e); n.alerts.push(...(e.alerts || []));
        continue;
      }
      const n = proc(p.pid, p.name, at, "activity");
      n.events.push(e); n.alerts.push(...(e.alerts || []));
      if (e.category === "process" && e.type === "stop") { n.ended = e.timestamp; continue; }
      let label = null;
      if (e.category === "network" && e.network) label = `${e.network.destination_hostname || e.network.destination_ip}:${txt(e.network.destination_port)}`;
      else if (e.category === "dns" && e.dns) label = e.dns.query_name;
      else if (e.category === "file" && e.file) label = e.file.path;
      else if (e.category === "registry" && e.registry) label = e.registry.key_path;
      else if ((e.category === "process_access" || e.category === "remote_thread") && e.raw && e.raw[e.category]) {
        const tgt = e.raw[e.category].target || {};
        if (tgt.pid != null) { const target = proc(tgt.pid, tgt.name, at, "target"); if (!edges.some((x) => x.from === n.key && x.to === target.key)) edges.push({ from: n.key, to: target.key, kind: e.category }); continue; }
      }
      if (!label) continue;
      const key = `${n.key}|${e.category}|${label}`;
      if (!nodes.has(key)) { nodes.set(key, { key, type: e.category, name: String(label), events: [], alerts: [], start: at }); edges.push({ from: n.key, to: key, kind: e.category }); }
      const leaf = nodes.get(key); leaf.events.push(e); leaf.alerts.push(...(e.alerts || []));
    }
    return { nodes, edges };
  }

  // Alerting nodes, their ancestors (the chain), and the chain root's subtree.
  function focusSet(graph, focus) {
    if (!focus) return null;
    const parents = new Map(), children = new Map();
    for (const e of graph.edges) {
      if (!parents.has(e.to)) parents.set(e.to, e.from);
      if (!children.has(e.from)) children.set(e.from, []);
      children.get(e.from).push(e.to);
    }
    const hits = [...graph.nodes.values()].filter((n) => n.alerts.some((a) => focus.alertIds.has(String(a.alert_id))) || (n.type === "process" && focus.pids.has(Number(n.pid))));
    const chain = new Set(), keep = new Set();
    for (const n of hits) { let k = n.key; while (k && !chain.has(k)) { chain.add(k); k = parents.get(k); } }
    const stack = [...chain].filter((k) => !chain.has(parents.get(k)));
    while (stack.length) { const k = stack.pop(); if (keep.has(k)) continue; keep.add(k); for (const c of children.get(k) || []) stack.push(c); }
    return { chain, keep, hits: new Set(hits.map((n) => n.key)) };
  }

  function layout(graph, keep) {
    const nodes = [...graph.nodes.values()].filter((n) => !keep || keep.has(n.key));
    const ids = new Set(nodes.map((n) => n.key));
    const edges = graph.edges.filter((e) => ids.has(e.from) && ids.has(e.to));
    const kids = new Map(), hasParent = new Set();
    for (const e of edges) { if (hasParent.has(e.to)) continue; hasParent.add(e.to); if (!kids.has(e.from)) kids.set(e.from, []); kids.get(e.from).push(e.to); }
    const byKey = new Map(nodes.map((n) => [n.key, n]));
    const order = (a, b) => (byKey.get(a).start || 0) - (byKey.get(b).start || 0);
    const pos = new Map(); let row = 0;
    function place(k, depth, seen) {
      if (seen.has(k)) return; seen.add(k);
      const cs = (kids.get(k) || []).filter((c) => !seen.has(c)).sort(order);
      const first = row;
      for (const c of cs) place(c, depth + 1, seen);
      pos.set(k, { x: depth, y: row > first ? (first + row - 1) / 2 : row++ });
    }
    const seen = new Set();
    for (const n of nodes.filter((x) => !hasParent.has(x.key)).sort((a, b) => order(a.key, b.key))) place(n.key, 0, seen);
    for (const n of nodes) if (!seen.has(n.key)) place(n.key, 0, seen);
    return { nodes, edges, pos, rows: row };
  }

  const ICON = { process: "⬢", network: "⇄", dns: "◎", file: "▤", registry: "⌘" };
  const NODE_W = 178, NODE_H = 38, COL = 240, ROW = 54, PAD = 28;
  function renderGraph() {
    const canvas = $("graph-svg"); if (!canvas) return;
    const hosts = [...new Set(state.events.map((e) => e.host_id))].sort();
    syncSelect("graph-host", new Set(hosts), "Select a host");
    if (!state.graphHost && hosts.length) state.graphHost = hosts[0];
    $("graph-host").value = state.graphHost || "";
    const graph = state.graphHost ? buildGraph(state.graphHost) : { nodes: new Map(), edges: [] };
    const focus = focusSet(graph, state.graphFocus);
    const scoped = focus && focus.keep.size && !$("graph-all").checked;
    const L = layout(graph, scoped ? focus.keep : null);
    const maxX = Math.max(0, ...[...L.pos.values()].map((p) => p.x));
    const width = Math.max(640, PAD * 2 + maxX * COL + NODE_W), height = Math.max(320, PAD * 2 + L.rows * ROW);
    canvas.setAttribute("viewBox", canvas.dataset.vb || `0 0 ${width} ${height}`);
    const g = svg("g");
    const at = (k) => { const p = L.pos.get(k); return { x: PAD + p.x * COL, y: PAD + p.y * ROW }; };
    for (const e of L.edges) {
      const a = at(e.from), b = at(e.to), y1 = a.y + NODE_H / 2, y2 = b.y + NODE_H / 2, x1 = a.x + NODE_W;
      const inChain = focus && focus.chain.has(e.from) && focus.chain.has(e.to);
      const cls = `edge edge-${e.kind}` + (inChain ? " chain" : "") + (state.graphKnown.size && !state.graphKnown.has(e.to) ? " fresh" : "");
      g.append(svg("path", { d: `M${x1},${y1} C${x1 + 34},${y1} ${b.x - 34},${y2} ${b.x},${y2}`, class: cls, "marker-end": "url(#arrow)" }));
    }
    const nowKnown = new Set();
    for (const n of L.nodes) {
      const p = at(n.key), top = n.alerts.reduce((m, a) => (SEV_RANK[sev(a.severity)] > SEV_RANK[m] ? sev(a.severity) : m), "info");
      const cls = ["node", "node-" + n.type, "sev-" + top];
      if (n.type === "process" && !n.observed) cls.push("inferred");
      if (focus && focus.chain.has(n.key)) cls.push("chain");
      if (focus && focus.hits.has(n.key)) cls.push("hit");
      if (state.graphSelected === n.key) cls.push("selected");
      if (state.graphKnown.size && !state.graphKnown.has(n.key)) cls.push("fresh");
      nowKnown.add(n.key);
      const grp = svg("g", { class: cls.join(" "), transform: `translate(${p.x},${p.y})`, tabindex: 0, role: "button" });
      grp.append(svg("rect", { width: NODE_W, height: NODE_H, rx: 7 }));
      const t1 = svg("text", { x: 10, y: 16, class: "n-title" }); t1.textContent = `${ICON[n.type] || "•"} ${String(n.name || "?").split("\\").pop().slice(0, 24)}`;
      const t2 = svg("text", { x: 10, y: 30, class: "n-sub" });
      const alertsLabel = n.alerts.length ? ` · ${n.alerts.length} alert${n.alerts.length > 1 ? "s" : ""}` : "";
      t2.textContent = n.type === "process" ? `pid ${n.pid}` + (n.observed ? (n.ended ? " · exited" : "") : " · start not observed") + alertsLabel : `${n.type} · ${n.events.length}×` + alertsLabel;
      const title = svg("title"); title.textContent = n.command_line || n.name || "";
      grp.append(t1, t2, title);
      grp.addEventListener("click", () => { state.graphSelected = n.key; renderGraph(); });
      g.append(grp);
    }
    state.graphKnown = nowKnown;
    canvas.replaceChildren(defs(), g);
    $("graph-empty").hidden = L.nodes.length > 0;
    const count = state.events.filter((e) => e.host_id === state.graphHost).length;
    $("graph-stats").textContent = state.graphHost ? `${L.nodes.length} nodes · ${L.edges.length} edges · built from ${count} ingested events on ${state.graphHost}` + (scoped ? " · scoped to the alert's process tree" : "") : "";
    if (state.graphSelected && graph.nodes.has(state.graphSelected)) renderNodePanel(graph.nodes.get(state.graphSelected));
  }
  function defs() {
    const d = svg("defs"), m = svg("marker", { id: "arrow", viewBox: "0 0 10 10", refX: 9, refY: 5, markerWidth: 7, markerHeight: 7, orient: "auto-start-reverse" });
    m.append(svg("path", { d: "M0,0 L10,5 L0,10 z", class: "arrowhead" })); d.append(m); return d;
  }
  function renderNodePanel(n) {
    const box = $("graph-node"); if (!box) return;
    const dl = el("dl", { class: "kv" });
    const add = (k, v) => { if (v != null && v !== "") dl.append(el("dt", {}, k), el("dd", { class: "mono" }, String(v))); };
    if (n.type === "process") {
      add("Process", n.name); add("PID", n.pid); add("Executable", n.executable); add("Command line", n.command_line);
      add("Parent (as reported)", n.parent); add("User", n.user); add("Started", n.timestamp); add("Exited", n.ended);
      add("Reported by", (n.sources || []).join(", "));
      add("Observation", n.observed ? "process creation observed" : "creation not observed — known only from " + (n.inferred === "parent" ? "a child's parent fields" : n.inferred === "target" ? "another process accessing it" : "its own activity"));
    } else { add("Type", n.type); add("Value", n.name); }
    add("Events", n.events.length);
    const uniq = [...new Map(n.alerts.map((a) => [a.alert_id, a])).values()];
    box.replaceChildren(el("h3", {}, n.type === "process" ? "Process" : n.type), dl,
      uniq.length ? el("h3", {}, "Alerts on this node") : null,
      uniq.length ? el("ul", { class: "member-list" }, uniq.map((a) => el("li", {}, sevChip(a.severity), el("button", { type: "button", class: "linkish", onclick: () => openAlertById(a.alert_id) }, `${a.rule_id} · ${a.alert_id}`)))) : null,
      el("h3", {}, "Events"), el("ul", { class: "member-list" }, n.events.slice(-8).reverse().map((e) => el("li", { class: "mono" }, `${clock(e.timestamp)} ${e.category}/${txt(e.type)} · ${txt(e.source)}`))));
  }
  function openAlertById(id) { const a = state.alerts.get(String(id)); const r = globalThis.PanopticonConsole; if (a && r && r.openAlert) r.openAlert(a); }

  async function ensureHostEvents(host) {
    try {
      const body = await getJSON("/api/events?limit=200&host_id=" + encodeURIComponent(host));
      for (const e of body.events || []) { const k = e.kind + ":" + e.event_id; if (!state.eventIds.has(k)) { state.eventIds.add(k); state.events.push(e); } }
      state.events.sort(newestFirst);
    } catch { /* the graph shows what is already loaded */ }
  }
  async function openGraph(host, focus, context, link) {
    state.graphLink = link || "host=" + encodeURIComponent(host);
    history.replaceState(null, "", "#graph?" + state.graphLink);
    state.graphHost = host; state.graphFocus = focus; state.graphSelected = null; state.graphKnown = new Set();
    $("graph-all").checked = !focus;
    $("graph-context").replaceChildren(...(context || [el("p", { class: "muted" }, "Live process tree for the selected host. Open the graph from an alert or incident to highlight its attack chain.")]));
    $("graph-node").replaceChildren(el("p", { class: "muted" }, "Select a node to inspect its metadata."));
    delete $("graph-svg").dataset.vb;
    await ensureHostEvents(host);
    for (const d of document.querySelectorAll("dialog[open]")) d.close();
    route();
  }
  function openGraphForAlert(a) {
    const ev = a.evidence || {};
    const pids = new Set([ev["process.pid"]].filter((p) => p != null).map(Number));
    openGraph(a.host_id, { alertIds: new Set([String(a.alert_id)]), pids }, [
      el("div", { class: "story-head" }, sevChip(a.severity), el("strong", {}, txt(a.title || a.rule_id)), el("span", { class: "muted" }, `${txt(a.rule_id)} · ${txt(a.mitre_tactic)} ${txt(a.mitre_technique)} · ${txt(a.host_id)}`)),
      el("p", { class: "muted" }, "Highlighted: the process the alert fired on and its ancestry, resolved from ingested telemetry by host, PID and time.")], "alert=" + encodeURIComponent(a.alert_id));
  }
  async function openGraphForIncident(id) {
    let payload;
    try { payload = await getJSON("/api/incidents/" + encodeURIComponent(id)); } catch (err) { window.alert("Cannot load incident: " + err.message); return; }
    const inc = payload.incident || {}, ev = inc.evidence || {};
    const alerts = Array.isArray(payload.alerts) ? payload.alerts : [];
    const alertIds = new Set(alerts.map((a) => String(a.alert_id || (a.alert || {}).alert_id)));
    const pids = new Set((Array.isArray(ev.stages) ? ev.stages : []).map((s) => Number(s.pid)).filter(Number.isFinite));
    const ctx = [el("div", { class: "story-head" }, sevChip(inc.severity), el("strong", {}, "Incident " + txt(inc.incident_id)), el("span", { class: "muted" }, `${txt(inc.host_id)} · score ${txt(ev.incident_score ?? inc.score)} · ${alertIds.size} member alerts`))];
    if (ev.attack_chain) ctx.push(el("p", { class: "mono chain-text" }, "Engine attack chain: " + ev.attack_chain));
    if (ev.process_lineage) ctx.push(el("p", { class: "mono" }, "Engine lineage: " + ev.process_lineage));
    if (Array.isArray(ev.causal_path) && ev.causal_path.length) ctx.push(el("ol", { class: "causal" }, ev.causal_path.map((l) => el("li", { class: "mono" }, String(l)))));
    ctx.push(el("p", { class: "muted" }, "The engine output above is authoritative. The graph is rebuilt from ingested telemetry with the member alerts' processes highlighted."));
    openGraph(inc.host_id, { alertIds, pids }, ctx, "incident=" + encodeURIComponent(id));
  }

  function wireGraphControls() {
    const canvas = $("graph-svg");
    const vb = () => (canvas.getAttribute("viewBox") || "0 0 640 320").split(" ").map(Number);
    const setVb = (v) => { const s = v.map((n) => Math.round(n)).join(" "); canvas.setAttribute("viewBox", s); canvas.dataset.vb = s; };
    canvas.addEventListener("wheel", (ev) => {
      ev.preventDefault();
      const [x, y, w, h] = vb(), f = ev.deltaY > 0 ? 1.12 : 1 / 1.12, r = canvas.getBoundingClientRect();
      const mx = x + ((ev.clientX - r.left) / r.width) * w, my = y + ((ev.clientY - r.top) / r.height) * h;
      setVb([mx - (mx - x) * f, my - (my - y) * f, w * f, h * f]);
    }, { passive: false });
    let drag = null;
    canvas.addEventListener("mousedown", (ev) => { if (ev.target.closest && ev.target.closest(".node")) return; drag = { x: ev.clientX, y: ev.clientY, vb: vb() }; canvas.classList.add("dragging"); });
    window.addEventListener("mousemove", (ev) => { if (!drag) return; const r = canvas.getBoundingClientRect(); const [x, y, w, h] = drag.vb; setVb([x - ((ev.clientX - drag.x) / r.width) * w, y - ((ev.clientY - drag.y) / r.height) * h, w, h]); });
    window.addEventListener("mouseup", () => { drag = null; canvas.classList.remove("dragging"); });
    $("graph-fit").addEventListener("click", () => { delete canvas.dataset.vb; renderGraph(); });
    $("graph-host").addEventListener("change", async () => { state.graphHost = $("graph-host").value; state.graphFocus = null; state.graphSelected = null; $("graph-all").checked = true; delete canvas.dataset.vb; $("graph-context").replaceChildren(el("p", { class: "muted" }, "Live process tree for " + state.graphHost + ".")); await ensureHostEvents(state.graphHost); renderGraph(); });
    $("graph-all").addEventListener("change", () => { delete canvas.dataset.vb; renderGraph(); });
  }

  // -- response summary + audit ---------------------------------------------------------
  function renderResponseSummary() {
    const box = $("response-summary"); if (!box) return;
    const src = (state.status && state.status.response_actions) || {};
    const agents = state.agents && Array.isArray(state.agents.agents) ? state.agents.agents : [];
    const channels = agents.filter((a) => a.response_channel && a.status !== "revoked");
    box.replaceChildren(
      ...[["PENDING", "awaiting an analyst decision", "medium"], ["AUTHORIZED", "approved and queued for the agent", "ok"], ["REJECTED", "declined by an analyst", null], ["EXPIRED", "not decided within the window", null]]
        .map(([k, sub, tone]) => tile(k.toLowerCase(), String(src[k] || 0), sub, src[k] ? tone : null)),
      el("article", { class: "tile mode " + (channels.length ? "tone-bad" : "tone-warn") },
        el("span", { class: "tile-label" }, "Execution mode"),
        el("strong", {}, channels.length ? "REAL ENDPOINT ACTIONS" : "NOT EXECUTED ON ANY HOST"),
        el("small", {}, channels.length ? `Authorized commands run on: ${channels.map((a) => a.host_id).join(", ")} (agent started with --enable-response).` : "No enrolled agent has opened a response channel, so approvals are recorded and queued but nothing runs on an endpoint.")),
    );
    const tbody = $("audit-body"); if (!tbody) return;
    if (state.auditError) { tbody.replaceChildren(el("tr", {}, el("td", { colspan: 5, class: "muted" }, "Audit history not available: " + state.auditError))); return; }
    const rows = state.audit.slice(-80).reverse();
    tbody.replaceChildren(...(rows.length ? rows.map((r) => el("tr", {},
      el("td", { class: "mono" }, txt(r.sequence)), el("td", { class: "mono" }, txt(r.occurred_at)), el("td", {}, el("strong", {}, txt(r.event_type || r.action || r.kind))),
      el("td", {}, txt(r.actor)), el("td", { class: "mono wrap" }, txt(r.request_id || r.asset_id)))) : [el("tr", {}, el("td", { colspan: 5, class: "muted" }, "No response decisions recorded yet."))]));
  }

  // -- health -----------------------------------------------------------------------------------
  function renderHealth() {
    const box = $("health-cards"); if (!box) return;
    const h = state.health, st = state.status, m = h && h.manager, worker = st && st.detection_worker;
    const card = (title, tone, rows) => el("article", { class: "hcard tone-" + tone }, el("h3", {}, el("span", { class: "dot" }), title), el("dl", { class: "kv" }, rows.flatMap(([k, v]) => [el("dt", {}, k), el("dd", { class: "mono" }, txt(v))])));
    const flat = (o) => Object.entries(o || {}).filter(([, v]) => v == null || typeof v !== "object").map(([k, v]) => [k.replace(/_/g, " "), v]);
    box.replaceChildren(
      card("Console server", h ? "ok" : "bad", h ? [["Status", h.console.status], ["Mode", h.console.mode], ["Uptime", h.console.uptime_seconds + " s"]] : [["Status", "unreachable"]]),
      card("Manager API · liveness", m && m.healthz.status === "ok" ? "ok" : "bad", m ? [["URL", m.url], ["/healthz", `${txt(m.healthz.http_status)} ${txt(m.healthz.status)}`], ["Latency", m.healthz.latency_ms + " ms"], ["Manager uptime", m.healthz.uptime_seconds != null ? m.healthz.uptime_seconds + " s" : null]] : [["Status", "Manager not configured"]]),
      card("Database · readiness", m && m.readyz.status === "ready" ? "ok" : "bad", m ? [["/readyz", `${txt(m.readyz.http_status)} ${txt(m.readyz.status)}`], ["Schema version", m.readyz.schema_version], ["Reason", m.readyz.reason], ["Latency", m.readyz.latency_ms + " ms"]] : [["Status", "not reported"]]),
      card("Detection worker", worker ? (worker.alive ? "ok" : "bad") : "warn", worker ? flat(worker).concat(flat(worker.ml).map(([k, v]) => ["ML · " + k, v])) : [["Status", "not reported"]]),
      card("Persisted records", st ? "ok" : "warn", st ? [
        ...Object.entries(st.events || {}).map(([k, v]) => ["events · " + k, v]),
        ...Object.entries(st.endpoint_records || {}).map(([k, v]) => ["endpoint records · " + k, v]),
        ["alerts", st.alerts], ["incidents open", st.incidents_open],
        ...Object.entries(st.response_actions || {}).map(([k, v]) => ["response actions · " + k, v]),
        ["agents enrolled", st.agents_enrolled], ["last event", st.last_event_at], ["last endpoint record", st.last_record_at]] : [["Status", "not reported"]]),
    );
    const errs = h ? h.recent_errors : [];
    $("health-errors").replaceChildren(...(errs.length ? errs.map((e) => el("tr", {}, el("td", { class: "mono" }, txt(e.at)), el("td", { class: "mono" }, e.path), el("td", {}, String(e.status)), el("td", { class: "mono wrap" }, e.message))) : [el("tr", {}, el("td", { colspan: 4, class: "muted" }, "No Manager errors since the console started."))]));
  }

  // -- hooks into app.js dialogs ------------------------------------------------------------------
  function addDialogButtons() {
    if ($("detail-respond") && !$("detail-graph")) {
      $("detail-respond").after(el("button", { id: "detail-graph", type: "button", class: "primary", onclick: () => {
        const a = state.alerts.get($("detail-id").textContent.trim());
        if (a) openGraphForAlert(a); else window.alert("This alert is not in the loaded alert set yet.");
      } }, "Open attack graph"));
    }
    if ($("incident-chain") && !$("incident-graph")) {
      $("incident-chain").after(el("button", { id: "incident-graph", type: "button", class: "primary", onclick: () => openGraphForIncident($("incident-title").textContent.replace(/^Incident\s+/, "").trim()) }, "Open attack graph"));
    }
  }

  document.addEventListener("DOMContentLoaded", () => {
    if (!$("soc-tiles")) return;
    window.addEventListener("hashchange", route);
    route();
    addDialogButtons();
    wireGraphControls();
    for (const id of ["ev-host", "ev-category", "ev-severity"]) $(id).addEventListener("change", renderEvents);
    $("ev-search").addEventListener("input", renderEvents);
    $("ev-pause").addEventListener("click", () => { state.paused = !state.paused; $("ev-pause").textContent = state.paused ? "Resume stream" : "Pause stream"; $("ev-pause").classList.toggle("primary", state.paused); renderEvents(); });
    $("ev-raw-close").addEventListener("click", () => $("ev-raw-dialog").close());
    pollEvents(); pollSlow();
    setInterval(pollEvents, 2000);
    setInterval(pollSlow, 5000);
  });
})();
