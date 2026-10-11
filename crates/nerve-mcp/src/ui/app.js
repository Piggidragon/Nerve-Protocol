// The Nerve center web UI. Plain JavaScript, no build step: the binary
// serves this file as is. Everything shown comes from /api; all changes send
// the CSRF token from /api/session.
"use strict";

let csrf = null;
let tab = "overview";
let overview = null;

const $ = (id) => document.getElementById(id);

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "onclick") e.addEventListener("click", v);
    else if (k === "class") e.className = v;
    else if (v !== undefined && v !== null && v !== false) e.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) {
    if (k === null || k === undefined) continue;
    e.append(typeof k === "string" || typeof k === "number" ? document.createTextNode(String(k)) : k);
  }
  return e;
}

async function api(method, path, body) {
  const opts = { method, headers: {}, credentials: "same-origin" };
  if (method === "POST") {
    opts.headers["Content-Type"] = "application/json";
    opts.headers["X-Nerve-CSRF"] = csrf || "";
    opts.body = JSON.stringify(body || {});
  }
  const r = await fetch(path, opts);
  let v = {};
  try { v = await r.json(); } catch (_) { /* empty body */ }
  if (r.status === 401) { showLogin(); throw new Error("log in first"); }
  if (!r.ok) {
    const why = v.data && v.data.field ? ` (${v.data.field})` : "";
    throw new Error((v.error || r.statusText) + (v.code ? ` [${v.code}]` : "") + why);
  }
  return v;
}

function when(ms) {
  if (!ms) return "never";
  return new Date(ms).toLocaleString();
}

function showLogin() {
  $("login").hidden = false;
  for (const p of document.querySelectorAll(".pane")) p.hidden = true;
}

async function start() {
  const s = await (await fetch("/api/session", { credentials: "same-origin" })).json();
  if (!s.logged_in) return showLogin();
  csrf = s.csrf;
  $("login").hidden = true;
  show(tab);
  refresh();
  setInterval(refresh, 2000);
}

$("login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const r = await fetch("/api/login", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ password: $("password").value }),
    });
    const v = await r.json();
    if (!r.ok) throw new Error(v.error || r.statusText);
    $("password").value = "";
    start();
  } catch (e) { $("login-error").textContent = e.message; }
});

function show(name) {
  tab = name;
  for (const b of document.querySelectorAll(".tab")) b.classList.toggle("on", b.dataset.tab === name);
  for (const p of document.querySelectorAll(".pane")) p.hidden = p.id !== name;
  refresh();
}
for (const b of document.querySelectorAll(".tab")) b.addEventListener("click", () => show(b.dataset.tab));

async function refresh() {
  if (!csrf) return;
  try {
    if (tab === "overview") renderOverview(await api("GET", "/api/overview"));
    else if (tab === "stats") renderStats(await api("GET", "/api/stats"));
    else if (tab === "audit") {
      overview = await api("GET", "/api/overview");
      renderAudit(await api("GET", "/api/audit"));
    } else if (tab === "settings" && !$("settings").dataset.loaded) loadSettings();
  } catch (e) { console.warn(e); }
}

function act(fn) {
  return async (ev) => {
    const b = ev.currentTarget;
    b.disabled = true;
    try { await fn(); await refresh(); }
    catch (e) { alert(e.message); }
    finally { b.disabled = false; }
  };
}

// ---- Overview ----

function renderOverview(o) {
  overview = o;
  $("center-name").textContent = o.center.name;
  $("alerts").replaceChildren(...o.alerts.slice(-5).map((a) =>
    el("p", { class: "alert" }, `${when(a.ts)}: ${a.text}`)));

  const waiting = [];
  for (const a of o.approvals) {
    waiting.push(el("div", { class: "card" },
      el("div", {}, el("b", {}, `${a.node}: ${a.cap}.${a.action}`), ` (${a.effect}, held by this center)`),
      el("div", { class: "mono" }, a.target),
      el("div", { class: "row" },
        el("button", { class: "primary", onclick: act(() => api("POST", "/api/approvals/center", { id: a.id, answer: "once" })) }, "Allow once"),
        el("button", { onclick: act(() => api("POST", "/api/approvals/center", { id: a.id, answer: "session" })) }, "Allow for this session"),
        el("button", { class: "danger", onclick: act(() => api("POST", "/api/approvals/center", { id: a.id, answer: "deny" })) }, "Deny"))));
  }
  for (const n of o.nodes) {
    for (const a of n.pending_approvals || []) {
      const can = n.approvals_answerable;
      const choices = a.choices || ["once", "deny"];
      const label = { once: "Allow once", session: "Allow for this session", time: "Allow for a while", deny: "Deny" };
      waiting.push(el("div", { class: "card" },
        el("div", {}, el("b", {}, `${n.name}: ${a.cap}.${a.action}`), " (held by the machine)"),
        el("div", { class: "mono" }, a.target || ""),
        (a.reasons || []).length ? el("div", { class: "muted" }, a.reasons.join("; ")) : null,
        can ? el("div", { class: "row" }, choices.map((c) => el("button", {
          class: c === "deny" ? "danger" : c === "once" ? "primary" : "",
          onclick: act(() => api("POST", "/api/approvals/node", {
            node_id: n.id, id: a.id, answer: c,
            minutes: c === "time" ? Math.min(a.max_minutes || 60, 60) : undefined,
          })),
        }, label[c] || c)))
          : el("p", { class: "muted" }, "This machine answers its approvals only locally.")));
    }
  }
  $("approvals").replaceChildren(...(waiting.length ? waiting : [el("p", { class: "muted" }, "Nothing is waiting.")]));

  $("nodes").replaceChildren(...(o.nodes.length ? o.nodes.map(nodeCard) : [el("p", { class: "muted" }, "No machines yet.")]));

  $("sessions").replaceChildren(...(o.sessions.length ? [el("div", { class: "scroll" }, el("table", {},
    el("tr", {}, el("th", {}, "Session"), el("th", {}, "Client"), el("th", {}, "Since"), el("th", {}, "Calls"), el("th", {}, "Machines"), el("th", {}, "")),
    o.sessions.map((s) => el("tr", {},
      el("td", { class: "mono" }, s.id), el("td", {}, `${s.client || "?"} (${s.transport})`),
      el("td", {}, when(s.started_ms)), el("td", {}, s.calls, s.tainted ? " (has read device content)" : ""),
      el("td", {}, s.nodes.join(", ")),
      el("td", {}, el("button", { onclick: act(() => api("POST", "/api/sessions/end", { id: s.id })) }, "End"))))))]
    : [el("p", { class: "muted" }, "No harness is connected.")]));
}

function nodeCard(n) {
  return el("div", { class: "card" },
    el("div", { class: "row" },
      el("span", { class: n.online ? "dot on" : "dot" }),
      el("b", {}, n.name), el("span", { class: "muted" }, `${n.platform}/${n.arch}`),
      el("span", { class: "muted" }, n.online ? `${n.status || "online"} since ${when(n.since_ms)}` : `last seen ${when(n.last_seen_ms)}`)),
    n.going_away ? el("p", { class: "muted" }, `Going away: ${n.going_away}`) : null,
    n.summary ? el("p", {}, n.summary) : null,
    el("p", { class: "muted" }, `Offers: ${n.capabilities.map((c) => c.id).join(", ") || "nothing yet"}`),
    el("div", { class: "row" },
      el("button", { onclick: act(async () => {
        const name = prompt("New name (a-z, 0-9 and -)", n.name);
        if (name && name !== n.name) await api("POST", "/api/nodes/rename", { id: n.id, name });
      }) }, "Rename"),
      el("button", { class: "danger", onclick: act(async () => {
        if (confirm(`Remove ${n.name}? It has to be paired again to come back.`)) await api("POST", "/api/nodes/remove", { id: n.id });
      }) }, "Remove")));
}

$("pair").addEventListener("click", act(async () => {
  const p = await api("POST", "/api/pair");
  const box = $("pairing");
  box.hidden = false;
  box.replaceChildren(el("div", { class: "card" },
    el("p", {}, "On the machine, run:"),
    el("p", { class: "mono" }, `nerve-node pair '${p.link}'`),
    el("p", { class: "muted" }, `Code ${p.code}, valid until ${when(p.expires_ms)}, for one machine. ` +
      (p.pin ? `Certificate pin ${p.pin}.` : "Plain HTTP on loopback, no pin.")),
    el("p", { class: "muted" }, "A QR code is not offered yet.")));
}));

// ---- Statistics ----

function renderStats(s) {
  const rows = Object.entries(s.nodes).map(([name, d]) => {
    const calls = Object.entries(d.calls || {}).map(([k, c]) =>
      `${k}: ${c.count}${c.errors ? ` (${c.errors} failed)` : ""}, avg ${c.count ? Math.round(c.total_ms / c.count) : 0} ms`).join("; ");
    return el("tr", {}, el("td", {}, name), el("td", {}, Math.round((d.online_ms || 0) / 60000), " min"),
      el("td", {}, d.links || 0, " / ", d.drops || 0), el("td", {}, d.approvals_asked || 0), el("td", {}, calls || "none"));
  });
  $("stats-body").replaceChildren(el("p", { class: "muted" }, `Kept for ${s.retention_days} days.`),
    el("div", { class: "scroll" }, el("table", {},
      el("tr", {}, el("th", {}, "Machine"), el("th", {}, "Online"), el("th", {}, "Links / drops"), el("th", {}, "Approvals"), el("th", {}, "Calls")),
      rows)));
}

// ---- Audit ----

function renderAudit(a) {
  const nodes = Object.fromEntries((overview ? overview.nodes : []).map((n) => [n.id, n]));
  const list = a.decisions.slice().reverse();
  $("audit-body").replaceChildren(...(list.length ? [el("div", { class: "scroll" }, el("table", {},
    el("tr", {}, el("th", {}, "When"), el("th", {}, "Machine"), el("th", {}, "Call"), el("th", {}, "Target"), el("th", {}, "Decision"), el("th", {}, "")),
    list.map((d) => {
      const n = nodes[d.node_id];
      const write = n && n.settings_write;
      const cmd = d.cap === "exec" && d.target;
      const why = !n ? "The machine is no longer paired." : !write ? "This machine did not give this center the settings grant." : "";
      const rule = (list_, wildcard) => act(async () => {
        const r = await api("POST", "/api/audit/rule", { node_id: d.node_id, list: list_, command: d.target, wildcard });
        alert(`Added ${list_} rule: ${r.pattern}`);
      });
      return el("tr", {}, el("td", {}, when(d.ts)), el("td", {}, d.node), el("td", {}, `${d.cap}.${d.action}`),
        el("td", { class: "mono" }, d.target || ""), el("td", {}, d.decision, d.by ? ` (${d.by})` : ""),
        el("td", {}, cmd ? el("div", { class: "row" },
          el("button", { disabled: !write, title: why, onclick: rule("allow", false) }, "Allow"),
          el("button", { disabled: !write, title: why, onclick: rule("allow", true) }, "Allow as wildcard"),
          el("button", { class: "danger", disabled: !write, title: why, onclick: rule("deny", false) }, "Deny"),
          !write ? el("span", { class: "muted" }, why) : null) : null));
    })))] : [el("p", { class: "muted" }, "No decisions yet.")]));
}

// ---- Settings ----

const EFFECTS = ["read", "sense", "write", "actuate", "execute"];

async function loadSettings() {
  $("settings").dataset.loaded = "1";
  const c = await api("GET", "/api/center");
  $("c-name").value = c.name;
  $("c-days").value = c.retention_days;
  $("c-effects").replaceChildren(...EFFECTS.map((e) => el("label", {}, `${e} `,
    (() => {
      const s = el("select", { "data-effect": e }, ...["on", "ask", "off"].map((r) => el("option", { value: r }, r)));
      s.value = c.effects[e] || "on";
      return s;
    })())));
  await loadTokens();
  const o = await api("GET", "/api/overview");
  $("node-settings").replaceChildren(...(o.nodes.length ? o.nodes.map(nodeSettings) : [el("p", { class: "muted" }, "No machines yet.")]));
}

$("center-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const effects = {};
  for (const s of document.querySelectorAll("[data-effect]")) effects[s.dataset.effect] = s.value;
  try {
    await api("POST", "/api/center", { name: $("c-name").value, retention_days: Number($("c-days").value), effects });
    $("c-saved").textContent = "Saved.";
  } catch (e) { $("c-saved").textContent = e.message; }
});

async function loadTokens() {
  const t = await api("GET", "/api/tokens");
  $("tokens").replaceChildren(...t.map((x) => el("div", { class: "row" }, el("span", {}, x.label), el("span", { class: "muted" }, when(x.created_ms)),
    el("button", { class: "danger", onclick: act(async () => { await api("POST", "/api/tokens/delete", { id: x.id }); await loadTokens(); }) }, "Delete"))));
}

$("token-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    const r = await api("POST", "/api/tokens/create", { label: $("t-label").value });
    $("t-new").textContent = `New token (shown once): ${r.token}`;
    $("t-label").value = "";
    await loadTokens();
  } catch (e) { $("t-new").textContent = e.message; }
});

function nodeSettings(n) {
  const box = el("div", { class: "card" }, el("b", {}, n.name));
  if (!n.settings_write) {
    box.append(el("p", { class: "muted" }, "This machine keeps its settings to itself (settings grant off). Change them with nerve-node on the machine."));
    return box;
  }
  if (!n.online) {
    box.append(el("p", { class: "muted" }, "Offline; its settings can be changed when it is back."));
    return box;
  }
  const area = el("textarea", { spellcheck: "false" });
  const msg = el("p", { class: "muted" });
  let version = null;
  const load = async () => {
    const s = await api("GET", `/api/nodes/settings?id=${encodeURIComponent(n.id)}`);
    area.value = JSON.stringify(s.document, null, 2);
    version = s.version;
    msg.textContent = `Version ${version}.`;
  };
  box.append(area, el("div", { class: "row" },
    el("button", { onclick: act(load) }, "Reload"),
    el("button", { class: "primary", onclick: act(async () => {
      let doc;
      try { doc = JSON.parse(area.value); } catch (e) { msg.textContent = `Not valid JSON: ${e.message}`; return; }
      try {
        const r = await api("POST", "/api/nodes/settings", { id: n.id, document: doc, if_version: version });
        version = r.version;
        msg.textContent = `Saved, version ${version}.`;
      } catch (e) { msg.textContent = `The machine refused: ${e.message}`; }
    }) }, "Save")), msg);
  load().catch((e) => { msg.textContent = e.message; });
  return box;
}

start();
