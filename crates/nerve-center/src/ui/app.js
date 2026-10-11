// The Nerve center web UI. Plain JavaScript, no build step: the binary
// serves this file as is. Everything shown comes from /api; all changes send
// the CSRF token from /api/session. The page asks the center every two
// seconds and draws again only when the answer changed.
"use strict";

// Lucide icons (ISC licence), inner markup only; icon() wraps them in an svg.
const ICONS = {
  overview: "<rect width=\"7\" height=\"9\" x=\"3\" y=\"3\" rx=\"1\"/><rect width=\"7\" height=\"5\" x=\"14\" y=\"3\" rx=\"1\"/><rect width=\"7\" height=\"9\" x=\"14\" y=\"12\" rx=\"1\"/><rect width=\"7\" height=\"5\" x=\"3\" y=\"16\" rx=\"1\"/>",
  stats: "<path d=\"M3 3v16a2 2 0 0 0 2 2h16\"/><path d=\"M18 17V9\"/><path d=\"M13 17V5\"/><path d=\"M8 17v-3\"/>",
  audit: "<path d=\"M20 13c0 5-3.5 7.5-7.66 8.95a1 1 0 0 1-.67-.01C7.5 20.5 4 18 4 13V6a1 1 0 0 1 1-1c2 0 4.5-1.2 6.24-2.72a1.17 1.17 0 0 1 1.52 0C14.51 3.81 17 5 19 5a1 1 0 0 1 1 1z\"/><path d=\"m9 12 2 2 4-4\"/>",
  settings: "<path d=\"M12.22 2h-.44a2 2 0 0 0-2 2v.18a2 2 0 0 1-1 1.73l-.43.25a2 2 0 0 1-2 0l-.15-.08a2 2 0 0 0-2.73.73l-.22.38a2 2 0 0 0 .73 2.73l.15.1a2 2 0 0 1 1 1.72v.51a2 2 0 0 1-1 1.74l-.15.09a2 2 0 0 0-.73 2.73l.22.38a2 2 0 0 0 2.73.73l.15-.08a2 2 0 0 1 2 0l.43.25a2 2 0 0 1 1 1.73V20a2 2 0 0 0 2 2h.44a2 2 0 0 0 2-2v-.18a2 2 0 0 1 1-1.73l.43-.25a2 2 0 0 1 2 0l.15.08a2 2 0 0 0 2.73-.73l.22-.39a2 2 0 0 0-.73-2.73l-.15-.08a2 2 0 0 1-1-1.74v-.5a2 2 0 0 1 1-1.74l.15-.09a2 2 0 0 0 .73-2.73l-.22-.38a2 2 0 0 0-2.73-.73l-.15.08a2 2 0 0 1-2 0l-.43-.25a2 2 0 0 1-1-1.73V4a2 2 0 0 0-2-2z\"/><circle cx=\"12\" cy=\"12\" r=\"3\"/>",
  server: "<rect width=\"20\" height=\"8\" x=\"2\" y=\"2\" rx=\"2\" ry=\"2\"/><rect width=\"20\" height=\"8\" x=\"2\" y=\"14\" rx=\"2\" ry=\"2\"/><line x1=\"6\" x2=\"6.01\" y1=\"6\" y2=\"6\"/><line x1=\"6\" x2=\"6.01\" y1=\"18\" y2=\"18\"/>",
  menu: "<line x1=\"4\" x2=\"20\" y1=\"12\" y2=\"12\"/><line x1=\"4\" x2=\"20\" y1=\"6\" y2=\"6\"/><line x1=\"4\" x2=\"20\" y1=\"18\" y2=\"18\"/>",
  x: "<path d=\"M18 6 6 18\"/><path d=\"m6 6 12 12\"/>",
  plus: "<path d=\"M5 12h14\"/><path d=\"M12 5v14\"/>",
  trash: "<path d=\"M3 6h18\"/><path d=\"M19 6v14c0 1-1 2-2 2H7c-1 0-2-1-2-2V6\"/><path d=\"M8 6V4c0-1 1-2 2-2h4c1 0 2 1 2 2v2\"/><line x1=\"10\" x2=\"10\" y1=\"11\" y2=\"17\"/><line x1=\"14\" x2=\"14\" y1=\"11\" y2=\"17\"/>",
  sun: "<circle cx=\"12\" cy=\"12\" r=\"4\"/><path d=\"M12 2v2\"/><path d=\"M12 20v2\"/><path d=\"m4.93 4.93 1.41 1.41\"/><path d=\"m17.66 17.66 1.41 1.41\"/><path d=\"M2 12h2\"/><path d=\"M20 12h2\"/><path d=\"m6.34 17.66-1.41 1.41\"/><path d=\"m19.07 4.93-1.41 1.41\"/>",
  moon: "<path d=\"M12 3a6 6 0 0 0 9 9 9 9 0 1 1-9-9Z\"/>",
  monitor: "<rect width=\"20\" height=\"14\" x=\"2\" y=\"3\" rx=\"2\"/><line x1=\"8\" x2=\"16\" y1=\"21\" y2=\"21\"/><line x1=\"12\" x2=\"12\" y1=\"17\" y2=\"21\"/>",
  logout: "<path d=\"M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4\"/><polyline points=\"16 17 21 12 16 7\"/><line x1=\"21\" x2=\"9\" y1=\"12\" y2=\"12\"/>",
  copy: "<rect width=\"14\" height=\"14\" x=\"8\" y=\"8\" rx=\"2\" ry=\"2\"/><path d=\"M4 16c-1.1 0-2-.9-2-2V4c0-1.1.9-2 2-2h10c1.1 0 2 .9 2 2\"/>",
  check: "<path d=\"M20 6 9 17l-5-5\"/>",
  alert: "<circle cx=\"12\" cy=\"12\" r=\"10\"/><line x1=\"12\" x2=\"12\" y1=\"8\" y2=\"12\"/><line x1=\"12\" x2=\"12.01\" y1=\"16\" y2=\"16\"/>",
  refresh: "<path d=\"M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8\"/><path d=\"M21 3v5h-5\"/><path d=\"M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16\"/><path d=\"M8 16H3v5\"/>",
  key: "<path d=\"M2.586 17.414A2 2 0 0 0 2 18.828V21a1 1 0 0 0 1 1h3a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h1a1 1 0 0 0 1-1v-1a1 1 0 0 1 1-1h.172a2 2 0 0 0 1.414-.586l.814-.814a6.5 6.5 0 1 0-4-4z\"/><circle cx=\"16.5\" cy=\"7.5\" r=\".5\" fill=\"currentColor\"/>",
  edit: "<path d=\"M21.174 6.812a1 1 0 0 0-3.986-3.987L3.842 16.174a2 2 0 0 0-.5.83l-1.321 4.352a.5.5 0 0 0 .623.622l4.353-1.32a2 2 0 0 0 .83-.497z\"/><path d=\"m15 5 4 4\"/>",
  link: "<path d=\"M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71\"/><path d=\"M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71\"/>",
  lock: "<rect width=\"18\" height=\"11\" x=\"3\" y=\"11\" rx=\"2\" ry=\"2\"/><path d=\"M7 11V7a5 5 0 0 1 10 0v4\"/>",
  ban: "<circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"m4.9 4.9 14.2 14.2\"/>",
  ok: "<circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"m9 12 2 2 4-4\"/>",
  wait: "<path d=\"M5 22h14\"/><path d=\"M5 2h14\"/><path d=\"M17 22v-4.172a2 2 0 0 0-.586-1.414L12 12l-4.414 4.414A2 2 0 0 0 7 17.828V22\"/><path d=\"M7 2v4.172a2 2 0 0 0 .586 1.414L12 12l4.414-4.414A2 2 0 0 0 17 6.172V2\"/>",
  plug: "<path d=\"M12 22v-5\"/><path d=\"M9 8V2\"/><path d=\"M15 8V2\"/><path d=\"M18 8v5a4 4 0 0 1-4 4h-4a4 4 0 0 1-4-4V8Z\"/>",
  info: "<circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"M12 16v-4\"/><path d=\"M12 8h.01\"/>",
  chev: "<path d=\"m6 9 6 6 6-6\"/>",
  help: "<circle cx=\"12\" cy=\"12\" r=\"10\"/><path d=\"M9.09 9a3 3 0 0 1 5.83 1c0 2-3 3-3 3\"/><path d=\"M12 17h.01\"/>"
};

const SVG = "http://www.w3.org/2000/svg";
const PAGES = {
  overview: { title: "Overview", view: pageOverview },
  stats: { title: "Statistics", view: pageStats },
  audit: { title: "Audit", view: pageAudit },
  help: { title: "Help", view: pageHelp },
  settings: { title: "Settings", view: pageSettings },
};

let csrf = null;
let lastSig = null;
let busy = false;
let down = false;
let settingsRun = 0;
const state = { overview: null, stats: null, audit: null, help: null, pairing: null, settings: null, newToken: null };

const $ = (id) => document.getElementById(id);

function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else if (k === "class") e.className = v;
    else if (v !== undefined && v !== null && v !== false) e.setAttribute(k, v === true ? "" : v);
  }
  for (const k of kids.flat()) {
    if (k === null || k === undefined || k === false) continue;
    e.append(typeof k === "string" || typeof k === "number" ? document.createTextNode(String(k)) : k);
  }
  return e;
}

function icon(name, cls) {
  const s = document.createElementNS(SVG, "svg");
  s.setAttribute("class", "ico" + (cls ? " " + cls : ""));
  fillIcon(s, name);
  return s;
}

function fillIcon(s, name) {
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("aria-hidden", "true");
  s.innerHTML = ICONS[name] || "";
}

for (const s of document.querySelectorAll("svg[data-icon]")) fillIcon(s, s.dataset.icon);

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
  if (r.status === 401) {
    location.assign("/login");
    const err = new Error("Your session ended. Sign in again.");
    err.auth = true;
    throw err;
  }
  if (!r.ok) {
    const why = v.data && v.data.field ? ` (${v.data.field})` : "";
    throw new Error((v.error || r.statusText) + (v.code ? ` [${v.code}]` : "") + why);
  }
  return v;
}

// ---- Formatting ----

function when(ms) {
  return ms ? new Date(ms).toLocaleString() : "never";
}

function ago(ms) {
  if (!ms) return "never";
  const s = Math.max(0, Math.round((Date.now() - ms) / 1000));
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

function duration(ms) {
  const m = Math.round(ms / 60000);
  if (ms < 60000) return `${Math.round(ms / 1000)} s`;
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  return h < 48 ? `${h} h ${m % 60} min` : `${Math.floor(h / 24)} d ${h % 24} h`;
}

function plural(n, one, many) {
  return `${n} ${n === 1 ? one : many || one + "s"}`;
}

// ---- Feedback: toasts and dialogs ----

function notify(text, kind) {
  const box = $("toasts");
  const t = el("div", { class: "toast " + (kind || "ok") }, icon(kind === "error" ? "alert" : "check"), el("span", {}, text));
  box.append(t);
  while (box.children.length > 4) box.firstChild.remove();
  setTimeout(() => t.remove(), kind === "error" ? 7000 : 3500);
}

// One modal: a title, an optional message and text field, Cancel and a
// confirm button. Resolves with the field text (or true), null when cancelled.
function modal(o) {
  return new Promise((resolve) => {
    const d = $("dlg");
    const input = o.field
      ? el("input", { class: "input", type: "text", value: o.field.value || "", required: true, pattern: o.field.pattern, autocomplete: "off", spellcheck: "false" })
      : null;
    let ok = false;
    const form = el("form", { method: "dialog", onsubmit: () => { ok = true; } },
      el("h2", {}, o.title),
      o.message ? el("p", { class: "msg" }, o.message) : null,
      input ? el("label", { class: "field" }, el("span", { class: "label" }, o.field.label), input) : null,
      el("div", { class: "foot" },
        el("button", { type: "button", class: "btn ghost", onclick: () => d.close() }, "Cancel"),
        el("button", { type: "submit", class: "btn " + (o.danger ? "danger" : "primary") }, o.confirm)));
    d.addEventListener("close", () => resolve(ok ? (input ? input.value : true) : null), { once: true });
    d.replaceChildren(form);
    d.showModal();
    if (input) { input.focus(); input.select(); }
  });
}

// Runs a button action: disabled while it works, errors become a toast, and
// the page is asked again afterwards.
function act(fn) {
  return async (ev) => {
    const b = ev.currentTarget;
    b.disabled = true;
    try { await fn(); await tick(); draw(false); }
    catch (e) { if (!e.auth) notify(e.message, "error"); }
    finally { b.disabled = false; }
  };
}

async function copy(text) {
  try {
    await navigator.clipboard.writeText(text);
    notify("Copied.");
  } catch (_) {
    notify("Copying is blocked here. Select the text and copy it by hand.", "error");
  }
}

// ---- Page building blocks ----

function head(ic, title, sub, stats) {
  return el("section", { class: "page-head" },
    el("div", { class: "top" },
      el("div", { class: "tile" }, icon(ic, "lg")),
      el("div", {}, el("h2", {}, title), sub ? el("p", {}, sub) : null)),
    stats ? el("div", { class: "stats-row" }, stats.map(([n, label, tone]) =>
      el("div", { class: "stat" }, el("b", { class: tone ? "tone-" + tone : "" }, n), el("span", {}, label)))) : null);
}

function section(title, sub, action, ...kids) {
  return el("section", { class: "sec" },
    el("div", { class: "sec-head" }, el("div", {}, el("h3", {}, title), sub ? el("p", {}, sub) : null), action),
    kids);
}

function empty(text) {
  return el("div", { class: "empty" }, text);
}

function banner(kind, ic, text) {
  return el("div", { class: "banner " + kind }, icon(ic), el("span", {}, text));
}

function pill(kind, text) {
  return el("span", { class: "pill " + kind }, text);
}

function btn(label, kind, onclick, ic) {
  return el("button", { type: "button", class: "btn sm " + (kind || ""), onclick }, ic ? icon(ic, "sm") : null, label);
}

// ---- Help ----

// The node commands, as the node's own CLI definition lists them: the center
// sends that list (/api/help), nothing here names a command.
function pageHelp() {
  const h = state.help && state.help.node;
  if (!h) return [empty("Loading…")];
  const rows = (args) => el("div", { class: "rows" }, args.map((a) =>
    el("div", {}, el("code", {}, a.name), el("span", { class: "v" }, a.about))));
  return [
    head("help", "Help", "The commands of nerve-node, the program that links a machine to its centers. Run them in a shell on that machine.",
      [[h.commands.length, "commands"]]),
    el("div", { class: "list" },
      h.global.length ? el("div", { class: "card" }, el("p", { class: "meta" }, "Every command takes"), rows(h.global)) : null,
      h.commands.map((c) => el("div", { class: "card", id: "cmd-" + c.name.replace(/ /g, "-") },
        el("div", { class: "card-top" }, el("span", { class: "name mono" }, c.name)),
        el("p", { class: "meta" }, c.about),
        el("code", { class: "code" }, c.usage),
        c.args.length ? rows(c.args) : null))),
  ];
}

// ---- Overview ----

function pageOverview() {
  const o = state.overview;
  if (!o) return [empty("Loading…")];
  const online = o.nodes.filter((n) => n.online).length;
  return [
    head("overview", o.center.name, o.center.url, [
      [`${online}/${o.nodes.length}`, "machines online", online ? "ok" : ""],
      [o.sessions.length, o.sessions.length === 1 ? "session" : "sessions"],
    ]),
    o.alerts.slice(-5).map((a) => banner("warn", "alert", `${when(a.ts)}: ${a.text}`)),
    section("Machines", null, btn("Pair a machine", "primary", act(async () => { state.pairing = await api("POST", "/api/pair"); }), "plus"),
      state.pairing ? pairingCard(state.pairing) : null,
      o.nodes.length ? el("div", { class: "list" }, o.nodes.map(nodeCard)) : empty("No machines yet. Pair one to get started.")),
    section("Sessions", "Harnesses that are connected to this center.", null,
      o.sessions.length ? el("div", { class: "list" }, o.sessions.map(sessionCard)) : empty("No harness is connected.")),
  ];
}

function pairingCard(p) {
  const command = `nerve-node pair '${p.link}'`;
  return el("div", { class: "card", id: "pairing" },
    el("div", { class: "card-top" }, icon("link"), el("span", { class: "name" }, "Pair a machine"),
      el("button", { type: "button", class: "btn ghost icon sm push", "aria-label": "Dismiss", onclick: () => { state.pairing = null; draw(true); } }, icon("x", "sm"))),
    el("p", { class: "meta" }, "On the machine, run:"),
    el("code", { class: "code" }, command),
    el("p", { class: "meta" }, `Code ${p.code}, valid until ${when(p.expires_ms)}, for one machine. ` +
      (p.pin ? `Certificate pin ${p.pin}.` : "Plain HTTP on loopback, no pin.")),
    el("p", { class: "meta faint" }, "A QR code is not offered yet."),
    el("div", { class: "actions" }, btn("Copy command", "", () => copy(command), "copy")));
}

function nodeCard(n) {
  const caps = n.capabilities || [];
  return el("div", { class: "card" },
    el("div", { class: "card-top" },
      el("span", { class: "dot" + (n.online ? " up" : "") }),
      el("span", { class: "name" }, n.name),
      pill(n.online ? "up" : "down", n.online ? n.status || "online" : "offline"),
      el("span", { class: "meta push" }, `${n.platform}/${n.arch}`)),
    el("p", { class: "meta", title: when(n.online ? n.since_ms : n.last_seen_ms) },
      n.online ? `Since ${ago(n.since_ms)}` : `Last seen ${ago(n.last_seen_ms)}`),
    n.going_away ? el("p", { class: "meta" }, `Going away: ${n.going_away}`) : null,
    n.summary ? el("p", {}, n.summary) : null,
    caps.length
      ? el("div", { class: "chips" }, caps.map((c) => el("span", { class: "chip" + (c.exposure === "off" ? " off" : ""), title: `${c.summary || c.id} (${c.exposure})` }, c.id)))
      : el("p", { class: "meta" }, "Offers nothing yet."),
    el("div", { class: "actions" },
      btn("Rename", "ghost", act(async () => {
        const name = await modal({ title: `Rename ${n.name}`, confirm: "Rename", field: { label: "New name (a-z, 0-9 and -)", value: n.name, pattern: "[a-z0-9\\-]+" } });
        if (name && name !== n.name) await api("POST", "/api/nodes/rename", { id: n.id, name });
      }), "edit"),
      btn("Remove", "ghost", act(async () => {
        const yes = await modal({ title: `Remove ${n.name}?`, message: "It has to be paired again to come back.", confirm: "Remove", danger: true });
        if (yes) await api("POST", "/api/nodes/remove", { id: n.id });
      }), "trash")));
}

function sessionCard(s) {
  return el("div", { class: "card" },
    el("div", { class: "card-top" }, icon("plug"), el("span", { class: "name" }, s.client || "Unknown client"),
      pill("", s.transport),
      el("span", { class: "push" }, btn("End", "danger", act(() => api("POST", "/api/sessions/end", { id: s.id }))))),
    el("p", { class: "meta" }, `Since ${ago(s.started_ms)}, ${plural(s.calls, "call")}`),
    s.nodes.length ? el("div", { class: "chips" }, s.nodes.map((n) => el("span", { class: "chip" }, n))) : null,
    el("p", { class: "meta faint mono" }, s.id));
}

// ---- Statistics ----

function pageStats() {
  const s = state.stats;
  if (!s) return [empty("Loading…")];
  const names = Object.keys(s.nodes);
  return [
    head("stats", "Statistics", `Kept for ${plural(s.retention_days, "day")}.`, [[names.length, names.length === 1 ? "machine" : "machines"]]),
    section("All machines", null, null, dayCard(s.total || {})),
    section("Per machine", null, null, names.length
      ? el("div", { class: "list" }, names.map((n) => dayCard(s.nodes[n], n)))
      : empty("No machines yet.")),
  ];
}

function dayCard(d, name) {
  const calls = Object.entries(d.calls || {}).sort((a, b) => b[1].count - a[1].count);
  const errors = Object.entries(d.errors || {}).sort((a, b) => b[1] - a[1]);
  const total = calls.reduce((n, [, c]) => n + c.count, 0);
  const failed = calls.reduce((n, [, c]) => n + c.errors, 0);
  const metrics = [
    [duration(d.online_ms || 0), "Online"], [d.links || 0, "Links"], [d.drops || 0, "Drops"],
    [total, "Calls"], [failed, "Failed calls"],
  ];
  const rows = (title, list, line) => list.length ? [el("p", { class: "meta" }, title), el("div", { class: "rows" }, list.map(([k, v]) =>
    el("div", {}, el("span", { class: "mono" }, k), el("span", { class: "v" }, line(v))))) ] : null;
  return el("div", { class: "card" },
    name ? el("div", { class: "card-top" }, icon("server"), el("span", { class: "name" }, name)) : null,
    el("div", { class: "metrics" }, metrics.map(([v, l]) => el("div", { class: "metric" }, el("b", {}, v.toLocaleString()), el("span", {}, l)))),
    rows("Calls", calls, (c) => `${c.count}${c.errors ? `, ${c.errors} failed` : ""}, avg ${c.count ? Math.round(c.total_ms / c.count) : 0} ms, max ${c.max_ms} ms`),
    rows("Errors", errors, (n) => n));
}

// ---- Audit ----

const DECISIONS = {
  allowed: { ic: "ok", tone: "ok", pill: "up" },
  denied: { ic: "ban", tone: "danger", pill: "down" },
  forbidden: { ic: "lock", tone: "danger", pill: "down" },
};

function pageAudit() {
  const a = state.audit;
  if (!a || !state.overview) return [empty("Loading…")];
  const nodes = Object.fromEntries(state.overview.nodes.map((n) => [n.id, n]));
  const list = a.decisions.slice().reverse();
  const shown = list.slice(0, 200);
  return [
    head("audit", "Audit", "Every decision about a call, newest first.", [[list.length, list.length === 1 ? "decision" : "decisions"]]),
    shown.length ? el("div", { class: "list" }, shown.map((d) => auditRow(d, nodes[d.node_id])), list.length > shown.length
      ? el("p", { class: "meta" }, `Showing the latest ${shown.length} of ${list.length}.`) : null)
      : empty("No decisions yet."),
  ];
}

function auditRow(d, n) {
  const k = DECISIONS[d.decision] || { ic: "info", tone: "", pill: "" };
  const write = n && n.settings_write;
  const why = !n ? "The machine is no longer paired." : !write ? "This machine did not give this center the settings grant." : "";
  const rule = (list, wildcard) => act(async () => {
    const r = await api("POST", "/api/audit/rule", { node_id: d.node_id, list, command: d.target, wildcard });
    notify(`Added ${list} rule: ${r.pattern}`);
  });
  const ruleBtn = (label, kind, list, wildcard) => {
    const b = btn(label, kind, rule(list, wildcard));
    if (!write) { b.disabled = true; b.title = why; }
    return b;
  };
  const cmd = d.cap === "exec" && d.target;
  return el("div", { class: "card audit-row" },
    el("div", { class: "line" },
      el("span", { class: "tone-" + k.tone }, icon(k.ic)),
      el("b", {}, d.node), el("span", { class: "mono" }, `${d.cap}.${d.action}`),
      pill(k.pill, d.decision + (d.by ? ` by ${d.by}` : "") + (d.code ? ` [${d.code}]` : "")),
      el("span", { class: "when", title: when(d.ts) }, ago(d.ts))),
    d.target ? el("code", { class: "target mono" }, d.target) : null,
    cmd ? el("div", { class: "actions" }, ruleBtn("Allow", "", "allow", false), ruleBtn("Allow as wildcard", "", "allow", true), ruleBtn("Deny", "danger", "deny", false)) : null,
    cmd && !write ? el("p", { class: "meta" }, why) : null);
}

// ---- Settings ----

function pageSettings() {
  const s = state.settings;
  if (!s) return [empty("Loading…")];
  s.tokensBox = el("div", { class: "list" });
  drawTokens();
  const name = el("input", { class: "input", type: "text", maxlength: "64", value: s.center.name, id: "c-name" });
  const days = el("input", { class: "input num", type: "number", min: "1", max: "366", value: s.center.retention_days, id: "c-days" });
  return [
    head("settings", "Settings", "The center, the tokens harnesses use, and each machine's own settings."),
    section("Center", null, null, el("div", { class: "card" },
      el("div", { class: "form-row" },
        el("label", { class: "field" }, el("span", { class: "label" }, "Name"), name),
        el("label", { class: "field" }, el("span", { class: "label" }, "Keep statistics for (days)"), days)),
      el("div", { class: "actions" }, el("button", { type: "button", class: "btn primary", onclick: act(async () => {
        await api("POST", "/api/center", { name: name.value, retention_days: Number(days.value) });
        notify("Saved.");
      }) }, "Save")))),
    section("Harness tokens", "A token lets an AI harness call this center over HTTP.", null,
      el("div", { class: "list" }, el("div", { class: "card" }, tokenForm()), s.tokensBox)),
    section("Machines", "Settings kept on each machine itself.", null,
      s.nodes.length ? el("div", { class: "list" }, s.nodes.map(nodeSettings)) : empty("No machines yet.")),
  ];
}

function tokenForm() {
  const label = el("input", { class: "input", type: "text", placeholder: "Label, for example the harness name", "aria-label": "Token label", maxlength: "64" });
  return el("div", { class: "form-row" }, el("label", { class: "field" }, el("span", { class: "label" }, "New token"), label),
    el("button", { type: "button", class: "btn primary", onclick: act(async () => {
      const r = await api("POST", "/api/tokens/create", { label: label.value });
      label.value = "";
      state.newToken = r.token;
      await loadTokens();
    }) }, icon("key", "sm"), "Create"));
}

async function loadTokens() {
  state.settings.tokens = await api("GET", "/api/tokens");
  drawTokens();
}

function drawTokens() {
  const s = state.settings;
  s.tokensBox.replaceChildren(...[
    state.newToken ? el("div", { class: "banner ok" }, icon("key"),
      el("span", {}, "New token, shown once: ", el("code", { class: "mono" }, state.newToken)),
      el("button", { type: "button", class: "btn ghost sm", onclick: () => copy(state.newToken) }, icon("copy", "sm"), "Copy"),
      el("button", { type: "button", class: "btn ghost sm", "aria-label": "Hide", onclick: () => { state.newToken = null; drawTokens(); } }, icon("x", "sm"))) : null,
    s.tokens.length ? s.tokens.map((t) => el("div", { class: "card" }, el("div", { class: "card-top" },
      icon("key"), el("span", { class: "name" }, t.label || "(no label)"), el("span", { class: "meta push" }, `Created ${ago(t.created_ms)}`),
      btn("Delete", "danger", act(async () => { await api("POST", "/api/tokens/delete", { id: t.id }); await loadTokens(); }), "trash"))))
      : el("p", { class: "meta" }, "No tokens yet.")].flat().filter(Boolean));
}

// The sudo password is sealed here, in the browser, for a one-shot offer the
// machine signed (spec/protocol.md §7.4.1): X25519, HKDF-SHA256, AES-256-GCM.
// The center relays the sealed box and cannot open it.
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
async function sealSudo(offer, password) {
  const enc = new TextEncoder();
  const subtle = crypto.subtle;
  const mine = await subtle.generateKey({ name: "X25519" }, false, ["deriveBits"]);
  const theirs = await subtle.importKey("raw", unb64(offer.key), { name: "X25519" }, false, []);
  const shared = await subtle.deriveBits({ name: "X25519", public: theirs }, mine.privateKey, 256);
  const hkdf = await subtle.importKey("raw", shared, "HKDF", false, ["deriveKey"]);
  const key = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode("nerve-sudo-v1"), info: enc.encode(offer.offer) },
    hkdf, { name: "AES-GCM", length: 256 }, false, ["encrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = enc.encode(JSON.stringify({ password, offer: offer.offer, ts: Date.now() }));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: enc.encode(offer.offer) }, key, plain);
  const pub = await subtle.exportKey("raw", mine.publicKey);
  return { offer: offer.offer, key: b64(pub), iv: b64(iv), ct: b64(ct) };
}

// The machine's sudo switch: on only with a password its `sudo -v` accepts.
function sudoSwitch(n) {
  const label = el("span", { class: "meta" }, "Sudo: …");
  const pw = el("input", { type: "password", class: "input", autocomplete: "off", placeholder: "sudo password", "aria-label": `Sudo password of ${n.name}` });
  const show = (on) => { label.textContent = on === "on" ? "Sudo: on" : "Sudo: off"; };
  const on = btn("Turn sudo on", "", act(async () => {
    const password = pw.value;
    pw.value = "";
    if (!password) { notify("Enter the machine's sudo password first.", "error"); return; }
    const offer = await api("POST", "/api/nodes/sudo/offer", { id: n.id });
    const sealed = await sealSudo(offer, password);
    const r = await api("POST", "/api/nodes/sudo", { id: n.id, on: true, sealed });
    show(r.sudo);
    notify(`Sudo is on for ${n.name}: permitted sudo commands run.`);
  }));
  const off = btn("Turn sudo off", "", act(async () => {
    const r = await api("POST", "/api/nodes/sudo", { id: n.id, on: false });
    show(r.sudo);
    notify(`Sudo is off for ${n.name}.`);
  }));
  return { show, row: el("div", { class: "actions" }, label, pw, on, off) };
}

// A machine's own settings are fetched when its card is opened, so the page
// does not ask every machine up front.
function nodeSettings(n) {
  const body = el("div", { class: "body" });
  const card = el("details", { class: "card" },
    el("summary", {}, el("span", { class: "dot" + (n.online ? " up" : "") }), el("span", { class: "name" }, n.name),
      pill(n.online ? "up" : "down", n.online ? "online" : "offline"), icon("chev", "sm chev")),
    body);
  if (!n.settings_write) {
    body.append(el("p", { class: "meta" }, "This machine keeps its settings to itself (settings grant off). Change them with nerve-node on the machine."));
    return card;
  }
  if (!n.online) {
    body.append(el("p", { class: "meta" }, "Offline; its settings can be changed when it is back."));
    return card;
  }
  const area = el("textarea", { class: "json", spellcheck: "false", "aria-label": `Settings of ${n.name}` });
  const msg = el("p", { class: "meta" });
  const sudo = sudoSwitch(n);
  let version = null;
  const load = async () => {
    const s = await api("GET", `/api/nodes/settings?id=${encodeURIComponent(n.id)}`);
    area.value = JSON.stringify(s.document, null, 2);
    version = s.version;
    msg.textContent = `Version ${version}.`;
    sudo.show(s.sudo);
  };
  body.append(sudo.row, area, msg, el("div", { class: "actions" },
    btn("Reload", "", act(load), "refresh"),
    btn("Save", "primary", act(async () => {
      let doc;
      try { doc = JSON.parse(area.value); } catch (e) { msg.textContent = `Not valid JSON: ${e.message}`; return; }
      try {
        const r = await api("POST", "/api/nodes/settings", { id: n.id, document: doc, if_version: version });
        version = r.version;
        msg.textContent = `Saved, version ${version}.`;
        notify(`Saved the settings of ${n.name}.`);
      } catch (e) { if (e.auth) throw e; msg.textContent = `The machine refused: ${e.message}`; }
    }))));
  card.addEventListener("toggle", () => {
    if (card.open && version === null) load().catch((e) => { msg.textContent = e.message; });
  });
  return card;
}

async function loadSettings() {
  const run = ++settingsRun;
  try {
    const [center, tokens, overview] = await Promise.all([api("GET", "/api/center"), api("GET", "/api/tokens"), api("GET", "/api/overview")]);
    if (run !== settingsRun) return;
    state.settings = { center, tokens, nodes: overview.nodes, tokensBox: null };
    if (current() === "settings") draw(true);
  } catch (e) {
    if (!e.auth) notify(e.message, "error");
  }
}

// ---- Drawing and polling ----

function current() {
  const h = location.hash.slice(1);
  return PAGES[h] ? h : "overview";
}

function signature(page) {
  const minute = Math.floor(Date.now() / 60000);
  return JSON.stringify([page, state.overview, page === "stats" ? state.stats : page === "audit" ? state.audit : page === "help" ? !!state.help : null, state.pairing, minute]);
}

function draw(force) {
  const page = current();
  if (page === "settings") {
    if (force) $("page").replaceChildren(...PAGES.settings.view().flat());
    return;
  }
  const sig = signature(page);
  if (!force && sig === lastSig) return;
  lastSig = sig;
  $("page").replaceChildren(...PAGES[page].view().flat());
}

async function tick() {
  if (busy || !csrf) return;
  busy = true;
  try {
    const page = current();
    const jobs = [api("GET", "/api/overview")];
    if (page === "stats") jobs.push(api("GET", "/api/stats"));
    if (page === "audit") jobs.push(api("GET", "/api/audit"));
    // The command list does not change while the center runs: ask once.
    if (page === "help" && !state.help) jobs.push(api("GET", "/api/help"));
    const [o, extra] = await Promise.all(jobs);
    state.overview = o;
    if (page === "stats") state.stats = extra;
    if (page === "audit") state.audit = extra;
    if (page === "help" && extra) state.help = extra;
    if (down) notify("Connected to the center again.");
    down = false;
    draw(false);
  } catch (e) {
    if (!e.auth && !down) notify("Cannot reach the center. Trying again.", "error");
    down = !e.auth;
  } finally {
    busy = false;
  }
}

// ---- Shell: navigation, drawer, theme ----

function setNav(open) {
  $("shell").dataset.nav = open ? "open" : "";
  $("nav-open").setAttribute("aria-expanded", String(open));
  if (open) $("nav-close").focus();
}

function go() {
  const page = current();
  for (const a of document.querySelectorAll("[data-page]")) {
    if (a.dataset.page === page) a.setAttribute("aria-current", "page");
    else a.removeAttribute("aria-current");
  }
  $("top-title").textContent = PAGES[page].title;
  setNav(false);
  state.newToken = null;
  lastSig = null;
  const p = $("page");
  p.classList.remove("enter");
  void p.offsetWidth;
  p.classList.add("enter");
  $("scroll").scrollTop = 0;
  if (page === "settings") {
    state.settings = null;
    draw(true);
    loadSettings();
  } else {
    draw(true);
  }
  tick();
}

$("nav-open").addEventListener("click", () => setNav(true));
$("nav-close").addEventListener("click", () => { setNav(false); $("nav-open").focus(); });
$("scrim").addEventListener("click", () => setNav(false));
for (const a of document.querySelectorAll("[data-page]")) a.addEventListener("click", () => setNav(false));
document.addEventListener("keydown", (ev) => {
  if (ev.key === "Escape" && $("shell").dataset.nav === "open") { setNav(false); $("nav-open").focus(); }
});
window.addEventListener("hashchange", go);
document.addEventListener("visibilitychange", () => { if (!document.hidden) tick(); });

const THEME_KEY = "nerve.theme";
const light = matchMedia("(prefers-color-scheme: light)");

function storedTheme() {
  try { return localStorage.getItem(THEME_KEY) || "system"; } catch (_) { return "system"; }
}

function applyTheme(choice, animate) {
  const root = document.documentElement;
  const dark = choice === "dark" || (choice !== "light" && !light.matches);
  if (animate) {
    root.classList.add("switching");
    setTimeout(() => root.classList.remove("switching"), 220);
  }
  root.dataset.theme = dark ? "dark" : "light";
  const m = document.querySelector('meta[name="theme-color"]');
  if (m) m.content = dark ? "#0a0a0c" : "#fafafb";
  for (const b of document.querySelectorAll("[data-theme-choice]")) {
    b.setAttribute("aria-checked", String(b.dataset.themeChoice === choice));
  }
}

for (const b of document.querySelectorAll("[data-theme-choice]")) {
  b.addEventListener("click", () => {
    try { localStorage.setItem(THEME_KEY, b.dataset.themeChoice); } catch (_) { /* storage blocked: lasts until reload */ }
    applyTheme(b.dataset.themeChoice, true);
  });
}
light.addEventListener("change", () => { if (storedTheme() === "system") applyTheme("system", true); });
applyTheme(storedTheme(), false);

async function start() {
  try {
    const r = await fetch("/api/session", { credentials: "same-origin" });
    const s = await r.json();
    if (!s.logged_in) return location.replace("/login");
    csrf = s.csrf;
    $("signout").hidden = !s.login;
  } catch (_) {
    return $("page").replaceChildren(banner("", "alert", "Cannot reach the center. Reload to try again."));
  }
  go();
  setInterval(() => { if (!document.hidden) tick(); }, 2000);
}

start();
