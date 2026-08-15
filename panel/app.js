/* wifi-zero 3.1 — consola interactiva */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const token = () => localStorage.getItem("wz_token") || "";

const state = {
  view: "overview",
  hosts: [],
  aps: [],
  networks: [],
  events: [],
  wl: [],
  stats: {},
  health: {},
  stations: [],
  onlyCrit: false,
  evCrit: false,
  q: "",
  sort: { key: "score", dir: -1 },
  lastEvent: 0,
};

async function getJSON(url) {
  const r = await fetch(url, { headers: token() ? { Authorization: "Bearer " + token() } : {} });
  if (r.status === 401) { location.href = "/login"; throw new Error("401"); }
  if (!r.ok) throw new Error(r.statusText);
  return r.json();
}
async function postJSON(url, body, method = "POST") {
  const r = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json", ...(token() ? { Authorization: "Bearer " + token() } : {}) },
    body: method === "DELETE" ? undefined : JSON.stringify(body || {}),
  });
  if (r.status === 401) { location.href = "/login"; throw new Error("401"); }
  return r.json();
}

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s ?? "";
  return d.innerHTML;
}
function fmtTs(ts) {
  if (!ts) return "—";
  const n = ts > 1e12 ? ts : ts * 1000;
  return new Date(n).toTimeString().slice(0, 8);
}
function fmtWhen(ts) {
  if (!ts) return "—";
  const n = ts > 1e12 ? ts : ts * 1000;
  return new Date(n).toLocaleString();
}
function scoreColor(tier) {
  return tier === "crit" ? "#ff5d73" : tier === "warn" ? "#f0c14b" : "#4ad39a";
}
function scoreCell(tier, score) {
  const c = scoreColor(tier);
  return `<span class="score-bar"><i style="width:${score}%;background:${c}"></i></span>
          <span style="color:${c}">${score}</span>`;
}
function trustCell(t) {
  if (t === true) return '<span class="badge b-online">confiable</span>';
  if (t === false) return '<span class="badge b-crit">no confiable</span>';
  return '<span class="badge b-warn">desconocido</span>';
}
function toast(msg, level = "info") {
  const el = document.createElement("div");
  el.className = "toast " + level;
  el.innerHTML = `<span class="sev ${level}">${level.toUpperCase()}</span>${esc(msg)}`;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), 6000);
}

function setView(name) {
  state.view = name;
  $$(".view").forEach((v) => v.classList.toggle("hidden", v.id !== "view-" + name));
  $$("#nav button").forEach((b) => b.classList.toggle("active", b.dataset.view === name));
}

function applyHostFilter(list) {
  const q = state.q.toLowerCase();
  return list.filter((h) => {
    if (state.onlyCrit && h.tier !== "crit") return false;
    if (!q) return true;
    return [h.ip, h.mac, h.vendor, h.hostname, h.label].join(" ").toLowerCase().includes(q);
  });
}

function renderCards() {
  const s = state.stats;
  const items = [
    ["Hosts", s.hosts ?? 0, ""],
    ["En línea", s.up ?? 0, ""],
    ["Críticos", s.crit_hosts ?? 0, "crit"],
    ["Avisos", s.warn_hosts ?? 0, "warn"],
    ["APs", s.aps ?? 0, ""],
    ["OPEN", s.open_aps ?? 0, (s.open_aps || 0) > 0 ? "warn" : ""],
  ];
  $("#cards").innerHTML = items.map(([l, n, k]) =>
    `<div class="card ${k}"><div class="n">${n}</div><div class="l">${l}</div></div>`).join("");
}

function renderRisk() {
  const hosts = state.hosts;
  const avg = hosts.length ? Math.round(hosts.reduce((a, h) => a + (h.score || 0), 0) / hosts.length) : 0;
  const max = hosts.reduce((m, h) => Math.max(m, h.score || 0), 0);
  const crit = hosts.filter((h) => h.tier === "crit").length;
  const rows = [
    ["Promedio", avg, avg >= 60 ? "crit" : avg >= 30 ? "warn" : "ok"],
    ["Máximo", max, max >= 60 ? "crit" : max >= 30 ? "warn" : "ok"],
    ["Hosts críticos", crit, crit ? "crit" : "ok"],
  ];
  $("#riskOverview").innerHTML = rows.map(([l, v, t]) =>
    `<div class="risk-row"><span>${l}</span>
      <div class="bar"><i style="width:${typeof v === "number" && l !== "Hosts críticos" ? v : Math.min(100, v * 20)}%;background:${scoreColor(t)}"></i></div>
      <strong>${v}</strong></div>`).join("");
}

function renderStation() {
  const st = (state.stations || []).slice(-1)[0] || state.health.station;
  if (!st) { $("#stationBox").innerHTML = '<span class="muted">sin estación</span>'; return; }
  $("#stationBox").innerHTML = `
    <div><strong>${esc(st.ssid) || "—"}</strong></div>
    <div class="mac">${esc(st.bssid || "")}</div>
    <div class="sub">${st.rssi ?? "—"} dBm · ${st.link_speed_mbps ?? "—"} Mbps · ${esc(st.ip || "")}</div>`;
}

function renderHotHosts() {
  const top = applyHostFilter(state.hosts).slice(0, 6);
  $("#hotHosts").innerHTML = top.length ? `<div class="table-wrap"><table><tbody>${
    top.map((h) => `<tr class="clickable" data-ip="${h.ip}">
      <td>${h.ip}</td><td>${scoreCell(h.tier, h.score)}</td>
      <td>${h.state ? '<span class="badge b-online">on</span>' : '<span class="badge b-offline">off</span>'}</td>
      <td class="vendor">${esc(h.vendor) || "?"}</td></tr>`).join("")
  }</tbody></table></div>` : '<p class="muted">Sin hosts — pulsa Escanear</p>';
}

function renderHosts() {
  const tb = $("#tHosts tbody");
  let list = applyHostFilter(state.hosts);
  const { key, dir } = state.sort;
  list = list.slice().sort((a, b) => {
    let va = a[key], vb = b[key];
    if (key === "state" || key === "trusted") { va = Number(!!va); vb = Number(!!vb); }
    if (va == null) va = "";
    if (vb == null) vb = "";
    if (va < vb) return -1 * dir;
    if (va > vb) return 1 * dir;
    return 0;
  });
  if (!list.length) {
    tb.innerHTML = '<tr><td colspan="8" class="muted">Sin hosts — pulsa Escanear</td></tr>';
    return;
  }
  tb.innerHTML = list.map((h) => {
    const ports = (h.ports || []).map((p) => `<span class="pill">${p.port}/${esc(p.service) || ""}</span>`).join("");
    return `<tr class="clickable" data-ip="${h.ip}">
      <td>${h.ip}</td>
      <td class="mac">${h.mac || "—"}</td>
      <td><span class="vendor">${esc(h.vendor) || "?"}</span></td>
      <td>${trustCell(h.trusted)}</td>
      <td>${scoreCell(h.tier, h.score)}</td>
      <td>${h.state ? '<span class="badge b-online">online</span>' : '<span class="badge b-offline">offline</span>'}</td>
      <td class="ts">${fmtWhen(h.last_seen)}</td>
      <td>${ports || '<span class="muted">—</span>'}</td>
    </tr>`;
  }).join("");
}

function channelOf(ap) {
  return ap.channel ?? ap.frequency_mhz ?? "?";
}
function bandOf(ap) {
  const f = ap.frequency_mhz;
  if (!f) return ap.band || "?";
  if (f < 3000) return "2.4";
  if (f < 5925) return "5";
  return "6";
}

function renderHeat() {
  const buckets = {};
  for (const a of state.aps) {
    const ch = a.channel;
    if (ch == null) continue;
    const k = bandOf(a) + ":" + ch;
    buckets[k] = (buckets[k] || 0) + 1;
  }
  const keys = Object.keys(buckets).sort();
  $("#heat").innerHTML = keys.length ? keys.map((k) => {
    const n = buckets[k];
    const a = Math.min(1, n / 4);
    return `<div class="cell" style="background:rgba(62,224,176,${0.12 + a * 0.55})"><b>${k.split(":")[1]}</b><span>${n}</span></div>`;
  }).join("") : '<span class="muted">sin muestras de canal</span>';
}

function renderAPs() {
  const q = state.q.toLowerCase();
  const aps = state.aps.filter((a) =>
    !q || [a.ssid, a.bssid, a.vendor, a.encryption].join(" ").toLowerCase().includes(q));
  $("#tAP tbody").innerHTML = aps.map((a) => {
    const enc = a.encryption || "?";
    const encb = enc === "OPEN" ? '<span class="badge b-crit">OPEN</span>'
      : enc === "WPA3" ? '<span class="badge b-online">WPA3</span>'
      : `<span class="badge b-warn">${esc(enc)}</span>`;
    const twin = a.twin ? ' <span class="badge b-crit">twin</span>' : "";
    return `<tr>
      <td>${esc(a.ssid) || "&lt;oculto&gt;"}${twin}</td>
      <td class="mac">${a.bssid}</td>
      <td>${a.channel ?? "—"}</td>
      <td>${bandOf(a)}</td>
      <td>${a.rssi ?? "—"}</td>
      <td>${encb}</td>
      <td>${scoreCell(a.tier, a.risk || 0)}</td>
      <td class="vendor">${esc(a.vendor) || "?"}</td>
    </tr>`;
  }).join("") || '<tr><td colspan="8" class="muted">sin APs</td></tr>';
  $("#tNets tbody").innerHTML = (state.networks || []).map((n) =>
    `<tr><td>${esc(n.ssid) || "…"}</td><td class="mac">${n.bssid}</td><td>${n.count}</td></tr>`).join("");
}

function renderWL() {
  const tb = $("#tWL tbody");
  const wl = state.wl || [];
  tb.innerHTML = wl.map((w) => `<tr>
    <td class="mac">${esc(w.mac)}</td>
    <td>${esc(w.label) || "—"}</td>
    <td>${w.trusted ? '<span class="badge b-online">confiable</span>' : '<span class="badge b-crit">no confiable</span>'}</td>
    <td><button class="btn" data-del="${esc(w.mac)}">Quitar</button></td>
  </tr>`).join("") || '<tr><td colspan="4" class="muted">vacía — añade MACs conocidas</td></tr>';
}

function evItem(e) {
  return `<li><span class="ts">${fmtTs(e.ts)}</span><span class="sev ${e.level}">${(e.level || "").toUpperCase()}</span>${esc(e.message)}</li>`;
}
function renderEvents() {
  const evs = state.events.filter((e) => !state.evCrit || e.level !== "info").slice(-80).reverse();
  const html = evs.map(evItem).join("") || '<li class="muted">sin eventos</li>';
  $("#events").innerHTML = html;
  $("#eventsMini").innerHTML = evs.slice(0, 12).map(evItem).join("") || '<li class="muted">sin eventos</li>';
}

function renderTopo() {
  const gw = state.hosts.find((h) => (h.label || "").toLowerCase().includes("router") || (h.ip || "").endsWith(".1"));
  const nodes = applyHostFilter(state.hosts).slice(0, 24);
  $("#topoMap").innerHTML = nodes.map((h) =>
    `<div class="node ${h === gw ? "gw" : ""} ${h.tier === "crit" ? "crit" : ""} clickable" data-ip="${h.ip}">
      <div class="ip">${h.ip}</div>
      <div class="vendor">${esc(h.vendor) || h.mac || ""}</div>
      <div>${scoreCell(h.tier, h.score)}</div>
    </div>`).join("") || '<span class="muted">sin mapa</span>';
}

function renderHealth() {
  const h = state.health || {};
  const mon = h.monitor_pid ? `monitor #${h.monitor_pid}` : "monitor off";
  const bat = h.battery_pct != null ? `${h.battery_pct}%${h.charging ? " ⚡" : ""}` : "bat ?";
  $("#healthBox").innerHTML = `${mon}<br>${bat}<br>último scan: ${fmtWhen(h.last_run)}`;
  $("#liveDot").classList.toggle("off", !h.monitor_pid);
  $("#ver").textContent = "schema v" + (state.stats.version || "?");
}

function paint() {
  renderCards();
  renderRisk();
  renderStation();
  renderHotHosts();
  renderHosts();
  renderHeat();
  renderAPs();
  renderWL();
  renderEvents();
  renderTopo();
  renderHealth();
}

function pushEvent(d) {
  if (!d || !d.message) return;
  if (d.id && d.id <= state.lastEvent) return;
  if (d.id) state.lastEvent = d.id;
  state.events.push(d);
  if (state.events.length > 200) state.events = state.events.slice(-200);
  if (d.level === "crit" || d.level === "warn") toast(d.message, d.level);
  renderEvents();
  $("#liveState").textContent = "SSE · vivo";
}

async function openHost(ip) {
  const h = await getJSON("/api/hosts/" + encodeURIComponent(ip));
  if (!h) return;
  $("#dTitle").textContent = h.ip;
  const ports = (h.ports || []).map((p) =>
    `<tr><td>${p.port}</td><td>${esc(p.proto)}</td><td>${esc(p.service)}</td><td>${esc(p.product) || ""}</td></tr>`).join("");
  const ev = (h.events || []).slice(-12).reverse().map(evItem).join("");
  $("#dBody").innerHTML = `
    <p class="sub">${esc(h.mac || "sin MAC")} · ${esc(h.vendor) || "?"} · riesgo ${h.score ?? "?"} (${h.tier || "?"})</p>
    <p>${trustCell(h.trusted)} ${h.state ? '<span class="badge b-online">online</span>' : '<span class="badge b-offline">offline</span>'}</p>
    <p>
      <button class="btn primary" data-act="trust">Confiar</button>
      <button class="btn" data-act="block">No confiable</button>
      <button class="btn ghost" data-act="del">Quitar WL</button>
    </p>
    <img alt="uptime" style="width:100%" src="/chart/uptime.svg?ip=${encodeURIComponent(ip)}&token=${encodeURIComponent(token())}">
    <img alt="riesgo" style="width:100%;margin-top:8px" src="/chart/risk.svg?ip=${encodeURIComponent(ip)}&token=${encodeURIComponent(token())}">
    <h2>Puertos</h2>
    <table><tbody>${ports || '<tr><td class="muted">ninguno</td></tr>'}</tbody></table>
    <h2>Eventos</h2>
    <ul class="ev-log">${ev || '<li class="muted">—</li>'}</ul>
    <p><a href="/host.html?ip=${encodeURIComponent(ip)}">página completa →</a></p>`;
  $("#drawer").classList.remove("hidden");
  $("#drawer").dataset.ip = ip;
  $("#drawer").dataset.mac = h.mac || "";
}

async function refresh() {
  try {
    const d = await getJSON("/api/dashboard");
    state.stats = d.stats || {};
    state.hosts = d.hosts || [];
    state.aps = d.aps || [];
    state.networks = d.networks || [];
    state.stations = d.stations || [];
    state.wl = d.whitelist || [];
    state.health = d.health || {};
    if (d.events && d.events.length) {
      state.events = d.events;
      state.lastEvent = d.events[d.events.length - 1].id || state.lastEvent;
    }
    paint();
  } catch (e) {
    try {
      const [stats, hosts, aps, ev, wl] = await Promise.all([
        getJSON("/api/stats"), getJSON("/api/hosts"), getJSON("/api/aps"),
        getJSON("/api/events?since=" + state.lastEvent), getJSON("/api/whitelist"),
      ]);
      state.stats = stats; state.hosts = hosts; state.aps = aps.aps || [];
      state.networks = aps.networks || []; state.wl = wl.whitelist || [];
      if (ev.events) {
        ev.events.forEach((x) => { if (x.id > state.lastEvent) state.events.push(x); });
        if (ev.events.length) state.lastEvent = ev.events[ev.events.length - 1].id;
      }
      paint();
    } catch (err) { console.warn(err); }
  }
}

async function sseLoop() {
  while (true) {
    try {
      const res = await fetch("/sse/events", { headers: { Authorization: "Bearer " + token() } });
      if (res.status === 401) { location.href = "/login"; return; }
      if (!res.body) { await new Promise((r) => setTimeout(r, 3000)); continue; }
      $("#liveState").textContent = "SSE · conectado";
      const reader = res.body.getReader();
      const dec = new TextDecoder();
      let buf = "";
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += dec.decode(value, { stream: true });
        let i;
        while ((i = buf.indexOf("\n\n")) >= 0) {
          const chunk = buf.slice(0, i);
          buf = buf.slice(i + 2);
          for (const line of chunk.split("\n")) {
            if (line.startsWith("data: ")) {
              try { pushEvent(JSON.parse(line.slice(6))); } catch (e) {}
            }
          }
        }
      }
    } catch (e) { /* reconectar */ }
    $("#liveState").textContent = "SSE · reconectando";
    await new Promise((r) => setTimeout(r, 3000));
  }
}

function boot() {
  $$("#nav button").forEach((b) => b.addEventListener("click", () => setView(b.dataset.view)));
  $("#q").addEventListener("input", () => { state.q = $("#q").value; paint(); });
  $("#onlyCrit").addEventListener("change", () => { state.onlyCrit = $("#onlyCrit").checked; paint(); });
  $("#evCrit").addEventListener("change", () => { state.evCrit = $("#evCrit").checked; paint(); });
  $("#btnScan").addEventListener("click", async () => {
    const b = $("#btnScan"); b.disabled = true; b.textContent = "…";
    try { await postJSON("/api/scan"); toast("Escaneo lanzado", "info"); } catch (e) {}
    setTimeout(() => { b.disabled = false; b.textContent = "Escanear"; refresh(); }, 1800);
  });
  $("#btnExport").addEventListener("click", () => {
    location.href = "/export/hosts.csv?token=" + encodeURIComponent(token());
  });
  $("#btnLogout").addEventListener("click", () => { localStorage.removeItem("wz_token"); location.href = "/login"; });
  $("#dClose").addEventListener("click", () => $("#drawer").classList.add("hidden"));
  document.addEventListener("click", async (e) => {
    const row = e.target.closest("[data-ip]");
    if (row && !e.target.closest("button")) { openHost(row.dataset.ip); return; }
    const del = e.target.closest("[data-del]");
    if (del) {
      await postJSON("/api/whitelist?mac=" + encodeURIComponent(del.dataset.del), {}, "DELETE");
      refresh();
    }
    const act = e.target.closest("[data-act]");
    if (act) {
      const mac = $("#drawer").dataset.mac;
      if (!mac) return;
      if (act.dataset.act === "del") {
        await postJSON("/api/whitelist?mac=" + encodeURIComponent(mac), {}, "DELETE");
      } else {
        await postJSON("/api/whitelist", { mac, trusted: act.dataset.act === "trust", label: "" });
      }
      refresh();
      openHost($("#drawer").dataset.ip);
    }
  });
  $("#tHosts").addEventListener("click", (e) => {
    const th = e.target.closest("th[data-sort]");
    if (!th) return;
    const k = th.dataset.sort;
    if (state.sort.key === k) state.sort.dir *= -1;
    else state.sort = { key: k, dir: k === "score" ? -1 : 1 };
    renderHosts();
  });
  $("#wlForm").addEventListener("submit", async (e) => {
    e.preventDefault();
    const mac = $("#wlMac").value.trim().toLowerCase();
    if (!mac) return;
    await postJSON("/api/whitelist", {
      mac, label: $("#wlLabel").value.trim(), trusted: $("#wlTrust").value === "1",
    });
    $("#wlMac").value = ""; $("#wlLabel").value = "";
    refresh();
  });
  document.addEventListener("keydown", (e) => {
    if (e.target.matches("input,textarea,select")) return;
    if (e.key === "/") { e.preventDefault(); $("#q").focus(); }
    if (e.key === "s") $("#btnScan").click();
    if (e.key === "1") setView("overview");
    if (e.key === "2") setView("hosts");
    if (e.key === "3") setView("radio");
    if (e.key === "4") setView("topo");
    if (e.key === "5") setView("events");
    if (e.key === "Escape") $("#drawer").classList.add("hidden");
  });

  getJSON("/api/topology").then((ifs) => {
    const arr = Array.isArray(ifs) ? ifs : [];
    $("#topoIfs").innerHTML = arr.map((i) =>
      `<span class="pill">${esc(i.iface)} ${esc(i.ip)}/${i.prefix}</span>`).join("") || "";
  }).catch(() => {});

  sseLoop();
  refresh();
  setInterval(refresh, 12000);
}

(async function init() {
  if (location.pathname === "/login") return;
  if (!token()) { location.href = "/login"; return; }
  try { await getJSON("/api/health"); } catch (e) { return; }
  boot();
})();
