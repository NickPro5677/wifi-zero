/* wifi-zero 2.0 — cliente del panel */
const $ = (s) => document.querySelector(s);
let lastEvent = 0;
let onlyCrit = false;

const token = () => localStorage.getItem("wz_token") || "";

async function getJSON(url) {
  const r = await fetch(url, { headers: token() ? { Authorization: "Bearer " + token() } : {} });
  if (r.status === 401) { location.href = "/login"; throw new Error("401"); }
  return r.json();
}
async function postJSON(url, body) {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...(token() ? { Authorization: "Bearer " + token() } : {}) },
    body: JSON.stringify(body || {}),
  });
  if (r.status === 401) { location.href = "/login"; throw new Error("401"); }
  return r.json();
}

// login check
(async function init() {
  if (location.pathname === "/login") return;
  if (!token()) { location.href = "/login"; return; }
  try { await getJSON("/api/stats"); } catch (e) { return; }
  boot();
})();

function esc(s) { const d = document.createElement("div"); d.textContent = s ?? ""; return d.innerHTML; }
function fmtTs(ts) { return ts ? new Date(ts * 1000).toTimeString().slice(0, 8) : "—"; }

function scoreCell(tier, score) {
  const c = tier === "crit" ? "#ff7a7a" : tier === "warn" ? "#e8c66a" : "#6fce9a";
  return `<span class="score-bar"><i style="width:${score}%;background:${c}"></i></span>
          <span class="tier" style="color:${c}">${score}</span>`;
}

function trustCell(trusted) {
  if (trusted === true) return '<span class="badge b-online">confiable</span>';
  if (trusted === false) return '<span class="badge b-crit">no confiable</span>';
  return '<span class="badge b-warn">desconocido</span>';
}

function renderStats(s) {
  $("#ver").textContent = `v${s.version || "?"}`;
  const cards = [
    ["Hosts", s.hosts ?? 0], ["Con línea", s.up ?? 0], ["APs", s.aps ?? 0],
    ["Eventos", s.events ?? 0], ["Puertos", s.port_ips ?? 0],
  ];
  $("#cards").innerHTML = cards.map(([l, n]) =>
    `<div class="card"><div class="n">${n}</div><div class="l">${l}</div></div>`).join("");
}

function renderHosts(hosts) {
  const tb = $("#tHosts tbody");
  if (!hosts.length) {
    tb.innerHTML = '<tr><td colspan="8" class="muted">Sin hosts — pulsa «Escanear»</td></tr>';
    return;
  }
  const q = ($("#q").value || "").toLowerCase();
  const filtered = hosts.filter((h) =>
    !q || [h.ip, h.mac, h.vendor, h.hostname].join(" ").toLowerCase().includes(q))
    .filter((h) => !onlyCrit || h.tier === "crit");
  tb.innerHTML = filtered.map((h) => {
    const ports = (h.ports || []).map((p) => `<span class="pill">${p.port}/${p.service || ""}</span>`).join("");
    return `<tr>
      <td><a href="/host.html?ip=${h.ip}">${h.ip}</a></td>
      <td class="mac">${h.mac || "—"}</td>
      <td><span class="vendor">${esc(h.vendor) || "?"}</span></td>
      <td>${trustCell(h.trusted)}</td>
      <td>${scoreCell(h.tier, h.score)}</td>
      <td>${h.state ? '<span class="badge b-online">online</span>' : '<span class="badge b-offline">offline</span>'}</td>
      <td class="ts">${h.last_seen}</td>
      <td>${ports || '<span class="muted">—</span>'}</td>
    </tr>`;
  }).join("");
}

function renderAPs(data) {
  const aps = data.aps || [];
  const tb = $("#tAP tbody");
  tb.innerHTML = aps.map((a) => {
    const rssi = a.rssi == null ? "—" : a.rssi;
    const enc = a.encryption || "?";
    const encb = enc === "OPEN" ? '<span class="badge b-crit">OPEN</span>'
      : enc === "WPA3" ? '<span class="badge b-online">WPA3</span>' : `<span class="badge b-warn">${enc}</span>`;
    const b32 = Math.max(0, Math.min(100, Math.round(((a.rssi ?? -100) + 100) * 2.2)));
    return `<tr>
      <td><a href="/chart/signals.svg?bssid=${a.bssid}" target="_blank">${a.ssid || "<oculto>"}</a></td>
      <td class="mac">${a.bssid}</td>
      <td>${a.channel ?? "—"}</td>
      <td>${rssi}</td>
      <td>${encb}</td>
      <td><span class="vendor">${esc(a.vendor) || "?"}</span></td>
      <td>${a.rssi != null ? `<span class="score-bar"><i style="width:${b32}%"></i></span>` : ""}</td>
    </tr>`;
  }).join("");
  const nets = data.networks || [];
  const tn = $("#tNets tbody");
  tn.innerHTML = nets.map((n) => `<tr><td>${esc(n.ssid) || "…"}</td><td class="mac">${n.bssid}</td><td>${n.count}</td></tr>`).join("");
}

function renderEvents(events) {
  if (!events.length) return;
  lastEvent = events[events.length - 1].id;
  const list = $("#events");
  events.slice(-25).forEach((e) => {
    const li = document.createElement("li");
    li.innerHTML = `<span class="ts">${fmtTs(e.ts)}</span><span class="sev ${e.level}">${e.level.toUpperCase()}</span>&nbsp;${esc(e.message)}`;
    list.prepend(li);
  });
  while (list.children.length > 60) list.lastChild.remove();
}

async function refresh() {
  try {
    const [stats, hosts, aps, ev] = await Promise.all([
      getJSON("/api/stats"),
      getJSON("/api/hosts"),
      getJSON("/api/aps"),
      getJSON("/api/events?since=" + lastEvent),
    ]);
    renderStats(stats);
    renderHosts(hosts);
    renderAPs(aps);
    if (ev.events.length) renderEvents(ev.events);
  } catch (e) { console.warn(e); }
}

function boot() {
  $("#btnScan").addEventListener("click", async () => {
    const b = $("#btnScan"); b.disabled = true; b.textContent = "…";
    try { await postJSON("/api/scan"); } catch (e) {}
    setTimeout(() => { b.disabled = false; b.textContent = "⚡ Escanear"; }, 1500);
  });
  $("#btnExport").addEventListener("click", () => {
    if (token()) location.href = "/export/hosts.csv?token=" + encodeURIComponent(token());
  });
  $("#btnLogout").addEventListener("click", () => { localStorage.removeItem("wz_token"); location.href = "/login"; });
  $("#btnOnlyCrit").addEventListener("click", () => {
    onlyCrit = !onlyCrit;
    $("#btnOnlyCrit").style.borderColor = onlyCrit ? "#ff7a7a" : "";
    refresh();
  });
  $("#q").addEventListener("input", () => refresh());

  // SSE en vivo
  try {
    const es = new EventSource("/sse/events?token=" + encodeURIComponent(token()));
    es.addEventListener("event", (ev) => {
      const d = JSON.parse(ev.data);
      const li = document.createElement("li");
      li.innerHTML = `<span class="ts">${fmtTs(d.ts)}</span><span class="sev ${d.level}">${d.level.toUpperCase()}</span>&nbsp;${esc(d.message)}`;
      $("#events").prepend(li);
      $("#liveState").textContent = "●";
    });
    es.onerror = () => {};
  } catch (e) {}

  refresh();
  setInterval(refresh, 8000);
}