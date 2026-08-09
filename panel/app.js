/* wifi-zero panel client */
const $ = (s) => document.querySelector(s);
let lastEvent = 0;

async function getJSON(url) {
  const r = await fetch(url);
  return r.json();
}

function badge(state) {
  if (state === "online") return '<span class="badge b-online">online</span>';
  return '<span class="badge b-offline">offline</span>';
}

function renderStats(s) {
  const cards = [
    ["Hosts", s.hosts ?? 0],
    ["Con línea", s.up ?? 0],
    ["APs visibles", s.aps ?? 0],
    ["Puertos", s.port_ips ?? 0],
    ["Eventos", s.events ?? 0],
  ];
  $("#cards").innerHTML = cards
    .map(([l, n]) => `<div class="card"><div class="n">${n}</div><div class="l">${l}</div></div>`)
    .join("");
}

function renderHosts(hosts) {
  const tb = $("#tHosts tbody");
  if (!hosts.length) {
    tb.innerHTML = '<tr><td colspan="6" class="muted">Sin hosts todavía — pulsa «Escanear ahora»</td></tr>';
    return;
  }
  tb.innerHTML = hosts
    .map((h) => {
      const ports = (h.ports || []).map((p) =>
        `<span class="pill" style="background:#1d2b45">${p.port}/${p.service || "?"}</span>`).join(" ");
      return `<tr>
        <td>${h.ip}</td>
        <td class="mac">${h.mac || "—"}</td>
        <td><span class="vendor">${h.vendor || "?"}</span></td>
        <td>${badge(h.state_txt)}</td>
        <td class="ts">${h.last_seen}</td>
        <td>${ports || '<span class="muted">—</span>'}</td>
      </tr>`;
    })
    .join("");
}

function renderAPs(aps) {
  const tb = $("#tAP tbody");
  if (!aps.length) {
    tb.innerHTML = '<tr><td colspan="6" class="muted">Sin APs en vista</td></tr>';
    return;
  }
  tb.innerHTML = aps
    .map((a) => {
      const rssi = a.rssi == null ? "—" : a.rssi;
      return `<tr>
        <td>${a.ssid || "<oculto>"}</td>
        <td class="mac">${a.bssid}</td>
        <td>${a.channel ?? "—"}</td>
        <td class="muted">${a.frequency_mhz ?? "—"}</td>
        <td>${rssi}</td>
        <td><span class="vendor">${a.vendor || "?"}</span></td>
      </tr>`;
    })
    .join("");
}

function renderEvents(events) {
  if (!events.length) return;
  lastEvent = events[events.length - 1].id;
  const list = $("#events");
  events
    .slice(-25)
    .forEach((e) => {
      const li = document.createElement("li");
      li.innerHTML = `<span class="ts">${fmtTs(e.ts)}</span>` +
        `<span class="sev ${e.level}">${e.level.toUpperCase()}</span>&nbsp;${esc(e.message)}`;
      list.prepend(li);
    });
  while (list.children.length > 40) list.lastChild.remove();
}

function esc(s) {
  const d = document.createElement("div");
  d.textContent = s;
  return d.innerHTML;
}

function fmtTs(ts) {
  const d = new Date(ts * 1000);
  return d.toTimeString().slice(0, 8);
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
    renderAPs(aps.aps);
    if (ev.events.length) renderEvents(ev.events);
  } catch (e) {
    console.warn(e);
  }
}

$("#btnScan").addEventListener("click", async () => {
  const btn = $("#btnScan");
  btn.textContent = "…";
  btn.disabled = true;
  try {
    await fetch("/api/scan", { method: "POST" });
    setTimeout(() => { btn.textContent = "⚡ Escanear ahora"; btn.disabled = false; }, 2000);
  } catch (e) { btn.disabled = false; }
});

$("#btnExport").addEventListener("click", () => {
  window.location = "/hosts.csv";
});

refresh();
setInterval(refresh, 10000);