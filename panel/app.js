/* wifi-zero 3.0 — cliente del panel */
const $ = (s) => document.querySelector(s);
let lastEvent = 0;
let onlyCrit = false;
let evCrit = false;

const token = () => localStorage.getItem("wz_token") || "";

async function getJSON(url) {
  const r = await fetch(url, { headers: token() ? { Authorization: "Bearer " + token() } : {} });
  if (r.status === 401) { location.href = "/login"; throw new Error("401"); }
  return r.json();
}
async function postJSON(url, body, method = "POST") {
  const r = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json", ...(token() ? { Authorization: "Bearer " + token() } : {}) },
    body: method === "POST" ? JSON.stringify(body || {}) : undefined,
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
      <td><a href="/host.html?ip=${h.ip}">${h.ip}</a> <a href="/chart/risk.svg?ip=${h.ip}" target="_blank" title="riesgo histórico">📈</a></td>
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

function renderWL(wl) {
  const tb = $("#tWL tbody");
  tb.innerHTML = (wl || []).map((w) => `<tr>
    <td class="mac">${esc(w.mac)}</td>
    <td>${esc(w.label) || "—"}</td>
    <td>${w.trusted ? '<span class="badge b-online">confiable</span>' : '<span class="badge b-crit">no confiable</span>'}</td>
    <td><button class="btn" data-del="${esc(w.mac)}">✕</button></td>
  </tr>`).join("") || '<tr><td colspan="4" class="muted">vacía — añade MACs conocidas para reducir ruido</td></tr>';
  tb.querySelectorAll("[data-del]").forEach((b) =>
    b.addEventListener("click", async () => {
      await postJSON("/api/whitelist?mac=" + encodeURIComponent(b.dataset.del), {}, "DELETE");
      refresh();
    }));
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
    const risk = a.tier === "crit" ? `<span class="badge b-crit">${a.risk ?? "?"}</span>`
      : a.tier === "warn" ? `<span class="badge b-warn">${a.risk ?? "?"}</span>` : `<span class="badge b-online">${a.risk ?? "0"}</span>`;
    return `<tr>
      <td><a href="/chart/signals.svg?bssid=${a.bssid}" target="_blank">${a.ssid || "<oculto>"}</a></td>
      <td class="mac">${a.bssid}</td>
      <td>${a.channel ?? "—"}</td>
      <td>${rssi}</td>
      <td>${encb}</td>
      <td>${risk}</td>
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
  events.filter((e) => !evCrit || e.level !== "info").slice(-25).forEach((e) => {
    const li = document.createElement("li");
    li.innerHTML = `<span class="ts">${fmtTs(e.ts)}</span><span class="sev ${e.level}">${e.level.toUpperCase()}</span>&nbsp;${esc(e.message)}`;
    list.prepend(li);
  });
  while (list.children.length > 60) list.lastChild.remove();
}

function pushEvent(d) {
  if (evCrit && d.level === "info") return;
  const list = $("#events");
  const li = document.createElement("li");
  li.innerHTML = `<span class="ts">${fmtTs(d.ts)}</span><span class="sev ${d.level}">${d.level.toUpperCase()}</span>&nbsp;${esc(d.message)}`;
  list.prepend(li);
  while (list.children.length > 60) list.lastChild.remove();
  $("#liveState").textContent = "●";
}

async function refresh() {
  try {
    const [stats, hosts, aps, ev, wl] = await Promise.all([
      getJSON("/api/stats"),
      getJSON("/api/hosts"),
      getJSON("/api/aps"),
      getJSON("/api/events?since=" + lastEvent),
      getJSON("/api/whitelist"),
    ]);
    renderStats(stats);
    renderHosts(hosts);
    renderAPs(aps);
    renderWL(wl.whitelist);
    if (ev.events.length) renderEvents(ev.events);
  } catch (e) { console.warn(e); }
}

async function sseLoop() {
  // SSE vía fetch+stream: el token viaja en la cabecera Authorization, no en la URL
  while (true) {
    try {
      const res = await fetch("/sse/events", { headers: { Authorization: "Bearer " + token() } });
      if (res.status === 401) { location.href = "/login"; return; }
      if (!res.body) { await new Promise((r) => setTimeout(r, 3000)); continue; }
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
    } catch (e) { /* reconexión */ }
    await new Promise((r) => setTimeout(r, 3000));
  }
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
  $("#btnEvCrit").addEventListener("click", () => {
    evCrit = !evCrit;
    $("#btnEvCrit").style.borderColor = evCrit ? "#ff7a7a" : "";
  });
  $("#q").addEventListener("input", () => refresh());
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

  sseLoop();
  refresh();
  setInterval(refresh, 8000);
}