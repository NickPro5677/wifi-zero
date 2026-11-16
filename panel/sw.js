/* wifi-zero service worker — cache del shell; network-first para API/SSE */
const CACHE = "wz-shell-v4";
const SHELL = [
  "/",
  "/login",
  "/setup",
  "/app.js",
  "/style.css",
  "/favicon.svg",
  "/manifest.webmanifest",
];

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const url = new URL(e.request.url);
  if (url.origin !== self.location.origin) return;
  // nunca cachear API, SSE ni mutaciones
  if (
    url.pathname.startsWith("/api/") ||
    url.pathname.startsWith("/sse/") ||
    url.pathname.startsWith("/export/") ||
    url.pathname.startsWith("/chart/") ||
    e.request.method !== "GET"
  ) {
    return;
  }
  e.respondWith(
    fetch(e.request)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(e.request, copy));
        return res;
      })
      .catch(() => caches.match(e.request).then((r) => r || caches.match("/")))
  );
});
