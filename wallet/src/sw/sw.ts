// meshu wallet service worker — offline-first, zero build glue.
//
// Install: fetch the shell ('./'), extract every asset URL it references
// (script/link/manifest), precache them + the shell itself. After install the
// app boots fully from cache — the offline contract. This is self-maintaining
// across builds: whatever index.html references gets cached.
//
// Version: stamped per build by vite-plugin-precache-sw (hash of build time),
// so each deploy replaces the cache — never serve a stale shell.

declare const VERSION: string;

// This file compiles as a module-typed service worker; the build emits sw.js.
declare const self: ServiceWorkerGlobalScope;
export {}; // module mode (a bare script would collide with Window typings)

const CACHE = `meshu-wallet-${VERSION}`;

const ASSET_URL_RE =
  /(?:<(?:script|img)[^>]+src="([^"]+)")|(?:<link[^>]+href="([^"]+)")|(?:<a[^>]+href="([^"]+\.webmanifest)")/g;

self.addEventListener('install', (event: ExtendableEvent) => {
  event.waitUntil(
    (async () => {
      const cache = await caches.open(CACHE);
      const urls = new Set<string>(['./', './manifest.webmanifest']);
      try {
        const shell = await fetch('./', { cache: 'no-store' });
        const html = await shell.text();
        for (const m of html.matchAll(ASSET_URL_RE)) {
          const url = m[1] ?? m[2] ?? m[3];
          if (url && !url.startsWith('data:') && !url.startsWith('http')) {
            urls.add(new URL(url, self.location.href).pathname);
          }
        }
      } catch {
        // no network at install — cache what we can; runtime cache-first will
        // fill in on later online loads.
      }
      await cache.addAll([...urls]);
      await self.skipWaiting();
    })(),
  );
});

self.addEventListener('activate', (event: ExtendableEvent) => {
  event.waitUntil(
    caches
      .keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim()),
  );
});

self.addEventListener('fetch', (event: FetchEvent) => {
  const req = event.request;
  if (req.method !== 'GET' || !req.url.startsWith(self.location.origin)) {
    return; // non-same-origin (e.g. future gateway HTTPS) goes to network
  }
  event.respondWith(
    caches.match(req).then(hit => {
      if (hit) return hit;
      return fetch(req)
        .then(resp => {
          const copy = resp.clone();
          caches.open(CACHE).then(c => c.put(req, copy));
          return resp;
        })
        .catch(() => {
          // Offline + not cached: fall back to the shell for navigations.
          if (req.mode === 'navigate') {
            return caches.match('./').then(shell => shell ?? Response.error());
          }
          return Response.error();
        });
    }),
  );
});
