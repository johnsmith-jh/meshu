// minimal shell cache — makes the page installable-ish; hello-world only
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('fetch', e => {
  e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
});