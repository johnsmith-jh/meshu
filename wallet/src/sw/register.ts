/** Register the service worker (no-op where unavailable — e.g. insecure dev). */
export function registerServiceWorker(): void {
  if (!('serviceWorker' in navigator)) {
    return;
  }
  navigator.serviceWorker
    .register('./sw.js', { type: 'module' })
    .catch(err => console.warn('SW registration failed (offline shell disabled):', err));
}
