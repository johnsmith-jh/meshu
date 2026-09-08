# meshu wallet PWA

The browser side of meshu: an Android-first PWA that talks BLE (Web Bluetooth)
to the wallet's MeshCore companion node, and through it over the LoRa mesh to
the meshu gateway daemon.

**Independent from the gateway daemon by design** (POC-WALLET.md §9.3): this
app is served from its own HTTPS origin (a real CA-signed cert is required —
browsers block Web Bluetooth and `fetch()` to plain HTTP). The gateway sits
behind no web server at all for the mesh path; when the wallet has internet it
may additionally POST to the gateway's HTTPS endpoint, but the mesh transport
needs nothing but the radio.

Status: hello-world only — connects to the node, sends APP_START, shows
SELF_INFO. No Cashu logic yet.

## Run it

Serve this folder over HTTPS from any static host (Caddy/nginx, GitHub Pages,
Cloudflare Pages, …) and open it in Android Chrome. No build step.

## Layout

| File | What |
|---|---|
| `index.html` | The whole app (inline JS for now) |
| `manifest.webmanifest` | PWA manifest |
| `sw.js` | Minimal shell cache |