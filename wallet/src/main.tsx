import { render } from 'preact';
import { App } from './ui/app';
import { VERSION } from './version';
import { registerServiceWorker } from './sw/register';

// meshu wallet — offline-first shell. Everything renders locally; no network
// dependency beyond the (optional) gateway transports.

document.title = 'meshu wallet';
const ver = document.getElementById('ver');
if (ver) ver.textContent = VERSION;

render(<App />, document.getElementById('app')!);

registerServiceWorker();
