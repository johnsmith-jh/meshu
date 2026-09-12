import type { Plugin } from 'vite';
import { VERSION } from './src/version';

/**
 * Injects the meshu version string into the service worker source and stamps
 * it with a build id so every deploy produces a distinct SW byte payload —
 * which is what retires the previous cache (never serve a stale shell).
 */
export function precacheSw(): Plugin {
  let isServe = false;

  return {
    name: 'meshu-precache-sw',
    configResolved(cfg) {
      isServe = cfg.command === 'serve';
    },
    transform(code, id) {
      if (!id.endsWith('sw/sw.ts')) return null;
      const stamp = isServe ? ' (dev)' : ` build ${new Date().toISOString()}`;
      return `export const VERSION = ${JSON.stringify(VERSION + stamp)};\n${code}`;
    },
  };
}
