import { defineConfig } from 'vite';
import { resolve } from 'node:path';
import { precacheSw } from './vite-plugin-precache-sw';

// meshu wallet — static build, no runtime CDN, everything vendored.
export default defineConfig({
  base: './',
  resolve: {
    alias: { '@': resolve(__dirname, 'src') },
  },
  plugins: [precacheSw()],
  build: {
    target: 'es2022',
    sourcemap: false,
    outDir: 'dist',
    // Emit sw.js as its own module entry so the precache plugin transforms it.
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        sw: resolve(__dirname, 'src/sw/sw.ts'),
      },
      output: {
        // Keep the SW filename stable for registration; Vite inlines chunks.
        entryFileNames: chunk =>
          chunk.name === 'sw' ? 'sw.js' : 'assets/[name]-[hash].js',
      },
    },
  },
});
