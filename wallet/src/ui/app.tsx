import { VERSION } from '../version';

/** Mount-and-go UI for Phase 0: proves offline boot + renders the version. */
export function App() {
  return (
    <>
      <div class="card">
        offline-first shell — if you can read this without network, the
        service worker did its job.
      </div>
      <div class="card">build: {VERSION}</div>
    </>
  );
}
