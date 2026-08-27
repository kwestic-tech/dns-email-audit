/**
 * The bundle's entry point for Phase 2. TEMPORARY — deleted in Phase 6.
 *
 * **This file is a marked ADAPTER.** It exists so ES modules and the remaining
 * `window`-attached IIFEs can coexist while the conversion happens one
 * responsibility at a time behind a delivery boundary that already works. Every
 * adapter carries the sentinel below so `tools/` can count them, and Phase 6
 * asserts the count has reached zero.
 *
 *   LEGACY_ADAPTER
 *
 * **This file must not gain an `export`.** `globalName` is forbidden until
 * §10's stage 3, and the two facts are connected: esbuild assigns the ENTRY
 * POINT'S EXPORTS to `globalName`, so an entry with none plus an early
 * `globalName: 'DnsAudit'` would emit a top-level `var DnsAudit` that
 * overwrites the real object from `js/dns.js:5601` — breaking the application
 * on the very commit that moves the delivery boundary. Asserted by
 * `tests/contract/state-matrix.test.mjs`.
 */

/* ── LEGACY_ADAPTER ───────────────────────────────────────────────────────
 * Import order IS evaluation order, and that is the whole reason the global
 * installation lives in its own module rather than in this file's body: ES
 * imports are hoisted, so assignments written here would run AFTER every IIFE
 * below had already evaluated against undefined globals. See
 * src/data/legacy-globals.js.
 */
import './data/legacy-globals.js';

// The hand-written layers, still IIFEs, in their original dependency order.
import '../js/i18n.js';
import '../js/render.js';
import '../js/dns.js';
import '../js/app.js';
