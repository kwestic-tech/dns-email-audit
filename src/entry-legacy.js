/**
 * The bundle's entry point for Phase 1. TEMPORARY — deleted in Phase 6.
 *
 * Seven side-effect imports, in the exact order `index.html` loaded them. No
 * code moves in this file's lifetime and no code is written into it: every one
 * of the seven remains the plain IIFE it is today, still assigning to `window`,
 * still communicating through globals.
 *
 * That is the whole point of Phase 1. The build lands before anything moves, so
 * every later commit is checked against the artifact the browser actually
 * receives rather than against source the browser never sees. Version 0.1 of
 * the plan had these the other way round and could not keep the browser working
 * between its own commits (round 1, F1).
 *
 * **This file must not gain an `export`.** `globalName` is forbidden until
 * §10's stage 3, and the two facts are connected: esbuild assigns the ENTRY
 * POINT'S EXPORTS to `globalName`, so an entry with none plus an early
 * `globalName: 'DnsAudit'` would emit a top-level `var DnsAudit` that
 * overwrites the real object from `js/dns.js:5601` — breaking the application
 * on the very commit that moves the delivery boundary. The spike confirmed the
 * bundle works with `globalName` omitted, which is why it is omitted.
 *
 * The order below is load-bearing and is asserted, not trusted:
 * `tools/build-bundle.mjs` reads it back out of the metafile and compares it
 * against `index.html`'s own script list at v0.5.0.
 */

// Generated data first: the three globals the hand-written code reads at
// evaluation time. `js/dns.js` builds its public-suffix sets from
// `__PUBLIC_SUFFIX_RULES__` while its IIFE runs, so a later import would leave
// them empty.
import '../js/locales-en.js';
import '../js/public-suffixes.js';
import '../js/dkim-selectors.js';

// Then the hand-written layers, in dependency order.
import '../js/i18n.js';
import '../js/render.js';
import '../js/dns.js';
import '../js/app.js';
