/* ──────────────────────────────────────────────────────────────────────────
   The bundle's entry point, and composition only.

   Four things happen here and nothing else:

     1. build the browser platform from the ambient `window`;
     2. construct ONE audit runtime over it and the three generated tables;
     3. publish the temporary compatibility globals;
     4. export the two-member supported facade.

   The page itself — every control, every listener, the boot, the renderer and
   the exported artifacts — belongs to `src/ui/`. The audit belongs to
   `src/audit/`. This file knows neither; it builds a runtime, and the runtime
   wires the page.

   Not side-effect-free, and it is the only file under `src/` that is not.
   Import it and the application constructs itself. `src/runtime.js` is the
   side-effect-free half, and `tests/contract/runtime.test.mjs` asserts that
   importing THAT touches no DOM and makes no request.

   ── This file is a marked ADAPTER ────────────────────────────────────────

     LEGACY_ADAPTER

   Two things make it one, and both end in Phase 6:

   • It reads the ambient `window` to build its platform. Nothing else under
     `src/` may — `src/platform/browser.js` takes its window as an argument
     precisely so the read happens in one place, and this is that place. That
     half is not a debt; an entry point has to start somewhere.
   • It installs the remaining compatibility globals: the three generated
     tables, the i18n/renderer wiring names, and `__APP_TEST__`. Each has a
     repository consumer and no ESM owner yet, and Task 6.2 asserts that no
     adapter remains.

   `window.DnsAudit` is NOT assigned here. esbuild assigns the ENTRY POINT'S
   EXPORTS to `globalName` — spec §10's generated boundary — so the two exports
   at the foot of this file ARE that global.
   ────────────────────────────────────────────────────────────────────────── */

import { createAuditRuntime } from './runtime.js';

import { createBrowserPlatform } from './platform/browser.js';
import { LOCALE_EN } from './data/locales-en.js';
import { PUBLIC_SUFFIX_RULES } from './data/public-suffixes.js';
import { DKIM_SELECTOR_CATALOG } from './data/dkim-selectors.js';

/* ── LEGACY_ADAPTER ───────────────────────────────────────────────────────
 * The three generated tables, published as globals for compatibility.
 *
 * Nothing in the application reads them: every consumer takes its data as an
 * argument, which is what lets a test hand the engine a four-rule public
 * suffix list. The module exists to keep the globals present until Phase 6
 * removes the adapter. See its own header for why it is a side-effect import
 * rather than an assignment here.
 */
import './data/legacy-globals.js';

/**
 * ONE runtime for the page, and one platform inside it.
 *
 * The production construction path, and there is only one: no second way to
 * build the application exists and no branch here runs only for tests. Unit
 * and integration suites call the same `createAuditRuntime()`.
 *
 * One runtime means one DoH cache, which is v0.5.0's page lifetime exactly —
 * `tools/scoring.test.mjs:1888-1891` asserts the sibling reuse and
 * `PRIVACY.md:30-33` publishes the fan-out it produces. A second runtime here
 * would halve the cache's reach and change a published figure.
 */
const platform = createBrowserPlatform(window);
const runtime = createAuditRuntime({
  publicSuffixRules: PUBLIC_SUFFIX_RULES,
  dkimSelectorCatalog: DKIM_SELECTOR_CATALOG,
  englishBundle: LOCALE_EN,
  platform,
});

/**
 * The five names published as compatibility globals below.
 *
 * Read off the runtime, which owns the single instance of each. `DnsAudit` is
 * NOT bound here: nothing in this file calls the engine, and a binding with no
 * consumer is a claim that something does.
 */
const i18n = runtime.i18n;
const t = i18n.t;
const tp = i18n.tp;
const tRaw = i18n.tRaw;
const R = runtime.renderer;

/* ── LEGACY_ADAPTER: the i18n and renderer wiring globals ─────────────────
 * Five names, with no consumer inside the application: every module takes what
 * it needs as an argument or an import. They are published because removing a
 * browser-visible name is a compatibility DECISION and this release has made
 * the two it authorized. Task 6.2 removes them and asserts no adapter remains.
 */
const global = window;
global.i18n = i18n;
global.t = t;
global.tp = tp;
global.tRaw = tRaw;
global.R = R;

/* ── LEGACY_ADAPTER: the test surface ─────────────────────────────────────
 * The two authorized compatibility deltas this release makes are recorded in
 * `tests/fixtures/equivalence/compatibility-deltas.json`: the fourteen
 * function globals removed at Task 2.8, and `window.DnsAudit` narrowed to the
 * two-member facade at 2.7. Both were DECISIONS — the search proved no
 * repository consumer, which is not the same as no consumer — and
 * `analyzeDomain` and `checkConnectivity` are the supported surface from
 * 0.6.0 onward.
 */

// Exposed for tools/render.test.mjs and tools/export.test.mjs, which drive
// these directly rather than through a live page. The members come from
// `ui/events.js`; the marked adapter that puts them on the window stays here,
// because a global surface should be written in exactly one place that a
// sentinel scan can find.
global.__APP_TEST__ = runtime.ui;

/**
 * The supported facade, and the only supported browser API from 0.6.0 onward.
 * Spec §10, stage 3.
 *
 * Two members, from a 95-member engine surface — the two the UI calls, and
 * the two anything outside the page can. These are not merely the module's
 * exports: esbuild assigns the ENTRY POINT'S
 * EXPORTS to `globalName`, so this list IS `window.DnsAudit`. A third export
 * added here would widen the supported API of the shipped application.
 *
 * That is why it is checked in rather than inferred. `src/facade.expected.json`
 * names the members, `tests/build/parity.test.mjs` asserts it against BOTH this
 * module's exports and the built bundle's global — exactly, in both directions
 * — and `tests/contract/state-matrix.test.mjs` reads the same file, so the
 * source contract and the artifact contract cannot drift apart.
 */
export const analyzeDomain = runtime.analyzeDomain;
export const checkConnectivity = runtime.checkConnectivity;
