/**
 * Construct the ESM i18n and renderer, and install them as the globals the
 * remaining IIFEs read. TEMPORARY — deleted in Phase 6.
 *
 *   LEGACY_ADAPTER
 *
 * `js/dns.js` and `js/app.js` are still IIFEs that reach for `window.i18n`,
 * `window.t`, `window.tp`, `window.tRaw` and `window.R`. They keep working
 * because this runs first — a side-effect module, imported before them, which
 * is a real ordering guarantee where an assignment in the entry point's body
 * would not be: ES imports are hoisted.
 *
 * ONE instance of each, matching the singleton the IIFEs were. The factories
 * exist so `createAuditRuntime()` (Task 2.5) can build a fresh set per runtime
 * and tests can hold two that share nothing; production still gets exactly one
 * per page, which is what keeps the observable behaviour identical.
 *
 * The English bundle is PASSED, never imported by `src/i18n/`. Spec §11.
 */

import { createAuditRuntime } from './runtime.js';
import { createBrowserPlatform } from './platform/browser.js';
import { LOCALE_EN } from './data/locales-en.js';
import { PUBLIC_SUFFIX_RULES } from './data/public-suffixes.js';
import { DKIM_SELECTOR_CATALOG } from './data/dkim-selectors.js';

/**
 * ONE runtime for the page, and one platform inside it.
 *
 * This is the production construction path, and there is only one: no second
 * way to build the application exists, and no branch here runs only for tests.
 * Unit and integration suites call the same `createAuditRuntime()` with fixture
 * data.
 *
 * One runtime means one DoH cache, which is v0.5.0's page lifetime exactly —
 * `tools/scoring.test.mjs:1888-1891` asserts the sibling reuse and
 * `PRIVACY.md:30-33` publishes the fan-out it produces. A second runtime here
 * would halve the cache's reach and change a published figure.
 */
const runtime = createAuditRuntime({
  publicSuffixRules: PUBLIC_SUFFIX_RULES,
  dkimSelectorCatalog: DKIM_SELECTOR_CATALOG,
  englishBundle: LOCALE_EN,
  platform: createBrowserPlatform(window),
});

/* ── LEGACY_ADAPTER: publish the runtime's parts as the globals js/app.js reads ──
 *
 * js/app.js is the last IIFE. It reaches for window.i18n, window.t, window.tp,
 * window.tRaw, window.R and window.DnsAudit, and it boots i18n itself from its
 * own DOMContentLoaded listener — which is why `runtime.mount()` is not called
 * here. Task 2.6 converts that file and this whole block goes with it.
 */
window.i18n = runtime.i18n;
// The app calls t()/tp() a few hundred times, so these stayed convenience
// globals rather than property lookups. Same function identities as before.
window.t = runtime.i18n.t;
window.tp = runtime.i18n.tp;
window.tRaw = runtime.i18n.tRaw;
window.R = runtime.renderer;

// All 95 members until Task 2.8, which removes the unsupported surface as its
// own authorized compatibility delta.
window.DnsAudit = runtime.engine;
