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

import { createI18n } from './i18n/index.js';
import { createRenderer } from './ui/render.js';
import { createDnsEngine } from '../js/dns.js';
import { LOCALE_EN } from './data/locales-en.js';
import { PUBLIC_SUFFIX_RULES } from './data/public-suffixes.js';
import { DKIM_SELECTOR_CATALOG } from './data/dkim-selectors.js';

/**
 * The ambient primitives i18n needs, gathered in one place.
 *
 * Task 2.4 replaces this literal with `browserPlatform` from
 * `src/platform/browser.js`, which names the complete set spec §11 requires.
 * It is written out here rather than deferred because the module cannot reach
 * for these itself any more, and a half-declared dependency is worse than
 * either state.
 */
const platform = {
  document: window.document,
  localStorage: window.localStorage,
  fetch: (...args) => window.fetch(...args),
  navigator: window.navigator,
  console: window.console,
  crypto: window.crypto,
  AbortController: window.AbortController,
  URLSearchParams: window.URLSearchParams,
  setTimeout: (...args) => window.setTimeout(...args),
  clearTimeout: (...args) => window.clearTimeout(...args),
};

const i18n = createI18n({ englishBundle: LOCALE_EN, platform });

window.i18n = i18n;
// The app calls t()/tp() a few hundred times, so these stayed convenience
// globals rather than property lookups. Same function identities as before.
window.t = i18n.t;
window.tp = i18n.tp;
window.tRaw = i18n.tRaw;

// The renderer's dependency on the translator is an argument now, not a
// global it happened to find because index.html loaded i18n first.
window.R = createRenderer(() => window.document, i18n);

/**
 * ONE engine per page, which is what the IIFE was.
 *
 * The DoH cache lives inside it — `dohCache` is closure state now rather than
 * module state — so one engine per page is exactly the page-lifetime reuse
 * `tools/scoring.test.mjs:1888-1891` asserts and `PRIVACY.md:30-33` publishes
 * as "roughly 41 queries for a typical domain". Constructing a second one here
 * would halve the cache's reach and change a published figure. Task 2.5 moves
 * this call into `createAuditRuntime()`, which keeps the same rule.
 */
window.DnsAudit = createDnsEngine({
  publicSuffixRules: PUBLIC_SUFFIX_RULES,
  dkimSelectorCatalog: DKIM_SELECTOR_CATALOG,
  platform,
});
