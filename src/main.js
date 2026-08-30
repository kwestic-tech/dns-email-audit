/* ──────────────────────────────────────────────────────────────────────────
   The bundle's entry point, and composition only.

   Three things happen here and nothing else:

     1. build the browser platform from the ambient `window`;
     2. construct ONE audit runtime over it and the three generated tables;
     3. export the two-member supported facade.

   The page itself — every control, every listener, the boot, the renderer and
   the exported artifacts — belongs to `src/ui/`, and the runtime wires it. The
   audit belongs to `src/audit/`. This file knows neither.

   Not side-effect-free, and it is the only file under `src/` that is not.
   Import it and the application constructs itself. `src/runtime.js` is the
   side-effect-free half, and `tests/contract/runtime.test.mjs` asserts that
   importing THAT touches no DOM and makes no request.

   ── It writes no global ─────────────────────────────────────────────────

   **Task 6.2 retired the last adapter.** This file used to publish nine names
   on `window` — `__APP_TEST__`, the i18n and renderer wiring, and the three
   generated tables — and carried the adapter sentinel that counted it. Every
   one of them had a consumer with no ESM owner; each owner exists now, so the
   source graph creates **zero** globals.

   The sentinel string is deliberately not written here, not even in prose:
   `state-matrix.test.mjs` counts literal occurrences, and a file that
   describes the marker still carries it.

   `window.DnsAudit` is still created, and not here: esbuild assigns the ENTRY
   POINT'S EXPORTS to `globalName` — spec §10's generated boundary — so the two
   exports at the foot of this file ARE that global, and they are the only
   supported browser API from 0.6.0 onward.

   Reading the ambient `window` to build the platform is the one ambient read
   left, and it is not a debt: `src/platform/browser.js` takes its window as an
   argument precisely so the read happens in exactly one place, and an entry
   point has to start somewhere.
   ────────────────────────────────────────────────────────────────────────── */

import { createAuditRuntime } from './runtime.js';

import { createBrowserPlatform } from './platform/browser.js';
import { LOCALE_EN } from './data/locales-en.js';
import { PUBLIC_SUFFIX_RULES } from './data/public-suffixes.js';
import { DKIM_SELECTOR_CATALOG } from './data/dkim-selectors.js';

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
