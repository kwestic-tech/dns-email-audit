/* ──────────────────────────────────────────────────────────────────────────
   UI, rendering and orchestration. The bundle's entry point.

   All user-facing text comes from the i18n layer (src/i18n/index.js →
   locales/*.json). The audit logic lives in js/dns.js and speaks only in
   stable tokens; this file is where tokens become words.

   Nothing here builds markup from strings. Every rendered value goes through
   src/ui/render.js (`R.el`, `R.text`, `R.value`), so a DNS-derived string can
   only land in a text node or an allowlisted attribute. There is deliberately
   no escape helper in this file: leaving one available would invite a new
   concatenation site, and the whole point of 0.2.3 is that no such site can
   exist. The two document builders construct a detached tree and read
   `outerHTML` once — reading is permitted, writing never is.

   ── What Task 2.6 did, and what it deliberately did not ──────────────────

   This file is `js/app.js` with its IIFE wrapper replaced. The 1,801-line body
   below is BYTE-IDENTICAL to the body of `(function (global) { … })(window)`,
   still at its original two-space indent, apart from the three substitutions
   named under "Ambient primitives" and "Boot" below. Nothing moved between
   files, nothing was renamed, and nothing was reindented; the function list
   extracted before and after the conversion is identical, 63 entries.

   Binding the runtime's parts as module-level `const` is what buys that. The
   body called `t`, `tp`, `tRaw`, `i18n`, `R` and `DnsAudit` as globals the
   other IIFEs had installed; it now closes over the same values, taken from
   one `createAuditRuntime()` call, and its own text did not have to change.

   Not side-effect-free, and it is the only file in `src/` that is not. Import
   it and the application constructs itself and wires the page.
   `src/runtime.js` is the side-effect-free half, and `tests/contract/
   runtime.test.mjs` asserts that importing THAT touches no DOM and makes no
   request.

   ── This file is a marked ADAPTER ────────────────────────────────────────

     LEGACY_ADAPTER

   Two things make it one, and both are scheduled:

   • It reads the ambient `window` to build its platform. Nothing else under
     `src/` may — `src/platform/browser.js` takes its window as an argument
     precisely so that the read happens in exactly one place, and that place is
     the entry point.
   • It installs the 24-name legacy global surface (§10's inventory). Those
     names have no consumer left inside the repository as of this commit —
     `js/app.js` was the last one — and they are kept, unchanged, so that this
     commit moves NO browser-visible surface. The two authorized compatibility
     deltas that remove them are Tasks 2.7 and 2.8, recorded ahead of time in
     `tests/fixtures/equivalence/compatibility-deltas.json`. One surface change
     per commit, each one named.

   ── Ambient primitives ───────────────────────────────────────────────────

   The body reaches for nine ambient names — `document`, `fetch`, `setTimeout`,
   `Blob`, `FileReader`, `URL`, `AbortController`, `Intl` and `open`. All nine
   are on spec §11's list, and all nine are bound below FROM THE PLATFORM
   rather than left to resolve against whatever global object the module
   happens to evaluate in. That is not ceremony: under `node:vm` the old IIFE
   resolved them against the sandbox's `window`, and an ES module imported into
   Node resolves them against Node's global object, where `document` does not
   exist. The binding is what lets the same source run in a browser, in the
   bundle and in a suite.

   Two of the nine could not be a plain binding and are named here so neither
   looks like an accident:

   • `open` — `js/app.js:385` called it as `global.open(url, '_blank',
     'noopener')`, a property of the IIFE's window parameter. It is now
     `open(...)`, the platform's bound method. Spec `1.3` added it to §11 for
     this call site; the arguments, including `noopener`, are unchanged and
     `tests/contract/platform.test.mjs` asserts all three reach the window in
     order.
   • `Date` — `js/app.js:1651` rendered the report's timestamp with
     `new Date().toLocaleString(i18n.lang)`. `Date` is a language built-in and
     §11 does not inject those; `platform.formatDateTime(date, locale)` exists
     for exactly this call and performs exactly that call. Substituted here,
     which is what makes the exported report's timestamp a controlled INPUT to
     an equivalence run rather than a field the canonicalizer has to ignore —
     spec Design §8 permits no timestamp wildcard.

   ── Boot ─────────────────────────────────────────────────────────────────

   The `DOMContentLoaded` listener now calls `runtime.mount()` where it called
   `i18n.init()`. Same function, one boot: `mount()` IS `i18n.init()` today,
   and `src/legacy-bridge.js` — which deliberately never called it, to avoid
   booting twice — is retired by this commit. The wiring itself stays in the
   listener; moving it into `src/ui/events.js` is Task 5.6, and doing it here
   would put a UI change inside a wrapper-only conversion. Spec §35.
   ────────────────────────────────────────────────────────────────────────── */

import { createAuditRuntime } from './runtime.js';

import { createBrowserPlatform } from './platform/browser.js';
import { LOCALE_EN } from './data/locales-en.js';
import { PUBLIC_SUFFIX_RULES } from './data/public-suffixes.js';
import { DKIM_SELECTOR_CATALOG } from './data/dkim-selectors.js';

/* ── LEGACY_ADAPTER ───────────────────────────────────────────────────────
 * Import order IS evaluation order. The generated tables are installed as
 * globals by a side-effect module rather than by an assignment in this file's
 * body, because ES imports are hoisted and an assignment written here would
 * run after every import had already evaluated. Nothing reads those globals
 * any more — `js/app.js` was the last reader and it is this file now — so what
 * the import buys today is only the unchanged 24-name surface. Task 2.8
 * removes it with the rest of the transition inputs.
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
 * The six names the body used to read off `window`.
 *
 * Bound as `const` at module top so the body below did not have to change.
 * Same values, same function identities, one instance each — which is what the
 * IIFEs were.
 */
const i18n = runtime.i18n;
const t = i18n.t;
const tp = i18n.tp;
const tRaw = i18n.tRaw;
const R = runtime.renderer;
const DnsAudit = runtime.engine;


/* ── LEGACY_ADAPTER: the 24-name global surface, unchanged ────────────────
 * `global` was the IIFE's parameter and it was `window`. Kept as a binding so
 * the assignments at the foot of the body — the 14 function globals and
 * `__APP_TEST__` — are byte-identical to what they were, and so that Task 2.8
 * removes them as a contiguous, mechanically auditable block.
 *
 * The five wiring names below came from `src/legacy-bridge.js`, which this
 * commit retires. Nothing reads them any more. They are assigned so that this
 * commit changes no browser-visible surface at all; Task 2.8 removes them.
 */
const global = window;
global.i18n = i18n;
global.t = t;
global.tp = tp;
global.tRaw = tRaw;
global.R = R;
/* `window.DnsAudit` is NOT assigned here, and its absence is the Task 2.7
 * delta. esbuild produces that name from this module's exports — §10's
 * "generated boundary" — so the source graph creates 23 globals and the bundle
 * creates 24. Assigning it here as well would put the 95-member engine on the
 * window until the outer `var DnsAudit = …` overwrote it a moment later, which
 * is the clobber spec 0.2 nearly shipped, observed rather than reasoned about:
 * with both in place the window ends up holding the two-member object anyway.
 */


  /* ── The fourteen function globals are GONE, as of Task 2.8 ────────────
   *
   * `startAudit`, `cancelAudit`, `clearAll`, `exportCSV`, `exportHTML`,
   * `filterTable`, `loadExample`, `loadFile`, `openLearnMore`, `setLang`,
   * `showHelp`, `sortTable`, `toggleDetail` and `toggleShowMe` used to be
   * assigned here, under a comment that said "Exposed for the inline onclick
   * handlers in index.html". That comment had been wrong since 0.2.3: the CSP
   * carries no 'unsafe-inline', so `index.html` cannot have an inline handler
   * and does not have one. Every control is wired by `addEventListener` in the
   * `DOMContentLoaded` listener above, which is the only consumer these
   * functions ever had.
   *
   * Their removal is the second of the release's two authorized compatibility
   * deltas — spec §10, and `tests/fixtures/equivalence/compatibility-deltas.json`
   * records it. It is a DECISION, not a discovery: the search proved no
   * repository consumer, and it cannot prove no consumer. A static site can be
   * driven from a console, an extension or an embedding page absent from this
   * checkout, and this project publishes no documented JavaScript API to say
   * otherwise. `analyzeDomain` and `checkConnectivity` are the supported
   * surface from 0.6.0 onward.
   *
   * Everything below this line is still here on purpose. `__APP_TEST__` and the
   * i18n/renderer wiring names are marked adapters with repository consumers
   * and no ESM owner yet; they retire on their owners' schedule, which the
   * manifest's adapterRetirement block records.
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
 * Two members, from a 95-member surface — the only two the body above calls.
 * These are not merely the module's exports: esbuild assigns the ENTRY POINT'S
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
