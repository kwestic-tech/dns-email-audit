/* ──────────────────────────────────────────────────────────────────────────
   Build the application's layers in a DOM shim, and hand them back.

   There is no `node:vm` here and no script evaluation. Every layer the browser
   runs is an ES module — `src/main.js` is the entry point and, since Task 6.1,
   `js/` is gone entirely — so this module IMPORTS what it builds rather than
   reading it off disk and running it in a sandbox. That is the second half of
   Task 2.9: a sandbox cannot evaluate a module, and pretending otherwise is
   what forced the migration.

   What the shim provides is the browser: a document, a window object and the
   §11 primitive set.

   ── Two modes, and they answer different questions ───────────────────────

   | Mode | Builds | Gives back |
   | --- | --- | --- |
   | `loadLayers()` | the i18n, render and legacy-engine layers, test-locally, with injectable generated data | a shim window carrying **the harness's own properties** — `i18n`, `t`, `R`, `DnsAudit` and the three `__…__` table bindings |
   | `loadUi()` | a real production runtime, via `createAuditRuntime()` | its parts — renderer, i18n and the UI object — RETURNED, never published |

   **`loadLayers()`'s window properties are not application globals.** Nothing
   under `src/` writes them; this file does, on a private object, so a suite can
   prove WHICH generated table it was handed rather than trusting that it asked
   for the right one. Calling them the application's surface would be exactly
   backwards: the application publishes one name, and it publishes it only in
   the BUILT artifact.

   ── It does not load the artifact, and no longer pretends to ─────────────

   A third mode used to import `src/main.js` and claim the result carried the
   generated `DnsAudit` global. **It could not.** `globalName` is an esbuild
   wrapper around the built bundle; importing the source entry point returns
   module exports and writes nothing to any window. The branch had zero callers,
   so nothing ever looked at the empty window it produced. Task 6.2a removed it
   with its `globalThis.window` install and the one-per-process guard that
   existed only to protect it.

   Artifact loading belongs to the suites that own it, each measuring the
   generated global where it actually exists: `tests/build/parity.test.mjs`
   evaluates the bundle, the equivalence runner loads it as a subject, and
   `tests/build/file-url.test.mjs` opens it in Chrome.

   Test isolation for everything below the entry point comes from calling
   `createAuditRuntime()` again — two runtimes share no cache, no i18n instance
   and no engine — which is what `tests/contract/runtime.test.mjs` asserts and
   what `tools/scoring.test.mjs` uses.

   ── Generated data ──────────────────────────────────────────────────────

   `opts.data` supplies fixture tables to every layer this file constructs.
   `loadLayers()` takes it directly; `loadUi()` passes it to
   `createAuditRuntime()`, which is the composition root and the one place a
   consumer's data can be substituted on purpose. Nothing can be handed
   different data by accident, which is the whole reason generated tables are
   injected rather than imported by their consumers.

   This module exists so render, export, interpolate and the legacy-shape
   contracts share one definition of each layer.
   ────────────────────────────────────────────────────────────────────────── */

import { createDocument, MarkupSinkError } from './dom-shim.mjs';
import { PUBLIC_SUFFIX_RULES } from '../../src/data/public-suffixes.js';
import { DKIM_SELECTOR_CATALOG } from '../../src/data/dkim-selectors.js';
import { LOCALE_EN } from '../../src/data/locales-en.js';
import { createI18n } from '../../src/i18n/index.js';
import { createRenderer } from '../../src/ui/render.js';
import { createDnsEngine } from './legacy-engine.mjs';
import { createBrowserPlatform } from '../../src/platform/browser.js';
import { createAuditRuntime } from '../../src/runtime.js';

/** Set once the entry point has been imported. See "One application per process". */

/**
 * A window carrying the whole §11 primitive set.
 *
 * Every name has to be here, not just the ones a given suite exercises:
 * `createBrowserPlatform()` binds each method to its owner, so a missing one
 * throws at construction rather than degrading quietly on a path no test takes.
 */
function createWindow() {
  const document = createDocument();
  const win = {
    document,
    navigator: { language: 'en', languages: ['en'] },
    location: { href: 'https://dnsaudit.kwestic.com/' },
    localStorage: {
      getItem: () => null,
      setItem: () => {},
      removeItem: () => {},
    },
    fetch: async () => ({ ok: false }),
    console,
    setTimeout, clearTimeout,
    URL, URLSearchParams, AbortController,
    crypto, Date, Intl,
    Blob: class Blob { constructor(parts, options) { this.parts = parts; this.type = options && options.type; } },
    FileReader: class FileReader {},
    // Navigation is recorded, never performed. A suite that wants to assert on
    // `openLearnMore()` reads win.opened.
    opened: [],
  };
  win.open = (...args) => { win.opened.push(args); return null; };
  win.window = win;
  win.self = win;
  win.globalThis = win;
  return win;
}

/**
 * The layers BENEATH the application, built test-locally with injectable
 * generated data.
 *
 * Renamed from `loadApp()` at Task 6.2a, because the name had stopped being
 * true: its default branch imported `src/main.js` and its documentation said
 * that produced `window.DnsAudit`. **It could not.** `globalName` is an
 * esbuild wrapper around the BUILT artifact; importing the source ESM entry
 * point returns module exports and writes no global at all. The branch had
 * zero callers, so nothing ever observed the empty window it handed back —
 * another green path nothing reached. It is gone, along with the
 * `globalThis.window` install and the one-per-process guard that existed only
 * for it.
 *
 * **Artifact loading belongs to the suites that own it:**
 * `tests/build/parity.test.mjs` evaluates the real bundle, the equivalence
 * runner loads it as a subject, and `tests/build/file-url.test.mjs` opens it in
 * Chrome. Each of those measures the generated global where it actually exists.
 *
 * Production generated data by default; a suite that wants a fixture table says
 * so, and says which. Never a silent substitution.
 */
export async function loadLayers(opts = {}) {
  const win = createWindow();
  const document = win.document;
  const data = {
    publicSuffixRules: PUBLIC_SUFFIX_RULES,
    dkimSelectorCatalog: DKIM_SELECTOR_CATALOG,
    englishBundle: LOCALE_EN,
    ...(opts.data || {}),
  };
  const platform = createBrowserPlatform(win);
  const i18n = createI18n({ englishBundle: data.englishBundle, platform });
  win.i18n = i18n;
  win.t = i18n.t;
  win.tp = i18n.tp;
  win.tRaw = i18n.tRaw;
  // The bindings actually in force, published ON THIS SHIM WINDOW so a suite
  // can prove WHICH table it was handed rather than trusting that it asked for
  // the right one. These are the harness's own properties on a private object;
  // no module under `src/` writes them, and they are not application globals.
  // `tests/contract/legacy-shapes.test.mjs` reads all three and asserts they
  // are independent: substituting English must leave the other two correct.
  win.__PUBLIC_SUFFIX_RULES__ = data.publicSuffixRules;
  win.__DKIM_SELECTOR_CATALOG__ = data.dkimSelectorCatalog;
  win.__I18N_EN__ = data.englishBundle;
  if (opts.render !== false) win.R = createRenderer(() => win.document, i18n);
  if (opts.engine !== false) {
    win.DnsAudit = createDnsEngine({
      publicSuffixRules: data.publicSuffixRules,
      dkimSelectorCatalog: data.dkimSelectorCatalog,
      platform,
    });
  }
  attachAppElements(document);
  return win;
}

/**
 * The ids the application writes into. Created on demand so a test only pays
 * for what it uses, and after the application is built, because nothing in it
 * touches the DOM until a control is used — the shim records listeners and
 * dispatches none, so the `DOMContentLoaded` handler never fires here.
 */
function attachAppElements(document) {
  for (const id of ['tableBody', 'statsGrid', 'progressLog', 'toast', 'deepChecksNotice']) {
    const el = document.createElement(id === 'tableBody' ? 'tbody' : 'div');
    el.id = id;
    document.body.appendChild(el);
  }
  // The deep-checks toggle is a real checkbox, because the code under test
  // reads and writes `.checked` on it.
  const deepChecks = document.createElement('input');
  deepChecks.id = 'optDeepChecks';
  deepChecks.type = 'checkbox';
  deepChecks.checked = true;
  document.body.appendChild(deepChecks);
}

/**
 * The UI, over a shim window, without the entry point or a single global.
 *
 * Task 6.2. `tools/render.test.mjs` and `tools/export.test.mjs` used to reach
 * the renderer's internals through `window.__APP_TEST__` — a marked adapter
 * that existed for exactly those two suites. They import the runtime here
 * instead, which is a direct ESM path with no published name involved, and is
 * what let the last adapters retire.
 *
 * A whole runtime rather than `createUi()` alone, because the UI is built from
 * an i18n layer, a renderer and the facade callbacks, and assembling those by
 * hand in a test would be a second composition root that could drift from the
 * real one. `createAuditRuntime()` is the production path; this uses it.
 */
export async function loadUi(opts = {}) {
  const win = createWindow();
  const platform = createBrowserPlatform(win);
  const runtime = createAuditRuntime({
    publicSuffixRules: PUBLIC_SUFFIX_RULES,
    dkimSelectorCatalog: DKIM_SELECTOR_CATALOG,
    englishBundle: LOCALE_EN,
    ...(opts.data || {}),
    platform,
  });
  attachAppElements(win.document);
  return {
    win,
    document: win.document,
    R: runtime.renderer,
    i18n: runtime.i18n,
    t: runtime.i18n.t,
    tp: runtime.i18n.tp,
    tRaw: runtime.i18n.tRaw,
    ui: runtime.ui,
    runtime,
  };
}

export { MarkupSinkError };

/* ── Tree assertions ────────────────────────────────────────────────────
   The property under test is "every DNS-derived value landed in a text node
   or an allowlisted attribute". These walk a tree and answer that directly,
   which is why no selector engine is needed. */

/** Every text node's data, concatenated in document order. */
export function textOf(node) {
  return node.textContent;
}

/** Every element in the tree, this node included when it is an element. */
export function elements(node) {
  const out = node.nodeType === 1 ? [node] : [];
  for (const n of node.walk()) if (n.nodeType === 1) out.push(n);
  return out;
}

/** Every [name, value] attribute pair in the tree. */
export function attributes(node) {
  const out = [];
  for (const el of elements(node)) {
    el.attributes.forEach(({ name, value }) => out.push([name, value, el]));
    Object.keys(el.dataset).forEach((k) => {
      out.push(['data-' + k.replace(/[A-Z]/g, (m) => '-' + m.toLowerCase()), String(el.dataset[k]), el]);
    });
  }
  return out;
}

/**
 * Where in the tree a needle appears. Returns one of:
 *   'text'      — inside a text node (safe by definition of the DOM)
 *   'attribute' — inside an attribute value
 *   'tagname'   — inside an element's tag name (never acceptable)
 *   'absent'
 */
export function locate(node, needle) {
  for (const el of elements(node)) {
    if (el.localName.includes(needle.toLowerCase())) return 'tagname';
  }
  for (const [, value] of attributes(node)) {
    if (String(value).includes(needle)) return 'attribute';
  }
  return textOf(node).includes(needle) ? 'text' : 'absent';
}

/** True when no attribute in the tree is an event handler. */
export function hasNoEventHandlers(node) {
  return !attributes(node).some(([name]) => /^on/i.test(name));
}
