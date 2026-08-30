/* ──────────────────────────────────────────────────────────────────────────
   Load the application into a DOM shim, and hand back its window.

   There is no `node:vm` here any more, and no script evaluation. Every layer
   the browser runs is an ES module as of Task 2.6 — `src/main.js` is the entry
   point and, since Task 6.1, `js/` is gone entirely — so this
   module IMPORTS the application rather than reading it off disk and running
   it in a sandbox. That is the second half of Task 2.9: a sandbox cannot
   evaluate a module, and pretending otherwise is what forced the migration.

   What the shim still provides is the browser: a document, a window object and
   the §11 primitive set. `src/main.js` builds its platform from
   `globalThis.window`, so this file installs one before importing it. That
   read is the reason `src/main.js` carries the LEGACY_ADAPTER sentinel.

   ── One application per process ─────────────────────────────────────────

   Node's ES module cache is not a dependency-injection mechanism, and this
   file does not pretend it is. Importing `src/main.js` twice returns the SAME
   module instance, wired to the FIRST window — so a second `loadApp()` in one
   process would hand back a window the application never touched, and every
   assertion after it would be measuring nothing. That is the spike's failure
   mode exactly, so it throws instead. A suite that needs two independent
   applications is a suite that needs two processes.

   Test isolation for everything below the entry point comes from calling
   `createAuditRuntime()` again — two runtimes share no cache, no i18n instance
   and no engine — which is what `tests/contract/runtime.test.mjs` asserts and
   what `tools/scoring.test.mjs` uses.

   ── Generated data ──────────────────────────────────────────────────────

   `opts.data` still supplies fixture tables, and it still applies to every
   layer this file constructs itself. It does NOT reach `src/main.js`: the
   entry point imports the production tables, because that is what an entry
   point is. A suite that wants a fixture table builds the layer it is testing
   with `createAuditRuntime()` and injects there — the composition root exists
   so that a consumer can never be handed different data by accident, and the
   entry point is the one place where the data is deliberately fixed.

   This module exists so render, export and interpolate share one definition of
   "the app, loaded".
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
let entryLoaded = false;

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
 * Returns the application's window: `R`, `i18n`, `t`, `__APP_TEST__` and the
 * rest of the surface `src/main.js` installs, plus a few ids the renderer
 * writes into.
 *
 * `opts.app: false` stops before the entry point and constructs only the i18n
 * and render layers, for the interpolation suite, which needs neither a DOM
 * nor an engine. That path takes `opts.data`.
 */
export async function loadApp(opts = {}) {
  const win = createWindow();
  const document = win.document;

  if (opts.app === false) {
    // Production generated data by default; a suite that wants a fixture table
    // says so, and says which. Never a silent substitution.
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
    // The bindings actually in force, published so a suite can prove WHICH
    // table it was handed rather than trusting that it asked for the right one.
    // tests/contract/legacy-shapes.test.mjs reads all three and asserts they
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
  } else {
    if (entryLoaded) {
      throw new Error(
        'browser-harness: src/main.js is already loaded in this process. Node caches ES ' +
        'modules, so a second import would return the FIRST application and this window ' +
        'would never be touched — every assertion after it would measure nothing. ' +
        'Use one process per application, or loadApp({ app: false }) for the lower layers.');
    }
    if (opts.data) {
      throw new Error(
        'browser-harness: opts.data cannot reach src/main.js — the entry point imports the ' +
        'production tables by design. Build the layer under test with createAuditRuntime() ' +
        'and inject there, or pass { app: false }.');
    }
    // src/main.js reads the ambient window to build its platform. This is the
    // read that makes it a marked adapter, and this is where it is satisfied.
    globalThis.window = win;
    entryLoaded = true;
    await import('../../src/main.js');
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
