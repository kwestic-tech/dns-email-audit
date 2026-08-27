/* ──────────────────────────────────────────────────────────────────────────
   Load the browser-side code into a node:vm sandbox backed by the DOM shim.

   The hand-written files are still plain IIFEs that attach to `window`, so
   there is nothing to mock and no bundler involved for them. What changed in
   0.6.0 is the generated data: the public suffix list, the DKIM selector
   catalog and the English bundle are ES modules under `src/data/` now, and
   they are INJECTED into the sandbox here rather than evaluated as scripts.

   That is the composition root's rule arriving early, and it is the point. A
   consumer that imports its own generated data can never be handed different
   data by a test — which is precisely how the scoring suite came to report
   `1535 passed, 0 failed` against a public suffix list that had been swapped
   underneath it. `opts.data` is how a suite supplies a fixture table instead.

   This module exists so render, export and interpolate tests share one
   definition of "the app, loaded".
   ────────────────────────────────────────────────────────────────────────── */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

import { createDocument, MarkupSinkError } from './dom-shim.mjs';
import { PUBLIC_SUFFIX_RULES } from '../../src/data/public-suffixes.js';
import { DKIM_SELECTOR_CATALOG } from '../../src/data/dkim-selectors.js';
import { LOCALE_EN } from '../../src/data/locales-en.js';
import { createI18n } from '../../src/i18n/index.js';
import { createRenderer } from '../../src/ui/render.js';

export const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

/**
 * Returns the sandbox's `window`, with i18n, R and the app loaded, plus a few
 * ids the renderer writes into.
 *
 * `opts.files` overrides which browser files are loaded, for the interpolate
 * tests that only need js/i18n.js.
 */
export function loadApp(opts = {}) {
  const document = createDocument();
  // Production generated data by default; a suite that wants a fixture table
  // says so, and says which. Never a silent substitution.
  const data = {
    publicSuffixRules: PUBLIC_SUFFIX_RULES,
    dkimSelectorCatalog: DKIM_SELECTOR_CATALOG,
    englishBundle: LOCALE_EN,
    ...(opts.data || {}),
  };
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
    setTimeout,
    clearTimeout,
    URL,
    AbortController,
    URLSearchParams,
  };
  win.window = win;
  win.self = win;
  win.globalThis = win;
  // Injected before anything evaluates: js/i18n.js reads __I18N_EN__ and
  // js/dns.js builds its public-suffix sets while their IIFEs run.
  win.__PUBLIC_SUFFIX_RULES__ = data.publicSuffixRules;
  win.__DKIM_SELECTOR_CATALOG__ = data.dkimSelectorCatalog;
  win.__I18N_EN__ = data.englishBundle;
  vm.createContext(win);

  // i18n and the renderer are ES modules now, constructed here exactly as
  // src/legacy-bridge.js constructs them for the bundle, then installed as the
  // globals the remaining IIFEs still read. One instance each, matching the
  // singleton they were.
  const i18n = createI18n({
    englishBundle: data.englishBundle,
    // The same primitive set src/legacy-bridge.js passes, taken from the
    // sandbox rather than from Node's globals.
    platform: {
      document: win.document,
      localStorage: win.localStorage,
      fetch: (...args) => win.fetch(...args),
      navigator: win.navigator,
      console: win.console,
    },
  });
  win.i18n = i18n;
  win.t = i18n.t;
  win.tp = i18n.tp;
  win.tRaw = i18n.tRaw;
  if (opts.render !== false) win.R = createRenderer(() => win.document, i18n);

  const files = opts.files || ['js/app.js'];
  for (const file of files) {
    vm.runInContext(readFileSync(join(REPO, file), 'utf8'), win, { filename: file });
  }

  // The ids js/app.js writes into. Created on demand so a test only pays for
  // what it uses.
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

  return win;
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
