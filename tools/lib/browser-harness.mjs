/* ──────────────────────────────────────────────────────────────────────────
   Load the browser-side code into a node:vm sandbox backed by the DOM shim.

   Same approach tools/backtest.mjs already uses for js/dns.js: the files are
   plain IIFEs that attach to `window`, so there is nothing to mock and no
   bundler involved. This module exists so render, export and interpolate tests
   share one definition of "the app, loaded".
   ────────────────────────────────────────────────────────────────────────── */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

import { createDocument, MarkupSinkError } from './dom-shim.mjs';

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
  vm.createContext(win);

  const files = opts.files || [
    'js/locales-en.js',
    'js/i18n.js',
    'js/render.js',
    'js/app.js',
  ];
  for (const file of files) {
    vm.runInContext(readFileSync(join(REPO, file), 'utf8'), win, { filename: file });
  }

  // The ids js/app.js writes into. Created on demand so a test only pays for
  // what it uses.
  for (const id of ['tableBody', 'statsGrid', 'progressLog', 'toast']) {
    const el = document.createElement(id === 'tableBody' ? 'tbody' : 'div');
    el.id = id;
    document.body.appendChild(el);
  }

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
