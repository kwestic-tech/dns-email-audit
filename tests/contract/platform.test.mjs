#!/usr/bin/env node
/**
 * The browser platform adapter. Spec §11, Task 2.4.
 *
 * Three properties, and the third is the one that would otherwise ship broken:
 *
 *   1. the primitive set is COMPLETE — a missing name fails a module at run
 *      time, in a browser, on a path a unit test may never take;
 *   2. it is per-runtime, so two runtimes share nothing;
 *   3. every method that needs its original receiver HAS it.
 *
 * Node is far more forgiving than a browser about (3). A bare `fetch` or
 * `setTimeout` lifted off `window` throws `TypeError: Illegal invocation` in
 * every browser and works fine under Node, so a binding mistake here would pass
 * the whole suite and fail only in production. These assertions therefore test
 * the binding directly rather than testing that a call happens to work.
 */

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { createSuite } from '../lib/assert.mjs';
import { createBrowserPlatform, PLATFORM_PRIMITIVES } from '../../src/platform/browser.js';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, throws, section, report } = createSuite();

/**
 * A window whose methods REFUSE to run without their receiver, the way a
 * browser's do. This is the instrument: under a plain Node object every one of
 * these would work unbound and the test would prove nothing.
 */
function strictWindow(overrides = {}) {
  const win = {
    calls: [],
    Date,
    Intl,
    URL, URLSearchParams, AbortController,
    Blob: class Blob {}, FileReader: class FileReader {},
    document: { name: 'document' },
    navigator: { language: 'en' },
    console: { name: 'console' },
    localStorage: {
      store: new Map(),
      getItem(key) { if (this !== win.localStorage) throw new TypeError('Illegal invocation'); return this.store.get(key) ?? null; },
      setItem(key, value) { if (this !== win.localStorage) throw new TypeError('Illegal invocation'); this.store.set(key, value); },
    },
    crypto: {
      subtle: {
        digest(algorithm) { if (this !== win.crypto.subtle) throw new TypeError('Illegal invocation'); return `digest:${algorithm}`; },
      },
    },
    ...overrides,
  };
  win.fetch = function fetch(url) {
    if (this !== win) throw new TypeError('Illegal invocation');
    win.calls.push(url);
    return Promise.resolve({ ok: true, url });
  };
  win.setTimeout = function setTimeout(fn, ms) {
    if (this !== win) throw new TypeError('Illegal invocation');
    return { fn, ms };
  };
  win.clearTimeout = function clearTimeout(handle) {
    if (this !== win) throw new TypeError('Illegal invocation');
    win.calls.push(['clearTimeout', handle]);
  };
  return win;
}

/* ── 0. The instrument refuses unbound calls ──────────────────────────── */
section('0. The strict window really is strict');

const probe = strictWindow();
throws('an unbound fetch throws, as a browser would',
  () => { const bare = probe.fetch; bare('https://x/'); },
  error => error instanceof TypeError && /Illegal invocation/.test(error.message));
throws('an unbound setTimeout throws too',
  () => { const bare = probe.setTimeout; bare(() => {}, 0); },
  error => /Illegal invocation/.test(error.message));
throws('and an unbound localStorage.getItem',
  () => { const bare = probe.localStorage.getItem; bare('k'); },
  error => /Illegal invocation/.test(error.message));

/* ── 1. The set is complete ───────────────────────────────────────────── */
section('1. Every §11 primitive is present');

const platform = createBrowserPlatform(strictWindow());

// The names spec §11 lists, verbatim, checked against the module's own
// declaration so the two cannot drift.
const SPEC_11 = ['fetch', 'crypto', 'AbortController', 'URLSearchParams', 'setTimeout',
  'clearTimeout', 'document', 'localStorage', 'URL', 'Blob', 'FileReader',
  'Intl', 'console', 'now', 'formatDateTime'];
for (const name of SPEC_11) {
  eq(`§11 names ${name}, and the platform declares it`, PLATFORM_PRIMITIVES.includes(name), true);
  eq(`and provides it`, platform[name] !== undefined, true);
}
eq('the platform provides every name it declares',
  PLATFORM_PRIMITIVES.filter(name => platform[name] === undefined), []);

// Language built-ins are NOT platform services — §11 is explicit. Injecting
// them would be ceremony with no substitute anyone would want to supply.
for (const builtin of ['Promise', 'Map', 'Set', 'BigInt', 'JSON', 'Array']) {
  eq(`${builtin} is a required API, not an injected service`, platform[builtin], undefined);
}

/* ── 2. Receivers are bound ───────────────────────────────────────────── */
section('2. Methods keep their receivers');

// Pulled off the platform and called bare — which is exactly how a consuming
// module uses them after destructuring `const { fetch } = platform`.
const { fetch, setTimeout: schedule, clearTimeout: cancel } = platform;
eq('fetch works when destructured off the platform',
  (await fetch('https://cloudflare-dns.com/dns-query')).ok, true);
eq('setTimeout works when destructured', schedule(() => {}, 5).ms, 5);
cancel('handle');
eq('clearTimeout works when destructured', true, true);

// Host objects are passed WHOLE, so their own methods keep their receivers.
const strict = strictWindow();
const hostPlatform = createBrowserPlatform(strict);
hostPlatform.localStorage.setItem('lang', 'es');
eq('localStorage keeps its receiver through the platform',
  hostPlatform.localStorage.getItem('lang'), 'es');
eq('crypto.subtle keeps its receiver',
  hostPlatform.crypto.subtle.digest('SHA-256'), 'digest:SHA-256');
eq('document is the same object, not a copy', hostPlatform.document, strict.document);
eq('console is the same object', hostPlatform.console, strict.console);

// Constructors need no binding — `new` supplies the receiver — but they must be
// THIS window's, not the ambient ones.
eq('AbortController comes from the window', hostPlatform.AbortController, strict.AbortController);
eq('URL comes from the window', hostPlatform.URL, strict.URL);
eq('Blob comes from the window', hostPlatform.Blob, strict.Blob);
eq('FileReader comes from the window', hostPlatform.FileReader, strict.FileReader);

/* ── 3. Per runtime, never a singleton ────────────────────────────────── */
section('3. Ownership');

const first = createBrowserPlatform(strictWindow());
const second = createBrowserPlatform(strictWindow());
eq('two calls produce two platforms', first === second, false);
eq('and they do not share their fetch', first.fetch === second.fetch, false);

// Different windows, genuinely independent.
const windowA = strictWindow();
const windowB = strictWindow();
await createBrowserPlatform(windowA).fetch('https://a/');
eq('a call through one platform reaches only its own window', windowA.calls, ['https://a/']);
eq('and not the other', windowB.calls, []);

throws('a platform cannot be built without a window',
  () => createBrowserPlatform(undefined),
  error => /needs a window/.test(error.message));

/* ── 4. Time and locale are controlled inputs ─────────────────────────── */
section('4. Time and formatting');

/**
 * Production behaviour is `new Date().toLocaleString(i18n.lang)`, which is what
 * `js/app.js:1651` did. Preserved exactly — same call, same arguments — and
 * moved behind the platform so an equivalence run can pin it by supplying a
 * window whose `Date` is fixed. Spec Design §8 permits no timestamp wildcard,
 * and this is why it needs none.
 */
const FIXED = Date.UTC(2026, 0, 15, 12, 0, 0);
class PinnedDate extends Date {
  constructor(...args) { super(...(args.length ? args : [FIXED])); }
  static now() { return FIXED; }
}
const pinned = createBrowserPlatform(strictWindow({ Date: PinnedDate }));

eq('now() reads the window clock', pinned.now(), FIXED);
eq('and it is a capability, not a value captured once',
  typeof pinned.now, 'function');
eq('formatDateTime with no argument uses that clock',
  pinned.formatDateTime(undefined, 'en'), new Date(FIXED).toLocaleString('en'));
eq('formatDateTime matches the v0.5.0 call exactly',
  pinned.formatDateTime(new Date(FIXED), 'en'), new Date(FIXED).toLocaleString('en'));
eq('a locale change changes the output',
  pinned.formatDateTime(new Date(FIXED), 'en') === pinned.formatDateTime(new Date(FIXED), 'de'), false);

// The real clock still moves, so pinning is the test's doing and not the
// module's — a platform that always returned a fixed instant would be a
// production defect this suite would otherwise hide.
const live = createBrowserPlatform(strictWindow());
eq('an unpinned platform reports a real instant', live.now() > Date.UTC(2020, 0, 1), true);

/* ── 5. The module is the floor of the graph ──────────────────────────── */
section('5. src/platform imports nothing');

const source = readFileSync(join(REPO, 'src/platform/browser.js'), 'utf8');
eq('the platform module exists', existsSync(join(REPO, 'src/platform/browser.js')), true);
eq('and imports nothing — §12 gives it no outgoing edges',
  /^\s*import\s/m.test(source), false);
// It reads ambient names only through its `win` argument, which is what keeps
// browser-global access confined to it and to the marked adapters.
eq('it never reaches for the ambient window itself',
  /\b(?:^|[^.\w])window\s*\./.test(source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '')), false);

report();
