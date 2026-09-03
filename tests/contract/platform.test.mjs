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

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

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
    opened: [],
    Date,
    Intl,
    URL, URLSearchParams, AbortController,
    Blob: class Blob {}, FileReader: class FileReader {}, DOMParser: class DOMParser {},
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
  win.open = function open(url, target, features) {
    if (this !== win) throw new TypeError('Illegal invocation');
    win.opened.push([url, target, features]);
    return { closed: false };
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
throws('and an unbound open',
  () => { const bare = probe.open; bare('https://x/', '_blank', 'noopener'); },
  error => /Illegal invocation/.test(error.message));

/* ── 1. The set is complete ───────────────────────────────────────────── */
section('1. Every §11 primitive is present');

const platform = createBrowserPlatform(strictWindow());

/**
 * The names spec §11 lists, verbatim, checked against the module's own
 * declaration so the two cannot drift.
 *
 * `open` is here as of spec `1.3`, found by the completed conversion sweep over
 * `js/app.js` — the last legacy file, and therefore the last such finding. It
 * is NOT evidence that the scan below is exhaustive: the scan could not have
 * found it either.
 *
 * `nowIso` is here as of spec `1.9`, added for 0.9.0's report timestamp. The
 * alternative was an ambient `Date` read in `src/ui/` -- a breach this catalog
 * does not name and so could not have caught, which is the third instance of
 * the limit recorded at `1.2`.
 *
 * `navigator` is here as of spec `1.1`. Version 1.0 omitted it while claiming
 * the list named every ambient primitive the moved code uses, which was false:
 * `detectLang()` reads `navigator.languages` and `navigator.language`. The
 * omission was found by converting `js/i18n.js` in Task 2.2, not by reading the
 * spec, and the spec was amended rather than the implementation bent to match
 * it — framework §6 trigger 5.
 */
const SPEC_11 = ['fetch', 'crypto', 'AbortController', 'URLSearchParams', 'setTimeout',
  'clearTimeout', 'document', 'localStorage', 'navigator', 'open', 'URL', 'Blob',
  'FileReader', 'DOMParser', 'Intl', 'console', 'now', 'formatDateTime', 'nowIso'];
for (const name of SPEC_11) {
  eq(`§11 names ${name}, and the platform declares it`, PLATFORM_PRIMITIVES.includes(name), true);
  eq(`and provides it`, platform[name] !== undefined, true);
}
/**
 * `nowIso()` asserted by VALUE, not only by presence.
 *
 * Declaring a name and returning a real instant are different claims, and the
 * bidirectional list check above only makes the first. A stub returning
 * `'not-a-timestamp'` satisfies every other assertion in this file.
 */
eq('nowIso returns a canonical UTC timestamp',
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(platform.nowIso()), true);
eq('and it is the same clock now() reads',
  Math.abs(Date.parse(platform.nowIso()) - platform.now()) < 2000, true);
// Proven able to fail: the regex is what rejects a stub.
eq('a non-timestamp would not pass that check',
  /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test('not-a-timestamp'), false);

eq('the platform provides every name it declares',
  PLATFORM_PRIMITIVES.filter(name => platform[name] === undefined), []);
// Both directions: the declaration must not quietly grow past the spec either.
eq('and declares nothing the spec does not name',
  PLATFORM_PRIMITIVES.filter(name => !SPEC_11.includes(name)), []);

/**
 * Defense in depth against REGRESSION. Not a completeness proof, and spec `1.2`
 * corrects the `1.1` wording that called it one.
 *
 * What this establishes: **no module under `src/` reads a name from the
 * catalog below, with one exemption — the platform module itself.** There were
 * two more until Task 6.2 retired both adapters; the scan covers everything
 * they used to be excused from.
 *
 * What it does not, and cannot:
 *
 *   • **It cannot find an ambient identifier absent from `AMBIENT`.** The
 *     catalog is hand-written and bounded. The `navigator` omission that
 *     produced the 1.1 amendment would NOT have been caught here — that was
 *     found by converting `js/i18n.js`, where the module stopped being able to
 *     reach `window` and every dependency had to be named. Completeness of the
 *     §11 list rests on that conversion review, not on this scan.
 *   • **A regex is not scope analysis.** No modelling of scope, shadowing,
 *     computed member access or aliasing. The `declared` pattern below
 *     approximates "this name was destructured or passed in", and an
 *     approximation is what it is.
 *
 * Anything stronger needs real name-resolution analysis, and this release adds
 * no parser and no dependency for it.
 */
const AMBIENT = ['navigator', 'localStorage', 'document', 'fetch', 'crypto',
  'setTimeout', 'clearTimeout', 'sessionStorage', 'indexedDB', 'location', 'history', 'open'];
const srcFiles = (function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = join(dir, entry.name);
    return entry.isDirectory() ? walk(full) : (entry.name.endsWith('.js') ? [full] : []);
  });
})(join(REPO, 'src'));

const reaching = [];
for (const file of srcFiles) {
  const text = readFileSync(file, 'utf8');
  // ONE exemption, and it is the module whose whole job is the ambient read.
  // The marked-adapter escape that used to sit here is gone: Task 6.2 retired
  // both adapters, so every other module under `src/` is scanned — which makes
  // "zero adapters" an architectural state this contract depends on, not just
  // a number two other tests count.
  if (file.endsWith(join('platform', 'browser.js'))) continue;
  const body = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  for (const name of AMBIENT) {
    // A bare reference, not a property of something and not a declared local.
    const bare = new RegExp(`(^|[^.\\w$])${name}\\s*[.(\\[]`);
    const declared = new RegExp(`(?:const|let|var|function)\\s*\\{[^}]*\\b${name}\\b|\\b${name}\\s*[,}]\\s*=|\\(\\s*${name}\\b`);
    if (bare.test(body) && !declared.test(body)) {
      reaching.push(`${relative(REPO, file)} reaches for ${name}`);
    }
  }
}
eq('no src/ module reaches for an ambient primitive the platform does not name', reaching, []);

// And the scan can fail. Without this it would pass on a regex that matches
// nothing, which is how a regression check quietly stops being one. These
// bound what it does catch; they do not turn it into a proof of completeness.
const reachesFor = (body, name) => {
  const bare = new RegExp(`(^|[^.\\w$])${name}\\s*[.(\\[]`);
  const declared = new RegExp(`(?:const|let|var|function)\\s*\\{[^}]*\\b${name}\\b|\\b${name}\\s*[,}]\\s*=|\\(\\s*${name}\\b`);
  return bare.test(body) && !declared.test(body);
};
eq('the scan catches a module reading navigator ambiently',
  reachesFor('var preferred = navigator.languages;', 'navigator'), true);
eq('and one reading localStorage',
  reachesFor('localStorage.getItem("k")', 'localStorage'), true);
eq('but not one that destructured it from the platform',
  reachesFor('const { navigator } = platform; navigator.language;', 'navigator'), false);
eq('nor a property of something else',
  reachesFor('win.navigator.language; platform.document.title;', 'navigator'), false);
eq('this is exactly the shape the 1.0 spec would have permitted',
  reachesFor('var preferred = navigator.languages || [navigator.language];', 'navigator'), true);
// The stated limit, asserted so it cannot be forgotten: a name outside the
// catalog is invisible to this scan, whatever the module does with it.
eq('an ambient name absent from the catalog is NOT caught — a stated limit',
  AMBIENT.includes('matchMedia'), false);
eq('and the scan is silent about it',
  reaching.some(entry => entry.includes('matchMedia')), false);

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

/**
 * `open`, with its arguments preserved exactly.
 *
 * `openLearnMore()` calls `open(url, '_blank', 'noopener')`, and all three
 * matter: the Blob URL is the page, `_blank` is the new context, and `noopener`
 * is what stops the opened page holding a reference back through
 * `window.opener`. A platform that dropped or reordered them would be a
 * security regression that no other assertion here would notice.
 */
const navigating = strictWindow();
const navPlatform = createBrowserPlatform(navigating);
const { open: openUrl } = navPlatform;
openUrl('blob:learn-more', '_blank', 'noopener');
eq('open works when destructured off the platform', navigating.opened.length, 1);
eq('and the URL reaches the window unchanged', navigating.opened[0][0], 'blob:learn-more');
eq('with the _blank target', navigating.opened[0][1], '_blank');
eq('and noopener, which is the part that matters', navigating.opened[0][2], 'noopener');
eq('all three arguments, in order',
  navigating.opened[0], ['blob:learn-more', '_blank', 'noopener']);

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
eq('DOMParser comes from the window', hostPlatform.DOMParser, strict.DOMParser);

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
// browser-global access confined to this module and to the one ambient read an
// entry point has to make — `createBrowserPlatform(window)` in `src/main.js`.
eq('it never reaches for the ambient window itself',
  /\b(?:^|[^.\w])window\s*\./.test(source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '')), false);

report();
