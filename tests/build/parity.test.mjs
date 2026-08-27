#!/usr/bin/env node
/**
 * The built artifact behaves like the source it was built from. Task 1.9.
 *
 * Spec correction 6: every existing test loads SOURCE and the browser is served
 * the BUNDLE. "Build success" means esbuild exited zero; it says nothing about
 * whether the bundle behaves like its inputs. A minifier bug, a tree-shaking
 * mistake or a `this`-binding change would pass every other gate and reach
 * production.
 *
 * This loads the REAL `dist/app.min.js` — the same file `index.html` names and
 * the same file `_site/` publishes, asserted below rather than assumed. A
 * test-only bundle proves nothing about the shipped artifact and is not an
 * acceptable substitute (round 1, F3).
 *
 * The five-surface equivalence runner is the behavioural half and already runs
 * through this artifact. What this file adds is the SURFACE: the names, the
 * members and the constants, compared side by side, with the negative case that
 * proves the comparison can fail.
 */

import { readFileSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import vm from 'node:vm';

import { createSuite } from '../lib/assert.mjs';
import { createDocument } from '../../tools/lib/dom-shim.mjs';
import { scriptOrderFromMarkup } from '../../tools/build-bundle.mjs';
import { PUBLIC_SUFFIX_RULES } from '../../src/data/public-suffixes.js';
import { DKIM_SELECTOR_CATALOG } from '../../src/data/dkim-selectors.js';
import { LOCALE_EN } from '../../src/data/locales-en.js';
import { createI18n } from '../../src/i18n/index.js';
import { createRenderer } from '../../src/ui/render.js';
import { createDnsEngine } from '../../js/dns.js';
import { createBrowserPlatform } from '../../src/platform/browser.js';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, section, report } = createSuite();

const ARTIFACT = 'dist/app.min.js';
// The hand-written IIFEs. The three generated tables are ES modules under
// src/data/ as of Phase 2 and are INJECTED below, exactly as the adapter and
// the browser harness inject them -- a consumer that imports its own generated
// data can never be handed different data by a test.
const SOURCES = ['js/app.js'];

/**
 * The ambient names the harness supplies. Everything a load leaves behind
 * beyond these is a global the code created, which is the surface under test.
 */
const AMBIENT = ['document', 'navigator', 'location', 'localStorage', 'fetch', 'console',
  'setTimeout', 'clearTimeout', 'queueMicrotask', 'URL', 'URLSearchParams',
  'AbortController', 'crypto', 'Date', 'Intl', 'window', 'self', 'globalThis'];

/**
 * A fresh sandbox per load, and the load is cache-busted by construction:
 * `vm.runInContext` re-evaluates the source text every time, so neither Node's
 * module cache nor a previous load can leak into this one.
 */
function load(files, { injectData = false } = {}) {
  const document = createDocument();
  const win = {
    document,
    navigator: { language: 'en', languages: ['en'] },
    location: { href: 'https://dnsaudit.kwestic.com/' },
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    fetch: async () => ({ ok: false }),
    console, setTimeout, clearTimeout, queueMicrotask,
    URL, URLSearchParams, AbortController, crypto, Date, Intl,
  };
  win.window = win;
  win.self = win;
  win.globalThis = win;
  // The source side needs the generated tables installed the way the adapter
  // installs them for the bundle; the artifact carries its own.
  if (injectData) {
    win.__PUBLIC_SUFFIX_RULES__ = PUBLIC_SUFFIX_RULES;
    win.__DKIM_SELECTOR_CATALOG__ = DKIM_SELECTOR_CATALOG;
    win.__I18N_EN__ = LOCALE_EN;
    // Constructed the way src/legacy-bridge.js constructs them for the bundle.
    // The real adapter, over this sandbox window — what the bridge builds.
    const platform = createBrowserPlatform({
      ...win, Blob: class Blob {}, FileReader: class FileReader {},
      setTimeout: (...a) => setTimeout(...a), clearTimeout: (...a) => clearTimeout(...a),
    });
    const i18n = createI18n({ englishBundle: LOCALE_EN, platform });
    win.i18n = i18n;
    win.t = i18n.t;
    win.tp = i18n.tp;
    win.tRaw = i18n.tRaw;
    win.R = createRenderer(() => win.document, i18n);
    win.DnsAudit = createDnsEngine({
      publicSuffixRules: PUBLIC_SUFFIX_RULES,
      dkimSelectorCatalog: DKIM_SELECTOR_CATALOG,
      platform,
    });
  }
  vm.createContext(win);
  for (const file of files) {
    vm.runInContext(readFileSync(join(REPO, file), 'utf8'), win, { filename: file });
  }
  return win;
}

const globalsOf = win => Object.keys(win).filter(name => !AMBIENT.includes(name)).sort();

/* ── 1. The artifact under test is the shipped one ────────────────────── */
section('1. The artifact is the one that ships');

eq('the artifact exists', existsSync(join(REPO, ARTIFACT)), true);
const declared = scriptOrderFromMarkup(readFileSync(join(REPO, 'index.html'), 'utf8'));
eq('index.html names exactly one script', declared.length, 1);
eq('and it is the file under test', declared[0], ARTIFACT);

const artifactBytes = readFileSync(join(REPO, ARTIFACT));
eq('the artifact is the whole application, not a stub', artifactBytes.length > 100000, true);
eq('it carries the build banner', artifactBytes.toString('utf8', 0, 400).includes('Generated artifact'), true);
eq('it links its source map', artifactBytes.toString('utf8').includes('//# sourceMappingURL=app.min.js.map'), true);
// A classic script, which is what keeps file:// working and keeps the CSP shape.
eq('it is not an ES module', /^\s*(export|import)\s/m.test(artifactBytes.toString('utf8')), false);

/* ── 2. The global surface is identical ───────────────────────────────── */
section('2. Global surface');

const source = load(SOURCES, { injectData: true });
const bundle = load([ARTIFACT]);

const sourceGlobals = globalsOf(source);
const bundleGlobals = globalsOf(bundle);
eq('the source creates 24 globals', sourceGlobals.length, 24);
eq('the bundle creates the same set', bundleGlobals, sourceGlobals);
eq('none is missing', sourceGlobals.filter(n => !bundleGlobals.includes(n)), []);
eq('none is extra', bundleGlobals.filter(n => !sourceGlobals.includes(n)), []);

// `globalName` is omitted until §10 stage 3, so the bundle must NOT have
// introduced a name of its own. This is the assertion that would have caught
// the mistake version 0.2 of the spec nearly shipped.
eq('the bundle introduced no name of its own',
  bundleGlobals.filter(n => !sourceGlobals.includes(n)), []);

/* ── 3. The exported surface is identical ─────────────────────────────── */
section('3. DnsAudit and the test surface');

const sourceMembers = Object.keys(source.DnsAudit).sort();
const bundleMembers = Object.keys(bundle.DnsAudit).sort();
eq('DnsAudit has 95 members in source', sourceMembers.length, 95);
eq('and the same members in the bundle', bundleMembers, sourceMembers);
eq('__APP_TEST__ matches',
  Object.keys(bundle.__APP_TEST__).sort(), Object.keys(source.__APP_TEST__).sort());

/* ── 4. Scoring constants are byte-identical ──────────────────────────── */
section('4. Scoring constants');

for (const name of ['WEIGHTS', 'PARKED_WEIGHTS', 'GRADE_THRESHOLDS', 'POLICY_RANK']) {
  eq(`${name} is identical`,
    JSON.stringify(bundle.DnsAudit[name]), JSON.stringify(source.DnsAudit[name]));
}

/* ── 5. Generated data survived bundling intact ───────────────────────── */
section('5. Generated data');

eq('the public suffix list is whole',
  bundle.__PUBLIC_SUFFIX_RULES__.length, source.__PUBLIC_SUFFIX_RULES__.length);
eq('and it is the real one, not a fixture', bundle.__PUBLIC_SUFFIX_RULES__.length > 10000, true);
eq('the DKIM selector catalog is whole',
  Object.keys(bundle.__DKIM_SELECTOR_CATALOG__).length,
  Object.keys(source.__DKIM_SELECTOR_CATALOG__).length);
// The inlined English bundle is why file:// works at all: 125,172 bytes so the
// app needs no fetch to render text. If bundling dropped it, file:// would
// degrade silently to untranslated keys.
eq('the English bundle is inlined in the artifact',
  Object.keys(bundle.__I18N_EN__).length, Object.keys(source.__I18N_EN__).length);
eq('and the i18n layer resolves through it with no network',
  bundle.t('doc.title'), source.t('doc.title'));

/* ── 6. Behaviour agrees on a computed answer ─────────────────────────── */
section('6. Behaviour');

// Not a smoke test: `getOrganizationalDomain` reads the bundled PSL, and
// `analyzeDkimKey` runs the DER walk. Both would break quietly under a
// tree-shaking or minification fault while every name above still matched.
for (const probe of ['foo.blogspot.com', 'a.b.ck', 'www.example.co.uk']) {
  eq(`getOrganizationalDomain('${probe}') agrees`,
    bundle.DnsAudit.getOrganizationalDomain(probe), source.DnsAudit.getOrganizationalDomain(probe));
}
const key = 'v=DKIM1; k=rsa; p=' + (await import('../fixtures/equivalence/keys.mjs')).RSA_2048_SPKI;
eq('analyzeDkimKey agrees',
  JSON.stringify(bundle.DnsAudit.analyzeDkimKey(key)),
  JSON.stringify(source.DnsAudit.analyzeDkimKey(key)));
eq('and it read a real key', source.DnsAudit.analyzeDkimKey(key).keyBits, 2048);

/* ── 7. The comparison can fail ───────────────────────────────────────── */
section('7. Negative control');

/**
 * A parity check nobody has watched fail is not evidence.
 *
 * Loading a deliberately altered artifact must move every comparison above that
 * it should. This is built in memory rather than on disk so it cannot be
 * mistaken for a real build output.
 */
const altered = readFileSync(join(REPO, ARTIFACT), 'utf8')
  .replace('dmarc:30', 'dmarc:29')
  .replace('"dmarc":30', '"dmarc":29');
eq('the alteration applied', altered !== readFileSync(join(REPO, ARTIFACT), 'utf8'), true);

const alteredWin = (() => {
  const document = createDocument();
  const win = {
    document, navigator: { language: 'en', languages: ['en'] },
    location: { href: 'https://x/' },
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    fetch: async () => ({ ok: false }), console, setTimeout, clearTimeout, queueMicrotask,
    URL, URLSearchParams, AbortController, crypto, Date, Intl,
  };
  win.window = win; win.self = win; win.globalThis = win;
  vm.createContext(win);
  vm.runInContext(altered, win, { filename: 'altered' });
  return win;
})();
eq('an altered artifact fails the constants comparison',
  JSON.stringify(alteredWin.DnsAudit.WEIGHTS) === JSON.stringify(source.DnsAudit.WEIGHTS), false);
eq('and the difference is the one introduced', alteredWin.DnsAudit.WEIGHTS.dmarc, 29);
eq('while every other weight is untouched', alteredWin.DnsAudit.WEIGHTS.spf, source.DnsAudit.WEIGHTS.spf);

// And a global-surface difference is caught too.
const extraWin = (() => {
  const document = createDocument();
  const win = {
    document, navigator: { language: 'en', languages: ['en'] },
    location: { href: 'https://x/' },
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    fetch: async () => ({ ok: false }), console, setTimeout, clearTimeout, queueMicrotask,
    URL, URLSearchParams, AbortController, crypto, Date, Intl,
  };
  win.window = win; win.self = win; win.globalThis = win;
  vm.createContext(win);
  vm.runInContext(readFileSync(join(REPO, ARTIFACT), 'utf8') + '\nvar DnsAuditExtra = 1;', win, { filename: 'extra' });
  return win;
})();
eq('an extra global is caught',
  globalsOf(extraWin).filter(n => !sourceGlobals.includes(n)), ['DnsAuditExtra']);

report();
