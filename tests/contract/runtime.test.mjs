#!/usr/bin/env node
/**
 * The composition root. Spec §11, Task 2.5.
 *
 * Three properties, and the third is a published figure:
 *
 *   1. importing `src/runtime.js` does nothing — no DOM, no network, no global,
 *      no instance;
 *   2. two runtimes share nothing, so test isolation comes from constructing
 *      one rather than from cache-busting an import;
 *   3. ONE runtime holds ONE DoH cache with page lifetime, so sibling audits
 *      reuse answers. `PRIVACY.md:30-33` publishes the fan-out that produces —
 *      "roughly 41 queries for a typical domain" — and narrowing the cache
 *      raises it. That makes it a privacy-facing change, not a refactor.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, sep } from 'node:path';

import { createSuite } from '../lib/assert.mjs';
import { ANALYSIS_VERSION } from '../../src/audit/scoring.js';
import { validDkimSelector } from '../../src/core/dkim/dkim.js';
import { createDocument } from '../../tools/lib/dom-shim.mjs';
import { dohFixture, txt, ns, mx, a } from '../../tools/lib/doh-fixture.mjs';
import { FIXTURE_PSL_RULES, probePublicSuffixRules, assertFixtureIdentity } from '../lib/fixture-identity.mjs';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, throws, rejects, section, report } = createSuite();

/* ── 1. Importing it does nothing ─────────────────────────────────────── */
section('1. src/runtime.js is side-effect-free');

/**
 * This process has no `window`, no `document` and no `localStorage`. If
 * importing the module touched any of them it would already have thrown, so
 * reaching this line is itself the first half of the assertion — and the
 * import happened at the top of this file, before anything else ran.
 */
const runtimeModule = await import('../../src/runtime.js');
eq('the module imported without a browser in the process', typeof globalThis.window, 'undefined');
eq('and without a document', typeof globalThis.document, 'undefined');
eq('it exports exactly one thing', Object.keys(runtimeModule), ['createAuditRuntime']);
eq('which is a function', typeof runtimeModule.createAuditRuntime, 'function');

// Nothing is constructed until it is called: a network call would need `fetch`,
// and the module never has one to call.
let networkCalls = 0;
const countingFetch = async () => { networkCalls++; return { ok: false, status: 500 }; };
eq('importing performed no network I/O', networkCalls, 0);

// And the source says so structurally: no top-level construction, no ambient
// reads. A module that grew either would still import cleanly here.
const source = readFileSync(join(REPO, 'src/runtime.js'), 'utf8');
const code = source.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
eq('it reads no ambient browser global',
  /\b(?:window|document|localStorage|navigator)\s*\./.test(code), false);
// Anchored at column zero: module scope is the only unindented scope in this
// file, and an `^\s*` version matched `const i18n = createI18n(...)` INSIDE the
// factory — which is the construction that is supposed to be there.
eq('and constructs nothing at module scope',
  /^(?:const|let|var)\s+\w+\s*=\s*create[A-Z]/m.test(code), false);
eq('the check is real: it catches a top-level construction',
  /^(?:const|let|var)\s+\w+\s*=\s*create[A-Z]/m.test('const r = createAuditRuntime({});'), true);
eq('and ignores one inside a function',
  /^(?:const|let|var)\s+\w+\s*=\s*create[A-Z]/m.test('  const i18n = createI18n({});'), false);

throws('and it refuses to build a runtime without a platform',
  () => runtimeModule.createAuditRuntime({}),
  error => /needs a platform/.test(error.message));

/* ── 2. A runtime, built ──────────────────────────────────────────────── */
section('2. What a runtime is');

const ENGLISH = { meta: { code: 'en', name: 'English', nativeName: 'English', dir: 'ltr' }, doc: { title: 'T' } };

function makeRuntime(fetchImpl, DOMParserImpl = class DOMParser {}) {
  const document = createDocument();
  const platform = {
    fetch: fetchImpl,
    crypto, AbortController, URLSearchParams,
    setTimeout: (...args) => setTimeout(...args),
    clearTimeout: (...args) => clearTimeout(...args),
    document,
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    URL, Blob: class Blob {}, FileReader: class FileReader {}, DOMParser: DOMParserImpl,
    Intl, console, navigator: { language: 'en', languages: ['en'] },
    now: () => 0,
    formatDateTime: (d, l) => new Date(d ?? 0).toLocaleString(l),
  };
  return runtimeModule.createAuditRuntime({
    publicSuffixRules: FIXTURE_PSL_RULES,
    dkimSelectorCatalog: { providers: {}, generic: [], temporal: [], prefixes: [], excluded: [] },
    englishBundle: ENGLISH,
    platform,
  });
}

const runtime = makeRuntime(dohFixture({}));
eq('the facade is the two supported members plus the Phase 2 parts',
  Object.keys(runtime).sort(),
  ['analyzeDomain', 'checkConnectivity', 'engine', 'i18n', 'mount', 'renderer', 'ui', 'versions']);
// `ui` joined at Task 5.6, when §12's matrix put the `ui/` edge on this module
// rather than on the entry point. It is a Phase 2 part like `i18n`, `renderer`
// and `engine` — NOT a facade member: `src/facade.expected.json` is still the
// two supported names, asserted separately and in both directions.
eq('and `ui` is not on the supported facade',
  ['analyzeDomain', 'checkConnectivity'].includes('ui'), false);
eq('analyzeDomain is a function', typeof runtime.analyzeDomain, 'function');
eq('checkConnectivity is a function', typeof runtime.checkConnectivity, 'function');
eq('mount is a function', typeof runtime.mount, 'function');

/* ── The version metadata 0.9.0's report carries ──────────────────────── */
section('Version metadata (report-comparison 1.9 §2)');

const pkg = JSON.parse(readFileSync(join(REPO, 'package.json'), 'utf8'));

/**
 * The pin that makes the release commit bump both or fail.
 *
 * A browser cannot read `package.json`, and the bundle carries the version only
 * as a comment banner, so `runtime.js` holds a literal. That literal is exactly
 * the kind of thing that goes stale silently — which is what this catches.
 */
/**
 * ONE predicate, asserted in both directions.
 *
 * The negative case has to run the SAME comparison against the SAME live value,
 * or it proves nothing about the check. Comparing two locally constructed
 * strings would pass whatever `runtime.versions.app` held — including
 * `undefined` — which is the failure this control exists to rule out.
 */
const versionMatches = expected => runtime.versions.app === expected;

eq('APP_VERSION matches package.json', versionMatches(pkg.version), true);
eq('and the same predicate rejects a drifted version',
  versionMatches(`${pkg.version}-stale`), false);
eq('ANALYSIS_VERSION is carried too, from audit/scoring.js',
  runtime.versions.analysis, ANALYSIS_VERSION);
eq('both are integers or version strings, never undefined',
  [typeof runtime.versions.app, typeof runtime.versions.analysis], ['string', 'number']);
// Frozen so a consumer handed the runtime cannot rewrite its own provenance.
eq('the version object is frozen', Object.isFrozen(runtime.versions), true);
eq('and freezing actually holds', (() => {
  try { runtime.versions.app = 'tampered'; } catch (e) { /* strict mode throws */ }
  return runtime.versions.app;
})(), pkg.version);
// §0's boundary — the UI is HANDED these values rather than importing
// scoring — is asserted end-to-end when the UI consumes them in the export
// commit. What IS provable here is the half this module owns: the value came
// from `audit/scoring.js` and not from a second literal declared in the UI.
eq('the analysis version is the audit module\'s, not a copy',
  runtime.versions.analysis === ANALYSIS_VERSION, true);

/* -- The selector capability the report schema is composed with -------- */

/**
 * `src/ui/` may not import `core/dkim/`, so the DKIM selector grammar reaches
 * the report schema as a capability through this composition root.
 *
 * Asserted HERE, at the runtime, rather than only in the schema's own suite.
 * That suite imports the predicate directly, so it stays green whatever the
 * composition does -- and it did: `create-audit.js` briefly destructured
 * `validDkimSelector` from a factory that does not return it, shadowing the
 * module import with `undefined`, and the production path skipped every
 * selector check while 175 assertions passed.
 */
eq('the audit exposes the owner\'s selector predicate, not undefined',
  typeof runtime.engine.validDkimSelector, 'function');
eq('and it is the same function object the owner exports',
  runtime.engine.validDkimSelector === validDkimSelector, true);
// Behaviour, not just identity: a re-exported wrapper would pass the check
// above only if someone replaced the export with an equivalent object.
eq('it applies the owner grammar: underscore yes, dot no',
  [runtime.engine.validDkimSelector('a_b'), runtime.engine.validDkimSelector('a.b')],
  [true, false]);

// The generated data reached the engine, and it is the fixture table.
assertFixtureIdentity([probePublicSuffixRules(runtime.engine.getOrganizationalDomain, 'fixture')]);
eq('the fixture public suffix list is the one in force',
  runtime.engine.getOrganizationalDomain('foo.blogspot.com'), 'blogspot.com');
eq('and the English bundle reached i18n', runtime.i18n.t('doc.title'), 'T');

/* ── 2a. User-supplied artifacts enter through one injected parser ────── */
section('2a. The runtime owns artifact-analysis composition');

const parsed = [];
class RecordingDOMParser {
  parseFromString(text, type) {
    parsed.push({ text, type });
    return {
      documentElement: { localName: 'html', nodeName: 'html', attributes: [], childNodes: [] },
      getElementsByTagName: () => [],
    };
  }
}
const artifactRuntime = makeRuntime(dohFixture({}), RecordingDOMParser);
const callerParser = () => { throw new Error('caller parser must not run'); };
const artifactInput = {
  domain: 'example.test',
  bimiSvgText: '<html></html>',
  // The runtime owns this capability. Supplied data must not replace it.
  parseSvg: callerParser,
};
eq('the UI receives one artifact-analysis callback',
  typeof artifactRuntime.ui.analyzeArtifacts, 'function');
const artifactResult = artifactRuntime.ui.analyzeArtifacts(artifactInput);
eq('it drives the BIMI validator through the composed callback',
  artifactResult.artifactFindings[0].args, ['bad-root']);
eq('the supplied text reaches the platform parser unchanged', parsed[0].text, '<html></html>');
eq('the parser is forced to the SVG XML MIME type', parsed[0].type, 'image/svg+xml');
eq('composition does not mutate the caller input', artifactInput.parseSvg, callerParser);

/* ── 2b. One boot, one connectivity probe ─────────────────────────────── */
section('2b. There is exactly one mount path');

/**
 * A second boot path would run the language init twice and, more to the point,
 * put a SECOND connectivity probe on every page load — a figure `PRIVACY.md`
 * publishes and one of the five equivalence surfaces measures. The query trace
 * would catch it, but by then it would already be a privacy change.
 *
 * A lexical scan over `src/`, and named as one: it counts registration and
 * call SITES, not what happens at runtime, and would not see a listener added
 * through a computed name. It is defence against the specific regression a
 * move like Task 5.6 can leave behind — two boot paths, both working.
 */
const srcTree = (function walk(dir) {
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) return walk(full);
    return entry.name.endsWith('.js') && !entry.name.endsWith('.test.js') ? [full] : [];
  });
}(join(REPO, 'src')));
const BOOT = /addEventListener\(\s*'DOMContentLoaded'/g;
const countIn = (file, re) => (readFileSync(file, 'utf8').match(re) || []).length;

eq('exactly one module registers a DOMContentLoaded listener',
  srcTree.filter(f => countIn(f, BOOT)).map(f => relative(join(REPO, 'src'), f).split(sep).join('/')),
  ['ui/events.js']);
eq('and it registers exactly one',
  srcTree.reduce((n, f) => n + countIn(f, BOOT), 0), 1);
// The scan can fail: it really matches the registration it claims to find, and
// finds none in the entry point, which is composition only since Task 5.6.
eq('the scan matched a real registration',
  countIn(join(REPO, 'src/ui/events.js'), BOOT), 1);
eq('and the entry point registers none', countIn(join(REPO, 'src/main.js'), BOOT), 0);

/**
 * ONE mount, not two functions that behave alike.
 *
 * `runtime.js` passes `mount` to `createUi()` and returns it. If those were
 * two separate `() => i18n.init()` arrows they would behave identically and
 * every test here would pass — while the UI called a function that was not the
 * documented member, and replacing the returned one would not change how the
 * page boots. That is a construction defect a behavioural test cannot see, so
 * it is asserted structurally.
 *
 * A lexical count of `i18n.init()` call sites, and named as one: it would not
 * catch a second wrapper built through a computed name.
 */
const runtimeSource = readFileSync(join(REPO, 'src/runtime.js'), 'utf8');
// Comments discuss `i18n.init()` by name — this counts CODE, so they are
// stripped first. Counting them was this check's own first defect.
const runtimeCode = runtimeSource.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');

eq('runtime.js calls i18n.init() from exactly one place',
  (runtimeCode.match(/i18n\.init\(\)/g) || []).length, 1);
eq('and that place is a single named declaration',
  /const mount = \(\) => i18n\.init\(\);/.test(runtimeCode), true);
// Two uses, both the bare identifier: passed to createUi, returned to the
// caller. Bare means they cannot drift apart.
eq('the identifier is used exactly twice',
  (runtimeCode.match(/^\s*mount,$/gm) || []).length, 2);
eq('once as what the UI is given',
  /\n\s*mount,\n\s*englishBundle,/.test(runtimeCode), true);
// The scan can fail: a second wrapper is exactly what it is looking for.
eq('a second wrapper would be a second call site',
  ((runtimeCode + '\n  const other = () => i18n.init();').match(/i18n\.init\(\)/g) || []).length, 2);
eq('the runtime still exposes mount as a function', typeof runtime.mount, 'function');

/* ── 3. One runtime, one cache, page lifetime ─────────────────────────── */
section('3. The DoH cache belongs to the runtime');

/**
 * The property `tools/scoring.test.mjs:1888-1891` asserts and `PRIVACY.md`
 * publishes: a sibling subdomain reuses the upper steps of the first walk.
 * Measured here through the runtime rather than through the engine, because
 * the runtime is what owns the lifetime.
 */
const walkFixture = () => dohFixture({
  'delta.test NS': ns('ns1.delta.test'),
  'delta.test MX': mx('10 mail.delta.test'),
  'delta.test TXT': txt('v=spf1 -all'),
  '_dmarc.delta.test TXT': txt('v=DMARC1; p=reject; rua=mailto:d@delta.test'),
  'sub.delta.test NS': ns('ns1.delta.test'),
  'sub.delta.test MX': mx('10 mail.delta.test'),
  'sub.delta.test TXT': txt('v=spf1 -all'),
  'mail.delta.test A': a('203.0.113.5'),
});

const walkNames = calls => calls.filter(c => c.startsWith('_dmarc.')).map(c => c.split(' ')[0]);
const AUDIT = { advanced: false, dkim: false, www: false, wildcard: false, deepChecks: false, selectors: [] };

const shared = walkFixture();
const oneRuntime = makeRuntime(shared);
await oneRuntime.analyzeDomain('delta.test', AUDIT);
const afterFirst = walkNames(shared.calls).length;
await oneRuntime.analyzeDomain('sub.delta.test', AUDIT);
const afterSecond = walkNames(shared.calls).length;

eq('the first walk queried the tree', afterFirst > 1, true);
eq('and the sibling reused all but its own step', afterSecond - afterFirst, 1);
eq('the reused names are the ones the first walk answered',
  walkNames(shared.calls).slice(0, afterFirst).includes('_dmarc.delta.test'), true);

/* ── 4. Two runtimes share nothing ────────────────────────────────────── */
section('4. Isolation between runtimes');

const firstFixture = walkFixture();
const secondFixture = walkFixture();
const runtimeA = makeRuntime(firstFixture);
const runtimeB = makeRuntime(secondFixture);

await runtimeA.analyzeDomain('delta.test', AUDIT);
const aCalls = firstFixture.calls.length;
await runtimeB.analyzeDomain('delta.test', AUDIT);
const bCalls = secondFixture.calls.length;

eq('the second runtime queried for itself, reusing nothing', bCalls, aCalls);
eq('and its fixture saw every one of those queries', bCalls > 0, true);
// The decisive half: a shared cache would have made the second audit cheap.
await runtimeA.analyzeDomain('delta.test', AUDIT);
eq('while a repeat through the SAME runtime costs nothing', firstFixture.calls.length, aCalls);

eq('the two runtimes hold different engines', runtimeA.engine === runtimeB.engine, false);
eq('different i18n instances', runtimeA.i18n === runtimeB.i18n, false);
eq('and different renderers', runtimeA.renderer === runtimeB.renderer, false);

// Node's module cache is not a DI mechanism: importing the module twice gives
// the same function, and isolation comes from calling it again.
const reimported = await import('../../src/runtime.js');
eq('a second import is the same module', reimported.createAuditRuntime, runtimeModule.createAuditRuntime);
eq('and isolation still comes from constructing, not from importing',
  makeRuntime(dohFixture({})).engine === runtime.engine, false);

/* ── 5. The facade delegates to the engine ────────────────────────────── */
section('5. The two supported members');

const connectivity = makeRuntime(dohFixture({ 'example.com A': a('93.184.216.34') }));
eq('checkConnectivity reaches the resolver', await connectivity.checkConnectivity(), true);
const offline = makeRuntime(async () => { throw new Error('offline'); });
eq('and reports failure without throwing', await offline.checkConnectivity(), false);

await rejects('analyzeDomain propagates a core transport failure',
  () => makeRuntime(dohFixture({ 'boom.test': 'servfail' }))
    .analyzeDomain('boom.test', { ...AUDIT, signal: undefined }),
  error => error && error.kind === 'servfail');

report();
