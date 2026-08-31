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
// The generated tables, imported rather than read off globals. Task 6.2
// removed the globals with the last adapter; these are the same modules the
// entry point hands the runtime.
import { PUBLIC_SUFFIX_RULES } from '../../src/data/public-suffixes.js';
import { DKIM_SELECTOR_CATALOG } from '../../src/data/dkim-selectors.js';
import { LOCALE_EN } from '../../src/data/locales-en.js';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, section, report } = createSuite();

const ARTIFACT = 'dist/app.min.js';

/**
 * The ambient names the harness supplies. Everything a load leaves behind
 * beyond these is a global the code created, which is the surface under test.
 */
const AMBIENT = ['document', 'navigator', 'location', 'localStorage', 'fetch', 'console',
  'setTimeout', 'clearTimeout', 'queueMicrotask', 'URL', 'URLSearchParams',
  'AbortController', 'crypto', 'Date', 'Intl', 'window', 'self', 'globalThis',
  // Supplied by the harness, not created by the code: the rest of the §11 set,
  // the array the recorded `open` writes into, and the swappable fetch holder.
  'Blob', 'FileReader', 'open', 'opened', 'currentFetch'];

/**
 * A fresh sandbox per load, and the load is cache-busted by construction:
 * `vm.runInContext` re-evaluates the source text every time, so neither Node's
 * module cache nor a previous load can leak into this one.
 *
 * This is the ARTIFACT side. The artifact is a classic IIFE — that is what
 * keeps `file://` working — so a sandbox can still evaluate it, and evaluating
 * it is the whole point: this file exists to measure the file that ships.
 */
/**
 * One definition of "a browser", used by every load in this file.
 *
 * Written once because the two negative controls below have to build the SAME
 * window as the real loads: a control that differed from the thing it is
 * controlling proves nothing about it.
 */
function blankWindow() {
  const document = createDocument();
  const win = {
    document,
    navigator: { language: 'en', languages: ['en'] },
    location: { href: 'https://dnsaudit.kwestic.com/' },
    localStorage: { getItem: () => null, setItem: () => {}, removeItem: () => {} },
    // A HOLDER, not a value. `src/platform/browser.js` binds the primitive set
    // once per runtime, so a `win.fetch = x` written after the subject booted
    // would never reach it. The indirection is what lets one loaded application
    // — and the source side can only be loaded once, because Node caches ES
    // modules — be driven by a different fixture per assertion. Same move
    // `tools/scoring.test.mjs` makes for its 69 swaps.
    fetch: (...args) => win.currentFetch(...args),
    currentFetch: async () => ({ ok: false }),
    console, setTimeout, clearTimeout, queueMicrotask,
    URL, URLSearchParams, AbortController, crypto, Date, Intl,
    // Every window a platform is built from must carry the whole §11 set: the
    // adapter binds each method, so a missing one throws at construction rather
    // than degrading quietly. Navigation is recorded, never performed.
    opened: [],
    Blob: class Blob {}, FileReader: class FileReader {},
  };
  win.open = (...args) => { win.opened.push(args); return null; };
  win.window = win;
  win.self = win;
  win.globalThis = win;
  return win;
}

function load(files) {
  const win = blankWindow();
  vm.createContext(win);
  for (const file of files) {
    vm.runInContext(readFileSync(join(REPO, file), 'utf8'), win, { filename: file });
  }
  return win;
}

/**
 * The SOURCE side: the real ES module graph, evaluated by Node.
 *
 * There is nothing left to run in a sandbox. Task 2.6 converted the last
 * hand-written IIFE, so the source side is now an `import` of `src/main.js` —
 * the same entry point esbuild compiles — over a window this file supplies.
 * `src/main.js` reads the ambient `window` to build its platform, which is the
 * one ambient read an entry point has to make, so the window is installed
 * first. It carried an adapter marker until Task 6.2; it does not now.
 *
 * ONCE PER PROCESS, and it has to be: Node caches ES modules, so a second
 * import would return the first application and this window would never be
 * touched. This file needs exactly one source load and one artifact load, so
 * the constraint costs nothing here — but it is why the artifact side stays on
 * `vm`, where every load re-evaluates.
 */
async function loadSource() {
  const win = blankWindow();
  globalThis.window = win;
  const module = await import('../../src/main.js');
  return { win, module };
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

const { win: source, module: sourceModule } = await loadSource();
const bundle = load([ARTIFACT]);

const sourceGlobals = globalsOf(source);
const bundleGlobals = globalsOf(bundle);

/**
 * `DnsAudit` has exactly one producer, and after Task 2.7 it is the BUNDLER.
 *
 * `globalName` assigns the entry point's exports to that name, so the source
 * graph does not create it — spec §10's "generated boundary esbuild produces at
 * stage 3", and the reason the legacy assignment had to go in the same commit.
 * The one-name difference between the two sides is therefore the shape the
 * design predicts, and it is asserted as exactly one name rather than tolerated
 * as a mismatch.
 */
/**
 * ONE name, and Task 6.2 is why.
 *
 * Three authorized compatibility deltas brought it here: Task 2.7 contracted
 * `window.DnsAudit` from 95 members to two, Task 2.8 removed the fourteen
 * unsupported function globals, and **Task 6.2 removed the last nine** —
 * `__APP_TEST__`, the i18n/renderer wiring and the three generated-data
 * transition inputs. Each of those nine had a repository consumer with no ESM
 * owner; every owner exists now, so each was retired rather than dropped.
 *
 * Named rather than counted, so a name surviving that nobody kept is caught.
 */
const EXPECTED_GLOBALS = ['DnsAudit'];
eq('the bundle creates exactly the one name that survives Task 6.2',
  bundleGlobals, EXPECTED_GLOBALS);
eq('and none of the fourteen removed function globals is among them',
  ['startAudit', 'cancelAudit', 'clearAll', 'exportCSV', 'exportHTML', 'filterTable',
    'loadExample', 'loadFile', 'openLearnMore', 'setLang', 'showHelp', 'sortTable',
    'toggleDetail', 'toggleShowMe'].filter(n => bundleGlobals.includes(n)), []);

// The source graph creates NONE. `window.DnsAudit` is not written by any
// module: esbuild assigns the entry point's exports to `globalName`, which is
// §10's generated boundary and the whole of the difference between the two.
eq('the source graph creates no global at all', sourceGlobals, []);
eq('the bundle creates exactly one', bundleGlobals.length, 1);
eq('and the one name the bundle adds is DnsAudit',
  bundleGlobals.filter(n => !sourceGlobals.includes(n)), ['DnsAudit']);
eq('and it adds nothing else',
  bundleGlobals.filter(n => !sourceGlobals.includes(n) && n !== 'DnsAudit'), []);
eq('nothing the source creates is missing from the bundle',
  sourceGlobals.filter(n => !bundleGlobals.includes(n)), []);

/* ── 3. The supported facade, on both sides, exactly ──────────────────── */
section('3. The facade, the test surface and the 95 -> 2 contraction');

/**
 * Spec §10 stage 2: "The expected member list is checked in as
 * `src/facade.expected.json` and asserted against **both** the source module's
 * exports and the built bundle's global."
 *
 * CHECKED IN, not derived. A test that read the expected list out of the bundle
 * would agree with the bundle by construction and prove nothing. This compares
 * both sides against a list a person wrote before the build was allowed to
 * produce the surface — and it compares them EXACTLY, IN BOTH DIRECTIONS, so
 * the contraction from 95 members does not pass merely because Task 2.7 permits
 * the global surface to move.
 */
const FACADE = JSON.parse(readFileSync(join(REPO, 'src/facade.expected.json'), 'utf8'));
const expectedMembers = [...FACADE.members].sort();

eq('the checked-in facade is two members', expectedMembers, ['analyzeDomain', 'checkConnectivity']);
eq('and it names the global it governs', FACADE.globalName, 'DnsAudit');

// The SOURCE module's exports. `import * as` gives the module namespace, whose
// keys are exactly the declared exports.
const sourceExports = Object.keys(sourceModule).filter(n => n !== 'default').sort();
eq('the source module exports exactly the facade', sourceExports, expectedMembers);
eq('nothing the facade names is missing from the source',
  expectedMembers.filter(n => !sourceExports.includes(n)), []);
eq('and the source exports nothing the facade does not name',
  sourceExports.filter(n => !expectedMembers.includes(n)), []);
for (const name of expectedMembers) {
  eq(`the source's ${name} is callable`, typeof sourceModule[name], 'function');
}

// The BUNDLE's global, which is what a browser sees.
const bundleMembers = Object.keys(bundle.DnsAudit).sort();
eq('the bundle global exposes exactly the facade', bundleMembers, expectedMembers);
eq('nothing the facade names is missing from the bundle',
  expectedMembers.filter(n => !bundleMembers.includes(n)), []);
eq('and the bundle exposes nothing the facade does not name',
  bundleMembers.filter(n => !expectedMembers.includes(n)), []);
for (const name of expectedMembers) {
  eq(`the bundle's ${name} is callable`, typeof bundle.DnsAudit[name], 'function');
}

// And the two sides agree with each other, not merely with the file.
eq('source exports and bundle global are the same set', bundleMembers, sourceExports);

/**
 * The contraction, stated as a number so it cannot happen by accident.
 *
 * 95 members at v0.5.0 and through Task 2.6; two now. The other 93 were never
 * supported API — 77 were reached by `tools/scoring.test.mjs` and 4 by
 * `tools/backtest.mjs`, and both take direct ESM imports since Task 2.3.
 */
eq('the surface contracted from 95 members to 2', bundleMembers.length, 2);

/**
 * What esbuild adds that nobody specified, written down rather than ignored.
 *
 * `Object.keys()` returns the two members; `Object.getOwnPropertyNames()` also
 * returns a non-enumerable `__esModule` from esbuild's CommonJS interop. It is
 * observable, so it is recorded in `src/facade.expected.json` and pinned here.
 * An artifact that is written down is a fact about the build; one that is not
 * is a surface nobody is watching.
 */
eq('the only non-enumerable extra is the bundler artifact the facade records',
  Object.getOwnPropertyNames(bundle.DnsAudit).filter(n => !bundleMembers.includes(n)),
  FACADE.bundlerArtifacts.nonEnumerable);
eq('and it really is non-enumerable',
  Object.getOwnPropertyDescriptor(bundle.DnsAudit, '__esModule').enumerable, false);

// `__APP_TEST__` is gone from both, as of Task 6.2. It was never facade; it was
// a test surface, and `tools/render.test.mjs` and `tools/export.test.mjs`
// import the runtime directly now. Asserted absent on both sides, because a
// global that survives on one is exactly the drift this file exists to catch.
eq('__APP_TEST__ is on neither the bundle nor the source graph',
  [bundle.__APP_TEST__, source.__APP_TEST__], [undefined, undefined]);

/* ── 4. Behaviour through the facade ──────────────────────────────────── */
section('4. Behaviour, through the two members that are left');

/**
 * The artifact behaves like the source it was built from — asserted through the
 * only door that remains.
 *
 * Until Task 2.7 this section reached `DnsAudit.WEIGHTS`, `DnsAudit.
 * getOrganizationalDomain` and `DnsAudit.analyzeDkimKey` off the global and
 * compared them side by side. The facade contraction closes that door on
 * purpose: 93 members that were never supported API stopped being reachable
 * from a browser.
 *
 * Dropping the checks was not an option — a compatibility delta that passes
 * because the check that would have caught it disappeared is the failure this
 * whole branch is arranged to prevent. So they are asserted through
 * `analyzeDomain`, which is strictly stronger than what they replaced: a real
 * audit against a fixture resolver reads the bundled public suffix list, runs
 * the DER walk over a real 2048-bit key, applies every scoring weight and
 * builds the issue set. A tree-shaking fault, a minifier bug or a changed
 * constant moves the RESULT, which is what a user would have seen.
 *
 * The same fixture drives both sides, and it is a corpus case rather than a
 * hand-written one so the two instruments cannot drift.
 */
const { default: corpus } = await import('../fixtures/equivalence/corpus.mjs');

/**
 * The options the application itself passes, from `src/main.js:1528`.
 *
 * Written out rather than defaulted, because a default-off audit skips DKIM and
 * the advanced checks — and those are exactly the paths this section exists to
 * compare. `selectors` comes from the case, the way the runner reads it off the
 * control the user types into.
 */
function auditOptions(testCase) {
  const chosen = testCase.options || {};
  return {
    dkim: chosen.dkim ?? true,
    dkimComprehensive: chosen.dkimComprehensive ?? false,
    www: chosen.www ?? true,
    advanced: true,
    wildcard: chosen.wildcard ?? false,
    deepChecks: chosen.deepChecks ?? true,
    selectors: chosen.selectors || [],
  };
}

async function auditThrough(analyze, win, testCase) {
  win.currentFetch = testCase.fetch();
  const [{ domain }] = testCase.domains;
  return analyze(domain, auditOptions(testCase));
}

/**
 * Three cases, chosen for what each would notice.
 *
 * `enforcing-signed` publishes every control, so every weight contributes and a
 * changed one moves the score; it also carries the RSA key the DER walk decodes
 * and a DNSSEC chain the digest matcher has to verify. `dmarc-tree-walk`
 * exercises the organizational-domain walk, which is the public suffix list's
 * only path into a result. `bare-registered` is the empty end of the range, so
 * a fault that made everything look present would move it.
 */
for (const id of ['enforcing-signed', 'dmarc-tree-walk', 'bare-registered']) {
  const testCase = corpus.find(c => c.id === id);
  eq(`the corpus still has the ${id} case`, !!testCase, true);
  const fromSource = await auditThrough(sourceModule.analyzeDomain, source, testCase);
  const fromBundle = await auditThrough(bundle.DnsAudit.analyzeDomain, bundle, testCase);
  eq(`${id}: the whole result agrees`,
    JSON.stringify(fromSource), JSON.stringify(fromBundle));
  // And it is a real audit, not an empty object that would agree vacuously.
  eq(`${id}: produced a graded result`, typeof fromSource.score?.grade, 'string');
  eq(`${id}: and a numeric score`, Number.isFinite(fromSource.score?.pts), true);
}

/**
 * The two probes the old section made directly, kept as properties of a real
 * result rather than as calls on a member no longer exposed.
 */
const signed = await auditThrough(sourceModule.analyzeDomain, source,
  corpus.find(c => c.id === 'enforcing-signed'));
const signedKey = signed.dkimStatus?.selectors?.find(r => r.key?.keyBits);
eq('the DER walk ran and read a real 2048-bit key', signedKey?.key?.keyBits, 2048);
eq('and Web Crypto confirmed the key, so the platform reached the audit',
  signedKey?.key?.cryptoValidated, true);
eq('and every scoring pillar contributed, so a changed weight would move this',
  signed.score.breakdown.pillars.filter(p => p.pts > 0).length,
  signed.score.breakdown.pillars.length);
eq('a fully-configured domain grades in the A band', signed.score.grade.startsWith('A'), true);

/* ── 5. Generated data survived bundling intact ───────────────────────── */
section('5. Generated data');

/**
 * Read out of the ARTIFACT and the source MODULES, not off globals.
 *
 * Task 6.2 removed `__PUBLIC_SUFFIX_RULES__`, `__DKIM_SELECTOR_CATALOG__` and
 * `__I18N_EN__` from the window with the last adapter. The coverage they
 * carried does not go with them: the question was never "is the global set", it
 * was **"did the generated data survive bundling intact"**, and the artifact
 * itself answers that more directly than a name the app assigned.
 *
 * Spec §11 as of `1.4`: this is a BINDING-level check and there is no
 * behavioural one, because `getOrganizationalDomain()` is the only reader of
 * the PSL sets and no application code calls it. Section 6 below records why
 * an attempt to observe it through the facade would have been wrong.
 */
const artifactText = readFileSync(join(REPO, ARTIFACT), 'utf8');

eq('the public suffix list is the real one, not a fixture',
  PUBLIC_SUFFIX_RULES.length > 10000, true);
// The discriminating rule, not just the count — a truncated list of the right
// length would pass a length check. Same rule the fixture-identity probes use.
eq('the source module carries the private blogspot.com rule',
  PUBLIC_SUFFIX_RULES.includes('blogspot.com'), true);
eq('and the built artifact carries it too',
  artifactText.includes('blogspot.com'), true);
// Every rule, not a sample: the bundled text must contain the whole table.
eq('every public suffix rule survived bundling',
  PUBLIC_SUFFIX_RULES.filter(rule => !artifactText.includes(rule)), []);

eq('the DKIM selector catalog is whole in the artifact',
  Object.keys(DKIM_SELECTOR_CATALOG).filter(k => !artifactText.includes(k)), []);
eq('and it is the real one', Object.keys(DKIM_SELECTOR_CATALOG.providers).length > 10, true);

/**
 * The inlined English bundle is why `file://` works at all: the app needs no
 * fetch to render text, and if bundling dropped it `file://` would degrade
 * silently to untranslated keys.
 *
 * Checked over the ASCII-only strings, and the reason is measured rather than
 * assumed: **esbuild escapes non-ASCII as `\uXXXX`**, so `doc.title` — which
 * carries an em dash — is in the artifact and not as its own bytes. Probed
 * before asserting; the obvious `includes(LOCALE_EN.doc.title)` is false for a
 * bundle that contains it perfectly.
 */
const flatEnglish = [];
(function walk(node) {
  for (const value of Object.values(node)) {
    if (typeof value === 'string') flatEnglish.push(value);
    else if (value && typeof value === 'object') walk(value);
  }
}(LOCALE_EN));
const asciiEnglish = flatEnglish.filter(v => /^[\x20-\x7e]{12,}$/.test(v));
eq('the bundle carries a substantial English vocabulary to check',
  asciiEnglish.length > 250, true);
eq('and every ASCII English string is inlined in the artifact',
  asciiEnglish.filter(v => !artifactText.includes(v)), []);
// The escaping, asserted rather than left as a footnote — it is why the check
// above is scoped, and a build that stopped escaping would change the artifact.
eq('non-ASCII is escaped, which is why the check is ASCII-scoped',
  artifactText.includes('\\u2014'), true);

// The scan is only meaningful if it read the real artifact.
eq('the artifact scanned is the whole application', artifactText.length > 100000, true);

/* ── 6. The DMARC tree walk agrees ────────────────────────────────────── */
section('6. The organizational-domain walk');

/**
 * `getOrganizationalDomain` used to be called here directly, and this section
 * was going to be renamed "the bundled PSL, observed through the facade".
 *
 * **It would have been wrong, and naming that is the point.** The
 * `organizationalDomain` on a result is produced by `selectOrganizationalDomain()`
 * from the RFC 9989 discovery chain (`js/dns.js:2122`); it never consults the
 * public suffix list. Substituting the PSL would not move it. Spec `1.4`
 * records why: `getOrganizationalDomain()` is the only reader of the PSL sets
 * and no application code calls it, so the table has no path into any of the
 * five surfaces and none of them can be evidence about it. What the bundled
 * table's presence CAN be checked against is in section 5, and
 * `docs/maintenance-backlog.md` carries the finding.
 *
 * What this does establish is worth having on its own: the tree walk is one of
 * the two algorithms where ORDER is the behaviour (canonicalization.md §2), and
 * these assertions say the artifact walks identically to the source it was
 * built from.
 */
const walk = corpus.find(c => c.id === 'dmarc-tree-walk');
const walkSource = await auditThrough(sourceModule.analyzeDomain, source, walk);
const walkBundle = await auditThrough(bundle.DnsAudit.analyzeDomain, bundle, walk);
eq('the organizational domain the walk found agrees',
  walkSource.organizationalDomain, walkBundle.organizationalDomain);
eq('and the walk actually reached one', typeof walkSource.organizationalDomain, 'string');
eq('the source and bundle agree on where the DMARC record was found',
  JSON.stringify(walkSource.dmarcDiscovery), JSON.stringify(walkBundle.dmarcDiscovery));
eq('and on the domain the policy was read at',
  walkSource.dmarcAtDomain, walkBundle.dmarcAtDomain);

/* ── 7. The comparison can fail ───────────────────────────────────────── */
section('7. Negative control');

/**
 * A parity check nobody has watched fail is not evidence.
 *
 * Loading a deliberately altered artifact must move every comparison above that
 * it should. Built in memory rather than on disk so it cannot be mistaken for a
 * real build output.
 *
 * This control had to change with the facade. It used to read
 * `DnsAudit.WEIGHTS` off the altered global and compare the number; the engine
 * is not on the global any more, so the alteration is now observed the way a
 * user would observe it — through `analyzeDomain`, on the score. That is the
 * same door section 4 uses, which is the point: a control that reached the
 * defect by a route the real comparison does not use would not be controlling
 * the real comparison.
 */
const pristineArtifact = readFileSync(join(REPO, ARTIFACT), 'utf8');
const altered = pristineArtifact
  .replace('dmarc:30', 'dmarc:29')
  .replace('"dmarc":30', '"dmarc":29');
eq('the alteration applied', altered !== pristineArtifact, true);

function loadText(text, filename) {
  const win = blankWindow();
  vm.createContext(win);
  vm.runInContext(text, win, { filename });
  return win;
}

const alteredWin = loadText(altered, 'altered');
const signedCase = corpus.find(c => c.id === 'enforcing-signed');
const fromAltered = await auditThrough(alteredWin.DnsAudit.analyzeDomain, alteredWin, signedCase);
const fromPristine = await auditThrough(bundle.DnsAudit.analyzeDomain, bundle, signedCase);

eq('an altered artifact fails the result comparison',
  JSON.stringify(fromAltered) === JSON.stringify(fromPristine), false);
// And the difference is the one introduced, not incidental noise: the DMARC
// pillar is worth one point less, and nothing else moved.
eq('the DMARC pillar carries the altered maximum',
  fromAltered.score.breakdown.pillars.find(p => p.key === 'dmarc').max, 29);
eq('while the pristine artifact still carries 30',
  fromPristine.score.breakdown.pillars.find(p => p.key === 'dmarc').max, 30);
eq('and no other pillar moved',
  JSON.stringify(fromAltered.score.breakdown.pillars.filter(p => p.key !== 'dmarc')),
  JSON.stringify(fromPristine.score.breakdown.pillars.filter(p => p.key !== 'dmarc')));

// And a global-surface difference is caught too.
const extraWin = loadText(pristineArtifact + '\nvar DnsAuditExtra = 1;', 'extra');
eq('an extra global is caught',
  globalsOf(extraWin).filter(n => !bundleGlobals.includes(n)), ['DnsAuditExtra']);

/**
 * And a facade that grew a member is caught, which is the control this task
 * actually needs. `src/facade.expected.json` is only worth anything if the
 * comparison against it can fail.
 */
const widened = loadText(pristineArtifact + '\nDnsAudit.exportCSV = function () {};', 'widened');
eq('a widened facade is caught',
  Object.keys(widened.DnsAudit).sort().filter(n => !expectedMembers.includes(n)), ['exportCSV']);
// Narrowed by REPLACING the namespace, not by deleting from it. Measured while
// writing this control: esbuild's `__export` installs each member as a
// non-configurable getter, so `delete DnsAudit.checkConnectivity` silently does
// nothing and a control built that way would have passed while testing nothing.
eq('facade members are non-configurable, so they cannot be deleted',
  Object.getOwnPropertyDescriptor(bundle.DnsAudit, 'checkConnectivity').configurable, false);
const narrowed = loadText(
  pristineArtifact + '\nDnsAudit = { analyzeDomain: DnsAudit.analyzeDomain };', 'narrowed');
eq('and a narrowed facade is caught',
  expectedMembers.filter(n => !Object.keys(narrowed.DnsAudit).includes(n)), ['checkConnectivity']);

report();
