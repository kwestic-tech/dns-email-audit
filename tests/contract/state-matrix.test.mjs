#!/usr/bin/env node
/**
 * Enforces the four rules spec §12.1 attaches to the reviewed state registry.
 *
 *   1. Reject matrix rows naming missing suites or fixtures.
 *   2. Reject an algebra member with no coverage row.
 *   3. Compare each extracted module's exported state constants with the
 *      reviewed registry, once that module exists.
 *   4. Run targeted legacy contracts for computed values, thrown paths,
 *      booleans, nullability and absence until extraction is complete.
 *
 * Rules 3 and 4 are delegated: rule 4 lives in `legacy-shapes.test.mjs`, and
 * rule 3 has nothing to compare against until Phase 3 creates the first
 * `src/core/` module — so this file asserts that the delegation is wired and
 * that the extracted-module comparison covers every module that exists.
 *
 * What this file does NOT claim: that a static extractor discovered these
 * states. It did not. `tests/state-algebras.json` is a reviewed document, and
 * `legacy-shapes.test.mjs` section 6 executes the proof that a literal scan
 * under-reports it by three tokens.
 */

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

import { createSuite } from '../lib/assert.mjs';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, section, report } = createSuite();

const registry = JSON.parse(readFileSync(join(REPO, 'tests/state-algebras.json'), 'utf8'));
const matrix = JSON.parse(readFileSync(join(REPO, 'tests/state-matrix.json'), 'utf8'));

/* ── 1. Every named suite and fixture exists ──────────────────────────── */
section('1. Named suites and fixtures resolve');

// The corpus module is the single source of truth for which cases exist. An
// earlier draft read a separate corpus.json index, which would have been a
// second place for a case id to live and a second place for it to drift.
const { cases } = await import(pathToFileURL(join(REPO, 'tests/fixtures/equivalence/corpus.mjs')).href);
const corpus = new Set(cases.map(c => c.id));

const missingSuites = new Set();
const missingFixtures = new Set();
for (const row of matrix.rows) {
  for (const suite of row.suites) if (!existsSync(join(REPO, suite))) missingSuites.add(suite);
  for (const fixture of row.fixtures) if (!corpus.has(fixture)) missingFixtures.add(fixture);
}
eq('no row names a suite file that does not exist', [...missingSuites], []);
eq('no row names a corpus case that does not exist', [...missingFixtures], []);
// Shapes name their cases by review — a shape is a set of AXES, and an axis is
// not a value the path reader can observe, so these cannot be measured the way
// the enum rows are.
const shapeCases = new Set(registry.shapes.flatMap(shape => shape.fixtures || []));
eq('every non-enum shape names at least one corpus case',
  registry.shapes.filter(shape => !(shape.fixtures || []).length).map(s => s.id), []);
eq('and every case a shape names exists',
  [...shapeCases].filter(id => !corpus.has(id)), []);

// The other direction: a case nothing covers is a case nobody is measuring.
const namedCases = new Set([...matrix.rows.flatMap(row => row.fixtures), ...shapeCases]);
eq('every corpus case covers at least one registry member or shape',
  cases.map(c => c.id).filter(id => !namedCases.has(id)), []);

/* ── 2. Every registry member has exactly one covered row ─────────────── */
section('2. Registry coverage');

const rowCount = new Map();
for (const row of matrix.rows) {
  const key = `${row.algebra} ${row.member}`;
  rowCount.set(key, (rowCount.get(key) || 0) + 1);
}

const noRow = [];
const duplicated = [];
const uncovered = [];
for (const algebra of registry.algebras) {
  for (const member of algebra.members) {
    const key = `${algebra.id} ${member}`;
    const count = rowCount.get(key) || 0;
    if (count === 0) { noRow.push(`${algebra.id} :: ${member}`); continue; }
    if (count > 1) duplicated.push(`${algebra.id} :: ${member}`);
    const row = matrix.rows.find(r => r.algebra === algebra.id && r.member === member);
    if (!row.suites.length && !row.fixtures.length) uncovered.push(`${algebra.id} :: ${member}`);
  }
}
eq('every registry member has a matrix row', noRow, []);
eq('no member has two rows', duplicated, []);
// The gate, and deliberately not softened. A member with neither a suite nor a
// corpus fixture is a state nothing observes. Spec §12.1: "rejects an algebra
// member with no coverage row". A member the corpus genuinely cannot reach is
// framework §6 trigger 3 — stop and write a Codex review, never add an
// exemption here.
eq('every registry member is covered by a suite or a corpus fixture', uncovered, []);

const orphanRows = matrix.rows.filter(row => {
  const algebra = registry.algebras.find(a => a.id === row.algebra);
  return !algebra || !algebra.members.includes(row.member);
}).map(r => `${r.algebra} :: ${r.member}`);
eq('no matrix row names a member the registry does not have', orphanRows, []);

/* ── 3. Extracted module state constants match the registry ───────────── */
section('3. Extracted module constants (Phase 3 onward)');

/**
 * Every module under `src/`, and what state constants it exports.
 *
 * Rule 3 of spec §12.1: compare each extracted module's exported state
 * constants with the reviewed registry, once that module exists. Phase 1
 * creates exactly one module and it exports nothing — `src/entry-legacy.js` is
 * seven side-effect imports, and it must STAY that way, because esbuild assigns
 * the entry point's exports to `globalName` and an entry that grew one would
 * change what the bundle puts on `window`.
 *
 * So the comparison is written now, against an empty set, rather than deferred
 * to the phase where it first has something to say.
 */
const srcDir = join(REPO, 'src');
const srcModules = existsSync(srcDir)
  ? readdirSync(srcDir, { recursive: true })
    .map(String)
    .filter(p => p.endsWith('.js') && !p.endsWith('.test.js'))
    .sort()
  : [];

/**
 * Export names, read from the source rather than by importing.
 *
 * `src/entry-legacy.js` evaluates the seven browser IIFEs, and importing it in
 * Node throws on `window` before it can be inspected. The property under test
 * is syntactic anyway — whether the file declares an export — so it is read
 * syntactically. A module that reaches into `js/` is never imported here.
 */
function declaredExports(source) {
  const names = new Set();
  for (const m of source.matchAll(/^\s*export\s+(?:async\s+)?(?:const|let|var|function|class)\s+([A-Za-z_$][\w$]*)/gm)) names.add(m[1]);
  for (const m of source.matchAll(/^\s*export\s*\{([^}]*)\}/gm)) {
    for (const part of m[1].split(',')) {
      const name = part.trim().split(/\s+as\s+/).pop().trim();
      if (name) names.add(name);
    }
  }
  if (/^\s*export\s+default\b/m.test(source)) names.add('default');
  return [...names].sort();
}

/**
 * The FLOOR of the import graph is excluded from the state-constant comparison,
 * and the exclusion is mechanical rather than a judgment call: §12's
 * allowed-edge matrix gives `src/data/` and `src/platform/` no outgoing edges
 * at all, and a module that imports nothing holds no protocol vocabulary. What
 * they export is tables and primitive names — 10,239 public suffix rules, a
 * selector catalog, the §11 primitive list — and running the vocabulary
 * comparison over those reports every one of them as an unknown algebra.
 *
 * The floor's own rule is asserted directly instead, which is stronger.
 *
 * Spec §2 records it as "generated; not hand-edited, not unit-tested", and
 * §12's allowed-edge matrix gives it no outgoing edges at all: a generated file
 * that imports something has stopped being generated data. Its exports are
 * tables — 10,239 public suffix rules, a selector catalog, an English bundle —
 * not closed state vocabularies, and running the vocabulary comparison over
 * them reports every one of them as an unknown algebra.
 *
 * So the sink rule is asserted directly instead, which is the stronger check.
 */
const FLOOR = ['data/', 'platform/'];
const isFloor = p => FLOOR.some(prefix => p.startsWith(prefix));
const dataModules = srcModules.filter(p => p.startsWith('data/'));
const floorModules = srcModules.filter(isFloor);
const codeModules = srcModules.filter(p => !isFloor(p));

// Every floor module must actually be one. This is what makes the exclusion
// above a rule rather than a list: a file that grows an import stops being
// floor and rejoins the comparison.
for (const relative of floorModules) {
  const source = readFileSync(join(srcDir, relative), 'utf8');
  const importsSomething = /^\s*import\s/m.test(source);
  // The generated-data adapter is the one floor file that imports, and it is a
  // marked adapter whose whole job is to bind the tables to globals.
  if (relative === 'data/legacy-globals.js') continue;
  eq(`${relative} imports nothing — it is floor`, importsSomething, false);
}
eq('the floor is the generated data and the platform adapter',
  floorModules.sort(),
  ['data/dkim-selectors.js', 'data/legacy-globals.js', 'data/locales-en.js',
    'data/public-suffixes.js', 'platform/browser.js']);

eq('the generated data modules are the three tables and the adapter that installs them',
  dataModules.sort(),
  ['data/dkim-selectors.js', 'data/legacy-globals.js', 'data/locales-en.js', 'data/public-suffixes.js']);

for (const generated of ['data/public-suffixes.js', 'data/dkim-selectors.js', 'data/locales-en.js']) {
  const source = readFileSync(join(srcDir, generated), 'utf8');
  eq(`${generated} imports nothing — it is a sink`, /^\s*import\s/m.test(source), false);
  eq(`${generated} says it is generated`, /AUTO-GENERATED/.test(source), true);
  eq(`${generated} exports exactly one table`, declaredExports(source).length, 1);
}

/**
 * Adapters are marked so they can be counted, and Phase 6 asserts the count has
 * reached zero. The sentinel is a grep, deliberately: an adapter that forgot to
 * declare itself is one nobody will remove.
 */
const ADAPTER_SENTINEL = 'LEGACY_ADAPTER';
const adapters = srcModules.filter(p =>
  readFileSync(join(srcDir, p), 'utf8').includes(ADAPTER_SENTINEL)).sort();
eq('every adapter carries the sentinel, and these are the ones that exist',
  adapters, ['data/legacy-globals.js', 'entry-legacy.js', 'legacy-bridge.js']);
// The count only means something if it is going down. Recorded so a phase that
// adds one without removing another has to say so.
console.log(`  adapters remaining: ${adapters.length}`);

const legacyEntry = 'entry-legacy.js';
// Grows every Phase 2 commit, and named rather than counted so a module
// appearing here that nobody added is what this catches.
eq('src/ holds the entry point, the bridge and the converted layers',
  codeModules.sort(), ['entry-legacy.js', 'i18n/index.js', 'legacy-bridge.js', 'ui/render.js']);

/**
 * The property that makes omitting `globalName` safe, asserted rather than
 * assumed: esbuild assigns the ENTRY POINT'S EXPORTS to that name, so an entry
 * that grew one would change what the bundle puts on `window` — and with
 * `globalName: 'DnsAudit'` it would overwrite the real object from
 * js/dns.js:5601. The entry stays exportless until §10 stage 3.
 */
eq('the legacy entry point declares no exports',
  declaredExports(readFileSync(join(srcDir, legacyEntry), 'utf8')), []);

/**
 * Rule 3 of spec §12.1: compare each extracted module's exported state
 * constants with the reviewed registry, once that module exists. Written now
 * against an empty set rather than deferred to the phase where it first has
 * something to say.
 */
const unknownConstants = [];
for (const relative of codeModules) {
  const source = readFileSync(join(srcDir, relative), 'utf8');
  if (!declaredExports(source).length) continue;
  if (/from\s+['"][^'"]*\/js\//.test(source)) continue;   // still reaches legacy browser code
  const module = await import(pathToFileURL(join(srcDir, relative)).href);
  for (const [name, value] of Object.entries(module)) {
    const members = Array.isArray(value) ? value
      : (value && typeof value === 'object' ? Object.values(value) : null);
    if (!members || !members.length || !members.every(m => typeof m === 'string')) continue;
    const matching = registry.algebras.find(a => {
      const set = new Set(a.members);
      return members.length === set.size && members.every(m => set.has(m));
    });
    if (!matching) unknownConstants.push(`${relative}:${name} = [${members.join(', ')}]`);
  }
}
eq('every state constant a src/ module exports matches a registry algebra',
  unknownConstants, []);

/* ── 4. The targeted legacy contracts are wired ───────────────────────── */
section('4. Legacy contract delegation');

const legacy = join(REPO, 'tests/contract/legacy-shapes.test.mjs');
eq('the legacy shape contract exists', existsSync(legacy), true);
const legacySource = existsSync(legacy) ? readFileSync(legacy, 'utf8') : '';
for (const axis of ['Computed values', 'Thrown paths', 'Booleans, nullability and absence']) {
  eq(`it covers: ${axis}`, legacySource.includes(axis), true);
}
eq('and it runs its fixture-identity probes before any other assertion',
  legacySource.indexOf('assertFixtureIdentity(probes)') < legacySource.indexOf('1. Transport kinds'), true);

/* ── 5. The registry says what it is ──────────────────────────────────── */
section('5. Registry self-description');

eq('the registry names its baseline', registry.baseline, 'v0.5.0');
eq('every algebra declares whether it is closed',
  registry.algebras.filter(a => typeof a.closed !== 'boolean').map(a => a.id), []);
eq('every algebra names at least one construction site',
  registry.algebras.filter(a => !a.site && !a.memberSites).map(a => a.id), []);
eq('every non-enum shape names its axes',
  registry.shapes.filter(s => !Array.isArray(s.axes) || !s.axes.length).map(s => s.id), []);
eq('and every algebra observable in a result declares where',
  registry.algebras.filter(a => !Array.isArray(a.resultPaths)).map(a => a.id), []);

report();
