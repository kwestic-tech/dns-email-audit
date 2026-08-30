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
 * constants with the reviewed registry, once that module exists. It is written
 * against a set that is still nearly empty, rather than deferred to the phase
 * where it first has something to say.
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
 * `src/main.js` builds its platform from the ambient `window` and importing it
 * in Node throws before it can be inspected. The property under test is
 * syntactic anyway — which names the file declares — so it is read
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
  adapters, ['data/legacy-globals.js', 'main.js']);
// The count only means something if it is going down. Recorded so a phase that
// adds one without removing another has to say so.
console.log(`  adapters remaining: ${adapters.length}`);

const entryPoint = 'main.js';
// Grows every Phase 2 commit, and named rather than counted so a module
// appearing here that nobody added is what this catches. Task 2.6 retired
// `entry-legacy.js` and `legacy-bridge.js`: `src/main.js` is the entry point
// now, and it is the last file that was under `js/` apart from `dns.js`.
eq('src/ holds the entry point, the runtime and the converted layers',
  codeModules.sort(),
  ['audit/audit-domain.js', 'audit/context.js', 'audit/issues.js', 'audit/scoring.js',
    'core/bimi/bimi.js', 'core/caa/caa.js', 'core/dkim/dkim.js',
    'core/dmarc/org-domain.js', 'core/dmarc/record.js',
    'core/dmarc/report-auth.js', 'core/dmarc/tree-walk.js',
    'core/dns/cache.js', 'core/dns/doh.js', 'core/dns/errors.js', 'core/dns/existence.js',
    'core/dns/optional.js', 'core/dns/resolver.js',
    'core/dnssec/chain.js', 'core/dnssec/matching.js', 'core/dnssec/records.js',
    'core/mx/mx.js',
    'core/shared/base64.js', 'core/shared/ip.js', 'core/shared/record-fields.js',
    'core/shared/record-selection.js', 'core/shared/uri.js',
    'core/spf/spf.js',
    'core/transport/ext-value.js', 'core/transport/mta-sts.js',
    'core/transport/tls-rpt.js', 'core/transport/tlsa.js',
    'i18n/index.js', 'main.js', 'providers/detectors.js', 'runtime.js',
    'ui/render.js', 'ui/report.js']);

/**
 * The entry point exports the §10 facade and NOTHING else.
 *
 * esbuild assigns the ENTRY POINT'S EXPORTS to `globalName`, so as of Task 2.7
 * this list IS `window.DnsAudit`: a third export here would widen the supported
 * API of the shipped application.
 *
 * Read from `src/facade.expected.json` rather than written out again, so the
 * SOURCE contract and the ARTIFACT contract cannot drift apart —
 * `tests/build/parity.test.mjs` asserts the same file against the built
 * bundle's global. Syntactic here, behavioural there, one list.
 */
const facade = JSON.parse(readFileSync(join(srcDir, 'facade.expected.json'), 'utf8'));
eq('the checked-in facade is the two supported members',
  [...facade.members].sort(), ['analyzeDomain', 'checkConnectivity']);
eq('the entry point exports exactly the supported facade',
  declaredExports(readFileSync(join(srcDir, entryPoint), 'utf8')),
  [...facade.members].sort());
eq('and the facade names the global it governs', facade.globalName, 'DnsAudit');

/**
 * Rule 3 of spec §12.1: compare each extracted module's exported state
 * constants with the reviewed registry, once that module exists. Written now
 * against an empty set rather than deferred to the phase where it first has
 * something to say.
 */
/**
 * A CONTRACT CLARIFICATION, recorded at Task 4.5. Not a spec defect.
 *
 * Spec §12.1 rule 3 requires an owner's exported STATE CONSTANTS to match the
 * reviewed registry. It does not say every all-string export is a state
 * algebra — this check had generalized beyond the requirement, and the
 * generalization held only because nothing under `src/` had yet exported a
 * code-keyed reference table.
 *
 * `core/dnssec/records.js` and `matching.js` export four:
 *
 * | Table | Source |
 * | --- | --- |
 * | `DNSSEC_ALGORITHMS` | IANA DNS Security Algorithm Numbers |
 * | `DNSSEC_ZONE_SIGNING` | IANA, the Zone Signing column |
 * | `DNSSEC_DIGESTS` | IANA DS Digest Algorithms |
 * | `DNSSEC_DIGEST_WEBCRYPTO` | **NOT IANA** — this implementation's map from a numeric digest code to the Web Crypto algorithm name that computes it. A capability map, and open in a different direction: it grows when a runtime gains an algorithm, not when a registry does. |
 *
 * None of the four is an algebra. No result field ranges over them: what a
 * result carries is `algorithmName`, one value read out of a table, which is
 * why the reviewed registry models the eligibility ANSWER and not the name.
 * Inventing an algebra for each would make the registry claim a closed set
 * where the source publishes an open one — the exact failure the registry
 * exists to prevent, arriving through the check meant to enforce it.
 *
 * ── What actually proves this, and what does not ────────────────────────
 *
 * TWO controls, and only together:
 *
 *  1. `isNumericKeyedTable()` finds CANDIDATES mechanically. **Numeric keys do
 *     not semantically prove a table is reference data** — a state
 *     representation keyed by numeric code is perfectly possible, and this
 *     predicate would excuse it. It is a shape test, named for its shape.
 *  2. The closed four-entry inventory below is the SEMANTIC allowlist. Every
 *     accepted table is a reviewed decision, and a fifth is a decision someone
 *     has to make rather than something the shape test waves through.
 *
 * The shape test is proven in both directions, because a classifier that
 * cannot fail is not one. `DNSSEC_ZONE_SIGNING` was previously passing for the
 * wrong reason — its values are booleans, so it was skipped by accident rather
 * than classified.
 */
const isNumericKeyedTable = value => value && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).length > 0 && Object.keys(value).every(k => /^\d+$/.test(k));

eq('a code-keyed table has the shape', isNumericKeyedTable({ 1: 'SHA-1', 2: 'SHA-256' }), true);
eq('a vocabulary array does not', isNumericKeyedTable(['secure', 'insecure']), false);
eq('and neither does an object keyed by name — that would be a vocabulary',
  isNumericKeyedTable({ secure: 'a', insecure: 'b' }), false);
eq('nor an empty object, which claims nothing either way', isNumericKeyedTable({}), false);
eq('a mixed-key object does not have the shape', isNumericKeyedTable({ 1: 'a', named: 'b' }), false);
// The stated limit, asserted so it cannot be forgotten: a numeric-keyed STATE
// map has the same shape and would be excused by the predicate alone. The
// inventory below is what stops that, not this.
eq('a numeric-keyed state map has the same shape — the predicate cannot tell',
  isNumericKeyedTable({ 0: 'secure', 1: 'insecure' }), true);

/**
 * The same clarification as the numeric-keyed tables, arriving as an ARRAY.
 *
 * `DMARC_TAGS_RFC9989` and `DMARC_TAGS_REMOVED` are RFC 9989's tag NAME lists.
 * No result field ranges over either: `unknownTags` and `removedTags` are
 * computed by filtering a record's tags AGAINST them, so they are the input to
 * a comparison rather than the range of a field. The registry models the
 * ANSWERS — `dmarc.tagState` is `absent`/`valid`/`invalid` — and `dmarc.policy`
 * is five members because the FIELD can also be null or empty, which is why a
 * three-value list of the policy names RFC 9989 defines does not match it and
 * should not be invented to.
 *
 * There is no shape test here and there cannot be one: a reference vocabulary
 * and a state vocabulary are both arrays of strings. The control is the closed
 * inventory alone, which is the same semantic allowlist the numeric-keyed
 * tables get and is the half that was doing the work there too.
 */
const REFERENCE_VOCABULARIES = [
  'core/dmarc/record.js:DMARC_TAGS_RFC9989',
  'core/dmarc/record.js:DMARC_TAGS_REMOVED',
  // Accepted at Task 4.7. INPUT vocabulary, not a result algebra: it defines
  // the selector names the audit TRIES, while the selectors a result reports
  // as observed are unbounded. Its export is also required to reconstruct the
  // transitional legacy engine surface. Third instance of the same
  // clarification, first outside `core/dmarc/`.
  'core/dkim/dkim.js:DKIM_SELECTORS',
];

const unknownConstants = [];
const numericKeyedTables = [];
const referenceVocabularies = [];
for (const relative of codeModules) {
  const source = readFileSync(join(srcDir, relative), 'utf8');
  if (!declaredExports(source).length) continue;
  if (/from\s+['"][^'"]*\/js\//.test(source)) continue;   // still reaches legacy browser code
  // A marked adapter reads the ambient window by definition, so importing one
  // into a Node process with no browser globals throws before it can be
  // inspected. Its exports are read syntactically above instead — which is
  // where the entry point's facade is pinned.
  if (source.includes(ADAPTER_SENTINEL)) continue;
  const module = await import(pathToFileURL(join(srcDir, relative)).href);
  for (const [name, value] of Object.entries(module)) {
    if (isNumericKeyedTable(value)) { numericKeyedTables.push(`${relative}:${name}`); continue; }
    if (REFERENCE_VOCABULARIES.includes(`${relative}:${name}`)) {
      referenceVocabularies.push(`${relative}:${name}`); continue;
    }
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

/**
 * THE SEMANTIC CONTROL. The shape test above finds candidates; this decides
 * which are accepted, and it is closed.
 *
 * A new numeric-keyed export fails here until someone reviews it and adds it
 * by name — which is what keeps the shape test from becoming a loophole for a
 * numeric-keyed state map. An empty list would also mean the shape test had
 * stopped matching anything at all.
 */
// Each named entry must actually be exported, or the inventory is carrying a
// name for something that no longer exists and quietly excuses nothing.
eq('every named reference vocabulary is really exported',
  referenceVocabularies.sort(), [...REFERENCE_VOCABULARIES].sort());

eq('and the numeric-keyed tables it excused are exactly these, all reviewed',
  numericKeyedTables.sort(),
  ['core/dnssec/matching.js:DNSSEC_DIGEST_WEBCRYPTO',
    'core/dnssec/records.js:DNSSEC_ALGORITHMS',
    'core/dnssec/records.js:DNSSEC_DIGESTS',
    'core/dnssec/records.js:DNSSEC_ZONE_SIGNING']);

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
