#!/usr/bin/env node
/**
 * The two transport-kind inventories. Spec Design §3 as amended in `1.6`,
 * implementation Task 3.6.
 *
 * Cross-cutting, so it lives in `tests/contract/` rather than beside a module:
 * one inventory is about which owners may read a raw kind, the other about
 * which result fields may carry one, and neither belongs to a single module.
 *
 * ── Why there are two ───────────────────────────────────────────────────
 *
 * `1.5` had one list of three names and it could not answer either question.
 * `domainExists()` and `checkConnectivity()` are legitimate raw-kind readers
 * that propagate nothing; a layer-4 fallback propagates a caught kind without
 * reading a raw response at all. The lists overlap in neither direction, so
 * this file tests both and lets neither stand in for the other.
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';

import { createSuite } from '../lib/assert.mjs';
import { TRANSPORT_KINDS } from '../../src/core/dns/doh.js';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, section, report } = createSuite();

/* ── 1. The raw-kind reader allowlist ─────────────────────────────────── */
section('1. Raw-kind readers');

/**
 * Spec §3's reader inventory, by owning function or family.
 *
 * Organized by owner rather than by line number on purpose: a move within an
 * owner must not invalidate the contract, and Phase 4 moves all four of the
 * `js/dns.js` owners into their protocol directories.
 */
const ALLOWED_READERS = [
  { owner: 'core/dns', reader: 'existenceFromResponse / domainExists', preserves: 'nxdomain versus nodata, which is no versus yes' },
  { owner: 'core/dns', reader: 'checkConnectivity', preserves: 'the raw answer as a reachability boolean' },
  { owner: 'core/dmarc', reader: 'checkExternalReportAuth', preserves: 'the exact response kind, and failed kinds converted at the protocol boundary' },
  { owner: 'core/dmarc', reader: 'discoverDmarc', preserves: 'each walk step, and a failed walk distinguished from absence' },
  { owner: 'core/dnssec', reader: 'dnssecLookupStatus / checkDNSSEC', preserves: 'lookup completeness and the validated-servfail security signal' },
  { owner: 'audit', reader: 'the NS servfail DNSSEC preflight in analyzeDomain', preserves: 'the deliberate unchecked retry before orchestration continues' },
];

eq('the allowlist is six entries', ALLOWED_READERS.length, 6);
eq('every entry names what it preserves',
  ALLOWED_READERS.filter(r => !r.preserves).length, 0);
eq('and the owners are the four the spec names',
  [...new Set(ALLOWED_READERS.map(r => r.owner))].sort(),
  ['audit', 'core/dmarc', 'core/dns', 'core/dnssec']);

/**
 * The layer implementations are NOT exception edges, and keeping them off the
 * list is what stops the term meaning "anywhere a kind is mentioned".
 * `doh.js` constructs the kinds and `requireUsable()` gates on them: they ARE
 * layers 1 and 2.
 */
const LAYER_IMPLEMENTATIONS = ['src/core/dns/doh.js', 'src/core/dns/resolver.js'];
eq('the layer implementations are excluded from the allowlist',
  ALLOWED_READERS.filter(r => LAYER_IMPLEMENTATIONS.some(f => r.reader.includes(f))), []);

/* ── 2. The structural control, and what it does not prove ────────────── */
section('2. No raw-kind reader outside the named owners');

/**
 * **This is a lexical scan, not scope analysis**, and `1.2` is the precedent
 * for saying so rather than implying otherwise. It finds `.kind` compared
 * against a literal transport kind, attributes each hit to the enclosing
 * `function` declaration by walking backwards, and fails on a hit whose
 * enclosing function is not an allowed reader or a layer implementation.
 *
 * What it establishes: a NEW raw-kind reader added to a scanned file, in a
 * function nobody named, is caught. What it does not: a reader that stores the
 * kind in a variable first and compares that, one built by computed access, or
 * one in a file the scan does not cover. Defense in depth against regression,
 * which is a real and useful thing and a different thing from a proof.
 */
const SCANNED = ['js/dns.js', ...LAYER_IMPLEMENTATIONS,
  'src/core/dns/existence.js', 'src/core/dns/cache.js', 'src/core/dns/errors.js',
  'src/core/dns/optional.js', 'src/main.js', 'src/runtime.js',
  // Protocol owners extracted in Phase 4. `core/dnssec/chain.js` is the one
  // that actually holds readers — Task 4.5 moved `dnssecLookupStatus` and
  // `checkDNSSEC` out of `js/dns.js`, so the allowlist's `core/dnssec` row now
  // names code in this file. The others are scanned because a reader added to
  // a protocol owner must be caught wherever it lands, not only in the file
  // that happens to hold one today.
  'src/core/caa/caa.js', 'src/core/mx/mx.js', 'src/core/bimi/bimi.js',
  'src/core/dmarc/record.js', 'src/core/dmarc/org-domain.js',
  'src/core/dmarc/tree-walk.js', 'src/core/dmarc/report-auth.js',
  'src/core/transport/mta-sts.js', 'src/core/transport/tls-rpt.js',
  'src/core/transport/tlsa.js', 'src/core/transport/ext-value.js',
  'src/core/dnssec/records.js', 'src/core/dnssec/matching.js',
  'src/core/dnssec/chain.js',
  'src/core/shared/uri.js', 'src/core/shared/record-fields.js',
  'src/core/shared/ip.js', 'src/core/shared/base64.js'];

/** Function names the allowlist covers, plus the layer implementations' own. */
const ALLOWED_FUNCTIONS = new Set([
  'existenceFromResponse', 'domainExists', 'checkConnectivity',
  'checkExternalReportAuth', 'discoverDmarc', 'dnssecLookupStatus', 'checkDNSSEC',
  'analyzeDomain',
  // NOT the protocol factories. `createDnssecCheck`, `createDmarcDiscovery`
  // and `createReportAuth` each wrap a reader declared as `function NAME`, so
  // the backwards walk finds the READER and never reaches the factory —
  // proven by removing them and watching this list stay empty. `createExistence`
  // is the exception because its reader is a returned function EXPRESSION,
  // which the walk has nothing to land on. An allowlist entry that covers
  // nothing is worse than absent: it reads as coverage.
  // `domainExists` is returned from this factory, so a backwards walk from the
  // comparison lands on the factory's name rather than the reader's.
  'createExistence',
  // Layers 1 and 2, which construct and gate on the kinds.
  'responseKind', 'fetchDohOnce', 'dohFetch', 'requireUsable', 'createDohTransport',
  'createResolver', 'dohQuery', 'dohAll', 'acquireDohSlot',
]);

/**
 * A THROWN error's `.kind` is not a raw resolver response.
 *
 * `src/main.js:1568` reads `e.kind === 'cancelled'` to tell a cancelled audit
 * from a failed one, which is §12.1's **thrown-path** contract and not this
 * inventory at all. The scan found it and the finding was correct about the
 * text and wrong about the category, so the receiver is classified: an
 * identifier conventionally holding a caught value is a thrown-path read.
 *
 * A lexical convention, and named as one. A raw response stored in a variable
 * called `error` would be missed, and a thrown value in one called `response`
 * would be reported — neither is a real pattern in this codebase, and the check
 * below proves the classifier itself can fail.
 */
const CAUGHT_RECEIVERS = /(?:^|[^.\w$])(?:e|err|error)\.kind\s*(?:===|!==)/;

const KIND_LITERAL = new RegExp(`\\.kind\\s*(?:===|!==)\\s*['"](?:${TRANSPORT_KINDS.join('|')})['"]`);

function enclosingFunction(lines, at) {
  for (let i = at; i >= 0; i--) {
    const m = /^\s*(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/.exec(lines[i])
      || /^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)/.exec(lines[i]);
    if (m) return m[1];
  }
  return '(top level)';
}

const unnamedReaders = [];
for (const file of SCANNED) {
  const path = join(REPO, file);
  if (!existsSync(path)) continue;
  const lines = readFileSync(path, 'utf8').split('\n');
  lines.forEach((line, i) => {
    const code = line.replace(/\/\/.*$/, '');
    if (!KIND_LITERAL.test(code)) return;
    if (CAUGHT_RECEIVERS.test(code)) return;      // a thrown path, not a raw response
    const fn = enclosingFunction(lines, i);
    if (!ALLOWED_FUNCTIONS.has(fn)) unnamedReaders.push(`${file}:${i + 1} in ${fn}()`);
  });
}
eq('no raw-kind reader exists outside the named owners and the layer implementations',
  unnamedReaders, []);

/**
 * An empty `unnamedReaders` is also what a scan that reads NOTHING produces.
 * A protocol extraction moves a reader into a new file, and if the scanned set
 * is not extended in the same commit the check keeps passing while covering
 * less — silently, and in exactly the direction that matters.
 *
 * So the allowlist's owners are located: every owner named in section 1 must
 * be found by the same scan, in some scanned file, inside a function the
 * allowlist knows. This is what makes a stale `SCANNED` list a failure rather
 * than a quiet loss of coverage.
 */
const locatedIn = new Map();
for (const file of SCANNED) {
  const path = join(REPO, file);
  if (!existsSync(path)) continue;
  const lines = readFileSync(path, 'utf8').split('\n');
  lines.forEach((line, i) => {
    const code = line.replace(/\/\/.*$/, '');
    if (!KIND_LITERAL.test(code) || CAUGHT_RECEIVERS.test(code)) return;
    const fn = enclosingFunction(lines, i);
    if (!locatedIn.has(fn)) locatedIn.set(fn, file);
  });
}
eq('the scan actually reads something — an empty result would pass vacuously',
  locatedIn.size > 0, true);
// Task 4.5 moved these two out of js/dns.js. Named by FILE so the move is
// visible here rather than only in the diff.
eq('dnssecLookupStatus is found in core/dnssec/chain.js',
  locatedIn.get('dnssecLookupStatus'), 'src/core/dnssec/chain.js');
eq('and checkDNSSEC with it', locatedIn.get('checkDNSSEC'), 'src/core/dnssec/chain.js');
eq('while the core/dns readers are still where core/dns keeps them',
  locatedIn.get('existenceFromResponse'), 'src/core/dns/existence.js');
// Task 4.6 moved the last two protocol readers out. What remains in
// `js/dns.js` is the audit preflight, which Phase 5 owns — asserted so that
// move has to update this too.
eq('the DMARC readers moved to their owner at Task 4.6',
  [locatedIn.get('checkExternalReportAuth'), locatedIn.get('discoverDmarc')],
  ['src/core/dmarc/report-auth.js', 'src/core/dmarc/tree-walk.js']);
/**
 * Both DMARC readers live inside a factory and are still found under their own
 * names, because each is declared `function NAME`. That is what makes the
 * factory entries above unnecessary, and it is why these assertions name the
 * FILE: a reader can keep its name while moving anywhere, and the file is the
 * part a stale scanned set gets wrong.
 */
eq('and nothing raw-kind is left in js/dns.js but the audit preflight',
  [...locatedIn].filter(([, file]) => file === 'js/dns.js').map(([fn]) => fn),
  ['analyzeDomain']);

// And the scan can fail. Without this it would pass on a pattern that matches
// nothing, which is how a regression check quietly stops being one.
const probe = [
  'function somethingNew(response) {',
  "  if (response.kind === 'servfail') return 'bogus';",
  '}',
];
eq('the scan catches a new reader in an unnamed function',
  (() => { const fn = enclosingFunction(probe, 1); return KIND_LITERAL.test(probe[1]) && !ALLOWED_FUNCTIONS.has(fn); })(), true);
eq('and attributes it to the enclosing function', enclosingFunction(probe, 1), 'somethingNew');
eq('while a hit inside an allowed reader is permitted',
  ALLOWED_FUNCTIONS.has(enclosingFunction(['function checkConnectivity() {', "  r.kind === 'success';"], 1)), true);
// The stated limit, asserted so it cannot be forgotten.
eq('a kind held in a variable first is NOT caught — a stated limit',
  KIND_LITERAL.test("const k = response.kind; if (k === 'servfail') {}"), false);

// The thrown-path classifier, proven in both directions.
eq('a caught error\'s kind is classified as a thrown path, not a reader',
  CAUGHT_RECEIVERS.test("var cancelled = e && (e.name === 'AbortError' || e.kind === 'cancelled');"), true);
eq('while a raw response\'s kind is not',
  CAUGHT_RECEIVERS.test("if (response.kind === 'servfail') {}"), false);
eq('and the classifier is a naming convention, not analysis — a stated limit',
  CAUGHT_RECEIVERS.test("if (raw.kind === 'servfail') {}"), false);

/* ── 3. The kind-propagation inventory ────────────────────────────────── */
section('3. Typed propagation paths');

/**
 * Eleven typed result fields that may retain a closed transport kind, from
 * spec §3 — derived from result construction, then checked against the
 * baseline. The registry is the single source, so the two cannot drift.
 */
const registry = JSON.parse(readFileSync(join(REPO, 'tests/state-algebras.json'), 'utf8'));
const transport = registry.algebras.find(a => a.id === 'dns.transport.kind');

eq('the transport algebra declares its result paths', transport.resultPaths.length, 11);
eq('and they are the ones §3 names', [...transport.resultPaths].sort(), [
  'advanced.caa.error',
  'advanced.dnssec.chain[].detail.kind',
  'advanced.dnssec.error',
  'advanced.dnssec.lookups.dnskey.kind',
  'advanced.dnssec.lookups.ds.kind',
  'advanced.dnssec.lookups.ns.kind',
  'advanced.reportAuth[].error',
  'advanced.reportAuth[].exactKind',
  'advanced.spfLookups.queryError',
  'dmarcDiscovery.error',
  'dmarcDiscovery.steps[].kind',
]);

/**
 * The derived presentation mirror is deliberately absent. A bare
 * `issues[].args[]` pattern would let an unrelated argument that happened to
 * equal a kind earn transport coverage — the vacuous credit the measured
 * matrix exists to remove.
 */
eq('the issue-argument mirror is NOT a declared result path',
  transport.resultPaths.some(p => p.startsWith('issues')), false);
// Nor is the thrown audit error: it is not a result, and §12.1 owns it.
eq('nor is the thrown audit error.kind',
  transport.resultPaths.includes('error.kind'), false);

/* ── 4. Every declared path carries only closed kinds ─────────────────── */
section('4. Measured against the baseline');

const baseline = JSON.parse(readFileSync(join(REPO, 'tests/fixtures/equivalence/baseline-v0.5.0.json'), 'utf8'));
const kinds = new Set(TRANSPORT_KINDS);

/** Read one declared path out of a result, following `[]` into arrays. */
function readPath(node, path) {
  const out = [];
  (function walk(value, parts) {
    if (value === undefined || value === null) return;
    if (!parts.length) { out.push(value); return; }
    const [head, ...rest] = parts;
    if (head === '[]') { if (Array.isArray(value)) value.forEach(v => walk(v, rest)); return; }
    walk(value[head], rest);
  })(node, path.replace(/\[\]/g, '.[]').split('.').filter(Boolean));
  return out;
}

const observed = new Map(transport.resultPaths.map(p => [p, new Set()]));
for (const testCase of baseline.cases) {
  for (const entry of Object.values(testCase.result)) {
    if (!entry.result) continue;
    for (const path of transport.resultPaths) {
      for (const value of readPath(entry.result, path)) observed.get(path).add(value);
    }
  }
}

/**
 * A declared path carries transport kinds — and, on three of the eleven, its
 * own owner's algebra governs the field as well.
 *
 * `advanced.dnssec.error`, `advanced.reportAuth[].error` and
 * `advanced.reportAuth[].exactKind` each have their own registered algebra.
 * Two of the three are a SUPERSET of the transport kinds that can reach the
 * field, adding values only that owner can produce — `undefined` on
 * `dnssec.error`, `absent` and `name-too-long` on `reportAuth.error`. The
 * third, `reportAuth.exactKind`, is a subset: `success`, `nodata`, `nxdomain`
 * and nothing else. Found by writing the naive assertion ("every value is a
 * transport kind") and watching `name-too-long` fail it.
 *
 * So the contract is the union, taken from the registry rather than restated
 * here: a value belonging to neither the transport algebra nor the path's own
 * owner is off-contract. That is stronger than checking transport membership
 * alone, because it also catches an owner-specific value appearing on a path
 * whose owner does not declare it.
 */
function permittedOn(path) {
  const allowed = new Set(TRANSPORT_KINDS);
  for (const algebra of registry.algebras) {
    if (algebra.id === 'dns.transport.kind') continue;
    if ((algebra.resultPaths || []).includes(path)) algebra.members.forEach(m => allowed.add(m));
  }
  return allowed;
}

// The canonicalizer tags an explicitly-present undefined; that is absence, and
// `dnssec.error` names it as a member in those words.
const isAbsent = value => value && typeof value === 'object' && value.$undefined === true;

const offPath = [];
for (const [path, values] of observed) {
  const allowed = permittedOn(path);
  for (const value of values) {
    if (isAbsent(value)) { if (!allowed.has('undefined')) offPath.push(`${path} was absent but its owner does not allow it`); continue; }
    if (!allowed.has(value)) offPath.push(`${path} carried ${JSON.stringify(value)}`);
  }
}
eq('every value on every declared path is a transport kind or its own owner\'s',
  offPath, []);

// Eight of the eleven carry transport kinds and nothing else.
const transportOnly = transport.resultPaths.filter(path =>
  !registry.algebras.some(a => a.id !== 'dns.transport.kind' && (a.resultPaths || []).includes(path)));
eq('eight paths are transport-only', transportOnly.length, 8);
for (const path of transportOnly) {
  const stray = [...observed.get(path)].filter(v => !isAbsent(v) && !kinds.has(v));
  eq(`${path} carries only closed transport kinds`, stray, []);
}

// And the three that are not, named, so a fourth appearing is a decision
// someone has to make rather than something that slips through the union above.
eq('three paths share their field with an owner algebra',
  transport.resultPaths.filter(p => !transportOnly.includes(p)).sort(),
  ['advanced.dnssec.error', 'advanced.reportAuth[].error', 'advanced.reportAuth[].exactKind']);

/**
 * Source-reachability is the contract; corpus observation is coverage
 * evidence. They are reported separately so neither can be used as proof of
 * the other — which is what an empty `resultPaths` claimed for two releases.
 */
const unobserved = [...observed]
  .filter(([, values]) => [...values].every(isAbsent) || values.size === 0)
  .map(([path]) => path);
eq('and the corpus now reaches every declared path with a real kind', unobserved, []);

// The two paths the corpus gained at Task 3.6, asserted by name so a corpus
// change that silently dropped them is caught.
eq('the SPF lookup fallback path is reached', [...observed.get('advanced.spfLookups.queryError')], ['servfail']);
eq('and the report-auth exactKind reaches all three of its members',
  [...observed.get('advanced.reportAuth[].exactKind')].sort(), ['nodata', 'nxdomain', 'success']);

/* ── 5. The derived mirror, against its own key ───────────────────────── */
section('5. The dmarc-unverified issue copy');

/**
 * The DMARC walk's kind is interpolated into one issue's arguments. Tested
 * against THAT KEY, never as a pattern over all issue arguments.
 */
const mirrored = [];
const unrelatedArgs = [];
for (const testCase of baseline.cases) {
  for (const entry of Object.values(testCase.result)) {
    for (const issue of (entry.result && entry.result.issues) || []) {
      for (const arg of issue.args || []) {
        if (typeof arg !== 'string' || !kinds.has(arg)) continue;
        if (issue.key === 'dmarc-unverified') mirrored.push({ case: testCase.id, arg });
        else unrelatedArgs.push(`${issue.key} carried ${arg}`);
      }
    }
  }
}
eq('the mirror is reached', mirrored.length > 0, true);
eq('and it carries a real transport kind', kinds.has(mirrored[0].arg), true);
eq('the walk that produced it recorded the same kind',
  baseline.cases.find(c => c.id === mirrored[0].case)
    ? Object.values(baseline.cases.find(c => c.id === mirrored[0].case).result)
      .some(e => e.result && e.result.dmarcDiscovery && e.result.dmarcDiscovery.error === mirrored[0].arg)
    : false, true);
eq('no other issue key carries a transport kind today', unrelatedArgs, []);

/**
 * The negative control the review required: an unrelated issue argument must
 * not be able to earn transport coverage. Coverage is keyed on the semantically
 * typed paths above, and `issues[].args[]` is not among them — so an argument
 * equal to `timeout` from any other issue contributes nothing.
 */
const inventedIssue = { key: 'spf-cycle', args: ['timeout'] };
eq('an unrelated issue argument equal to a kind is not a declared path',
  transport.resultPaths.some(p => p.startsWith('issues')), false);
eq('so it cannot cover a transport member',
  readPath({ issues: [inventedIssue] }, transport.resultPaths.find(p => p.startsWith('issues')) || 'nothing.here'),
  []);
eq('and it would have been credited under a bare issues[].args[] pattern — which is why there is none',
  readPath({ issues: [inventedIssue] }, 'issues[].args[]'), ['timeout']);

report();
