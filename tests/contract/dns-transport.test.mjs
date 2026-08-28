#!/usr/bin/env node
/**
 * The transport layer's cross-cutting contracts. Task 3.7.
 *
 * Everything here asserts a RELATIONSHIP — between the layers, between the
 * modules, or between a module and the reviewed registry — which is why it is
 * in `tests/contract/` rather than beside one owner. What a single module owns
 * is pinned in its own co-located suite; those are not repeated here.
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, sep } from 'node:path';

import { createSuite } from '../lib/assert.mjs';
import { TRANSPORT_KINDS, RETRY_TERMINAL_KINDS, CACHEABLE_KINDS } from '../../src/core/dns/doh.js';
import { requireUsable, USABLE_KINDS, createResolver } from '../../src/core/dns/resolver.js';
import { optionalCheck, RETHROWN_ERROR_NAMES } from '../../src/core/dns/optional.js';
import { existenceFromResponse, EXISTENCE_STATES } from '../../src/core/dns/existence.js';
import { dnsError, dnsTypeNum } from '../../src/core/dns/errors.js';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, rejects, throws, section, report } = createSuite();

const registry = JSON.parse(readFileSync(join(REPO, 'tests/state-algebras.json'), 'utf8'));
const algebra = id => registry.algebras.find(a => a.id === id);

/* ── 1. The modules and the reviewed registry agree ───────────────────── */
section('1. Code and registry name the same sets');

/**
 * The registry is reviewed material and the modules are code; a contract that
 * restated the members here would be a third copy for the other two to drift
 * from. So each set is compared to its algebra.
 */
eq('the ten kinds match dns.transport.kind',
  [...TRANSPORT_KINDS].sort(), [...algebra('dns.transport.kind').members].sort());
eq('the retry-terminal set matches dns.retryTerminal',
  [...RETRY_TERMINAL_KINDS].sort(), [...algebra('dns.retryTerminal').members].sort());
eq('the cacheable set matches dns.cacheable',
  [...CACHEABLE_KINDS].sort(), [...algebra('dns.cacheable').members].sort());
// Named exactly, with no fallback: a silent default would let the comparison
// pass against a literal this file wrote instead of against the registry.
eq('dns.existence is the algebra that owns the states', !!algebra('dns.existence'), true);
eq('and the module names the same three',
  [...EXISTENCE_STATES].sort(), [...algebra('dns.existence').members].sort());

/* ── 2. The layer boundaries hold together ────────────────────────────── */
section('2. Layers 1 to 4');

eq('cacheable is a strict subset of retry-terminal',
  CACHEABLE_KINDS.every(k => RETRY_TERMINAL_KINDS.includes(k)) &&
  CACHEABLE_KINDS.length < RETRY_TERMINAL_KINDS.length, true);
eq('and they differ by exactly cancelled',
  RETRY_TERMINAL_KINDS.filter(k => !CACHEABLE_KINDS.includes(k)), ['cancelled']);
eq('the usable set is exactly the cacheable set',
  [...USABLE_KINDS].sort(), [...CACHEABLE_KINDS].sort());

/**
 * Seven throws, and the count is asserted rather than the list, so a kind
 * added to the closed set without a decision here fails.
 */
const rejectedKinds = TRANSPORT_KINDS.filter(k => !USABLE_KINDS.includes(k));
eq('seven kinds are rejected by the usability gate', rejectedKinds.length, 7);
for (const kind of rejectedKinds) {
  throws(`${kind} throws at layer 2`,
    () => requireUsable({ kind, answers: [] }, 'n', 'A'), error => error.kind === kind);
}

/** Layer 4's rethrow set, and its agreement with layer 1's naming. */
eq('two names are re-thrown', [...RETHROWN_ERROR_NAMES].sort(), ['AbortError', 'DnsTypeError']);
eq('only the cancelled kind carries a re-thrown name',
  TRANSPORT_KINDS.filter(k => RETHROWN_ERROR_NAMES.includes(dnsError(k, 'n', 'A').name)), ['cancelled']);

/* ── 3. Layer 4 is policy-neutral ─────────────────────────────────────── */
section('3. optionalCheck decides nothing about the unknown\'s shape');

/**
 * Spec §3 as amended in `1.6`. `optionalCheck()` returns what the caller
 * declared; a static fallback must not acquire a kind implicitly, and a caller
 * that wants one copies it deliberately.
 */
const failing = () => { throw dnsError('servfail', 'n', 'TXT'); };
eq('a null fallback stays null', await optionalCheck(failing, null), null);
eq('an array fallback stays an array', await optionalCheck(failing, []), []);
eq('a shape with no kind does not acquire one',
  await optionalCheck(failing, { found: false, records: [] }), { found: false, records: [] });
eq('and a fallback that asks for the kind gets it',
  await optionalCheck(failing, error => ({ unknown: true, queryError: (error && error.kind) || 'dns-error' })),
  { unknown: true, queryError: 'servfail' });
eq('with the declared default when the error carries no kind',
  await optionalCheck(() => { throw new TypeError('boom'); },
    error => ({ queryError: (error && error.kind) || 'dns-error' })),
  { queryError: 'dns-error' });

/**
 * The three fallback factories in the shipped source that copy a kind, and the
 * two other mechanisms that are not `optionalCheck()` fallbacks at all. Spec
 * §3 distinguishes them and this counts them, so a fourth appearing is a
 * decision rather than a drift.
 */
const engine = readFileSync(join(REPO, 'js/dns.js'), 'utf8');
const kindCopies = [...engine.matchAll(/\(\s*(error|e|err)\s*&&\s*\1\.kind\s*\)|(?:^|[^\w$])(e)\s*&&\s*\2\.kind/gm)];
eq('four sites copy a caught error\'s kind', kindCopies.length, 4);
eq('three of them are optionalCheck fallback factories, one is an internal catch',
  engine.split('\n').filter(l => /error\s*=>\s*\(\{/.test(l) && /\.kind/.test(l)).length, 3);

/* ── 4. No transport result carries a finding, severity, score or locale ─ */
section('4. The transport emits no protocol vocabulary');

/**
 * Spec §3: "`src/core/dns/` may emit none of them." Asserted over what the
 * layer actually returns, for every kind, rather than over the source text —
 * the old locale-key grep was withdrawn as vacuous because `en.json` is nested
 * and the tokens are values.
 */
const protocolWords = ['sev', 'crit', 'warn', 'score', 'pts', 'grade', 'key', 'issue', 'suggestion', 'msg'];
const shapes = [];
for (const kind of TRANSPORT_KINDS) {
  shapes.push({ answers: [], ad: false, status: -1, kind });
  if (USABLE_KINDS.includes(kind)) continue;
  try { requireUsable({ kind, answers: [] }, 'n', 'A'); } catch (error) {
    shapes.push({ name: error.name, kind: error.kind, queryName: error.queryName, queryType: error.queryType });
  }
}
const leaked = [];
for (const shape of shapes) {
  for (const field of Object.keys(shape)) {
    if (protocolWords.includes(field)) leaked.push(`a transport shape carried ${field}`);
  }
}
eq('no transport result or error shape carries protocol vocabulary', leaked, []);

const resolver = createResolver({ dohFetch: async () => ({ kind: 'success', answers: [{ type: 16, data: '"v=spf1 -all"' }] }) });
const normalized = await resolver.dohQuery('example.test', 'TXT');
eq('a normalized array is strings and nothing else',
  normalized.every(v => typeof v === 'string'), true);
eq('it carries no kind', normalized.some(v => TRANSPORT_KINDS.includes(v)), false);

/* ── 5. Import-graph direction ────────────────────────────────────────── */
section('5. Allowed edges and the cycle rule');

/**
 * Spec §12's matrix, for the directories that exist. An edge absent from the
 * matrix is a test failure, not a judgment call.
 */
const ALLOWED_EDGES = {
  'core/dns': ['core/dns', 'core/shared'],
  'core/shared': [],
  'data': [],
  'platform': [],
  'i18n': ['core/shared'],
  'ui': ['ui', 'i18n'],
  'runtime.js': ['core/dns', 'core/shared', 'audit', 'ui', 'i18n'],
  'main.js': ['runtime.js', 'platform', 'data'],
};

function srcModules(dir, base) {
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) return srcModules(full, base);
    return entry.name.endsWith('.js') && !entry.name.endsWith('.test.js') ? [relative(base, full)] : [];
  });
}
const srcDir = join(REPO, 'src');
const modules = srcModules(srcDir, srcDir).sort();

/** The directory an edge is judged by: a top-level file is its own owner. */
const areaOf = path => path.includes(sep) ? path.split(sep).slice(0, path.startsWith('core') ? 2 : 1).join('/') : path;

const graph = new Map();
const violations = [];
for (const path of modules) {
  const source = readFileSync(join(srcDir, path), 'utf8');
  const targets = [...source.matchAll(/^\s*import\s[^'"]*['"]([^'"]+)['"]/gm)].map(m => m[1]);
  graph.set(path, []);
  for (const target of targets) {
    if (target.startsWith('../js/') || target.includes('/js/')) continue;   // legacy, retired in Phase 6
    const resolved = relative(srcDir, join(dirname(join(srcDir, path)), target)).split(sep).join('/');
    graph.get(path).push(resolved);
    const from = areaOf(path);
    const to = areaOf(resolved.split('/').join(sep));
    if (from === to) continue;
    const allowed = ALLOWED_EDGES[from];
    if (!allowed) { violations.push(`${path}: no matrix row for ${from}`); continue; }
    if (!allowed.includes(to)) violations.push(`${from} -> ${to} (${path} imports ${resolved})`);
  }
}
eq('every import follows an allowed edge', violations, []);
eq('and the graph is not empty — the check has something to walk', graph.size > 5, true);

// Spec §12's floors.
eq('src/platform imports nothing',
  modules.filter(m => m.startsWith('platform') && graph.get(m).length), []);
eq('src/data imports nothing but its own siblings',
  modules.filter(m => m.startsWith('data') && graph.get(m).some(t => !t.startsWith('data'))), []);
eq('no core/dns module imports ui or audit',
  modules.filter(m => m.startsWith(join('core', 'dns')) &&
    graph.get(m).some(t => t.startsWith('ui/') || t.startsWith('audit/'))), []);
// §12 gives core/shared no outgoing edges at all — not even to a sibling here.
// The matrix row above is empty, but an empty row only fires on a CROSS-area
// import, and a sibling import is same-area. So the floor is asserted directly,
// the way src/platform's and src/data's are.
eq('src/core/shared imports nothing, siblings included',
  modules.filter(m => m.startsWith(join('core', 'shared')) && graph.get(m).length), []);

/**
 * The cycle rule: no strongly connected component with more than one module.
 * Acyclic is necessary but not sufficient — the matrix above is what catches a
 * graph that is acyclic and pointing the wrong way.
 */
function componentOf(start) {
  const seen = new Set([start]);
  const stack = [start];
  while (stack.length) {
    const node = stack.pop();
    for (const next of graph.get(node) || []) if (!seen.has(next)) { seen.add(next); stack.push(next); }
  }
  return seen;
}
const cyclic = modules.filter(m => [...componentOf(m)].some(other => other !== m && (componentOf(other) || new Set()).has(m)));
eq('no strongly connected component holds more than one module', cyclic, []);

// And the cycle check can fail.
const probe = new Map([['a.js', ['b.js']], ['b.js', ['a.js']]]);
const reach = (g, start) => { const s = new Set([start]); const st = [start];
  while (st.length) { const n = st.pop(); for (const x of g.get(n) || []) if (!s.has(x)) { s.add(x); st.push(x); } } return s; };
eq('a two-module cycle is caught by the same walk',
  reach(probe, 'a.js').has('b.js') && reach(probe, 'b.js').has('a.js'), true);

report();
