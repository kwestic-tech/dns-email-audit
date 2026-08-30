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
 * one other mechanism that is not an `optionalCheck()` fallback at all. Spec
 * §3 distinguishes them and this counts them, so a fifth appearing is a
 * decision rather than a drift.
 *
 * Counted across `js/dns.js` AND every extracted owner, because Phases 4 and 5
 * move them: Task 4.6 took `checkExternalReportAuth()`'s internal catch to
 * `core/dmarc/report-auth.js`, and Task 5.2 took all three fallback factories
 * to `src/audit/audit-domain.js` with the coordinator. A scan of the legacy
 * file alone would have reported the count falling to one as though three
 * sites had been deleted. Located as well as counted, for exactly that reason.
 */
const KIND_COPY = /\(\s*(error|e|err)\s*&&\s*\1\.kind\s*\)|(?:^|[^\w$])(e)\s*&&\s*\2\.kind/gm;
const kindCopySources = ['js/dns.js', ...(function walk(dir, base) {
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) return walk(full, base);
    return entry.name.endsWith('.js') && !entry.name.endsWith('.test.js')
      ? [`src/${relative(base, full).split(sep).join('/')}`] : [];
  });
}(join(REPO, 'src'), join(REPO, 'src')))];
const kindCopiesBySource = new Map();
for (const file of kindCopySources) {
  const path = join(REPO, file);
  if (!existsSync(path)) continue;
  const n = [...readFileSync(path, 'utf8').matchAll(KIND_COPY)].length;
  if (n) kindCopiesBySource.set(file, n);
}
eq('four sites copy a caught error\'s kind, wherever they now live',
  [...kindCopiesBySource.values()].reduce((a, b) => a + b, 0), 4);
eq('and they are in these files',
  [...kindCopiesBySource].sort().map(([f, n]) => `${f}:${n}`),
  ['src/audit/audit-domain.js:3', 'src/core/dmarc/report-auth.js:1']);

const coordinator = readFileSync(join(REPO, 'src/audit/audit-domain.js'), 'utf8');
// The three fallback factories are all at their call sites in the coordinator,
// which is where they moved at Task 5.2. The fourth is DMARC's internal catch,
// above — a different mechanism, in a different file, deliberately not merged
// into this count.
eq('three of them are optionalCheck fallback factories, one is an internal catch',
  coordinator.split('\n').filter(l => /error\s*=>\s*\(\{/.test(l) && /\.kind/.test(l)).length, 3);
// And the legacy file no longer holds one, which is the half a per-file count
// exists to distinguish from a deletion.
eq('js/dns.js copies no kind at all now', kindCopiesBySource.get('js/dns.js'), undefined);

/* ── 3b. Parsing ownership: Gate 5's condition on the coordinator ─────── */
section('3b. The coordinator holds no parsing rule');

/**
 * Gate 5, stated as a condition on a module: *"Coordinator holds no parsing
 * rule."* Spec §5 says the same thing in prose — `auditDomain()` "does not
 * parse records". Selecting which of a domain's TXT strings are a protocol's
 * records IS a parsing rule, and so is deciding what `present` means for one,
 * so those live with the protocols.
 *
 * A relationship between modules rather than a property of one, which is why
 * it is here and not in the co-located suite. Task 5.2 shipped these helpers
 * inside `src/audit/audit-domain.js` and review caught it; this is the check
 * that would have caught it instead.
 *
 * ── What this establishes, and what it does not ─────────────────────────
 *
 * A LEXICAL scan for `function NAME` declarations in a fixed set of files, in
 * the same spirit as the raw-kind scan in `transport-edges.test.mjs` and with
 * the same honesty about its limits.
 *
 * It establishes: none of these NAMES is declared in the coordinator, and each
 * is declared in the owner named beside it. It does NOT establish that no
 * parsing of any kind could be written there — an arrow function, a method, a
 * regex inlined at a call site, or the same rule under another name would all
 * pass. It is defense against the specific regression of moving one of these
 * back, which is the one that actually happened.
 */
const PARSER_OWNERS = [
  { name: 'startsWithCI', file: 'src/core/shared/record-selection.js' },
  { name: 'versionCandidates', file: 'src/core/shared/record-selection.js' },
  { name: 'leadingVersionMatches', file: 'src/core/shared/record-selection.js' },
  { name: 'selectSpfRecords', file: 'src/core/spf/spf.js' },
  { name: 'summarizeBimi', file: 'src/core/bimi/bimi.js' },
  { name: 'summarizeMtaSts', file: 'src/core/transport/mta-sts.js' },
  { name: 'summarizeTlsRpt', file: 'src/core/transport/tls-rpt.js' },
  { name: 'selectVerifications', file: 'src/providers/detectors.js' },
];

const declaresFunction = (source, name) =>
  new RegExp(`^\\s*(?:export\\s+)?(?:async\\s+)?function\\s+${name}\\b`, 'm').test(source);

eq('the coordinator declares none of the selector or parser helpers',
  PARSER_OWNERS.filter(h => declaresFunction(coordinator, h.name)).map(h => h.name), []);
eq('and every one of them is declared by the owner named for it',
  PARSER_OWNERS
    .filter(h => !declaresFunction(readFileSync(join(REPO, h.file), 'utf8'), h.name))
    .map(h => `${h.name} is not declared in ${h.file}`), []);
// An empty result is also what a scan that matches nothing produces, so the
// classifier is proven in both directions before either list above is trusted.
eq('the scan finds a function the coordinator really does declare',
  declaresFunction(coordinator, 'analyzeDomain'), true);
eq('and does not find one it only calls',
  declaresFunction(coordinator, 'summarizeBimi'), false);
eq('a call is not a declaration', declaresFunction('  const x = summarizeBimi(txt);', 'summarizeBimi'), false);

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
  // Created at Task 5.1. §12: audit reaches the protocol owners, `providers/`
  // and its own siblings — NOT `core/dns/` (the resolver handle is passed) and
  // not `core/shared/`, which the matrix does not give it. The row is written
  // from the matrix rather than from what `context.js` happens to import
  // today, which is nothing at all.
  'audit': ['core/bimi', 'core/caa', 'core/dkim', 'core/dmarc', 'core/dnssec',
    'core/mx', 'core/spf', 'core/transport', 'providers', 'audit'],
  'core/bimi': ['core/shared'],
  'core/caa': ['core/shared'],
  'core/dkim': ['core/shared'],
  'core/dmarc': ['core/shared'],
  'core/dns': ['core/dns', 'core/shared'],
  'core/dnssec': ['core/shared'],
  'core/mx': ['core/shared'],
  'core/shared': [],
  'core/spf': ['core/shared'],
  'core/transport': ['core/shared'],
  'data': [],
  'platform': [],
  'i18n': ['core/shared'],
  'ui': ['ui', 'i18n'],
  'runtime.js': ['core/dns', 'core/shared', 'audit', 'ui', 'i18n'],
  // §12's row is `runtime.js`, `platform/`, `data/` — and that describes
  // `src/main.js` AFTER Task 5.6, when the UI body it still holds has moved to
  // `ui/events.js` and this file is composition alone.
  //
  // Task 5.5 moved the exported CSV and report to `ui/report.js` while their
  // only caller is still here, which is a real edge the matrix does not grant.
  // It is admitted as TRANSITIONAL rather than pretended away — and it is
  // made self-removing: the assertion below fails the moment `main.js` stops
  // importing `ui/`, so the exemption cannot outlive the thing it excuses.
  'main.js': ['runtime.js', 'platform', 'data', 'ui'],
  'providers': ['core/shared'],
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

/**
 * The transitional `main.js -> ui` exemption, forced to expire.
 *
 * An exemption nothing obliges you to remove is a permanent hole. This asserts
 * the exemption is still NEEDED: once Task 5.6 moves the UI body out of
 * `src/main.js`, this fails and the `'ui'` entry above has to come out with it.
 */
eq('the transitional main.js -> ui edge is still in use — remove it at Task 5.6',
  (graph.get('main.js') || []).some(t => t.startsWith('ui/')), true);
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
 * §12's floor for a protocol owner, asserted over every protocol directory
 * that exists rather than one row at a time. A protocol reaches `core/shared/`
 * and its own siblings; the resolver and generated data are PASSED, so an
 * import of `core/dns/` is the specific failure this catches — it is the
 * convenient one, and it is the one that makes the module untestable without
 * a transport.
 */
const protocolDirs = [...new Set(modules
  .filter(m => m.startsWith(`core${sep}`) && !m.startsWith(join('core', 'dns')) &&
    !m.startsWith(join('core', 'shared')))
  .map(m => m.split(sep).slice(0, 2).join('/')))];
eq('there is at least one protocol owner to check', protocolDirs.length > 0, true);
eq('no protocol owner imports anything but core/shared and its own siblings',
  modules.filter(m => protocolDirs.includes(areaOf(m)) &&
    graph.get(m).some(t => {
      const to = areaOf(t.split('/').join(sep));
      return to !== areaOf(m) && to !== 'core/shared';
    })), []);

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
