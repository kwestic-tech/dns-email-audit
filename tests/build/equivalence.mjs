#!/usr/bin/env node
/**
 * The five-surface equivalence runner. Spec Design §8, Task 0.4.b.
 *
 *   node tests/build/equivalence.mjs --subject-root=. [--entry=classic]
 *   node tests/build/equivalence.mjs --subject-root=../dea-v050 --emit > baseline.json
 *   node tests/build/equivalence.mjs --subject-root=_site --case=<id>
 *
 * Surfaces, per spec Design §8:
 *
 *   result   canonical JSON of the WHOLE analyzeDomain() return
 *   trace    normalized query multiset, plus order where order is the behaviour
 *   csv      exact bytes, from the real exportCSV()
 *   report   canonical tree plus exact CSP and stylesheet bytes, from the real exportHTML()
 *   dom      canonical tree of the rendered rows, from the real appendRow()
 *
 * Everything is produced by calling the SUBJECT's own functions. `exportCSV()`
 * and `exportHTML()` run in full, download path included — the runner supplies
 * a `Blob` and `URL.createObjectURL` and captures what the browser would have
 * saved. Measuring a re-implementation of an export would prove nothing about
 * the export.
 *
 * This runner is the instrument the whole release is measured with, so it is
 * validated before it is trusted: `tests/build/equivalence.validate.mjs` runs it
 * twice against one root for byte-identity, then against deliberately mutated
 * copies of `js/`, and requires each mutation to be caught on the surface that
 * should catch it. Framework §4. A mutation that passes is a hole in the runner.
 */

import { readFileSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve } from 'node:path';

import { loadSubject, FIXED_INSTANT, FIXED_LOCALE, FIXED_TIMEZONE } from '../lib/subject.mjs';
import {
  encode, serialize, canonicalQueryTrace, orderedSubsequence,
  canonicalDom, reportByteRegions, applyExclusions,
} from '../lib/canonical.mjs';

const RUNNER_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');

/* ── Arguments ────────────────────────────────────────────────────────── */

function parseArgs(argv) {
  const args = { subjectRoot: '.', entry: 'classic', emit: false, case: null, baseline: null };
  for (const arg of argv) {
    const [key, value] = arg.startsWith('--') ? arg.slice(2).split('=') : [null, null];
    if (key === 'subject-root') args.subjectRoot = value;
    else if (key === 'entry') args.entry = value;
    else if (key === 'emit') args.emit = true;
    else if (key === 'case') args.case = value;
    else if (key === 'baseline') args.baseline = value;
    else if (key) throw new Error(`equivalence: unknown option --${key}`);
  }
  return args;
}

/* ── The tracing transport ────────────────────────────────────────────── */

/**
 * Wrap a fixture `fetch` so every query is recorded with its full identity —
 * name, type, `do` and `cd` — and so concurrency is observed rather than
 * assumed.
 *
 * `tools/lib/doh-fixture.mjs`'s own `calls` array records `"<name> <TYPE>"`
 * and drops the two flags. That is enough for the assertions it was written
 * for and not enough here: `cd=1` is the bogus-chain re-query and `do=1` is
 * what makes a TLSA answer's AD bit meaningful, so a refactor that lost either
 * flag would leave this surface silent.
 */
function tracingFetch(inner, css) {
  const calls = [];
  let active = 0;
  let maxConcurrency = 0;

  const impl = async (url, init) => {
    const href = String(url);
    // The report export fetches the stylesheet. Served from the subject's own
    // root by the caller, never from the network and never from this branch.
    if (!href.includes('cloudflare-dns.com')) {
      return { ok: true, status: 200, text: async () => css };
    }
    const params = new URL(href).searchParams;
    calls.push({
      name: String(params.get('name') || '').toLowerCase().replace(/\.$/, ''),
      type: TYPE_NAMES[params.get('type')] || params.get('type'),
      dnssec: params.get('do') === '1',
      checkingDisabled: params.get('cd') === '1',
    });
    active++;
    if (active > maxConcurrency) maxConcurrency = active;
    try {
      return await inner(url, init);
    } finally {
      active--;
    }
  };
  impl.calls = calls;
  impl.observed = () => ({ maxConcurrency, maxBatchSize: null });
  return impl;
}

const TYPE_NAMES = {
  1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA',
  43: 'DS', 48: 'DNSKEY', 52: 'TLSA', 257: 'CAA',
};

/* ── One case ─────────────────────────────────────────────────────────── */

/**
 * Run one corpus case against one subject root and return its five surfaces.
 *
 * A case may audit SEVERAL domains through ONE subject. That is not a
 * convenience: it is the only way to observe the DoH cache's page lifetime,
 * which `tools/scoring.test.mjs:1888-1891` asserts and `PRIVACY.md:30-33`
 * publishes. A runner that built a fresh page per domain would report a clean
 * trace while the cache was being narrowed underneath it.
 */
async function runCase(root, testCase, entry) {
  const cssPath = join(root, 'css', 'style.css');
  const css = existsSync(cssPath) ? readFileSync(cssPath, 'utf8') : '';
  const fetchImpl = tracingFetch(testCase.fetch(), css);

  const subject = loadSubject(root, {
    entry, fetch: fetchImpl, instant: FIXED_INSTANT, platform: testCase.platform,
  });
  const { win, document } = subject;

  // The download boundary. `js/app.js:1434` builds a Blob and clicks a
  // detached anchor; capturing at the Blob is capturing exactly the bytes the
  // browser would have written.
  const downloads = [];
  win.Blob = class Blob {
    constructor(parts, options) { downloads.push({ type: options && options.type, text: parts.join('') }); }
  };
  win.URL = new Proxy(URL, {
    get(target, property) {
      if (property === 'createObjectURL') return () => 'blob:equivalence';
      if (property === 'revokeObjectURL') return () => {};
      const value = target[property];
      return typeof value === 'function' ? value.bind(target) : value;
    },
  });

  // The runner observes the facade; it does not reach past it. `startAudit()`
  // owns the worker pool, the per-domain error isolation and the `results`
  // array the two exports read, so the audit is driven through the real entry
  // point and each result is captured as it crosses `analyzeDomain`. Calling
  // `analyzeDomain` directly instead would leave `results` empty, and
  // `exportCSV()` would emit a header row and nothing else — a surface that
  // cannot detect a change is worse than no surface.
  const audits = [];
  const realAnalyze = win.DnsAudit.analyzeDomain;
  win.DnsAudit.analyzeDomain = async (domain, options) => {
    try {
      const result = await realAnalyze.call(win.DnsAudit, domain, options);
      audits.push({ domain, outcome: 'result', result });
      return result;
    } catch (error) {
      // A thrown audit is a modelled outcome, not a runner failure — spec
      // §12.1's audit row names thrown cancellation and core transport errors
      // as states the corpus must reach. Recorded, then re-thrown so the
      // application's own isolation path runs.
      audits.push({
        domain,
        outcome: 'thrown',
        error: { name: error && error.name, kind: error && error.kind, message: error && error.message },
      });
      throw error;
    }
  };

  // Options are set the way a person sets them: on the controls `startAudit()`
  // reads. The defaults come from the subject's own index.html.
  const options = testCase.options || {};
  const control = id => document.getElementById(id);
  for (const [id, key] of [['optDKIM', 'dkim'], ['optDKIMComprehensive', 'dkimComprehensive'],
    ['optWWW', 'www'], ['optWildcard', 'wildcard'], ['optDeepChecks', 'deepChecks']]) {
    if (Object.prototype.hasOwnProperty.call(options, key)) control(id).checked = options[key];
  }
  if (options.selectors) control('dkimSelectors').value = options.selectors.join(' ');
  control('domainInput').value = testCase.domains.map(d => d.domain).join('\n');

  await win.startAudit();

  let csv = null;
  let report = null;
  if (audits.some(a => a.outcome === 'result')) {
    downloads.length = 0;
    win.exportCSV();
    csv = (downloads.find(d => d.type && d.type.startsWith('text/csv')) || {}).text ?? null;
    downloads.length = 0;
    await win.exportHTML();
    report = (downloads.find(d => d.type === 'text/html') || {}).text ?? null;
  }

  const calls = fetchImpl.calls;
  // `startAudit()` runs its own pre-flight `checkConnectivity()` before any
  // domain. It is a real query the application makes on every run and it stays
  // in the trace; a runner that filtered it out would report a fan-out the
  // browser does not have.
  return {
    id: testCase.id,
    description: testCase.description,
    // Part of the case's identity, not a detail. A surface set captured under a
    // substituted platform is not comparable with one captured under the host's
    // own, and recording it here is what makes that visible instead of showing
    // up as an unexplained result diff.
    platform: subject.manifest.platform,
    result: encode(audits.sort((a, b) => (a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0))),
    trace: {
      ...canonicalQueryTrace(calls, fetchImpl.observed()),
      // Order IS the behaviour for these two algorithms. Asserted separately
      // from the multiset, per canonicalization.md §2.
      dmarcWalk: orderedSubsequence(calls, c => c.name.startsWith('_dmarc.') && c.type === 'TXT'),
      spfEvaluation: orderedSubsequence(calls, c => c.type === 'TXT' && (testCase.spfNames || []).includes(c.name)),
    },
    csv,
    report: report === null ? null : reportSurface(report),
    dom: canonicalDom(document.getElementById('tableBody')),
  };
}

/**
 * The exported report's surface.
 *
 * The report is a SERIALIZED STRING, so it is compared by the hash of its exact
 * bytes. Re-parsing it with the same shim that produced it would compare the
 * shim's model of the document against itself and prove nothing about the
 * serializer — and a tree of tag names alone silently dropped the report's own
 * timestamp, which spec Design §8 makes a controlled INPUT rather than an
 * excluded field.
 *
 * The hash is what makes the comparison complete. Everything beside it exists
 * so a failure is diagnosable rather than "the hash moved":
 *
 *   csp / stylesheet   the two byte-exact regions canonicalization.md §4 names
 *   structure          the tag sequence, so a structural change says where
 *   generated          the timestamp line, extracted so a clock leak is obvious
 *   length             the cheapest signal of what kind of change happened
 */
function reportSurface(html) {
  const tags = [...html.matchAll(/<(\/?)([a-zA-Z][\w-]*)\b/g)].map(m => `${m[1]}${m[2].toLowerCase()}`);
  const generated = /<p[^>]*>([^<]*\d[^<]*)<\/p>/.exec(html);
  return {
    sha256: createHash('sha256').update(html, 'utf8').digest('hex'),
    length: Buffer.byteLength(html, 'utf8'),
    bytes: reportByteRegions(html),
    structure: tags.join(' '),
    generated: generated ? generated[1] : null,
  };
}

/* ── Entry point ──────────────────────────────────────────────────────── */

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const root = resolve(args.subjectRoot);

  const corpusPath = join(RUNNER_ROOT, 'tests/fixtures/equivalence/corpus.mjs');
  if (!existsSync(corpusPath)) {
    console.error('equivalence: no corpus at tests/fixtures/equivalence/corpus.mjs');
    process.exit(2);
  }
  const { cases } = await import(pathToFileURL(corpusPath).href);
  const selected = args.case ? cases.filter(c => c.id === args.case) : cases;
  if (!selected.length) {
    console.error(`equivalence: no case matching ${args.case}`);
    process.exit(2);
  }

  const surfaces = [];
  let manifest = null;
  for (const testCase of selected) {
    const produced = await runCase(root, testCase, args.entry);
    surfaces.push(produced);
    if (!manifest) manifest = loadSubject(root, { entry: args.entry }).manifest;
  }

  const document = {
    schema: 1,
    subject: {
      root: manifest.root,
      entry: manifest.entry,
      scripts: manifest.scripts,
      stylesheets: manifest.stylesheets,
      inputs: manifest.inputs,
    },
    environment: {
      node: manifest.node,
      icu: manifest.icu,
      unicode: manifest.unicode,
      instant: FIXED_INSTANT,
      instantISO: new Date(FIXED_INSTANT).toISOString(),
      locale: FIXED_LOCALE,
      timezone: FIXED_TIMEZONE,
      resolvedTimezone: manifest.resolvedTimezone,
    },
    // Spec Design §8: one entry per excluded field, each with a reason. No
    // wildcard classes. Expected to stay empty — time and locale are inputs.
    exclusions: [],
    cases: surfaces.map(s => ({ ...s, result: applyExclusions(s.result, []) })),
  };

  if (args.emit) {
    process.stdout.write(serialize(document));
    return;
  }

  const baselinePath = args.baseline
    ? resolve(args.baseline)
    : join(RUNNER_ROOT, 'tests/fixtures/equivalence/baseline-v0.5.0.json');
  if (!existsSync(baselinePath)) {
    console.error(`equivalence: no baseline at ${baselinePath}. Capture one with --emit.`);
    process.exit(2);
  }
  const baseline = JSON.parse(readFileSync(baselinePath, 'utf8'));
  const diffs = compare(baseline, document);

  for (const diff of diffs) console.log(`  ✗ ${diff}`);
  console.log(`\n${'='.repeat(60)}`);
  console.log(`${selected.length} cases, 5 surfaces, ${diffs.length} differences`);
  if (diffs.length) {
    console.log('\nAny difference on any surface is a STOP, not a note in the PR');
    console.log('description. A query-trace difference with an identical result');
    console.log('is still a stop: it means cache or concurrency behaviour moved,');
    console.log('and that is a published privacy figure.');
    process.exit(1);
  }
}

/**
 * Compare two runs surface by surface.
 *
 * Reported per case and per surface rather than as one blob diff, because
 * "which surface moved" is the first question and the five surfaces exist
 * precisely so that it has an answer. Environment and subject inputs are
 * reported separately: they are what BINDS a comparison, and a baseline
 * captured under a different ICU is not a baseline.
 */
export function compare(baseline, current) {
  const diffs = [];
  for (const field of ['node', 'icu', 'unicode', 'instant', 'locale', 'timezone', 'resolvedTimezone']) {
    if (baseline.environment?.[field] !== current.environment?.[field]) {
      diffs.push(`environment.${field}: ${baseline.environment?.[field]} -> ${current.environment?.[field]}`);
    }
  }
  const byId = new Map(baseline.cases.map(c => [c.id, c]));
  for (const currentCase of current.cases) {
    const baselineCase = byId.get(currentCase.id);
    if (!baselineCase) { diffs.push(`case ${currentCase.id}: absent from the baseline`); continue; }
    byId.delete(currentCase.id);
    if (baselineCase.platform !== currentCase.platform) {
      diffs.push(`case ${currentCase.id}: platform profile ${baselineCase.platform} -> ${currentCase.platform}`);
    }
    for (const surface of ['result', 'trace', 'csv', 'report', 'dom']) {
      const a = serialize(baselineCase[surface]);
      const b = serialize(currentCase[surface]);
      if (a !== b) diffs.push(`case ${currentCase.id}, surface ${surface}: ${firstDifference(a, b)}`);
    }
  }
  for (const missing of byId.keys()) diffs.push(`case ${missing}: in the baseline, not produced now`);
  return diffs;
}

/** The first differing line, which is almost always the useful one. */
function firstDifference(a, b) {
  const left = a.split('\n');
  const right = b.split('\n');
  for (let i = 0; i < Math.max(left.length, right.length); i++) {
    if (left[i] !== right[i]) {
      return `line ${i + 1}\n      baseline ${JSON.stringify(left[i] ?? null)}\n      current  ${JSON.stringify(right[i] ?? null)}`;
    }
  }
  return 'lengths differ';
}

export { runCase, tracingFetch, parseArgs };

// Guarded on argv[1] existing: this module is imported by the validator and by
// the coverage tool, and `node --input-type=module -e` has no argv[1] at all.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(error => {
    console.error(`equivalence: ${error.message}`);
    process.exit(2);
  });
}
