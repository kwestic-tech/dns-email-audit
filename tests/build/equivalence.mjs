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
import { execFileSync } from 'node:child_process';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, resolve, relative } from 'node:path';

import { loadSubject, FIXED_INSTANT, FIXED_LOCALE, FIXED_TIMEZONE } from '../lib/subject.mjs';
import {
  probePublicSuffixRules, probeDkimCatalog, probeEnglishBundle, assertFixtureIdentity,
} from '../lib/fixture-identity.mjs';
import {
  encode, serialize, canonicalQueryTrace, orderedSubsequence,
  canonicalDom, canonicalDomLines, canonicalCsv, reportByteRegions, applyExclusions,
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

  /**
   * Data profile: the runner supplies PRODUCTION generated data for all three
   * bindings, because a subject is a complete root and loads its own.
   *
   * Run before anything else and throwing rather than counting, per spec §11.
   * The spike is why: a bundled public suffix list silently replaced a fixture
   * and 1,535 assertions passed against the wrong data without a warning. Here
   * the failure mode is subtler and worse — a subject root assembled with one
   * file from somewhere else would produce a baseline that looks authoritative.
   */
  assertFixtureIdentity([
    probePublicSuffixRules(win.DnsAudit.getOrganizationalDomain, 'production'),
    probeDkimCatalog(win.DnsAudit.isRecognizedDkimSelector, 'production'),
    probeEnglishBundle(win.t, 'production'),
  ]);

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
    csv: csv === null ? null : csvSurface(csv),
    report: report === null ? null : reportSurface(report),
    dom: canonicalDomLines(document.getElementById('tableBody')),
  };
}

/**
 * The exported CSV's surface: exact bytes, one row per line.
 *
 * Held as lines rather than as one string for the same reason the DOM is —
 * `lines.join('\n')` reconstructs the file byte for byte, and a diff points at
 * the row that changed instead of printing the whole export twice. The split is
 * on `\n` alone, so the `\r` of each CRLF stays at the end of its line and
 * remains part of the comparison; the BOM stays on line one; nothing is
 * trimmed. The hash is what makes it complete.
 */
function csvSurface(text) {
  // Content first, digests after. `firstDifference()` reports the first line
  // that moved, and a hash line at the top would always be that line — telling
  // the reader only that something changed, which they already knew.
  return {
    lines: canonicalCsv(text).split('\n'),
    bytes: Buffer.byteLength(text, 'utf8'),
    sha256: createHash('sha256').update(text, 'utf8').digest('hex'),
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
    generated: generated ? generated[1] : null,
    bytes: reportByteRegions(html),
    structure: tags.join(' '),
    length: Buffer.byteLength(html, 'utf8'),
    sha256: createHash('sha256').update(html, 'utf8').digest('hex'),
  };
}

/**
 * What commit this subject root is, as git sees it.
 *
 * A built artifact root (`_site/`) is inside the working tree and describes as
 * the branch head, which is correct: it was built from that commit. A root that
 * is not a git checkout at all reports so rather than being left blank.
 */
function gitDescribe(root) {
  const run = args => execFileSync('git', ['-C', root, ...args], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] }).trim();
  try {
    const commit = run(['rev-parse', 'HEAD']);
    let described = commit;
    try { described = run(['describe', '--tags', '--always', '--dirty']); } catch { /* no tags */ }
    return { commit, described };
  } catch {
    return { commit: null, described: 'not a git checkout' };
  }
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
      // The commit, not the path. An absolute path is this machine's and would
      // differ in CI for no reason; spec Design §8 asks the manifest to bind
      // the commit or tag, and the input hashes below are what actually bind
      // the comparison.
      commit: gitDescribe(root),
      root: relative(RUNNER_ROOT, root) || '.',
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
  // Input hashes are what bind a comparison. A baseline whose inputs differ is
  // not a baseline for this subject, and saying so beats reporting thirty
  // surface diffs that all mean the same thing.
  const baselineInputs = new Map((baseline.subject?.inputs || []).map(i => [i.path, i.sha256]));
  for (const input of current.subject?.inputs || []) {
    if (!baselineInputs.has(input.path)) { diffs.push(`subject input ${input.path}: absent from the baseline`); continue; }
    if (baselineInputs.get(input.path) !== input.sha256) diffs.push(`subject input ${input.path}: content changed`);
    baselineInputs.delete(input.path);
  }
  for (const missing of baselineInputs.keys()) diffs.push(`subject input ${missing}: in the baseline, not loaded now`);

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

/**
 * The first few differing lines.
 *
 * Three rather than one: a surface that carries a digest beside its content
 * would otherwise report only "the hash moved", and a surface where one edit
 * shifts several lines reads better with a little context.
 */
function firstDifference(a, b) {
  const left = a.split('\n');
  const right = b.split('\n');
  const found = [];
  for (let i = 0; i < Math.max(left.length, right.length) && found.length < 3; i++) {
    if (left[i] !== right[i]) {
      found.push(`line ${i + 1}\n      baseline ${truncate(left[i])}\n      current  ${truncate(right[i])}`);
    }
  }
  return found.length ? found.join('\n    ') : 'lengths differ';
}

/** A single CSV row can be 2 KB. The differing part is near the front of it. */
function truncate(line) {
  const text = JSON.stringify(line ?? null);
  return text.length > 240 ? text.slice(0, 240) + `… (${text.length} chars)` : text;
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
