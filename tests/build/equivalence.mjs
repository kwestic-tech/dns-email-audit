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
  probePublicSuffixRules, probeDkimCatalog, probeEnglishBundle,
  probePublicSuffixArtifact, probeDkimCatalogArtifact, probeEnglishBundleArtifact, assertFixtureIdentity,
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
  /** How many requests are open right now. Used to wait for the page to settle. */
  impl.inFlight = () => active;
  return impl;
}

const TYPE_NAMES = {
  1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA',
  43: 'DS', 48: 'DNSKEY', 52: 'TLSA', 257: 'CAA',
};

/* ── One case, two executions ─────────────────────────────────────────── */

/**
 * Run one corpus case against one subject root and return its five surfaces.
 *
 * A case may audit SEVERAL domains through ONE subject. That is not a
 * convenience: it is the only way to observe the DoH cache's page lifetime,
 * which `tools/scoring.test.mjs:1888-1891` asserts and `PRIVACY.md:30-33`
 * publishes. A runner that built a fresh page per domain would report a clean
 * trace while the cache was being narrowed underneath it.
 *
 * ── Why there are two executions ────────────────────────────────────────
 *
 * Spec §8 as of `1.4`. The five surfaces are bound to one deterministic CASE,
 * not to one runtime, and this is where that stops being an abstraction.
 *
 * Until §10's stage 3 the runner captured the result surface by wrapping
 * `window.DnsAudit.analyzeDomain`, which worked because the global and the
 * engine the UI called were the same object. `globalName: 'DnsAudit'` ends
 * that: the global becomes esbuild's export namespace — non-configurable
 * accessors, and not the object `src/main.js` composes. That is the namespace
 * boundary working, and it means the result has to come from the supported
 * facade rather than from inside the UI's run.
 *
 * So:
 *
 *   UI execution      one subject, one runtime — query trace, CSV, HTML
 *                     report and DOM, driven through the real controls.
 *   Result execution  a second subject and runtime — the facade's
 *                     `analyzeDomain`, once per domain the UI audited.
 *
 * Neither warms the other: separate subjects, separate runtimes, separate DoH
 * caches, separate fixtures. The result execution's queries are a DIFFERENT
 * INSTRUMENT EXECUTION, not an exclusion from the trace surface — no exclusion
 * is added anywhere and `tests/lib/canonical.mjs`'s manifest stays empty. The
 * emitted trace is the UI execution's complete trace, pre-flight included.
 *
 * ── What replaces the guarantee that was lost ───────────────────────────
 *
 * Two surfaces captured from one process image agreed about which audit they
 * described because they could not do otherwise. Two executions can, so the
 * agreement is ASSERTED — see `bindExecutions()`. The UI execution also decides
 * what the result execution replays: its domain list and its post-gating
 * control states are READ from the page it produced rather than re-derived, so
 * the runner does not carry a second copy of `parseDomains()` or of the
 * deep-check limit.
 */
async function runCase(root, testCase, entry) {
  const ui = await runUiExecution(root, testCase, entry);
  const results = await runResultExecution(root, testCase, entry, ui.replay);

  if (results.probeForm !== ui.probeForm) {
    throw new Error(
      `equivalence: ${testCase.id} probed its two executions at different strengths ` +
      `(${ui.probeForm} vs ${results.probeForm}). They are not measuring the same subject.`);
  }

  const problems = bindExecutions(testCase, results.audits, ui);
  if (problems.length) {
    throw new Error(
      `equivalence: ${testCase.id}'s two executions do not describe the same audit.\n  ` +
      problems.join('\n  ') +
      '\n  The result surface and the other four are captured from separate runtimes ' +
      '(spec §8, 1.4); this binding is what stops two different cases being reported ' +
      'under one case id.');
  }

  return {
    id: testCase.id,
    description: testCase.description,
    // Part of the case's identity, not a detail. A surface set captured under a
    // substituted platform is not comparable with one captured under the host's
    // own, and recording it here is what makes that visible instead of showing
    // up as an unexplained result diff.
    platform: ui.platform,
    result: encode(results.audits.slice().sort((a, b) => (a.domain < b.domain ? -1 : a.domain > b.domain ? 1 : 0))),
    trace: ui.trace,
    csv: ui.csv === null ? null : csvSurface(ui.csv),
    report: ui.report === null ? null : reportSurface(ui.report),
    dom: ui.dom,
    // Not a surface. Carried out so the run can report at what strength this
    // subject's generated data was verified — see probeSubject().
    probeForm: ui.probeForm,
  };
}

/**
 * Fixture identity, at whatever strength the subject exposes — and say which.
 *
 * Two kinds of subject have to be measured by one instrument. `v0.5.0` and
 * every root up to Task 2.6 put all 95 engine members on `window.DnsAudit`, so
 * §11's probes can be run through them. From Task 2.7 the artifact exposes the
 * two-member facade, and neither reader is among them.
 *
 * The choice is made by capability and RECORDED, never inferred silently. This
 * runner already refuses to fall back from `--entry=esm` to the classic path
 * because "a silent fallback would report the wrong subject"; the same rule
 * applies to falling back to a weaker probe. The form reaches the emitted
 * manifest, so a run can never read as stronger evidence than it was.
 *
 * **Neither form is an application-behavioural fingerprint for the PSL**, and
 * spec §11 says so as of `1.4`: `getOrganizationalDomain()` is the only reader
 * of the public suffix sets and no application code calls it, so there is no
 * production path to observe. It is an engine/runtime fingerprint in the
 * `engine` form and a binding check in the `artifact` form.
 *
 * The second form was `binding` until Task 6.2, reading the three generated-data
 * globals. That task removed them with the last adapter, so the tables now live
 * inside the bundle's closure and the artifact TEXT is where their identity is
 * observable. **Same discriminators, different place** — the private
 * `blogspot.com` rule, the fixture selector, the fixture English title — which
 * is what makes it the same question rather than a weaker one. The form is
 * recorded in the emitted manifest either way, so a run can never read as
 * stronger evidence than it was.
 */
function probeSubject(win, scriptSource) {
  const engine = win.DnsAudit || {};
  const reachable = typeof engine.getOrganizationalDomain === 'function' &&
    typeof engine.isRecognizedDkimSelector === 'function';
  if (reachable) {
    return {
      form: 'engine',
      probes: [
        probePublicSuffixRules(engine.getOrganizationalDomain, 'production'),
        probeDkimCatalog(engine.isRecognizedDkimSelector, 'production'),
        probeEnglishBundle(win.t, 'production'),
      ],
    };
  }
  return {
    form: 'artifact',
    probes: [
      probePublicSuffixArtifact(scriptSource, 'production'),
      probeDkimCatalogArtifact(scriptSource, 'production'),
      probeEnglishBundleArtifact(scriptSource, 'production'),
    ],
  };
}

/**
 * Load a subject and run its data-identity probes before anything else.
 *
 * Data profile: the runner supplies PRODUCTION generated data for all three
 * bindings, because a subject is a complete root and loads its own.
 *
 * Throws rather than counting, per spec §11. The spike is why: a bundled public
 * suffix list silently replaced a fixture and 1,535 assertions passed against
 * the wrong data without a warning. Here the failure mode is subtler and worse
 * — a subject root assembled with one file from somewhere else would produce a
 * baseline that looks authoritative.
 */
function openSubject(root, testCase, entry, fetchImpl) {
  const subject = loadSubject(root, {
    entry, fetch: fetchImpl, instant: FIXED_INSTANT, platform: testCase.platform,
  });
  const probe = probeSubject(subject.win, subject.scriptSource);
  assertFixtureIdentity(probe.probes);
  return { ...subject, probeForm: probe.form };
}

/**
 * Wait until the page has stopped working.
 *
 * The boot chain — `DOMContentLoaded` → `runtime.mount()` → `checkConnectivity()`
 * — is started by a listener that returns nothing, so there is no promise to
 * await. What there is instead is an observable: the fixture knows how many
 * requests are open, and the page is settled when none is and none has started
 * for a full drain of the microtask and macrotask queues.
 *
 * Bounded, and loud if it does not converge. A quiescence loop that could spin
 * forever would turn a hang in the application into a hang in the instrument,
 * which is the worst way to learn about one.
 */
async function settle(fetchImpl, what) {
  for (let quiet = 0, drains = 0; quiet < 3; drains++) {
    if (drains > 5000) {
      throw new Error(`equivalence: ${what} never settled — ${fetchImpl.inFlight()} request(s) still open`);
    }
    const before = fetchImpl.calls.length;
    await new Promise(resolve => setImmediate(resolve));
    quiet = fetchImpl.inFlight() === 0 && fetchImpl.calls.length === before ? quiet + 1 : 0;
  }
}

/**
 * Click a control the way a person does, and wait for what it started.
 *
 * Task 2.8 removed `window.startAudit`, `window.exportCSV` and
 * `window.exportHTML` — three of the fourteen unsupported globals — and this is
 * what replaces them. It is a MORE FAITHFUL DRIVER, not a workaround: the path
 * from a click through the listener to the audit is now inside what the five
 * surfaces cover, where calling the global jumped over it.
 */
async function clickAndWait(element, fetchImpl, what) {
  const event = { type: 'click', bubbles: true, __results: [] };
  event.stopPropagation = () => { event.__stopped = true; };
  event.preventDefault = () => { event.__prevented = true; };
  event.target = element;
  element.dispatchEvent(event);
  // `startAudit` and `exportHTML` are async and wired straight to their
  // buttons; a browser discards the promise and so does `click()`. The runner
  // needs it, so it reads what the handlers returned off the event it built.
  await Promise.all(event.__results);
  await settle(fetchImpl, what);
}

/** The controls a case can set, and the option key each one feeds. */
const CONTROL_OPTIONS = [
  ['optDKIM', 'dkim'], ['optDKIMComprehensive', 'dkimComprehensive'],
  ['optWWW', 'www'], ['optWildcard', 'wildcard'], ['optDeepChecks', 'deepChecks'],
];

/**
 * The UI execution: four of the five surfaces, through the real controls.
 *
 * `startAudit()` owns the worker pool, the per-domain error isolation and the
 * `results` array the two exports read, so the audit is driven through the real
 * entry point exactly as before. Nothing here reaches past the UI.
 */
async function runUiExecution(root, testCase, entry) {
  const cssPath = join(root, 'css', 'style.css');
  const css = existsSync(cssPath) ? readFileSync(cssPath, 'utf8') : '';
  const fetchImpl = tracingFetch(testCase.fetch(), css);
  const subject = openSubject(root, testCase, entry, fetchImpl);
  const { win, document, downloads } = subject;
  const control = id => document.getElementById(id);

  /**
   * Boot the page, exactly as a browser does.
   *
   * `src/ui/events.js` wires every control from inside its `DOMContentLoaded`
   * listener — one listener, registered by `runtime.js` when it builds the UI
   * — so until this fires the page has no handlers on any button. The
   * runner used to skip it entirely and call `window.startAudit()`, which meant
   * it measured a page that had never booted — including the boot's own
   * `checkConnectivity()` query, which a real visitor always pays and the trace
   * never showed. Firing it is what Task 2.8 makes necessary and what makes the
   * trace honest; the baseline was recaptured with the same driver, so both
   * sides moved together.
   *
   * Settled before anything is clicked, because an audit that started while the
   * boot's request was still open would report a maximum concurrency that
   * depended on scheduling rather than on the application.
   */
  document.dispatchEvent({ type: 'DOMContentLoaded', bubbles: false });
  await settle(fetchImpl, `${testCase.id}: page boot`);

  // Options are set the way a person sets them: on the controls `startAudit()`
  // reads. The defaults come from the subject's own index.html.
  const options = testCase.options || {};
  for (const [id, key] of CONTROL_OPTIONS) {
    if (Object.prototype.hasOwnProperty.call(options, key)) control(id).checked = options[key];
  }
  if (options.selectors) control('dkimSelectors').value = options.selectors.join(' ');
  control('domainInput').value = testCase.domains.map(d => d.domain).join('\n');

  await clickAndWait(control('auditBtn'), fetchImpl, `${testCase.id}: audit`);

  const tableBody = document.getElementById('tableBody');
  const rows = [...tableBody.walk()].filter(n => n.nodeType === 1 && n.localName === 'tr' && n.dataset.domain);

  let csv = null;
  let report = null;
  // Exactly the condition this runner has always used, read off the page
  // instead of off the intercepted calls: a domain whose audit THREW renders
  // `data-overall="error"` and no grade, so "at least one non-error row" is
  // "at least one domain produced a result". Verified against all 30 baseline
  // cases before the interception was removed.
  if (rows.some(row => row.dataset.overall !== 'error')) {
    downloads.length = 0;
    await clickAndWait(control('exportCsvBtn'), fetchImpl, `${testCase.id}: CSV export`);
    csv = (downloads.find(d => d.type && d.type.startsWith('text/csv')) || {}).text ?? null;
    downloads.length = 0;
    await clickAndWait(control('exportHtmlBtn'), fetchImpl, `${testCase.id}: HTML export`);
    report = (downloads.find(d => d.type === 'text/html') || {}).text ?? null;
  }

  const calls = fetchImpl.calls;
  return {
    platform: subject.manifest.platform,
    probeForm: subject.probeForm,
    csv,
    report,
    dom: canonicalDomLines(tableBody),
    // `startAudit()` runs its own pre-flight `checkConnectivity()` before any
    // domain. It is a real query the application makes on every run and it
    // stays in the trace; a runner that filtered it out would report a fan-out
    // the browser does not have.
    trace: {
      ...canonicalQueryTrace(calls, fetchImpl.observed()),
      // Order IS the behaviour for these two algorithms. Asserted separately
      // from the multiset, per canonicalization.md §2.
      dmarcWalk: orderedSubsequence(calls, c => c.name.startsWith('_dmarc.') && c.type === 'TXT'),
      spfEvaluation: orderedSubsequence(calls, c => c.type === 'TXT' && (testCase.spfNames || []).includes(c.name)),
    },
    /**
     * What the result execution replays, taken from what the UI actually did.
     *
     * The domain list is the rows the application rendered — after its own
     * `parseDomains()` normalization, de-duplication and validity filtering —
     * and the control states are read AFTER the run, so any gating the
     * application applied to them (the deep-check limit above
     * `MAX_DEEP_CHECK_DOMAINS`) is already in what is read. The runner
     * therefore holds no second copy of either rule.
     */
    replay: {
      domains: rows.map(row => row.dataset.domain),
      options: Object.fromEntries([
        ...CONTROL_OPTIONS.map(([id, key]) => [key, !!control(id).checked]),
        // `src/ui/events.js` passes this unconditionally; it is not a control.
        ['advanced', true],
        ['selectors', String(control('dkimSelectors').value || '').split(/[\s,]+/)
          .map(value => value.trim().toLowerCase())
          .filter(value => /^[a-z0-9][a-z0-9_-]{0,62}$/.test(value))],
      ]),
    },
  };
}

/**
 * The result execution: the whole `analyzeDomain()` return, through the facade.
 *
 * A second subject and a second runtime, so this shares no DoH cache with the
 * UI execution and cannot warm it. Domains run in the order the UI rendered
 * them and sequentially, which makes cache reuse within this runtime
 * deterministic; the UI's worker pool is preserved in the execution that
 * actually reports a trace.
 */
async function runResultExecution(root, testCase, entry, replay) {
  const fetchImpl = tracingFetch(testCase.fetch(), '');
  const subject = openSubject(root, testCase, entry, fetchImpl);
  const { win } = subject;

  // The same options the UI computed, plus the signal `src/ui/events.js` attaches.
  const options = { ...replay.options, signal: new win.AbortController().signal };

  const audits = [];
  for (const domain of replay.domains) {
    try {
      audits.push({ domain, outcome: 'result', result: await win.DnsAudit.analyzeDomain(domain, options) });
    } catch (error) {
      // A thrown audit is a modelled outcome, not a runner failure — spec
      // §12.1's audit row names thrown cancellation and core transport errors
      // as states the corpus must reach.
      audits.push({
        domain,
        outcome: 'thrown',
        error: { name: error && error.name, kind: error && error.kind, message: error && error.message },
      });
    }
  }
  return { audits, probeForm: subject.probeForm };
}

/* ── The cross-surface binding ────────────────────────────────────────── */

/**
 * Do the two executions describe the same audit?
 *
 * Required by spec §8 as of `1.4`, and it is what replaces the agreement a
 * single process image used to give for free.
 *
 * ── The rule that decides what may be compared here ─────────────────────
 *
 * **Only fields that cannot differ because the code under test changed.** The
 * binding's job is to prove the two executions describe the same audit — not to
 * re-check a surface. Anything a code change could move on one side alone
 * belongs in the surface comparison, where it is REPORTED as a difference; put
 * it here and the same change aborts the run instead.
 *
 * That is not hypothetical. The first version of this compared the score
 * against the CSV's `Score` column, and the validator's own
 * "reorder two CSV columns" mutation — which must move the `csv` surface and
 * nothing else — crashed the runner instead. A CSV with swapped columns is a
 * CSV bug, and the instrument has a place to say so.
 *
 * So everything compared here is read from the **DOM**, structurally, and every
 * field is one both executions derive from the same audit:
 *
 * | Field | Result execution | UI execution |
 * | --- | --- | --- |
 * | domain set | `result.domain` | `tr[data-domain]` |
 * | grade | `result.score.grade` | `tr[data-grade]` |
 * | score | `result.score.pts` | `span.score-total`'s text in the detail panel |
 * | finding count | `result.findings.length` | `div.finding` |
 * | suggestion count | `result.suggestions.length` | `div.issue.tip` |
 *
 * A grading change moves both sides together and cannot trip this; two
 * different cases joined under one id cannot fail to.
 *
 * **The issue TOKEN set is deliberately not among them, and that is a
 * limitation rather than a choice.** `src/ui/events.js` renders each issue as
 * translated prose through `issueMessage()` and attaches no token attribute, so
 * the tokens are not observable on the UI side. Cardinality is what is, and it
 * sits beside the grade and the score, which move for any change to the issue
 * set that carries weight. Named here rather than implying the tokens were
 * compared.
 *
 * Validated before it was trusted: run over all 30 baseline cases this rule
 * matched 79 domains and 77 graded scores with zero mismatches, and
 * `equivalence.validate.mjs` §5 proves every clause of it can fail.
 */
export function bindExecutions(testCase, audits, ui) {
  const problems = [];

  // One pass, in document order: a row opens a domain's section and the first
  // `score-total` after it belongs to that domain's detail panel.
  const rows = new Map();
  let current = null;
  let expectScore = false;
  for (const line of ui.dom) {
    const domain = /data-domain="([^"]+)"/.exec(line);
    if (domain) {
      const grade = /data-grade="([^"]*)"/.exec(line);
      current = domain[1];
      expectScore = false;
      rows.set(current, { grade: grade ? grade[1] : null, score: null });
      continue;
    }
    if (/class="score-total/.test(line)) { expectScore = true; continue; }
    if (!expectScore) continue;
    expectScore = false;
    const text = /^\s*#3 "(\d+)"$/.exec(line);
    const row = current && rows.get(current);
    if (text && row && row.score === null) row.score = Number(text[1]);
  }

  const audited = audits.map(a => a.domain).sort();
  const rendered = [...rows.keys()].sort();
  if (String(audited) !== String(rendered)) {
    problems.push(`domain sets differ: result [${audited}] vs UI [${rendered}]`);
  }

  for (const audit of audits) {
    const row = rows.get(audit.domain);
    if (!row) continue;
    const score = audit.outcome === 'result' && audit.result && audit.result.score;
    if (!score) {
      // An unregistered or thrown domain renders no grade, and must not.
      if (row.grade !== null) {
        problems.push(`${audit.domain}: UI shows grade ${row.grade} for a result carrying no score`);
      }
      continue;
    }
    if (score.grade !== row.grade) problems.push(`${audit.domain}: grade ${score.grade} vs UI ${row.grade}`);
    if (score.pts !== row.score) problems.push(`${audit.domain}: score ${score.pts} vs UI ${row.score}`);
  }

  const counted = className => ui.dom.filter(line => line.trim() === `<div class="${className}">`).length;
  const total = key => audits.reduce((n, a) => n + ((a.result && a.result[key]) || []).length, 0);
  // The detail panel renders `result.findings` as `div.finding` (findings spec
  // §5), not the legacy `result.issues`; the severity view carries every
  // finding as a card — low/info hidden, not withheld — so the count is exact.
  if (total('findings') !== counted('finding')) {
    problems.push(`finding count ${total('findings')} vs UI ${counted('finding')}`);
  }
  if (total('suggestions') !== counted('issue tip')) {
    problems.push(`suggestion count ${total('suggestions')} vs UI ${counted('issue tip')}`);
  }

  return problems;
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

/**
 * The authorized compatibility deltas, folded into every emitted manifest.
 *
 * A delta is a deliberate change to the browser surface that no equivalence
 * surface can see — the globals appear in none of result, trace, CSV, report or
 * DOM. Recording them in the manifest is what stops them passing unnoticed, and
 * it is spec §10's requirement that each be "a named allowed delta in the
 * equivalence manifest".
 */
function readCompatibilityDeltas() {
  const path = join(RUNNER_ROOT, 'tests/fixtures/equivalence/compatibility-deltas.json');
  if (!existsSync(path)) return [];
  const manifest = JSON.parse(readFileSync(path, 'utf8'));
  return manifest.deltas.map(delta => ({
    id: delta.id, task: delta.task, status: delta.status, summary: delta.summary,
  }));
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

  // One form for the whole run, or the run is measuring two different things.
  const probeForms = [...new Set(surfaces.map(surface => surface.probeForm))];
  if (probeForms.length !== 1) {
    console.error(`equivalence: the subject probed at more than one strength (${probeForms.join(', ')})`);
    process.exit(2);
  }
  // Removed before comparison: it describes the RUN, not a surface, and leaving
  // it on each case would make it a sixth thing the diff walks.
  for (const produced of surfaces) delete produced.probeForm;

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
      /**
       * How this subject's generated data was verified. Spec §11, `1.4`.
       *
       * `engine` — the probes ran through engine members, which for the DKIM
       * catalog and the English bundle means through their real consumers.
       * `binding` — the artifact exposes only the two-member facade, so the
       * tables were checked at the binding.
       *
       * Recorded rather than inferred: a manifest that did not say which would
       * let a weaker run read as a stronger one. Neither form is an
       * application-behavioural fingerprint for the PSL, and §11 says why.
       */
      fixtureIdentity: probeForms[0],
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
    // Authorized changes to the browser-visible surface. NOT exclusions: no
    // surface is relaxed by them, and they appear on none of the five because
    // the surfaces observe the audit result. Named here so they cannot pass
    // silently. See tests/fixtures/equivalence/compatibility-deltas.json.
    compatibilityDeltas: readCompatibilityDeltas(),
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
  const { diffs, composition } = compare(baseline, document);

  if (composition.length) {
    console.log(`\nSubject composition differs from the baseline's (${baseline.subject.commit?.described || 'unknown'}).`);
    console.log('Expected while the delivery boundary and the module tree move.');
    console.log('Provenance, not a verdict — the five surfaces below are the verdict.');
    for (const change of composition) console.log(`    ${change}`);
    console.log('');
  }
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
  // Input hashes are PROVENANCE, not a gate.
  //
  // They were briefly compared as differences, and that was wrong: the subject
  // whose behaviour is being checked is by definition not the one the baseline
  // was captured from — Task 1.6 replaces seven script inputs with one, and
  // every commit after Phase 2 changes them again. Gating on them would have
  // reported a permanent false stop from the delivery-boundary commit onward,
  // and a surface that cries wolf is one people learn to ignore.
  //
  // What they are for is spec Design §8's requirement that a baseline record
  // what it was captured from, so a reader can tell. Reported, never counted.
  const baselineInputs = new Map((baseline.subject?.inputs || []).map(i => [i.path, i.sha256]));
  const composition = [];
  for (const input of current.subject?.inputs || []) {
    if (!baselineInputs.has(input.path)) composition.push(`+ ${input.path}`);
    else if (baselineInputs.get(input.path) !== input.sha256) composition.push(`~ ${input.path}`);
    baselineInputs.delete(input.path);
  }
  for (const missing of baselineInputs.keys()) composition.push(`- ${missing}`);

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
  return { diffs, composition };
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
