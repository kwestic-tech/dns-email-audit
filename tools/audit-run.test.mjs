#!/usr/bin/env node
/**
 * The audit run loop: how a run starts, and what stops a second one.
 *
 *   node tools/audit-run.test.mjs
 *
 * ── Why this suite exists separately from tools/render.test.mjs ──────────
 *
 * `render.test.mjs` calls one renderer at a time against a prepared result.
 * The defects this file covers are not in a renderer — they are in the order
 * of operations inside `startAudit()`, which is only reachable by booting the
 * application and clicking the button. So this suite builds the page from the
 * shipped `index.html` (via the equivalence runner's own skeleton builder, so
 * the ids are the subject's facts and not a hand-maintained copy), hands the
 * platform a `fetch` it controls, dispatches `DOMContentLoaded`, and drives
 * the controls.
 *
 * No seam was added to `src/`. `startAudit()` is not exported and is not
 * called directly here; the entry point is the click listener the application
 * registers on its own.
 *
 * ── The defect ──────────────────────────────────────────────────────────
 *
 * `startAudit()` read `auditController` as its re-entry guard and did not
 * write it until after `await checkConnectivity()`. A second click inside that
 * probe window passed the guard and started a second run. Both replaced
 * `results`, both reset the progress log and the table, and whichever finished
 * first set `auditController` to null and re-enabled the button while the
 * other was still querying — so Cancel no longer reached it. The published
 * per-run DNS fan-out doubled.
 *
 * The second half is the one a fix breaks: releasing the guard on every early
 * return. A run that assigns the controller and then bails on a failed
 * connectivity probe without clearing it locks the button for the rest of the
 * page's life, and because the button was never disabled nothing looks wrong.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';
import { loadUi } from './lib/browser-harness.mjs';
import { parseReport } from '../src/ui/report-data.js';
import { validDkimSelector } from '../src/core/dkim/dkim.js';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');
const INDEX_HTML = readFileSync(join(repo, 'index.html'), 'utf8');

let pass = 0, fail = 0;
const eq = (label, actual, expected) => {
  const a = JSON.stringify(actual), e = JSON.stringify(expected);
  if (a === e) { pass++; return; }
  fail++;
  console.log(`  ✗ ${label}\n      expected ${e}\n      actual   ${a}`);
};
const section = s => console.log(`\n${s}\n${'─'.repeat(s.length)}`);

const click = (el) => el.dispatchEvent({ type: 'click', target: el });
const settle = (turns = 60) =>
  new Promise(resolve => { let n = turns; (function spin() { n-- ? setTimeout(spin, 5) : resolve(); })(); });

/**
 * Boot the application against a fetch this suite owns.
 *
 * `connectivity` decides what the pre-flight probe sees. Every DoH query is
 * counted and answered with an empty NOERROR after a turn of the event loop,
 * which is the shape that matters: the probe has to still be in flight when
 * the second click arrives, or there is no window to test.
 */
async function boot({ connectivity = true } = {}) {
  const calls = { probe: 0, dns: 0 };
  const fetch = async (url) => {
    const name = new URL(String(url), 'https://cloudflare-dns.com').searchParams.get('name') || '';
    const isProbe = name === 'example.com';
    if (isProbe) calls.probe++; else calls.dns++;
    await new Promise(resolve => setTimeout(resolve, 5));
    if (isProbe && !connectivity) return { ok: false, status: 502, headers: { get: () => null } };
    return {
      ok: true,
      status: 200,
      headers: { get: () => 'application/dns-json' },
      json: async () => ({ Status: 0, Answer: [] }),
    };
  };
  const ui = await loadUi({ page: INDEX_HTML, fetch });
  ui.document.dispatchEvent({ type: 'DOMContentLoaded' });
  // Boot fires its own connectivity probe — `PRIVACY.md` publishes it as "once
  // per page load and once per run" — so let it finish and then zero the
  // counters. What every case below measures is the RUN's fan-out.
  await settle(20);
  calls.probe = 0;
  calls.dns = 0;
  return { ...ui, calls };
}

/* ── 1. One double click starts one run ──────────────────────────────── */
section('1. One double click starts one run');

{
  const { document, calls } = await boot();
  document.getElementById('domainInput').value = 'a.example\nb.example';

  const btn = document.getElementById('auditBtn');
  // Both clicks in the same tick, which is what a double click is. The first
  // suspends at `await checkConnectivity()`; the second arrives before its
  // continuation runs.
  click(btn);
  click(btn);
  await settle();

  // The probe is the measure the privacy documentation publishes: "once per
  // run, however many domains". Counting DNS queries instead would work too,
  // and is noisier — the run's own fan-out varies with the options.
  eq('the connectivity probe ran once, not twice', calls.probe, 1);
  eq('the run issued DNS queries at all', calls.dns > 0, true);
}

/* ── 2. A failed probe does not lock the interface ───────────────────── */
section('2. A failed probe does not lock the interface');

{
  const { document, calls } = await boot({ connectivity: false });
  document.getElementById('domainInput').value = 'a.example';
  const btn = document.getElementById('auditBtn');

  click(btn);
  await settle();
  eq('the offline banner is shown', document.getElementById('netBanner').style.display, 'block');
  eq('no DNS query was issued', calls.dns, 0);

  // The guard is now assigned before the probe, so a fix that forgets to
  // release it on this path leaves every later click returning in silence.
  click(btn);
  await settle();
  eq('a second attempt still reaches the probe', calls.probe, 2);
}

/* ── 3. An input the run refuses also releases the guard ─────────────── */
section('3. An input the run refuses also releases the guard');

{
  const { document, calls } = await boot();
  const btn = document.getElementById('auditBtn');

  // Empty input: refused before the probe, on a path that returns early.
  document.getElementById('domainInput').value = '';
  click(btn);
  await settle(5);
  eq('an empty input runs nothing', calls.probe, 0);

  document.getElementById('domainInput').value = 'a.example';
  click(btn);
  await settle();
  eq('and the next real run still starts', calls.probe, 1);
}

/* ── 4. A completed run stamps the report it can export ──────────────── */
section('4. A completed run stamps the report it can export');

/**
 * The production timestamp path, driven end to end.
 *
 * This section exists because the first attempt at covering it did not. The
 * export suite called the composed UI before any audit had run, so
 * `getRunContext()` was `null` and the timestamp assertions proved nothing;
 * the byte assertions then built `createReport()` by hand and supplied their
 * own run context, bypassing `events.js` and `platform.nowIso()` entirely.
 * Both mutations below left every suite green.
 *
 * `runContext` is run-loop state -- set once when a run finishes -- so it is
 * tested here, where a run is actually driven through the click path, rather
 * than in the suite that formats the bytes.
 */
{
  const FIXED = '2026-09-03T12:34:56.789Z';
  const FIXED_MS = Date.parse(FIXED);
  const booted = await boot();
  const { document, win } = booted;

  // The clock is a capability the runtime holds and `nowIso()` reads it
  // lazily, so pinning the window's `Date` pins the stamp -- the same lever
  // the equivalence runner uses.
  const RealDate = win.Date;
  class PinnedDate extends RealDate {
    constructor(...args) { super(...(args.length ? args : [FIXED_MS])); }
    static now() { return FIXED_MS; }
  }
  win.Date = PinnedDate;

  // Capture the download without a real browser: `dl()` sets `download` and
  // `href` on an anchor and clicks it.
  const downloads = [];
  const realCreate = document.createElement.bind(document);
  document.createElement = function (tag) {
    const node = realCreate(tag);
    if (tag === 'a') {
      const original = node.click ? node.click.bind(node) : function () {};
      node.click = function () { downloads.push({ name: node.download }); original(); };
    }
    return node;
  };
  // The shim's `Blob` is not the platform's, and this section asserts the
  // NAME rather than the bytes, so the object URL is stubbed outright.
  const realCreateObjectUrl = win.URL.createObjectURL;
  win.URL.createObjectURL = function () { return 'blob:export-test'; };

  document.getElementById('domainInput').value = 'a.example';
  document.getElementById('optDeepChecks').checked = false;
  click(document.getElementById('auditBtn'));
  await settle();

  const report = booted.ui.buildReportJson();

  // Fails if `nowIso()` returns anything but a real instant, and fails if the
  // completed run stops assigning the context.
  eq('the finished run stamped the pinned instant', report.generatedAt, FIXED);
  eq('and the report carries the options that run used',
    [report.options.deepChecks, report.options.advanced], [false, true]);
  eq('the run produced a domain to report on', report.domains.map(d => d.domain), ['a.example']);

  booted.ui.exportJSON();
  eq('the download name is derived from that instant',
    downloads.map(d => d.name), ['dns-email-audit-2026-09-03.json']);

  // The strongest oracle available: the importer requires a canonical UTC
  // instant that is also a real calendar date, so a stubbed `nowIso()` cannot
  // survive this even if it returned something ISO-shaped.
  const reimported = parseReport(JSON.stringify(report), { validSelector: validDkimSelector });
  eq('and the exported report re-imports through the same build',
    [reimported.ok, reimported.ok ? reimported.report.generatedAt : reimported.errors],
    [true, FIXED]);

  win.Date = RealDate;
  win.URL.createObjectURL = realCreateObjectUrl;
}

/* ── 5. Comparison mode ──────────────────────────────────────────────── */
section('5. Comparison mode');

/**
 * Driven through the booted page, because comparison is a MODE: what it does
 * to the table, the summary and the filters is the feature, and none of that
 * is reachable by calling `compareReports()` directly.
 *
 * The DOM shim answers element-scoped queries and not document-wide descendant
 * selectors, so every assertion below reads from the element that owns the
 * nodes. That limit is also why `renderComparisonRows()` looks its header row
 * up by id: a structural `thead tr` selector appended the delta header to a
 * DATA row here, and would have shipped that way.
 */
async function bootedRun(domains) {
  const booted = await boot();
  booted.document.getElementById('domainInput').value = domains;
  click(booted.document.getElementById('auditBtn'));
  await settle();
  return booted;
}

// The header row, the same way the application finds it: the real DOM answer
// where table sections exist, document order otherwise. Deliberately not an id
// in the markup — adding one moved the exported HTML report for all 32 cases.
const headRowOf = (doc) => {
  const table = doc.getElementById('resultsTable');
  if (table.tHead && table.tHead.rows && table.tHead.rows.length) return table.tHead.rows[0];
  return table.querySelectorAll('tr')[0];
};
const headCells = (doc) => Array.prototype.filter.call(
  headRowOf(doc).childNodes, n => n && n.id === 'compareHeadCell').length;
const deltaCells = doc => doc.getElementById('tableBody').querySelectorAll('.compare-cell').length;
const comparedRows = doc => Array.prototype.filter.call(
  doc.getElementById('tableBody').querySelectorAll('tr'), r => r.dataset && r.dataset.compare)
  .map(r => r.dataset.domain + '=' + r.dataset.compare);

{
  const { document, ui } = await bootedRun('a.example\nb.example');
  const current = ui.buildReportJson();
  eq('the run can be exported as a report', current.domains.map(d => d.domain), ['a.example', 'b.example']);

  // A baseline that has one of the two domains, so the other reads as added.
  const baseline = JSON.parse(JSON.stringify(current));
  baseline.domains = baseline.domains.filter(d => d.domain !== 'b.example');

  ui.acceptImportedReport(JSON.stringify(baseline));
  eq('importing a baseline enters comparison', ui.getComparison() !== null, true);
  eq('every domain gets a verdict', comparedRows(document),
    ['a.example=unchanged', 'b.example=added']);
  eq('the delta column is added once', headCells(document), 1);
  eq('and one cell per row', deltaCells(document), 2);
  eq('the exit control and the comparison filter appear',
    [document.getElementById('exitCompareBtn').style.display,
      document.getElementById('filterCompare').style.display], ['', '']);
  eq('the summary is replaced by the comparison summary',
    document.getElementById('statsGrid').textContent.includes('Unchanged'), true);

  // Entering twice must not stack a second column.
  ui.acceptImportedReport(JSON.stringify(baseline));
  eq('entering again does not add a second delta column', headCells(document), 1);
  eq('nor a second cell per row', deltaCells(document), 2);

  ui.exitComparison();
  eq('leaving discards the comparison', ui.getComparison(), null);
  eq('and takes the column with it', [headCells(document), deltaCells(document)], [0, 0]);
  eq('and the verdicts', comparedRows(document), []);
  eq('and hides the notice', document.getElementById('compareNotice').style.display, 'none');
}

/* A rejected file explains itself and changes nothing. */
{
  const { document, ui } = await bootedRun('a.example');
  const before = comparedRows(document);

  ui.acceptImportedReport('{"schema":"something-else","schemaVersion":1}');
  const notice = document.getElementById('compareNotice');
  eq('a foreign file is refused with the message for its code',
    notice.textContent.includes('not a report from this tool'), true);
  eq('and the notice is a warning, not the comparison banner',
    notice.className.includes('callout-warn'), true);
  eq('no comparison was entered', ui.getComparison(), null);
  eq('and the table is untouched', comparedRows(document), before);

  // A malformed field carries its schema path, untranslated, beneath the
  // localized sentence. That pairing is the whole of spec 1.7 section 4.
  ui.acceptImportedReport(JSON.stringify({
    schema: 'dns-email-audit/report', schemaVersion: 1,
    generatedAt: '2026-09-04T00:00:00.000Z',
    generator: { version: '0.9.0', analysisVersion: 1 },
    resolver: 'https://cloudflare-dns.com/dns-query',
    options: { dkim: true, dkimComprehensive: false, www: true, wildcard: true,
      advanced: true, deepChecks: true, selectors: [] },
    domains: [], extra: 1, badField: true,
  }).replace('"resolver":"https://cloudflare-dns.com/dns-query"', '"resolver":"https://"'));
  eq('a malformed field names itself in the message', [
    document.getElementById('compareNotice').textContent.includes('cannot read'),
    document.getElementById('compareNotice').textContent.includes('resolver'),
  ], [true, true]);
}

/* A hostile value inside an accepted report is data, and stays data. */
{
  const { document, ui } = await bootedRun('a.example');
  const report = ui.buildReportJson();
  const hostile = '<img src=x onerror=alert(1)>';
  report.domains[0].records.spf = [{ queryName: 'a.example', value: hostile }];
  ui.acceptImportedReport(JSON.stringify(report));
  eq('a report carrying a script-like record value is still accepted',
    ui.getComparison() !== null, true);
  const html = document.getElementById('resultsSection').innerHTML || '';
  eq('and no element was created from it', html.includes('<img src=x'), false);
}

/* Two reports, no audit: the second entry path section 6 names. */
{
  const booted = await boot();
  const { document, ui } = booted;
  const seed = await bootedRun('a.example');
  const first = seed.ui.buildReportJson();
  const second = JSON.parse(JSON.stringify(first));
  second.domains[0].score.pts = first.domains[0].score.pts;

  ui.acceptImportedReport(JSON.stringify(first));
  eq('one report alone does not start a comparison', ui.getComparison(), null);
  eq('and the page says what it is waiting for',
    document.getElementById('compareNotice').textContent.includes('Choose a saved report'), true);
  ui.acceptImportedReport(JSON.stringify(second));
  eq('the second one does', ui.getComparison() !== null, true);
  eq('with both domains accounted for',
    ui.getComparison().domains.length, first.domains.length);
}

console.log(`\n${'='.repeat(60)}`);
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
