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
    // Locale files are served from disk. Without this `setLang()` returns false
    // and `onChange` never fires, so a language-change assertion measures a
    // language that never changed — which is exactly how the first version of
    // section 5's locale test stayed green under a mutation that removed the
    // comparison re-render entirely.
    const raw = String(url);
    if (raw.startsWith('locales/')) {
      try {
        const body = readFileSync(join(repo, raw), 'utf8');
        return { ok: true, status: 200, headers: { get: () => 'application/json' },
          json: async () => JSON.parse(body) };
      } catch { return { ok: false, status: 404, headers: { get: () => null } }; }
    }
    const name = new URL(raw, 'https://cloudflare-dns.com').searchParams.get('name') || '';
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

// The header row. `tHead.rows[0]` where table sections exist; where they do
// not, DELIBERATELY the row a positional fallback would have picked — which is
// a data row, and is the thing to look at to prove nothing was appended there.
// The application itself has no such fallback: it returns null instead.
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
  // No header cell here: this environment models no table sections, and
  // `headerRow()` refuses to guess rather than append a `th` to a data row.
  eq('no header cell is invented without a header row', headCells(document), 0);
  eq('but there is one delta cell per row', deltaCells(document), 2);
  eq('and each names its column', document.getElementById('tableBody')
    .querySelectorAll('.compare-cell')[0].dataset.label, 'Change');
  eq('the exit control and the comparison filter appear',
    [document.getElementById('exitCompareBtn').style.display,
      document.getElementById('filterCompare').style.display], ['', '']);
  eq('the summary is replaced by the comparison summary',
    document.getElementById('statsGrid').textContent.includes('Unchanged'), true);

  // Entering twice must not stack a second column.
  ui.acceptImportedReport(JSON.stringify(baseline));
  eq('entering again invents no header cell either', headCells(document), 0);
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
  // localized sentence. That pairing is the whole of spec 1.8 section 4.
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

/**
 * A hostile value inside an accepted report is data, and stays data.
 *
 * BOTH directions. The first version of this asserted only that no `<img>`
 * element had been created — which passed while the renderer displayed nothing
 * at all, because the evidence was never rendered. Absence alone cannot tell
 * "escaped correctly" from "silently dropped".
 */
{
  const { document, ui } = await bootedRun('a.example');
  const report = ui.buildReportJson();
  const hostile = '<img src=x onerror=alert(1)>';
  report.domains[0].records.spf = [{ queryName: 'a.example', value: hostile }];
  ui.acceptImportedReport(JSON.stringify(report));
  eq('a report carrying a script-like record value is still accepted',
    ui.getComparison() !== null, true);
  const section = document.getElementById('resultsSection');
  eq('the record change is shown, naming its path',
    (section.textContent || '').includes('records.spf'), true);
  eq('and the hostile value is present AS TEXT',
    (section.textContent || '').includes(hostile), true);
  eq('while no element was created from it',
    (section.innerHTML || '').includes('<img src=x'), false);
}

/* The evidence behind a verdict, in the detail row the table already has. */
{
  const { document, ui } = await bootedRun('a.example');
  const current = ui.buildReportJson();
  const baseline = JSON.parse(JSON.stringify(current));
  baseline.domains[0].findings = [{
    id: 'dmarc.policy-none', protocol: 'dmarc', severity: 'high', confidence: 'confirmed',
    category: 'policy', effort: 'moderate', args: [], dependsOn: [],
    evidence: [{ kind: 'txt', queryName: '_dmarc.a.example', value: 'v=DMARC1; p=none' }],
  }];
  ui.acceptImportedReport(JSON.stringify(baseline));
  const body = document.getElementById('tableBody');
  eq('the detail row carries the comparison evidence',
    body.querySelectorAll('.compare-detail').length, 1);
  const detailText = body.querySelectorAll('.compare-detail')[0].textContent || '';
  const d = ui.getComparison().domains[0];
  // Whichever bucket the id lands in, the detail names it — a renderer that
  // read only the status would show none of these.
  eq('and names the finding it moved',
    detailText.includes('dmarc.policy-none'), true);
  eq('the comparison really did move that finding', [
    d.findings.resolved.includes('dmarc.policy-none'),
    d.findings.unknown.includes('dmarc.policy-none'),
  ].some(Boolean), true);
  eq('an incomparable protocol is named, not just counted',
    d.incomparableProtocols.length > 0
      && detailText.includes(d.incomparableProtocols[0].protocol), true);
}

/* Every domain the summary counts has a row, including one only the baseline
   has. `renderComparisonRows()` used to decorate existing rows only. */
{
  const seed = await bootedRun('a.example');
  const withOne = seed.ui.buildReportJson();
  const withTwo = JSON.parse(JSON.stringify(withOne));
  withTwo.domains.push(JSON.parse(JSON.stringify(withOne.domains[0])));
  withTwo.domains[1].domain = 'b.example';

  const { document, ui } = await bootedRun('a.example');
  ui.acceptImportedReport(JSON.stringify(withTwo));
  const verdicts = comparedRows(document);
  eq('a domain only the baseline had still gets a row',
    verdicts.includes('b.example=removed'), true);
  eq('and the table shows every domain the summary counted',
    verdicts.length, ui.getComparison().domains.length);
  eq('with a delta cell each', deltaCells(document), verdicts.length);

  ui.exitComparison();
  eq('leaving removes the rows it invented',
    document.getElementById('tableBody').querySelectorAll('.compare-only-row').length, 0);
  eq('and the evidence it added to the detail rows',
    document.getElementById('tableBody').querySelectorAll('.compare-detail').length, 0);
}

/* Clear takes the comparison and the run's provenance with it. */
{
  const { document, ui } = await bootedRun('a.example');
  ui.acceptImportedReport(JSON.stringify(ui.buildReportJson()));
  eq('a comparison is showing', ui.getComparison() !== null, true);

  click(document.getElementById('clearBtn'));
  eq('Clear discards the comparison', ui.getComparison(), null);
  // Without this, the remaining button exported an empty report carrying the
  // previous run's timestamp and options.
  eq('and the run context it was drawn from', ui.getRunContext(), null);
  eq('and stops offering the JSON export',
    document.getElementById('exportJsonBtn').style.display, 'none');
}

/* A language change rebuilds the mode, not just the rows. */
{
  const { document, ui, i18n } = await bootedRun('a.example');
  ui.acceptImportedReport(JSON.stringify(ui.buildReportJson()));
  const before = deltaCells(document);
  eq('a comparison is showing before the switch', before > 0, true);

  await i18n.setLang('de');
  await settle(10);
  eq('the delta cells survive a language change', deltaCells(document), before);
  eq('and so do the verdicts the filter selects on',
    comparedRows(document).length, before);
  eq('the comparison itself is untouched', ui.getComparison() !== null, true);
}

/* The other branch: a two-report comparison has no `results` behind it, and the
   locale handler returns early before it ever reaches the rebuild above. */
{
  const seed = await bootedRun('a.example');
  const report = seed.ui.buildReportJson();
  const other = JSON.parse(JSON.stringify(report));
  other.domains.push(JSON.parse(JSON.stringify(report.domains[0])));
  other.domains[1].domain = 'b.example';

  const { document, ui, i18n } = await boot();
  ui.acceptImportedReport(JSON.stringify(report));
  ui.acceptImportedReport(JSON.stringify(other));
  const before = deltaCells(document);
  eq('two imported reports are showing', before, ui.getComparison().domains.length);

  await i18n.setLang('de');
  await settle(10);
  eq('the language really changed', i18n.lang, 'de');
  eq('and the comparison survives it with all its rows', deltaCells(document), before);
  eq('and its verdicts', comparedRows(document).length, before);
  // Counts alone cannot catch this branch: it returns early WITHOUT rebuilding
  // the table, so the rows survive in the previous language and every count
  // stays right. What moves is the text.
  eq('and the comparison is re-rendered in the new language',
    document.getElementById('compareNotice').textContent.includes('Zwei Berichte im Vergleich'), true);
  eq('down to the verdicts in the table',
    document.getElementById('tableBody').textContent.includes('Unverändert'), true);
}

/* A pending single report is a localized message too. */
{
  const seed = await bootedRun('a.example');
  const { document, ui, i18n } = await boot();
  ui.acceptImportedReport(JSON.stringify(seed.ui.buildReportJson()));
  eq('the page is waiting for a second report', ui.getComparison(), null);
  await i18n.setLang('de');
  await settle(10);
  eq('and says so in the new language',
    document.getElementById('compareNotice').textContent.includes('Wählen Sie'), true);
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
  // The rows are the point. With no audit behind it there is nothing on the
  // page to decorate, and this path used to render a summary over an empty
  // table with the results section still hidden.
  eq('every compared domain has a row', comparedRows(document).length,
    ui.getComparison().domains.length);
  eq('and a delta cell', deltaCells(document), ui.getComparison().domains.length);
  eq('and the results section is revealed to hold them',
    [document.getElementById('resultsSection').style.display,
      document.getElementById('resultsToolbar').style.display], ['block', 'flex']);
}

/* Cross-version diffs make no causal claim, and an unknown id says so. */
{
  const { document, ui } = await bootedRun('a.example');
  const current = ui.buildReportJson();
  const baseline = JSON.parse(JSON.stringify(current));
  // A different build, carrying a finding this one has never heard of.
  baseline.generator.version = '0.8.0';
  baseline.domains[0].findings = [{
    id: 'future.finding', protocol: 'dmarc', severity: 'high', confidence: 'confirmed',
    category: 'policy', effort: 'moderate', args: [], dependsOn: [],
    evidence: [{ kind: 'txt', queryName: '_dmarc.a.example', value: 'v=DMARC1' }],
  }];
  ui.acceptImportedReport(JSON.stringify(baseline));
  eq('the two builds are recognized as different',
    ui.getComparison().meta.findingSemanticsMatch, false);

  const detail = document.getElementById('tableBody').querySelectorAll('.compare-detail')[0];
  const text = detail ? detail.textContent : '';
  // Acceptance criterion 6: across versions the diff is shown without a
  // verdict, so "resolved" — which asserts somebody fixed something — is
  // exactly what it must not say.
  eq('a cross-version diff is labelled by side, not by cause',
    [text.includes('In the baseline only'), text.includes('resolved')], [true, false]);
  eq('and an id this build does not know is explained rather than shown bare',
    text.includes('This build has no description for future.finding'), true);
}

/* Within one build the causal labels are the right ones. */
{
  const { document, ui } = await bootedRun('a.example');
  const current = ui.buildReportJson();
  const baseline = JSON.parse(JSON.stringify(current));
  baseline.domains[0].findings = [{
    id: 'dmarc.policy-none', protocol: 'dmarc', severity: 'high', confidence: 'confirmed',
    category: 'policy', effort: 'moderate', args: [], dependsOn: [],
    evidence: [{ kind: 'txt', queryName: '_dmarc.a.example', value: 'v=DMARC1; p=none' }],
  }];
  ui.acceptImportedReport(JSON.stringify(baseline));
  eq('the two builds agree', ui.getComparison().meta.findingSemanticsMatch, true);
  const text = document.getElementById('tableBody').querySelectorAll('.compare-detail')[0].textContent;
  const d = ui.getComparison().domains[0];
  eq('a same-build diff uses the causal label', d.findings.resolved.length
    ? text.includes('resolved') : text.includes('unknown'), true);
  eq('and a known id carries no unknown-id note',
    text.includes('This build has no description for dmarc.policy-none'), false);
}

/* An option mismatch is not a missing observation. */
{
  const { document, ui } = await bootedRun('a.example');
  const current = ui.buildReportJson();
  const baseline = JSON.parse(JSON.stringify(current));
  baseline.options.www = !baseline.options.www;
  ui.acceptImportedReport(JSON.stringify(baseline));

  const d = ui.getComparison().domains[0];
  const both = d.incomparableProtocols.filter(e => e.side === 'both');
  eq('an option difference marks protocols on BOTH sides', both.length > 0, true);
  const text = document.getElementById('tableBody').querySelectorAll('.compare-detail')[0].textContent;
  eq('and is described as an option difference',
    text.includes('with different options in the two reports'), true);
  // The mapping itself: every protocol marked on BOTH sides is described by the
  // option sentence. The renderer used to fold `both` onto `current` and say a
  // protocol was not observed in the current report when both reports had
  // observed it — a false statement about the data.
  eq('every both-sided protocol gets the option sentence, not a side sentence',
    both.filter(e => !text.includes(
      'Not comparable: ' + e.protocol + ' was checked with different options in the two reports')),
    []);
}

/* The delta header and the severity labels are presentation, and follow the
   language like everything else. */
{
  const { document, ui, i18n } = await bootedRun('a.example');
  const current = ui.buildReportJson();
  const baseline = JSON.parse(JSON.stringify(current));
  baseline.domains[0].findings = (current.domains[0].findings || []).map(f =>
    Object.assign({}, f, { severity: f.severity === 'high' ? 'low' : 'high' }));
  ui.acceptImportedReport(JSON.stringify(baseline));

  // The column's name reaches the reader through the cell's own `data-label`
  // as well as the header — that is how the responsive layout labels it — and
  // it is the half this environment can observe, because the shim models no
  // table sections and `headerRow()` now refuses to guess without one.
  const deltaLabel = () => {
    const cell = document.getElementById('tableBody').querySelectorAll('.compare-cell')[0];
    return cell ? cell.dataset.label : '';
  };
  eq('the delta column is named in the current language', deltaLabel(), 'Change');
  await i18n.setLang('de');
  await settle(10);
  eq('and follows a language change like every other heading', deltaLabel(), 'Änderung');
  eq('no header cell is invented where there is no header row to hold it',
    Array.prototype.filter.call(headRowOf(document).childNodes,
      n => n && n.id === 'compareHeadCell').length, 0);

  const detail = document.getElementById('tableBody').querySelectorAll('.compare-detail')[0];
  const d = ui.getComparison().domains[0];
  if (d.findings.severityChanged.length) {
    eq('a severity change is shown by its label, not its schema token',
      /Hoch|Niedrig|Mittel|Kritisch|Info/.test(detail.textContent), true);
  } else {
    eq('no severity change in this fixture, so nothing to label',
      d.findings.severityChanged.length, 0);
  }
}

/* Mid-run is not one of the two defined entry states. */
{
  const booted = await boot();
  const { document, ui } = booted;
  const seed = await bootedRun('a.example');
  const report = JSON.stringify(seed.ui.buildReportJson());

  document.getElementById('domainInput').value = 'a.example\nb.example';
  click(document.getElementById('auditBtn'));
  // Mid-flight: the run has started and has not finished.
  ui.acceptImportedReport(report);
  // Refused, not HELD. Without the guard the file becomes a pending baseline —
  // which the page announces — and is then either discarded by the new-run
  // teardown or silently never compared, depending on when it arrived.
  eq('a report offered during a run starts no comparison', ui.getComparison(), null);
  eq('and is not quietly held as a pending baseline either',
    document.getElementById('compareNotice').textContent.includes('Choose a saved report'), false);
  eq('and the import control is hidden while the run is in flight',
    document.getElementById('importReportLabel').style.display, 'none');

  await settle();
  eq('the run still finishes normally', ui.getRunContext() !== null, true);
  eq('and the control comes back with the other export buttons',
    document.getElementById('importReportLabel').style.display, '');
  ui.acceptImportedReport(report);
  eq('and a report offered afterwards is accepted', ui.getComparison() !== null, true);
}

/* An incomparable protocol carries two facts, and the page owes both. */
{
  const { document, ui } = await bootedRun('a.example');
  const current = ui.buildReportJson();
  const baseline = JSON.parse(JSON.stringify(current));
  // Two different reasons on the same side, so a renderer that reads only the
  // side cannot tell them apart and a renderer that reads only the reason
  // cannot place them.
  baseline.domains[0].observability.dkim = 'unproven';
  baseline.domains[0].observability.bimi = 'not-run';
  ui.acceptImportedReport(JSON.stringify(baseline));

  const d = ui.getComparison().domains[0];
  const reasonOf = (protocol, side) => (d.incomparableProtocols
    .filter(e => e.protocol === protocol && e.side === side)[0] || {}).reason;
  eq('the comparison distinguishes the two reasons',
    [reasonOf('dkim', 'baseline'), reasonOf('bimi', 'baseline')], ['unproven', 'not-run']);

  const text = document.getElementById('tableBody')
    .querySelectorAll('.compare-detail')[0].textContent;
  // Section 6: named "with its reason". "Checked and nothing established" and
  // "never checked" answer different questions — the first says the domain may
  // be misconfigured, the second says this run had the option off.
  eq('a protocol that was checked without result says so',
    text.includes('dkim was checked but not established'), true);
  eq('and one that was never checked says that instead',
    text.includes('bimi was not checked'), true);
  eq('while both still name the side that lacked them', [
    text.includes('Not comparable: dkim was not observed in the baseline report'),
    text.includes('Not comparable: bimi was not observed in the baseline report'),
  ], [true, true]);
  // Every reason in the data is accounted for, so a reason this build has no
  // sentence for cannot pass unnoticed.
  eq('and no reason in the comparison goes unrendered', d.incomparableProtocols
    .filter(e => e.reason === 'unproven' && !text.includes(e.protocol + ' was checked but not established'))
    .concat(d.incomparableProtocols
      .filter(e => e.reason === 'not-run' && !text.includes(e.protocol + ' was not checked'))), []);
}

/* An unrecognized id is explained wherever it appears — including the one
   bucket that is neither new nor resolved. */
{
  const seed = await bootedRun('a.example');
  const first = seed.ui.buildReportJson();
  // Both sides supplied, so both are under this test's control. Everything
  // observed, so nothing is blocked and the movement really is a severity
  // change rather than an `unknown`.
  first.domains[0].observability = Object.keys(first.domains[0].observability)
    .reduce((m, k) => Object.assign(m, { [k]: 'observed' }), {});
  const unknownFinding = (severity) => ({
    id: 'future.finding', protocol: 'dmarc', severity, confidence: 'confirmed',
    category: 'policy', effort: 'moderate', args: [], dependsOn: [],
    evidence: [{ kind: 'txt', queryName: '_dmarc.a.example', value: 'v=DMARC1' }],
  });
  first.domains[0].findings = [unknownFinding('low')];
  const second = JSON.parse(JSON.stringify(first));
  second.domains[0].findings = [unknownFinding('high')];

  const { document, ui } = await boot();
  ui.acceptImportedReport(JSON.stringify(first));
  ui.acceptImportedReport(JSON.stringify(second));

  const d = ui.getComparison().domains[0];
  eq('the id is in neither the new nor the resolved bucket',
    [d.findings.new, d.findings.resolved], [[], []]);
  eq('it moved in severity', d.findings.severityChanged.map(c => c.id), ['future.finding']);

  // With no run behind it there is no data row to carry a detail row: the
  // evidence lives in the invented row itself.
  const text = document.getElementById('tableBody')
    .querySelectorAll('.compare-only-row')[0].textContent;
  eq('the movement is shown', text.includes('future.finding'), true);
  // Section 4 is unconditional: an id this build cannot describe is shown WITH
  // the note, in every bucket it can reach. The note lived inside the line that
  // renders new/resolved/unknown, so this case — present on both sides — got a
  // bare token.
  eq('and the id this build cannot describe is explained here too',
    text.includes('This build has no description for future.finding'), true);
}

console.log(`\n${'='.repeat(60)}`);
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
