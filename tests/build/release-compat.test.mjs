#!/usr/bin/env node
/**
 * Bound each intentional release difference from the preceding oracle.
 * Finished-release baselines pin all five surfaces exactly; this suite proves
 * a new baseline did not hide unrelated movement inside an intentional change.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { createSuite } from '../lib/assert.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const historical = JSON.parse(readFileSync(join(ROOT, 'tests/fixtures/equivalence/baseline-v0.5.0.json'), 'utf8'));
const release070 = JSON.parse(readFileSync(join(ROOT, 'tests/fixtures/equivalence/baseline-v0.7.0.json'), 'utf8'));
const release080 = JSON.parse(readFileSync(join(ROOT, 'tests/fixtures/equivalence/baseline-v0.8.0.json'), 'utf8'));
const release090 = JSON.parse(readFileSync(join(ROOT, 'tests/fixtures/equivalence/baseline-v0.9.0.json'), 'utf8'));
const { eq, section, report } = createSuite();

const byId = document => new Map(document.cases.map(c => [c.id, c]));
const historicalById = byId(historical);
const release070ById = byId(release070);

function stripAdditiveFields(value) {
  if (Array.isArray(value)) return value.map(stripAdditiveFields);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value)
    .filter(([key]) => key !== 'findings' && key !== 'remediationPlan')
    .map(([key, child]) => [key, stripAdditiveFields(child)]));
}

function traceViolations(document) {
  return document.cases.flatMap(c =>
    JSON.stringify(historicalById.get(c.id)?.trace) === JSON.stringify(c.trace) ? [] : [c.id]);
}

function legacyResultViolations(document) {
  return document.cases.flatMap(c =>
    JSON.stringify(historicalById.get(c.id)?.result) === JSON.stringify(stripAdditiveFields(c.result)) ? [] : [c.id]);
}

function csvRows(lines) {
  const rows = [];
  let cells = [];
  let cell = '';
  let quoted = false;
  const text = lines.join('\n');
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch === '"') {
      if (quoted && text[i + 1] === '"') { cell += '"'; i++; }
      else quoted = !quoted;
    } else if (ch === ',' && !quoted) {
      cells.push(cell); cell = '';
    } else if (ch === '\n' && !quoted) {
      cells.push(cell); rows.push(cells); cells = []; cell = '';
    } else cell += ch;
  }
  cells.push(cell);
  rows.push(cells);
  return rows;
}

function csvViolations(document) {
  return document.cases.flatMap(c => {
    const before = csvRows(historicalById.get(c.id)?.csv.lines || []);
    const after = csvRows(c.csv.lines || []);
    if (before.length !== after.length) return [c.id + ':line-count'];
    return before.flatMap((oldCells, i) => {
      const newCells = after[i];
      const prefixMatches = JSON.stringify(newCells.slice(0, oldCells.length)) === JSON.stringify(oldCells);
      return prefixMatches && newCells.length === oldCells.length + 3 ? [] : [c.id + ':row-' + i];
    });
  });
}

section('The 0.7.0 difference class is exact');

eq('the historical and release baselines cover the same cases',
  [...historicalById.keys()].sort(), [...byId(release070).keys()].sort());
eq('the DNS trace is byte-identical in every case', traceViolations(release070), []);
eq('legacy results are byte-identical after removing the two additive fields',
  legacyResultViolations(release070), []);
eq('CSV changes only by three appended cells on every row', csvViolations(release070), []);

section('Each release-compatibility rule has a negative control');

const changedTrace = structuredClone(release070);
changedTrace.cases[0].trace.total++;
eq('a trace movement is caught', traceViolations(changedTrace), [release070.cases[0].id]);

const changedResult = structuredClone(release070);
changedResult.cases[0].result[0].result.domain = 'mutated.test';
eq('a legacy result movement is caught', legacyResultViolations(changedResult), [release070.cases[0].id]);

const insertedCsv = structuredClone(release070);
insertedCsv.cases[0].csv.lines[0] = '"inserted",' + insertedCsv.cases[0].csv.lines[0];
eq('an inserted CSV cell is caught', csvViolations(insertedCsv), [release070.cases[0].id + ':row-0']);

const OLD_MTA_STS_COPY = 'The MTA-STS TXT record is valid, but this browser-only audit cannot verify the HTTPS policy file because most policy hosts do not permit cross-origin reads.';
const NEW_MTA_STS_COPY = 'The MTA-STS TXT record is valid, but the DNS-only audit did not fetch its HTTPS policy. Supply the policy in the local artifact panel to validate it without a network request.';
const ARTIFACT_CSS = /\/\* ── Local artifact validation ── \*\/\n[\s\S]*?(?=\/\* ── Options ── \*\/)/;

function release080Violations(document) {
  const candidateById = byId(document);
  const expectedIds = [...release070ById.keys()].sort();
  const actualIds = [...candidateById.keys()].sort();
  const violations = JSON.stringify(expectedIds) === JSON.stringify(actualIds) ? [] : ['case-set'];

  for (const id of expectedIds) {
    const before = release070ById.get(id);
    const after = candidateById.get(id);
    if (!after) continue;

    if (JSON.stringify(before.result) !== JSON.stringify(after.result)) violations.push(id + ':result');
    if (JSON.stringify(before.trace) !== JSON.stringify(after.trace)) violations.push(id + ':trace');

    const artifactHeaders = ['Artifact Finding IDs', 'Artifact Severities', 'Artifact Evidence (User Supplied)'];
    const expectedCsv = csvRows(before.csv.lines).map((row, index) =>
      row.map(cell => cell.replace(OLD_MTA_STS_COPY, NEW_MTA_STS_COPY))
        .concat(index === 0 ? artifactHeaders : ['', '', '']));
    if (JSON.stringify(expectedCsv) !== JSON.stringify(csvRows(after.csv.lines))) violations.push(id + ':csv');

    const expectedDom = before.dom.map(line => line.replace(OLD_MTA_STS_COPY, NEW_MTA_STS_COPY));
    if (JSON.stringify(expectedDom) !== JSON.stringify(after.dom)) violations.push(id + ':dom');

    const oldReport = before.report;
    const newReport = after.report;
    const oldStyle = oldReport.bytes.stylesheet;
    const newStyle = newReport.bytes.stylesheet;
    const styleDelta = Buffer.byteLength(newStyle, 'utf8') - Buffer.byteLength(oldStyle, 'utf8');
    // The standalone report contains the MTA-STS finding in both its legacy
    // issue list and structured-finding card, hence two exact replacements.
    const copyDelta = id === 'enforcing-signed'
      ? 2 * (Buffer.byteLength(NEW_MTA_STS_COPY, 'utf8') - Buffer.byteLength(OLD_MTA_STS_COPY, 'utf8')) : 0;
    const reportIsBounded =
      newReport.generated === oldReport.generated &&
      newReport.bytes.csp === oldReport.bytes.csp &&
      newReport.structure === oldReport.structure &&
      newStyle.replace(ARTIFACT_CSS, '') === oldStyle &&
      newReport.bytes.stylesheetBytes === oldReport.bytes.stylesheetBytes + styleDelta &&
      newReport.length === oldReport.length + styleDelta + copyDelta;
    // The report hash must move when its authorized bytes move. Its exact new
    // value is pinned by baseline-v0.8.0; this cross-release test bounds why it
    // differs rather than attempting to transform a hash.
    if (!reportIsBounded || newReport.sha256 === oldReport.sha256) violations.push(id + ':report');
  }
  return violations;
}

section('The 0.8.0 difference class is exact');

eq('the 0.8.0 baseline differs only by its authorized surface changes',
  release080Violations(release080), []);

section('Every 0.8.0 compatibility rule has a negative control');

const missingCase080 = structuredClone(release080);
missingCase080.cases.pop();
eq('a case-set movement is caught', release080Violations(missingCase080), ['case-set']);

const changedResult080 = structuredClone(release080);
changedResult080.cases[0].result[0].result.domain = 'mutated.test';
eq('a 0.8.0 result movement is caught', release080Violations(changedResult080), [release080.cases[0].id + ':result']);

const changedTrace080 = structuredClone(release080);
changedTrace080.cases[0].trace.total++;
eq('a 0.8.0 trace movement is caught', release080Violations(changedTrace080), [release080.cases[0].id + ':trace']);

const changedCsv080 = structuredClone(release080);
changedCsv080.cases[0].csv.lines[0] = '"inserted",' + changedCsv080.cases[0].csv.lines[0];
eq('an unauthorized 0.8.0 CSV cell is caught', release080Violations(changedCsv080), [release080.cases[0].id + ':csv']);

const changedDom080 = structuredClone(release080);
changedDom080.cases[0].dom.push('unauthorized node');
eq('an unauthorized 0.8.0 DOM change is caught', release080Violations(changedDom080), [release080.cases[0].id + ':dom']);

const changedReportCss080 = structuredClone(release080);
changedReportCss080.cases[0].report.bytes.stylesheet += '.unauthorized{}';
eq('an unauthorized 0.8.0 report stylesheet change is caught',
  release080Violations(changedReportCss080), [release080.cases[0].id + ':report']);

const changedReportStructure080 = structuredClone(release080);
changedReportStructure080.cases[0].report.structure += ' script';
eq('an unauthorized 0.8.0 report structure change is caught',
  release080Violations(changedReportStructure080), [release080.cases[0].id + ':report']);

/**
 * 0.9.0 authorized exactly two surface changes, and this bounds them.
 *
 * `result` gains the per-protocol `observability` map -- a new FIELD, so the
 * whole of the 0.8.0 result must survive underneath it untouched. The report's
 * stylesheet gains the comparison rules below and nothing else, which moves its
 * byte count, the document length and therefore its hash; the hash is not
 * transformed here, only required to move, for the reason the 0.8.0 rule gives.
 *
 * Everything else is pinned equal. The comparison feature is entirely a second
 * mode over an already-rendered table: no query is issued for it, no CSV column
 * is added, no ordinary audit's DOM changes, and the exported report's
 * STRUCTURE is the same document it was.
 */
const COMPARISON_CSS = [
  ".callout-warn { background: var(--warn-bg); border-color: var(--warn); }",
  ".callout-warn strong { color: var(--warn); }",
  "",
  "/* Comparison mode. The delta cell is added to the table only while two reports",
  "   are held in memory, so nothing here applies to an ordinary audit. */",
  ".compare-cell { text-align: center; white-space: nowrap; }",
  "/* Same treatment as the unproven-pillar grade marker: a dashed edge means the",
  "   tool did not establish this, which is not the same as a zero. */",
  ".compare-unknown { display: inline-block; border: 1px dashed var(--border); border-radius: 6px;",
  "  padding: 1px 6px; font-size: 11px; color: var(--ink3); }",
].join('\n') + '\n';
const COMPARISON_CSS_BYTES = Buffer.byteLength(COMPARISON_CSS, 'utf8');

/** The 0.8.0 result, from a 0.9.0 one: the added field removed, nothing else. */
function stripObservability(results) {
  return results.map(entry => Object.fromEntries(Object.entries(entry).map(([key, value]) =>
    [key, key === 'result' && value && typeof value === 'object'
      ? Object.fromEntries(Object.entries(value).filter(([field]) => field !== 'observability'))
      : value])));
}

const release080ById = byId(release080);

function release090Violations(after) {
  const violations = [];
  if (JSON.stringify([...byId(after).keys()].sort()) !== JSON.stringify([...release080ById.keys()].sort())) {
    return ['case-set'];
  }
  for (const c of after.cases) {
    const before = release080ById.get(c.id);
    const id = c.id;

    if (JSON.stringify(stripObservability(c.result)) !== JSON.stringify(before.result)) violations.push(id + ':result');
    if (JSON.stringify(c.trace) !== JSON.stringify(before.trace)) violations.push(id + ':trace');
    if (JSON.stringify(c.csv) !== JSON.stringify(before.csv)) violations.push(id + ':csv');
    if (JSON.stringify(c.dom) !== JSON.stringify(before.dom)) violations.push(id + ':dom');

    const oldReport = before.report;
    const newReport = c.report;
    const reportIsBounded =
      newReport.generated === oldReport.generated &&
      newReport.bytes.csp === oldReport.bytes.csp &&
      newReport.structure === oldReport.structure &&
      newReport.bytes.stylesheet.replace(COMPARISON_CSS, '') === oldReport.bytes.stylesheet &&
      newReport.bytes.stylesheetBytes === oldReport.bytes.stylesheetBytes + COMPARISON_CSS_BYTES &&
      newReport.length === oldReport.length + COMPARISON_CSS_BYTES;
    if (!reportIsBounded || newReport.sha256 === oldReport.sha256) violations.push(id + ':report');
  }
  return violations;
}

section('The 0.9.0 difference class is exact');

eq('the 0.9.0 baseline differs only by its authorized surface changes',
  release090Violations(release090), []);
// The added field is really there -- otherwise the rule above passes by
// comparing nothing to nothing. An audited domain is one that produced a score;
// the corpus's unregistered domain carries no observation to describe, which is
// the one result in eighty with no map and the reason 31 cases moved, not 32.
const auditedResults090 = release090.cases
  .flatMap(c => c.result.map(entry => entry.result))
  .filter(r => r && r.score);
eq('every audited domain carries the new observability map',
  [auditedResults090.length, auditedResults090.filter(r => !r.observability).length], [79, 0]);
eq('and the one result without a score is the unregistered domain', release090.cases
  .flatMap(c => c.result.map(entry => entry.result))
  .filter(r => r && !r.score).map(r => r.unregistered === true), [true]);

section('Every 0.9.0 compatibility rule has a negative control');

const missingCase090 = structuredClone(release090);
missingCase090.cases.pop();
eq('a case-set movement is caught', release090Violations(missingCase090), ['case-set']);

const changedResult090 = structuredClone(release090);
changedResult090.cases[0].result[0].result.domain = 'mutated.test';
eq('a 0.9.0 result movement is caught', release090Violations(changedResult090), [release090.cases[0].id + ':result']);

// The one this release most needs: `observability` is the ONLY field the strip
// removes, so a second new field alongside it is unauthorized and must show.
const extraField090 = structuredClone(release090);
extraField090.cases[0].result[0].result.somethingElse = true;
eq('a second new result field is not covered by the authorized one',
  release090Violations(extraField090), [release090.cases[0].id + ':result']);

const changedTrace090 = structuredClone(release090);
changedTrace090.cases[0].trace.total++;
eq('a 0.9.0 trace movement is caught', release090Violations(changedTrace090), [release090.cases[0].id + ':trace']);

const changedCsv090 = structuredClone(release090);
changedCsv090.cases[0].csv.lines[0] = '"inserted",' + changedCsv090.cases[0].csv.lines[0];
eq('an unauthorized 0.9.0 CSV cell is caught', release090Violations(changedCsv090), [release090.cases[0].id + ':csv']);

const changedDom090 = structuredClone(release090);
changedDom090.cases[0].dom.push('unauthorized node');
eq('an unauthorized 0.9.0 DOM change is caught', release090Violations(changedDom090), [release090.cases[0].id + ':dom']);

const changedReportCss090 = structuredClone(release090);
changedReportCss090.cases[0].report.bytes.stylesheet += '.unauthorized{}';
eq('an unauthorized 0.9.0 report stylesheet change is caught',
  release090Violations(changedReportCss090), [release090.cases[0].id + ':report']);

const changedReportStructure090 = structuredClone(release090);
changedReportStructure090.cases[0].report.structure += ' script';
eq('an unauthorized 0.9.0 report structure change is caught',
  release090Violations(changedReportStructure090), [release090.cases[0].id + ':report']);

// A stylesheet that grew by the authorized bytes without the authorized RULES
// is not bounded -- the byte count alone would accept any 632-byte addition.
const forgedCss090 = structuredClone(release090);
forgedCss090.cases[0].report.bytes.stylesheet =
  release080ById.get(release090.cases[0].id).report.bytes.stylesheet + 'x'.repeat(COMPARISON_CSS_BYTES);
eq('a different addition of the same size is caught',
  release090Violations(forgedCss090), [release090.cases[0].id + ':report']);


report();
