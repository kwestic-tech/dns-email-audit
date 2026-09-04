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
const release091 = JSON.parse(readFileSync(join(ROOT, 'tests/fixtures/equivalence/baseline-v0.9.1.json'), 'utf8'));
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


/* ── 0.9.1: MX address validity ───────────────────────────────────────── */

const release090ById = byId(release090);

/**
 * 0.9.1 moved every MX host that is background setup off RFC 5737
 * documentation space, because those addresses are not globally routable and
 * would raise `mx.unroutable` in cases whose subject is SPF, DKIM, DMARC or
 * DNSSEC. Each stub is the SAME LENGTH as the address it replaces, so the
 * substitution moves no rendered byte and `report.length` is identical to
 * 0.9.0's everywhere except the one authorized case.
 *
 * Both sides are normalized to a token rather than the old baseline being
 * rewritten forward, because two of these addresses also appear in the
 * `mx-dangling` remediation copy, which did NOT change.
 */
const MX_STUB_ADDRESSES = [
  ['192.0.2.20', '100.2.0.20'],
  ['198.51.100.5', '100.51.100.5'],
  ['198.51.100.10', '100.51.100.10'],
  ['203.0.113.5', '100.0.113.5'],
  ['203.0.113.9', '100.0.113.9'],
  ['203.0.113.11', '100.0.113.11'],
  ['203.0.113.13', '100.0.113.13'],
  ['2001:db8::20', '2a01:100::20'],
];

function normalizeStubAddresses(value) {
  let text = JSON.stringify(value);
  MX_STUB_ADDRESSES.forEach(([before, after], index) => {
    const token = '<<mx-stub-' + index + '>>';
    text = text.split(after).join(token).split(before).join(token);
  });
  return text;
}

/** The one case that keeps documentation addresses, and gains one finding. */
const NON_ROUTABLE_MX_CASE = 'mx-health-and-tlsa';
const AUTHORIZED_FINDING_ID = 'mx.unroutable';
const AUTHORIZED_FINDING_KEY = 'mx-unroutable';

/* ── The seven new fields, removed only where they are authorized ─────── */

/**
 * Four fields on `advanced.mxHealth` and three on each of its `hosts[]`.
 *
 * Scoped to those paths deliberately. A recursive strip by NAME would let one
 * of these seven names appear anywhere else in the result and ride through
 * unexamined, which is a different change wearing an authorized name.
 */
const MX_HEALTH_FIELDS = ['addressLiteralHosts', 'unroutableHosts',
  'partiallyRoutableHosts', 'nullMxConflict'];
const MX_HOST_FIELDS = ['isAddressLiteral', 'addressScopes', 'reachability'];

function stripMxValidity(resultEntries) {
  const copy = structuredClone(resultEntries);
  for (const entry of copy) {
    const mxHealth = entry && entry.result && entry.result.advanced
      && entry.result.advanced.mxHealth;
    if (!mxHealth) continue;
    for (const field of MX_HEALTH_FIELDS) delete mxHealth[field];
    for (const host of mxHealth.hosts || []) {
      for (const field of MX_HOST_FIELDS) delete host[field];
    }
  }
  return copy;
}

/**
 * The authorized finding, removed from the three paths that carry it and from
 * no others: `issues[]` (keyed), `findings[]` (id'd), and
 * `remediationPlan[].findings[]`, which holds bare id STRINGS.
 */
function stripAuthorizedFinding(resultEntries) {
  const copy = structuredClone(resultEntries);
  for (const entry of copy) {
    const r = entry && entry.result;
    if (!r) continue;
    if (Array.isArray(r.issues)) {
      r.issues = r.issues.filter(i => i.key !== AUTHORIZED_FINDING_KEY);
    }
    if (Array.isArray(r.findings)) {
      r.findings = r.findings.filter(f => f.id !== AUTHORIZED_FINDING_ID);
    }
    for (const step of r.remediationPlan || []) {
      if (Array.isArray(step.findings)) {
        step.findings = step.findings.filter(id => id !== AUTHORIZED_FINDING_ID);
      }
    }
  }
  return copy;
}

/* ── The authorized finding, removed from the rendered surfaces ───────── */

const indentOf = line => (line.match(/^\s*/) || [''])[0].length;

function subtreeEnd(lines, start) {
  const base = indentOf(lines[start]);
  let end = start + 1;
  while (end < lines.length && (lines[end].trim() === '' || indentOf(lines[end]) > base)) end++;
  return end;
}

/**
 * Reconstruct the 0.9.0 DOM from the 0.9.1 DOM of the authorized case.
 *
 * Three named removals, and nothing else: the critical badge the new finding
 * introduces, the `finding-group` subtree it opens, and its `plan-finding`
 * entry in the remediation plan — plus the row's `data-overall`, which reverts
 * from `crit` to the `warn` it was. Anything else added to this case survives
 * the transformation and fails the comparison, which is the point: the
 * authorization is for one finding, not for the whole case.
 */
function removeAuthorizedFindingFromDom(lines) {
  const out = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/<span title="1 critical">/.test(line)) { i++; continue; }
    if (/<div class="finding-group">/.test(line) && /finding-sev-critical/.test(lines[i + 1] || '')) {
      i = subtreeEnd(lines, i) - 1;
      continue;
    }
    if (new RegExp('data-finding-id="' + AUTHORIZED_FINDING_ID + '"').test(line)) {
      i = subtreeEnd(lines, i) - 1;
      continue;
    }
    out.push(line.replace('data-overall="crit"', 'data-overall="warn"'));
  }
  return out;
}

/** The rendered English message, matched by prefix so its arguments may vary. */
const AUTHORIZED_MESSAGE_PREFIX = 'MX host resolves only into unreachable address space:';

const AUTHORIZED_CSV_SEGMENTS = new Set([AUTHORIZED_FINDING_ID]);

/**
 * Remove the authorized finding from the four CSV cells that carry it.
 *
 * `Finding Severities` is positional against `Finding IDs`, so its entry is
 * dropped at the index the id occupied rather than by matching the word
 * `critical` — which would also delete an unrelated critical severity.
 */
function removeAuthorizedFindingFromCsv(lines) {
  const rows = csvRows(lines);
  const header = rows[0] || [];
  const idColumn = header.indexOf('Finding IDs');
  const severityColumn = header.indexOf('Finding Severities');
  return rows.map((cells, rowIndex) => {
    if (rowIndex === 0) return cells;
    const dropAt = idColumn >= 0
      ? cells[idColumn].split(' | ').indexOf(AUTHORIZED_FINDING_ID)
      : -1;
    return cells.map((cell, column) => {
      if (column === severityColumn && dropAt >= 0) {
        return cell.split(' | ').filter((_, i) => i !== dropAt).join(' | ');
      }
      const parts = cell.split(' | ');
      const kept = parts.filter(part =>
        !AUTHORIZED_CSV_SEGMENTS.has(part) && !part.startsWith(AUTHORIZED_MESSAGE_PREFIX));
      return kept.join(' | ');
    });
  });
}

const scoresOf = c => c.result.map(entry => entry.result)
  .map(r => (r && r.score) ? [r.score.pts, r.score.grade] : null);

function release091Violations(after) {
  const violations = [];
  if (JSON.stringify([...byId(after).keys()].sort()) !== JSON.stringify([...release090ById.keys()].sort())) {
    return ['case-set'];
  }
  for (const c of after.cases) {
    const before = release090ById.get(c.id);
    const id = c.id;
    const authorized = id === NON_ROUTABLE_MX_CASE;

    // Zero query-trace movement, in every case without exception. 0.9.1 issues
    // no new lookup, and this is the published privacy figure.
    if (JSON.stringify(c.trace) !== JSON.stringify(before.trace)) violations.push(id + ':trace');

    // No score and no grade moves anywhere: these findings are advisory.
    if (JSON.stringify(scoresOf(c)) !== JSON.stringify(scoresOf(before))) violations.push(id + ':score');

    // Results differ only by the seven new fields on their authorized paths,
    // the stub addresses, and — in one case — the single new finding.
    const newResult = stripMxValidity(authorized ? stripAuthorizedFinding(c.result) : c.result);
    if (normalizeStubAddresses(newResult) !== normalizeStubAddresses(before.result)) {
      violations.push(id + ':result');
    }

    // CSV and DOM are compared in EVERY case, the authorized one included:
    // there the authorized finding is removed first, so anything else added to
    // that case still fails.
    const newCsv = authorized ? removeAuthorizedFindingFromCsv(c.csv.lines) : c.csv;
    const oldCsv = authorized ? csvRows(before.csv.lines) : before.csv;
    if (normalizeStubAddresses(newCsv) !== normalizeStubAddresses(oldCsv)) violations.push(id + ':csv');

    const newDom = authorized ? removeAuthorizedFindingFromDom(c.dom) : c.dom;
    if (normalizeStubAddresses(newDom) !== normalizeStubAddresses(before.dom)) violations.push(id + ':dom');

    // The report surface, bounded rather than unread. The stubs are
    // length-preserving, so only the authorized case may move structure or
    // length; the fixed bytes may never move; and the hash must move exactly
    // when the rendered content did.
    const oldReport = before.report;
    const newReport = c.report;
    const contentMoved = JSON.stringify(c.dom) !== JSON.stringify(before.dom)
      || JSON.stringify(c.csv) !== JSON.stringify(before.csv);
    const reportIsBounded =
      newReport.generated === oldReport.generated &&
      newReport.bytes.csp === oldReport.bytes.csp &&
      newReport.bytes.stylesheet === oldReport.bytes.stylesheet &&
      newReport.bytes.stylesheetBytes === oldReport.bytes.stylesheetBytes &&
      (authorized
        ? newReport.structure !== oldReport.structure && newReport.length > oldReport.length
        : newReport.structure === oldReport.structure && newReport.length === oldReport.length) &&
      ((newReport.sha256 !== oldReport.sha256) === contentMoved);
    if (!reportIsBounded) violations.push(id + ':report');
  }
  return violations;
}

section('The 0.9.1 difference class is exact');

eq('the 0.9.1 baseline differs only by its authorized surface changes',
  release091Violations(release091), []);

// The rule above passes by comparing nothing to nothing unless the new fields
// are really present, and unless the one authorized finding is really raised.
const mxHealths091 = release091.cases
  .flatMap(c => c.result.map(entry => entry.result))
  .map(r => r && r.advanced && r.advanced.mxHealth)
  .filter(Boolean);
eq('every mxHealth carries the four new top-level fields',
  [mxHealths091.length > 0,
    mxHealths091.filter(m => !MX_HEALTH_FIELDS.every(f => f in m)).length],
  [true, 0]);

const unroutableCases = release091.cases
  .filter(c => (c.result || []).some(e => e.result && e.result.advanced && e.result.advanced.mxHealth
    && e.result.advanced.mxHealth.unroutableHosts.length))
  .map(c => c.id);
eq('and exactly one case raises mx.unroutable — the deliberately non-routable one',
  unroutableCases, [NON_ROUTABLE_MX_CASE]);

// The stubs are length-preserving, which is what makes the report bound exact.
eq('no report length moved except in the authorized case',
  release091.cases.filter(c => c.report.length !== release090ById.get(c.id).report.length)
    .map(c => c.id),
  [NON_ROUTABLE_MX_CASE]);

section('Every 0.9.1 compatibility rule has a negative control');

const missingCase091 = structuredClone(release091);
missingCase091.cases.pop();
eq('a case-set movement is caught', release091Violations(missingCase091), ['case-set']);

const changedTrace091 = structuredClone(release091);
changedTrace091.cases[0].trace.total++;
eq('a query-trace movement is caught',
  release091Violations(changedTrace091), [release091.cases[0].id + ':trace']);

const changedScore091 = structuredClone(release091);
changedScore091.cases[0].result[0].result.score.pts += 1;
eq('a score movement is caught',
  release091Violations(changedScore091).filter(v => v.endsWith(':score')),
  [release091.cases[0].id + ':score']);

const changedResult091 = structuredClone(release091);
changedResult091.cases[0].result[0].result.domain = 'mutated.test';
eq('a result movement outside the new fields is caught',
  release091Violations(changedResult091).filter(v => v.endsWith(':result')),
  [release091.cases[0].id + ':result']);

// An eighth new field inside mxHealth would ride in if the strip list were open.
const extraField091 = structuredClone(release091);
extraField091.cases[0].result[0].result.advanced.mxHealth.somethingElse = true;
eq('a further new mxHealth field is not covered by the authorized seven',
  release091Violations(extraField091).filter(v => v.endsWith(':result')),
  [release091.cases[0].id + ':result']);

// And one of the seven authorized NAMES, outside its authorized path, is a
// different change wearing an authorized name.
const misplacedField091 = structuredClone(release091);
misplacedField091.cases[0].result[0].result.reachability = 'global';
eq('an authorized field name outside advanced.mxHealth is caught',
  release091Violations(misplacedField091).filter(v => v.endsWith(':result')),
  [release091.cases[0].id + ':result']);

// The authorized finding is authorized in ONE case only.
const strayFinding091 = structuredClone(release091);
strayFinding091.cases[0].result[0].result.issues.push({ key: AUTHORIZED_FINDING_KEY, sev: 'crit', args: ['x', 'y'] });
eq('the authorized finding appearing in another case is caught',
  release091Violations(strayFinding091).filter(v => v.endsWith(':result')),
  [release091.cases[0].id + ':result']);

const changedCsv091 = structuredClone(release091);
changedCsv091.cases[0].csv.lines[0] = '"inserted",' + changedCsv091.cases[0].csv.lines[0];
eq('an unauthorized CSV cell is caught',
  release091Violations(changedCsv091).filter(v => v.endsWith(':csv')),
  [release091.cases[0].id + ':csv']);

const changedDom091 = structuredClone(release091);
changedDom091.cases[0].dom.push('unauthorized node');
eq('an unauthorized DOM change is caught',
  release091Violations(changedDom091).filter(v => v.endsWith(':dom')),
  [release091.cases[0].id + ':dom']);

/* The authorized case needs its OWN controls: the rules above all mutate
   cases[0], which is not the authorized case, so they never exercise the
   branch that removes the finding. */

const authorizedIndex = release091.cases.findIndex(c => c.id === NON_ROUTABLE_MX_CASE);

const changedAuthorizedCsv = structuredClone(release091);
changedAuthorizedCsv.cases[authorizedIndex].csv.lines[1] += ',"unauthorized"';
eq('an unrelated CSV cell in the AUTHORIZED case is caught',
  release091Violations(changedAuthorizedCsv).filter(v => v.endsWith(':csv')),
  [NON_ROUTABLE_MX_CASE + ':csv']);

const changedAuthorizedDom = structuredClone(release091);
changedAuthorizedDom.cases[authorizedIndex].dom.push('      <div class="unauthorized">');
eq('an unrelated DOM node in the AUTHORIZED case is caught',
  release091Violations(changedAuthorizedDom).filter(v => v.endsWith(':dom')),
  [NON_ROUTABLE_MX_CASE + ':dom']);

// A second finding in the authorized case is not covered by the one authorized.
const secondFindingDom = structuredClone(release091);
secondFindingDom.cases[authorizedIndex].dom.push('              <div class="finding" data-finding-id="mx.address-literal">');
eq('a SECOND finding rendered into the authorized case is caught',
  release091Violations(secondFindingDom).filter(v => v.endsWith(':dom')),
  [NON_ROUTABLE_MX_CASE + ':dom']);

const changedReportCss091 = structuredClone(release091);
changedReportCss091.cases[0].report.bytes.stylesheet += '.unauthorized{}';
eq('an unauthorized report stylesheet change is caught',
  release091Violations(changedReportCss091).filter(v => v.endsWith(':report')),
  [release091.cases[0].id + ':report']);

const changedReportStructure091 = structuredClone(release091);
changedReportStructure091.cases[0].report.structure += ' script';
eq('an unauthorized report structure change is caught',
  release091Violations(changedReportStructure091).filter(v => v.endsWith(':report')),
  [release091.cases[0].id + ':report']);

const changedReportLength091 = structuredClone(release091);
changedReportLength091.cases[0].report.length += 1;
eq('an unauthorized report length change is caught',
  release091Violations(changedReportLength091).filter(v => v.endsWith(':report')),
  [release091.cases[0].id + ':report']);

// A hash that did not move while the content did would mean the oracle is
// recording a stale report.
const frozenHash091 = structuredClone(release091);
frozenHash091.cases[0].report.sha256 = release090ById.get(release091.cases[0].id).report.sha256;
eq('a report hash that failed to move with the content is caught',
  release091Violations(frozenHash091).filter(v => v.endsWith(':report')),
  [release091.cases[0].id + ':report']);


report();
