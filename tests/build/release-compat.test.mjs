#!/usr/bin/env node
/**
 * Bound each intentional release difference from the preceding oracle.
 * Finished-release baselines pin all five surfaces exactly; this suite proves
 * a new baseline did not hide unrelated movement inside an intentional change.
 */

import { readFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
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
 * How many times the authorized finding may appear, and in what shape.
 *
 * The authorization is for ONE finding with ONE rendering, not for any number
 * of entries bearing its key nor for arbitrary content wearing its id. Every
 * remover below validates count AND shape, and refuses — by returning null,
 * which its caller turns into a violation — on either.
 */
const AUTHORIZED_ISSUE = Object.freeze({
  key: 'mx-unroutable',
  sev: 'crit',
  args: ['dual.mx.test, v4only.mx.test',
    '198.51.100.20 (documentation), 2001:db8::20 (documentation), 198.51.100.21 (documentation)'],
});
/**
 * The complete authorized finding — all fourteen fields, not the seven identity
 * ones. Validating a subset let `args`, `evidence`, `blocks`, `dependsOn`,
 * `keyspace`, `noteArgs` and `noteKey` change arbitrarily while the finding was
 * still removed as though it were the one that was authorized.
 *
 * `noteArgs` and `noteKey` are the oracle's encoding of `undefined`.
 */
const AUTHORIZED_FINDING_SHAPE = Object.freeze({
  args: ['dual.mx.test, v4only.mx.test',
    '198.51.100.20 (documentation), 2001:db8::20 (documentation), 198.51.100.21 (documentation)'],
  blocks: [],
  category: 'transport',
  confidence: 'confirmed',
  dependsOn: [],
  effort: 'moderate',
  evidence: [
    { kind: 'host', queryName: 'hosts.mx.test', value: '10 dual.mx.test' },
    { kind: 'host', queryName: 'hosts.mx.test', value: '20 v4only.mx.test' },
    { kind: 'host', queryName: 'hosts.mx.test', value: '30 unknown.mx.test' },
  ],
  id: 'mx.unroutable',
  key: 'mx-unroutable',
  keyspace: 'issue',
  noteArgs: { $undefined: true },
  noteKey: { $undefined: true },
  protocol: 'mx',
  severity: 'critical',
});

/**
 * The material the new finding adds around itself: the severity badge it
 * introduces, and the `finding-group` shell it opens because the case had no
 * critical group before. Both are removed by the reconstruction, so both are
 * pinned by exact content for the same reason the finding subtrees are — a
 * remover that recognizes a wrapper only by its opening classes will discard
 * any text those classes happen to enclose.
 */
const AUTHORIZED_DOM_BADGE = Object.freeze({
  lines: 2, sha256: 'f5d8102bee4ca099ac0a0d7064c6a882699f83553b4c054e441951adc18b030c',
});
const AUTHORIZED_DOM_GROUP_SHELL = Object.freeze({
  lines: 3, sha256: '73ea388c4c84f37ffa0d1e22ae468bbb6005c50cecb11e038d39ccaaae6acb9b',
});

/** The two rendered occurrences, by role, size and exact content. */
const AUTHORIZED_DOM_SUBTREES = [
  { role: 'finding', lines: 52, sha256: '9422943a0b297ec39f6ad2489aa61f1c845830f63b34a106e594cb1343715b8e' },
  { role: 'plan-finding', lines: 6, sha256: '3eb9f3c770388f55ed48019fd62f654600ca6b177a9001eae306be6c993fe783' },
];

const sha256 = text => createHash('sha256').update(text).digest('hex');

/** Key-order-independent deep comparison: the oracle emits object keys sorted. */
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.keys(value).sort().map(k => [k, canonical(value[k])]));
}
const deepEqual = (a, b) => JSON.stringify(canonical(a)) === JSON.stringify(canonical(b));

/** Remove the first match only, and report how many there were. */
function removeOne(list, predicate) {
  let seen = 0;
  const kept = [];
  for (const item of list) {
    if (predicate(item)) { seen++; if (seen === 1) continue; }
    kept.push(item);
  }
  return { kept, seen };
}

/**
 * The authorized finding, removed from the three paths that carry it and from
 * no others: `issues[]` (keyed), `findings[]` (id'd), and
 * `remediationPlan[].findings[]`, which holds bare id STRINGS.
 *
 * Each entry's SHAPE is checked before it is removed. Counting alone would let
 * the sole authorized issue carry arbitrary arguments or a different severity
 * and still be discarded as though it were the rendering that was authorized.
 */
function stripAuthorizedFinding(resultEntries) {
  const copy = structuredClone(resultEntries);
  let issues = 0;
  let findings = 0;
  let planFindings = 0;
  let shapeHeld = true;
  for (const entry of copy) {
    const r = entry && entry.result;
    if (!r) continue;
    if (Array.isArray(r.issues)) {
      // Whole-object equality, key-order-independent: the oracle emits keys
      // sorted, and an order difference is not a shape difference.
      for (const issue of r.issues.filter(i => i.key === AUTHORIZED_FINDING_KEY)) {
        if (!deepEqual(issue, AUTHORIZED_ISSUE)) shapeHeld = false;
      }
      const out = removeOne(r.issues, i => i.key === AUTHORIZED_FINDING_KEY);
      r.issues = out.kept; issues += out.seen;
    }
    if (Array.isArray(r.findings)) {
      // All fourteen fields, and no others.
      for (const finding of r.findings.filter(f => f.id === AUTHORIZED_FINDING_ID)) {
        if (!deepEqual(finding, AUTHORIZED_FINDING_SHAPE)) shapeHeld = false;
      }
      const out = removeOne(r.findings, f => f.id === AUTHORIZED_FINDING_ID);
      r.findings = out.kept; findings += out.seen;
    }
    for (const step of r.remediationPlan || []) {
      if (!Array.isArray(step.findings)) continue;
      const out = removeOne(step.findings, id => id === AUTHORIZED_FINDING_ID);
      step.findings = out.kept; planFindings += out.seen;
    }
  }
  if (!shapeHeld || issues !== 1 || findings !== 1 || planFindings !== 1) return null;
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
 * Finding-wide, not severity-wide: the `finding-group` wrapper is removed only
 * after its own subtree is proven to hold no remaining finding, so a SECOND
 * critical finding in that group survives into the comparison.
 *
 * Each removed subtree is validated by role, line count and content hash before
 * it goes. Removing whatever happens to carry the id would let the authorized
 * subtree's contents be rewritten freely — the count would still be two.
 */
function removeAuthorizedFindingFromDom(lines) {
  const findingId = new RegExp('data-finding-id="' + AUTHORIZED_FINDING_ID.replace('.', '\\.') + '"');
  const badges = [];
  const seen = [];
  let overallReverts = 0;
  const withoutFinding = [];
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (/<span title="1 critical">/.test(line)) {
      const end = subtreeEnd(lines, i);
      const body = lines.slice(i, end);
      badges.push({ lines: body.length, sha256: sha256(body.join('\n')) });
      i = end - 1;
      continue;
    }
    if (findingId.test(line)) {
      const end = subtreeEnd(lines, i);
      const body = lines.slice(i, end);
      seen.push({
        role: /class="finding"/.test(line) ? 'finding'
          : /class="plan-finding"/.test(line) ? 'plan-finding' : 'unknown',
        lines: body.length,
        sha256: sha256(body.join('\n')),
      });
      i = end - 1;
      continue;
    }
    // The row's severity attribute reverts, and exactly one row may carry it.
    // An unvalidated blanket replace would silently rewrite a second domain's
    // row too — the same class of gap as an unvalidated wrapper removal.
    if (line.includes('data-overall="crit"')) overallReverts++;
    withoutFinding.push(line.replace('data-overall="crit"', 'data-overall="warn"'));
  }
  if (badges.length !== 1
    || overallReverts !== 1
    || JSON.stringify(badges[0]) !== JSON.stringify(AUTHORIZED_DOM_BADGE)
    || JSON.stringify(seen) !== JSON.stringify(AUTHORIZED_DOM_SUBTREES)) return null;

  const shells = [];
  const out = [];
  for (let i = 0; i < withoutFinding.length; i++) {
    const line = withoutFinding[i];
    if (/<div class="finding-group">/.test(line)
      && /finding-sev-critical/.test(withoutFinding[i + 1] || '')) {
      const groupEnd = subtreeEnd(withoutFinding, i);
      const body = withoutFinding.slice(i + 1, groupEnd);
      // Only an EMPTIED group is the wrapper the authorized finding opened —
      // and its own text is checked before it goes, not just its classes.
      if (!body.some(l => /<div class="finding"/.test(l))) {
        const shell = withoutFinding.slice(i, groupEnd);
        shells.push({ lines: shell.length, sha256: sha256(shell.join('\n')) });
        i = groupEnd - 1;
        continue;
      }
    }
    out.push(line);
  }
  if (shells.length !== 1
    || JSON.stringify(shells[0]) !== JSON.stringify(AUTHORIZED_DOM_GROUP_SHELL)) return null;
  return out;
}

/**
 * The complete rendered message, matched in full.
 *
 * Matching a prefix let arbitrary text after `address space:` be counted once,
 * removed, and normalized back to 0.9.0 — the whole rendered string is the
 * authorized material, so the whole string is what is compared.
 */
const AUTHORIZED_CSV_ISSUE_SEGMENT = 'MX host resolves only into unreachable address '
  + 'space: dual.mx.test, v4only.mx.test (198.51.100.20 (documentation), '
  + '2001:db8::20 (documentation), 198.51.100.21 (documentation)) — no sending '
  + 'server on the internet can deliver to it.';

/**
 * The four columns that carry the authorized finding, resolved by header.
 *
 * Each must contain exactly ONE authorized segment. Requiring only "no more
 * than one" accepted a CSV with none at all — a renderer that silently stopped
 * emitting the finding would have passed.
 */
const AUTHORIZED_CSV_COLUMNS = ['Issues', 'Finding IDs', 'Finding Severities', 'Remediation Step 1'];

function removeAuthorizedFindingFromCsv(lines) {
  const rows = csvRows(lines);
  const header = rows[0] || [];
  const columnOf = name => header.indexOf(name);
  const issuesColumn = columnOf('Issues');
  const idColumn = columnOf('Finding IDs');
  const severityColumn = columnOf('Finding Severities');
  const planColumn = columnOf('Remediation Step 1');
  if ([issuesColumn, idColumn, severityColumn, planColumn].some(i => i < 0)) return null;

  let ok = true;
  const mapped = rows.map((cells, rowIndex) => {
    if (rowIndex === 0) return cells;
    const segments = column => cells[column].split(' | ');
    const isAuthorized = (part, column) => column === issuesColumn
      ? part === AUTHORIZED_CSV_ISSUE_SEGMENT
      : part === AUTHORIZED_FINDING_ID;

    // Exactly one authorized segment in each of the three id/message columns.
    for (const column of [issuesColumn, idColumn, planColumn]) {
      if (segments(column).filter(part => isAuthorized(part, column)).length !== 1) ok = false;
    }
    // And the severity that sits at the id's index is the authorized one.
    const dropAt = segments(idColumn).indexOf(AUTHORIZED_FINDING_ID);
    if (dropAt < 0 || segments(severityColumn)[dropAt] !== 'critical') ok = false;

    return cells.map((cell, column) => {
      if (column === severityColumn) {
        return cell.split(' | ').filter((_, i) => i !== dropAt).join(' | ');
      }
      if (column !== issuesColumn && column !== idColumn && column !== planColumn) return cell;
      return removeOne(cell.split(' | '), part => isAuthorized(part, column)).kept.join(' | ');
    });
  });
  return ok ? mapped : null;
}

/* ── The authorized report movement, stated exactly ───────────────────── */

/**
 * What the report guard proves, and what it cannot.
 *
 * The oracle records a report's length, its ORDERED element structure, its
 * fixed byte counts and a hash — never its body. So no rule here can prove the
 * authorized report's text is 0.9.0's plus the rendered finding. What is proven
 * is that its size moved by exactly the measured amount, that its structure
 * changed by exactly the measured ordered edit — no deletions, and insertions
 * at named positions — and that the hash tracks content, the last established
 * by the cases whose content did not move, where the hash must be identical.
 *
 * An earlier version reduced both structures to token COUNTS, which accepted a
 * reversal of the entire sequence. Order is present in the oracle and is bound.
 */
const AUTHORIZED_REPORT_LENGTH_DELTA = 3371;
const AUTHORIZED_REPORT_STRUCTURE_EDITS = [
  [109, ['span']],
  [110, ['/span']],
  [527, ['/div', 'div', 'div', '/div', 'div', 'code']],
  [529, ['/code', 'span', 'span', '/span', '/span']],
  [531, ['code', 'span', '/span', '/code', 'span', 'span', '/span', '/span', '/div']],
  [532, ['code', 'span', '/span', '/code', 'span', 'span', '/span', '/span']],
  [533, ['/div']],
  [534, ['button', '/button', 'div', 'div', '/div', 'div', '/div', 'div', '/div', 'div',
    'div', '/div', '/div', '/div', '/div', '/div', '/div', '/div', 'div', 'div', '/div',
    'div', 'span', '/span', 'div', 'span', '/span', 'div', 'span', '/span', 'span',
    '/span', 'span', '/span', '/div', 'div', 'div', '/div', 'div']],
  [1012, ['div', 'span', '/span', 'div', 'span', '/span']],
  [1015, ['/div', '/div']],
];

/** Ordered edit script from `before` to `after`: insertion runs, and deletions. */
function structureEdits(beforeText, afterText) {
  const a = beforeText.split(' ');
  const b = afterText.split(' ');
  const n = a.length;
  const m = b.length;
  const dp = Array.from({ length: n + 1 }, () => new Uint16Array(m + 1));
  for (let i = n - 1; i >= 0; i--) {
    for (let j = m - 1; j >= 0; j--) {
      dp[i][j] = a[i] === b[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
    }
  }
  const inserted = [];
  let i = 0;
  let j = 0;
  let deletions = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) { i++; j++; }
    else if (dp[i + 1][j] >= dp[i][j + 1]) { i++; deletions++; }
    else { inserted.push([i, b[j]]); j++; }
  }
  while (j < m) { inserted.push([i, b[j]]); j++; }
  while (i < n) { i++; deletions++; }
  const runs = [];
  for (const [position, token] of inserted) {
    const last = runs[runs.length - 1];
    if (last && last[0] === position) last[1].push(token);
    else runs.push([position, [token]]);
  }
  return { runs, deletions };
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
    // the stub addresses, and — in one case — one occurrence of one finding.
    const withoutFinding = authorized ? stripAuthorizedFinding(c.result) : c.result;
    if (withoutFinding === null) violations.push(id + ':result');
    else if (normalizeStubAddresses(stripMxValidity(withoutFinding))
      !== normalizeStubAddresses(before.result)) violations.push(id + ':result');

    // CSV and DOM are compared in EVERY case, the authorized one included.
    const newCsv = authorized ? removeAuthorizedFindingFromCsv(c.csv.lines) : c.csv;
    const oldCsv = authorized ? csvRows(before.csv.lines) : before.csv;
    if (newCsv === null) violations.push(id + ':csv');
    else if (normalizeStubAddresses(newCsv) !== normalizeStubAddresses(oldCsv)) violations.push(id + ':csv');

    const newDom = authorized ? removeAuthorizedFindingFromDom(c.dom) : c.dom;
    if (newDom === null) violations.push(id + ':dom');
    else if (normalizeStubAddresses(newDom) !== normalizeStubAddresses(before.dom)) violations.push(id + ':dom');

    // The report surface. The stubs are length-preserving, so the background
    // cases may not move at all; the authorized case must move by exactly the
    // measured length and gain exactly the measured elements.
    const oldReport = before.report;
    const newReport = c.report;
    const contentMoved = JSON.stringify(c.dom) !== JSON.stringify(before.dom)
      || JSON.stringify(c.csv) !== JSON.stringify(before.csv);
    const fixedBytesHeld =
      newReport.generated === oldReport.generated &&
      newReport.bytes.csp === oldReport.bytes.csp &&
      newReport.bytes.stylesheet === oldReport.bytes.stylesheet &&
      newReport.bytes.stylesheetBytes === oldReport.bytes.stylesheetBytes;
    let movementIsExact;
    if (authorized) {
      // Ordered, not merely compositional: no token may be deleted, and the
      // insertions must land at exactly the recorded positions.
      const edits = structureEdits(oldReport.structure, newReport.structure);
      movementIsExact =
        newReport.length === oldReport.length + AUTHORIZED_REPORT_LENGTH_DELTA
        && edits.deletions === 0
        && JSON.stringify(edits.runs) === JSON.stringify(AUTHORIZED_REPORT_STRUCTURE_EDITS);
    } else {
      movementIsExact = newReport.length === oldReport.length
        && newReport.structure === oldReport.structure;
    }
    // The hash must track content: identical where nothing moved, different
    // where something did. This is what makes the hash meaningful at all.
    const hashTracksContent = (newReport.sha256 !== oldReport.sha256) === contentMoved;
    if (!fixedBytesHeld || !movementIsExact || !hashTracksContent) violations.push(id + ':report');
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
// It must be inserted INSIDE the critical group, which is the shape the
// renderer actually produces: appending a line at the end of the document does
// not exercise the branch that removes the group wrapper.
const domLines091 = release091.cases[authorizedIndex].dom;
const criticalGroupIndex = domLines091.findIndex((line, i) =>
  /<div class="finding-group">/.test(line) && /finding-sev-critical/.test(domLines091[i + 1] || ''));
eq('the authorized case really has a critical finding group', criticalGroupIndex >= 0, true);

const secondFindingDom = structuredClone(release091);
{
  const lines = secondFindingDom.cases[authorizedIndex].dom;
  const indent = ' '.repeat((lines[criticalGroupIndex].match(/^\s*/) || [''])[0].length + 2);
  lines.splice(criticalGroupIndex + 2, 0,
    indent + '<div class="finding" data-finding-id="mx.address-literal">',
    indent + '  <span class="msg">');
}
eq('a SECOND finding inside the authorized critical group is caught',
  release091Violations(secondFindingDom).filter(v => v.endsWith(':dom')),
  [NON_ROUTABLE_MX_CASE + ':dom']);

/* Multiplicity: the authorization is for ONE occurrence of one finding. */

const duplicateIssue091 = structuredClone(release091);
duplicateIssue091.cases[authorizedIndex].result[0].result.issues.push(
  { key: AUTHORIZED_FINDING_KEY, sev: 'crit', args: ['second', 'occurrence'] });
eq('a duplicated authorized issue is caught',
  release091Violations(duplicateIssue091).filter(v => v.endsWith(':result')),
  [NON_ROUTABLE_MX_CASE + ':result']);

const duplicateDom091 = structuredClone(release091);
duplicateDom091.cases[authorizedIndex].dom.push(
  '              <div class="finding" data-finding-id="mx.unroutable">');
eq('a duplicated authorized DOM subtree is caught',
  release091Violations(duplicateDom091).filter(v => v.endsWith(':dom')),
  [NON_ROUTABLE_MX_CASE + ':dom']);

/* The authorized report movement is exact, and its controls mutate the
   authorized case — every control above mutates cases[0], which is bounded by
   the stricter "must not move at all" branch. */

const authorizedStructure091 = structuredClone(release091);
authorizedStructure091.cases[authorizedIndex].report.structure = 'html totally unauthorized /html';
eq('an arbitrary structure in the authorized report is caught',
  release091Violations(authorizedStructure091).filter(v => v.endsWith(':report')),
  [NON_ROUTABLE_MX_CASE + ':report']);

const authorizedLength091 = structuredClone(release091);
authorizedLength091.cases[authorizedIndex].report.length += 1;
eq('an off-by-one length in the authorized report is caught',
  release091Violations(authorizedLength091).filter(v => v.endsWith(':report')),
  [NON_ROUTABLE_MX_CASE + ':report']);

const authorizedFrozenHash091 = structuredClone(release091);
authorizedFrozenHash091.cases[authorizedIndex].report.sha256 =
  release090ById.get(NON_ROUTABLE_MX_CASE).report.sha256;
eq('an authorized report hash that failed to move is caught',
  release091Violations(authorizedFrozenHash091).filter(v => v.endsWith(':report')),
  [NON_ROUTABLE_MX_CASE + ':report']);

/* Order, shape and absence — the three the counts alone did not close. */

// Reversing the structure preserves every token count. A guard that compares
// multisets accepts it; one that compares the ordered edit does not.
const reorderedStructure091 = structuredClone(release091);
{
  const report = reorderedStructure091.cases[authorizedIndex].report;
  report.structure = report.structure.split(' ').reverse().join(' ');
}
eq('a reordered authorized structure with identical token counts is caught',
  release091Violations(reorderedStructure091).filter(v => v.endsWith(':report')),
  [NON_ROUTABLE_MX_CASE + ':report']);

// Shape, not just count: one authorized issue carrying different arguments is
// not the rendering that was authorized.
const mutatedIssueArgs091 = structuredClone(release091);
mutatedIssueArgs091.cases[authorizedIndex].result[0].result.issues
  .find(i => i.key === AUTHORIZED_FINDING_KEY).args = ['anything', 'at all'];
eq('the authorized issue carrying different arguments is caught',
  release091Violations(mutatedIssueArgs091).filter(v => v.endsWith(':result')),
  [NON_ROUTABLE_MX_CASE + ':result']);

const mutatedIssueSeverity091 = structuredClone(release091);
mutatedIssueSeverity091.cases[authorizedIndex].result[0].result.issues
  .find(i => i.key === AUTHORIZED_FINDING_KEY).sev = 'info';
eq('the authorized issue at a different severity is caught',
  release091Violations(mutatedIssueSeverity091).filter(v => v.endsWith(':result')),
  [NON_ROUTABLE_MX_CASE + ':result']);

const mutatedFindingShape091 = structuredClone(release091);
mutatedFindingShape091.cases[authorizedIndex].result[0].result.findings
  .find(f => f.id === AUTHORIZED_FINDING_ID).category = 'hygiene';
eq('the authorized finding in a different category is caught',
  release091Violations(mutatedFindingShape091).filter(v => v.endsWith(':result')),
  [NON_ROUTABLE_MX_CASE + ':result']);

// The structured finding carries fourteen fields, not seven. Changing the ones
// that are not identity fields, while every identity field stays put, is the
// case a subset check could not see.
const mutatedFindingArgs091 = structuredClone(release091);
mutatedFindingArgs091.cases[authorizedIndex].result[0].result.findings
  .find(f => f.id === AUTHORIZED_FINDING_ID).args = ['anything', 'at all'];
eq('the authorized finding with rewritten args is caught',
  release091Violations(mutatedFindingArgs091).filter(v => v.endsWith(':result')),
  [NON_ROUTABLE_MX_CASE + ':result']);

const mutatedFindingEvidence091 = structuredClone(release091);
mutatedFindingEvidence091.cases[authorizedIndex].result[0].result.findings
  .find(f => f.id === AUTHORIZED_FINDING_ID).evidence = [
    { kind: 'host', queryName: 'elsewhere.test', value: '10 elsewhere.test' }];
eq('the authorized finding with rewritten evidence is caught',
  release091Violations(mutatedFindingEvidence091).filter(v => v.endsWith(':result')),
  [NON_ROUTABLE_MX_CASE + ':result']);

// And the CSV message is the whole rendered string, not its opening.
const mutatedCsvSuffix091 = structuredClone(release091);
{
  const csv = mutatedCsvSuffix091.cases[authorizedIndex].csv;
  csv.lines = csv.lines.map(line =>
    line.replace('no sending server on the internet can deliver to it.',
      'arbitrary replacement text.'));
}
eq('the authorized CSV message rewritten after its prefix is caught',
  release091Violations(mutatedCsvSuffix091).filter(v => v.endsWith(':csv')),
  [NON_ROUTABLE_MX_CASE + ':csv']);

// Content inside the authorized DOM subtree, with both occurrence counts intact.
const mutatedSubtree091 = structuredClone(release091);
{
  const lines = mutatedSubtree091.cases[authorizedIndex].dom;
  const at = lines.findIndex(l => /data-finding-id="mx\.unroutable"/.test(l));
  lines[at + 1] = lines[at + 1].replace(/".*"/, '"rewritten content"');
}
eq('rewritten content inside the authorized DOM subtree is caught',
  release091Violations(mutatedSubtree091).filter(v => v.endsWith(':dom')),
  [NON_ROUTABLE_MX_CASE + ':dom']);

// The material around the finding is removed too, so it is bound too: the
// badge the finding introduces and the group shell it opens. Both mutations
// below leave the two authorized finding subtrees, and every count, untouched.
const mutatedBadge091 = structuredClone(release091);
{
  const lines = mutatedBadge091.cases[authorizedIndex].dom;
  const at = lines.findIndex(l => /<span title="1 critical">/.test(l));
  lines[at + 1] = lines[at + 1].replace(/".*"/, '"arbitrary badge content"');
}
eq('rewritten content in the authorized severity badge is caught',
  release091Violations(mutatedBadge091).filter(v => v.endsWith(':dom')),
  [NON_ROUTABLE_MX_CASE + ':dom']);

const mutatedGroupLabel091 = structuredClone(release091);
{
  const lines = mutatedGroupLabel091.cases[authorizedIndex].dom;
  const group = lines.findIndex((l, i) =>
    /<div class="finding-group">/.test(l) && /finding-sev-critical/.test(lines[i + 1] || ''));
  const label = lines.findIndex((l, i) => i > group && /#3 /.test(l));
  lines[label] = lines[label].replace(/".*"/, '"arbitrary group label"');
}
eq('a rewritten critical-group label is caught',
  release091Violations(mutatedGroupLabel091).filter(v => v.endsWith(':dom')),
  [NON_ROUTABLE_MX_CASE + ':dom']);

// Found while auditing the transform for the same class of gap rather than
// waiting for it to be reported: the row-severity revert was a blanket string
// replace, so a second row carrying it would have been rewritten unexamined.
const secondOverall091 = structuredClone(release091);
secondOverall091.cases[authorizedIndex].dom.push('  <tr data-overall="crit">');
eq('a second row carrying the reverted severity attribute is caught',
  release091Violations(secondOverall091).filter(v => v.endsWith(':dom')),
  [NON_ROUTABLE_MX_CASE + ':dom']);

// Absence: a renderer that silently stopped emitting the finding into CSV.
const csvWithout091 = structuredClone(release091);
csvWithout091.cases[authorizedIndex].csv = structuredClone(
  release090ById.get(NON_ROUTABLE_MX_CASE).csv);
eq('the authorized CSV missing its finding entirely is caught',
  release091Violations(csvWithout091).filter(v => v.endsWith(':csv')),
  [NON_ROUTABLE_MX_CASE + ':csv']);

// And one expected segment removed while the others remain.
const csvPartial091 = structuredClone(release091);
{
  const csv = csvPartial091.cases[authorizedIndex].csv;
  csv.lines = csv.lines.map(line => line.replace(' | mx.unroutable', '').replace('mx.unroutable | ', ''));
}
eq('the authorized CSV missing one expected segment is caught',
  release091Violations(csvPartial091).filter(v => v.endsWith(':csv')),
  [NON_ROUTABLE_MX_CASE + ':csv']);

// The limit, stated rather than implied: the oracle records no report body, so
// an ARBITRARY different hash on the authorized report cannot be distinguished
// from the real one. What the guard proves is the exact length delta, the exact
// element-composition delta, and that the hash moves with content and only with
// content — the latter established by the cases below, where nothing moved.
const unmovedCases = release091.cases.filter(c => {
  const before = release090ById.get(c.id);
  return JSON.stringify(c.dom) === JSON.stringify(before.dom)
    && JSON.stringify(c.csv) === JSON.stringify(before.csv);
});
eq('the cases whose content did not move keep their exact report hash',
  [unmovedCases.length > 0,
    unmovedCases.filter(c => c.report.sha256 !== release090ById.get(c.id).report.sha256).length],
  [true, 0]);

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
