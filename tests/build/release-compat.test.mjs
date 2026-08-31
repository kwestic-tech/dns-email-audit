#!/usr/bin/env node
/**
 * Bound the intentional 0.7.0 difference from the historical v0.5.0 oracle.
 * The finished 0.7.0 baseline pins all five surfaces exactly; this suite proves
 * the release did not hide an unrelated legacy-result, trace or CSV movement
 * inside the intentional findings/UI change.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { createSuite } from '../lib/assert.mjs';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const previous = JSON.parse(readFileSync(join(ROOT, 'tests/fixtures/equivalence/baseline-v0.5.0.json'), 'utf8'));
const current = JSON.parse(readFileSync(join(ROOT, 'tests/fixtures/equivalence/baseline-v0.7.0.json'), 'utf8'));
const { eq, section, report } = createSuite();

const byId = document => new Map(document.cases.map(c => [c.id, c]));
const previousById = byId(previous);

function stripAdditiveFields(value) {
  if (Array.isArray(value)) return value.map(stripAdditiveFields);
  if (!value || typeof value !== 'object') return value;
  return Object.fromEntries(Object.entries(value)
    .filter(([key]) => key !== 'findings' && key !== 'remediationPlan')
    .map(([key, child]) => [key, stripAdditiveFields(child)]));
}

function traceViolations(document) {
  return document.cases.flatMap(c =>
    JSON.stringify(previousById.get(c.id)?.trace) === JSON.stringify(c.trace) ? [] : [c.id]);
}

function legacyResultViolations(document) {
  return document.cases.flatMap(c =>
    JSON.stringify(previousById.get(c.id)?.result) === JSON.stringify(stripAdditiveFields(c.result)) ? [] : [c.id]);
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
    const before = csvRows(previousById.get(c.id)?.csv.lines || []);
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
  [...previousById.keys()].sort(), [...byId(current).keys()].sort());
eq('the DNS trace is byte-identical in every case', traceViolations(current), []);
eq('legacy results are byte-identical after removing the two additive fields',
  legacyResultViolations(current), []);
eq('CSV changes only by three appended cells on every row', csvViolations(current), []);

section('Each release-compatibility rule has a negative control');

const changedTrace = structuredClone(current);
changedTrace.cases[0].trace.total++;
eq('a trace movement is caught', traceViolations(changedTrace), [current.cases[0].id]);

const changedResult = structuredClone(current);
changedResult.cases[0].result[0].result.domain = 'mutated.test';
eq('a legacy result movement is caught', legacyResultViolations(changedResult), [current.cases[0].id]);

const insertedCsv = structuredClone(current);
insertedCsv.cases[0].csv.lines[0] = '"inserted",' + insertedCsv.cases[0].csv.lines[0];
eq('an inserted CSV cell is caught', csvViolations(insertedCsv), [current.cases[0].id + ':row-0']);

report();
