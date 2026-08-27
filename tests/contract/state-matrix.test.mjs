#!/usr/bin/env node
/**
 * Enforces the four rules spec §12.1 attaches to the reviewed state registry.
 *
 *   1. Reject matrix rows naming missing suites or fixtures.
 *   2. Reject an algebra member with no coverage row.
 *   3. Compare each extracted module's exported state constants with the
 *      reviewed registry, once that module exists.
 *   4. Run targeted legacy contracts for computed values, thrown paths,
 *      booleans, nullability and absence until extraction is complete.
 *
 * Rules 3 and 4 are delegated: rule 4 lives in `legacy-shapes.test.mjs`, and
 * rule 3 has nothing to compare against until Phase 3 creates the first
 * `src/core/` module — so this file asserts that the delegation is wired and
 * that the extracted-module comparison covers every module that exists.
 *
 * What this file does NOT claim: that a static extractor discovered these
 * states. It did not. `tests/state-algebras.json` is a reviewed document, and
 * `legacy-shapes.test.mjs` section 6 executes the proof that a literal scan
 * under-reports it by three tokens.
 */

import { readFileSync, existsSync, readdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { createSuite } from '../lib/assert.mjs';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, section, report } = createSuite();

const registry = JSON.parse(readFileSync(join(REPO, 'tests/state-algebras.json'), 'utf8'));
const matrix = JSON.parse(readFileSync(join(REPO, 'tests/state-matrix.json'), 'utf8'));

/* ── 1. Every named suite and fixture exists ──────────────────────────── */
section('1. Named suites and fixtures resolve');

const corpusManifest = join(REPO, 'tests/fixtures/equivalence/corpus.json');
const corpus = existsSync(corpusManifest)
  ? new Set(JSON.parse(readFileSync(corpusManifest, 'utf8')).cases.map(c => c.id))
  : new Set();

const missingSuites = new Set();
const missingFixtures = new Set();
for (const row of matrix.rows) {
  for (const suite of row.suites) if (!existsSync(join(REPO, suite))) missingSuites.add(suite);
  for (const fixture of row.fixtures) if (!corpus.has(fixture)) missingFixtures.add(fixture);
}
eq('no row names a suite file that does not exist', [...missingSuites], []);
eq('no row names a corpus case that does not exist', [...missingFixtures], []);

/* ── 2. Every registry member has exactly one covered row ─────────────── */
section('2. Registry coverage');

const rowCount = new Map();
for (const row of matrix.rows) {
  const key = `${row.algebra} ${row.member}`;
  rowCount.set(key, (rowCount.get(key) || 0) + 1);
}

const noRow = [];
const duplicated = [];
const uncovered = [];
for (const algebra of registry.algebras) {
  for (const member of algebra.members) {
    const key = `${algebra.id} ${member}`;
    const count = rowCount.get(key) || 0;
    if (count === 0) { noRow.push(`${algebra.id} :: ${member}`); continue; }
    if (count > 1) duplicated.push(`${algebra.id} :: ${member}`);
    const row = matrix.rows.find(r => r.algebra === algebra.id && r.member === member);
    if (!row.suites.length && !row.fixtures.length) uncovered.push(`${algebra.id} :: ${member}`);
  }
}
eq('every registry member has a matrix row', noRow, []);
eq('no member has two rows', duplicated, []);
// The gate, and deliberately not softened. A member with neither a suite nor a
// corpus fixture is a state nothing observes. Spec §12.1: "rejects an algebra
// member with no coverage row". A member the corpus genuinely cannot reach is
// framework §6 trigger 3 — stop and write a Codex review, never add an
// exemption here.
eq('every registry member is covered by a suite or a corpus fixture', uncovered, []);

const orphanRows = matrix.rows.filter(row => {
  const algebra = registry.algebras.find(a => a.id === row.algebra);
  return !algebra || !algebra.members.includes(row.member);
}).map(r => `${r.algebra} :: ${r.member}`);
eq('no matrix row names a member the registry does not have', orphanRows, []);

/* ── 3. Extracted module state constants match the registry ───────────── */
section('3. Extracted module constants (Phase 3 onward)');

const srcDir = join(REPO, 'src');
const extracted = existsSync(srcDir) ? readdirSync(srcDir) : [];
// Nothing under src/ yet, so there is nothing to compare. Asserted rather than
// skipped: the day src/ appears this number moves, and the comparison has to be
// written before that phase can gate.
eq('src/ does not exist yet, so no module exports state constants', extracted.length, 0);

/* ── 4. The targeted legacy contracts are wired ───────────────────────── */
section('4. Legacy contract delegation');

const legacy = join(REPO, 'tests/contract/legacy-shapes.test.mjs');
eq('the legacy shape contract exists', existsSync(legacy), true);
const legacySource = existsSync(legacy) ? readFileSync(legacy, 'utf8') : '';
for (const axis of ['Computed values', 'Thrown paths', 'Booleans, nullability and absence']) {
  eq(`it covers: ${axis}`, legacySource.includes(axis), true);
}
eq('and it runs its fixture-identity probes before any other assertion',
  legacySource.indexOf('assertFixtureIdentity(probes)') < legacySource.indexOf('1. Transport kinds'), true);

/* ── 5. The registry says what it is ──────────────────────────────────── */
section('5. Registry self-description');

eq('the registry names its baseline', registry.baseline, 'v0.5.0');
eq('every algebra declares whether it is closed',
  registry.algebras.filter(a => typeof a.closed !== 'boolean').map(a => a.id), []);
eq('every algebra names at least one construction site',
  registry.algebras.filter(a => !a.site && !a.memberSites).map(a => a.id), []);
eq('every non-enum shape names its axes',
  registry.shapes.filter(s => !Array.isArray(s.axes) || !s.axes.length).map(s => s.id), []);

report();
