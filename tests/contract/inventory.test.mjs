#!/usr/bin/env node
/**
 * Enforce the contract inventory. Spec Testing item 1, Task 0.5.
 *
 *   node tests/contract/inventory.test.mjs
 *
 * Runs every suite `tests/inventory.json` names, compares what each printed
 * against what is recorded, and reports the total.
 *
 * Deliberately NOT part of `npm test`: it runs the whole suite as
 * subprocesses, so including it there would run everything twice. It is a
 * phase-gate command, and `npm run inventory` is its name.
 *
 * The gate is the AREA LIST, not the number. A count can stay level while a
 * meaningful assertion is deleted and an unrelated one added — round 1's
 * finding H — and the spike proved the stronger version of the same point:
 * 1,535 assertions passed against a silently substituted public suffix list
 * and the count did not move.
 */

import { readFileSync, existsSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { createSuite } from '../lib/assert.mjs';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, section, report } = createSuite();

const inventory = JSON.parse(readFileSync(join(REPO, 'tests/inventory.json'), 'utf8'));

/* ── 1. Every named suite exists and passes ───────────────────────────── */
section('1. Every inventory area has a passing suite');

const measured = new Map();
for (const suite of inventory.suites) {
  const path = join(REPO, suite.path);
  eq(`${suite.path} exists`, existsSync(path), true);
  if (!existsSync(path)) continue;

  let output = '';
  let failed = false;
  try {
    output = execFileSync('node', [path], { cwd: REPO, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (error) {
    output = String(error.stdout || '') + String(error.stderr || '');
    failed = true;
  }
  eq(`${suite.path} passes`, failed, false);

  const match = /(\d+) passed, (\d+) failed/.exec(output);
  measured.set(suite.path, match ? Number(match[1]) : null);
  eq(`${suite.path} reports no failures`, match ? Number(match[2]) : 0, 0);

  // A suite that reports a count must report the recorded one. This is the
  // tripwire, and it fires in both directions: a silent decrease is the case
  // the spec cares about, and a silent increase means the inventory was not
  // updated with the work.
  if (suite.assertions !== null) {
    eq(`${suite.path} reports ${suite.assertions} assertions`, match ? Number(match[1]) : null, suite.assertions);
  } else {
    eq(`${suite.path} reports findings rather than a count`, match, null);
  }

  eq(`${suite.path} names the areas it covers`, suite.areas.length > 0, true);
}

/* ── 2. The total, reported ───────────────────────────────────────────── */
section('2. Assertion total (reported, not gating)');

const total = [...measured.values()].reduce((sum, n) => sum + (n || 0), 0);
const recorded = inventory.suites.reduce((sum, s) => sum + (s.assertions || 0), 0);
eq('the recorded per-suite counts sum to what ran', recorded, total);
console.log(`  total: ${total}   baseline at ${inventory.baseline.release}: ${inventory.baseline.total}   ` +
  `delta: ${total >= inventory.baseline.total ? '+' : ''}${total - inventory.baseline.total}`);
if (total < inventory.baseline.total) {
  console.log('  A DECREASE must name the assertions removed and where the property moved.');
}

/* ── 3. Nothing is dropped silently ───────────────────────────────────── */
section('3. Inventory integrity');

const areas = inventory.suites.flatMap(s => s.areas);
eq('no area is listed twice', areas.length, new Set(areas).size);
eq('every suite path is unique',
  inventory.suites.length, new Set(inventory.suites.map(s => s.path)).size);
eq('everything deliberately outside npm test says why',
  (inventory.notInNpmTest || []).filter(entry => !entry.why || !entry.why.trim()).map(e => e.command), []);

// The suites npm test actually runs must be the ones the inventory records —
// otherwise a suite could be dropped from the script and the inventory would
// still claim its areas are covered.
const scripts = JSON.parse(readFileSync(join(REPO, 'package.json'), 'utf8')).scripts;
const inTest = scripts.test.split('&&').map(part => {
  const match = /node\s+(\S+)/.exec(part.trim());
  return match ? match[1] : null;
}).filter(Boolean);
eq('npm test runs exactly the suites the inventory names',
  [...inTest].sort(), inventory.suites.map(s => s.path).sort());

/* ── 4. The README's total is derived, not remembered ─────────────────── */
section('4. The README quotes the measured total');

/**
 * README.md tells a reader how many assertions `npm test` runs. Nothing checked
 * that number, and it has gone stale twice: `ROADMAP.md` records "README.md
 * still cites 174 assertions; corrected in 0.2.3", and 0.9.1 shipped saying
 * 5,624 after retiring an oracle took the suite to 5,617.
 *
 * Section 3 already proves `npm test` runs exactly the inventoried suites, so
 * the sum above IS the figure the README is claiming. This binds them.
 */
const readme = readFileSync(join(REPO, 'README.md'), 'utf8');
const quoted = /\|\s*`npm test`\s*\|[^|]*?\*\*([\d,]+)\*\*/.exec(readme);

// A reworded row must fail here rather than silently stop checking anything.
eq('the README states a total for `npm test`', quoted !== null, true);
eq('and it is the total that actually ran',
  quoted ? Number(quoted[1].replace(/,/g, '')) : null, total);
if (quoted && Number(quoted[1].replace(/,/g, '')) !== total) {
  console.log(`  README says ${quoted[1]}; the suites ran ${total}. Update README.md.`);
}

report();
