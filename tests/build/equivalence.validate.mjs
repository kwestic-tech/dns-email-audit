#!/usr/bin/env node
/**
 * Validate the equivalence runner before the baseline is captured.
 *
 * Framework §4, and it is mandatory rather than advisory:
 *
 *   1. Run it twice against the same root → byte-identical. Catches
 *      nondeterminism in the runner itself: map ordering, timestamps, ICU.
 *   2. Run it against a deliberately MUTATED copy of `js/` — flip one `WEIGHTS`
 *      value, reorder one array, change one issue token, drop one DNS query —
 *      and confirm each mutation is caught, ON THE SURFACE THAT SHOULD CATCH IT.
 *   3. A mutation that passes is a hole in the runner. Fix it before capturing
 *      the baseline, not after.
 *
 * Step 2 is what would have caught the `a.b.ck` probe. The surface attribution
 * is the part that matters: a runner where every mutation lights up every
 * surface tells you something broke and nothing about where, and five surfaces
 * that always move together are one surface with four decorations.
 */

import { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { createSuite } from '../lib/assert.mjs';
import { serialize } from '../lib/canonical.mjs';
import { runCase } from './equivalence.mjs';
import { cases as allCases } from '../fixtures/equivalence/corpus.mjs';

/**
 * The subset this file runs against, and it is a stated cap rather than a
 * silent one.
 *
 * This validates the INSTRUMENT, not the corpus: it needs enough cases to
 * exercise all five surfaces and to let every mutation below land somewhere.
 * The full corpus is 30 cases and each mutation costs a complete pass, so
 * validating against all of them costs about seven minutes for no additional
 * evidence about the runner.
 *
 * Section 1 asserts that this subset does exercise every surface, so the cap
 * cannot quietly stop being sufficient.
 */
const VALIDATION_SUBSET = [
  'enforcing-signed',        // every control present; DKIM, DNSSEC, both exports
  'bare-registered',         // nothing published — the spf-missing token
  'cache-reuse-siblings',    // two domains, one page — the cache mutation
  'unregistered',            // the three-property early-return shape
  'dnssec-orphan-ds',        // the computed DS claims
  'mx-health-and-tlsa',      // MX health, TLSA, the AAAA lookup
];
const cases = allCases.filter(c => VALIDATION_SUBSET.includes(c.id));

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, section, report } = createSuite();

const SURFACES = ['result', 'trace', 'csv', 'report', 'dom'];

/** A subject root holding only what a subject is: the shipped files. */
function makeRoot(label) {
  const root = mkdtempSync(join(tmpdir(), `equivalence-${label}-`));
  for (const path of ['index.html', 'js', 'css', 'locales']) {
    cpSync(join(REPO, path), join(root, path), { recursive: true });
  }
  return root;
}

async function run(root) {
  const surfaces = new Map();
  for (const testCase of cases) {
    surfaces.set(testCase.id, await runCase(root, testCase, 'classic'));
  }
  return surfaces;
}

/** Which surfaces differ, per case, between two runs. */
function movedSurfaces(a, b) {
  const moved = new Set();
  for (const [id, left] of a) {
    const right = b.get(id);
    if (!right) { moved.add('MISSING CASE'); continue; }
    for (const surface of SURFACES) {
      if (serialize(left[surface]) !== serialize(right[surface])) moved.add(surface);
    }
  }
  return [...moved].sort();
}

/* ── 1. Determinism ───────────────────────────────────────────────────── */
section('1. The runner is deterministic');

console.log(`validating against ${cases.length} of ${allCases.length} corpus cases: ${VALIDATION_SUBSET.join(', ')}`);
console.log('(the instrument is what is under test here, not the corpus)');

const pristine = makeRoot('pristine');
const first = await run(pristine);
const second = await run(pristine);
eq('two runs against one root move no surface', movedSurfaces(first, second), []);
eq('the subset is the one named above', cases.map(c => c.id).sort(), [...VALIDATION_SUBSET].sort());
eq('every case produced all five surfaces',
  [...first.values()].filter(c => SURFACES.some(s => c[s] === undefined)).map(c => c.id), []);
// A surface that is null for every case cannot detect anything, which is the
// failure the first draft of this runner actually had: `exportCSV()` read an
// array nothing had populated and emitted a header row for all eight cases.
for (const surface of SURFACES) {
  const distinct = new Set([...first.values()].map(c => serialize(c[surface])));
  eq(`the ${surface} surface distinguishes cases`, distinct.size > 1, true);
}

/* ── 2. Mutations, and the surface each must land on ──────────────────── */
section('2. Mutations are caught on the right surface');

/**
 * Each mutation names the surfaces that MUST move and the surfaces that must
 * NOT. Both halves are asserted. "Must not move" is the half that proves the
 * five surfaces are five instruments rather than one.
 */
const MUTATIONS = [
  {
    label: 'flip one WEIGHTS value (spf 15 -> 14)',
    file: 'js/dns.js',
    from: 'dmarc: 30, spf: 15, dkim: 15, dnssec: 15,',
    to: 'dmarc: 30, spf: 14, dkim: 15, dnssec: 15,',
    mustMove: ['csv', 'dom', 'report', 'result'],
    mustHold: ['trace'],
  },
  {
    // The same edit to a DIFFERENT weight, and it reaches less far. Measured,
    // not assumed — this expectation was written as "csv moves too" and the
    // validator refused it. `calcDmarcScore()` builds `pts` from fixed
    // components (js/dns.js:4515) and `WEIGHTS.dmarc` is only the pillar's
    // `max` (js/dns.js:5322), so the total, the grade and therefore every CSV
    // column stay identical while the breakdown the UI renders changes.
    //
    // Kept as a case because it is the clearest evidence in this file that the
    // five surfaces have genuinely different reach.
    label: 'flip a WEIGHTS value that is a ceiling only (dmarc 30 -> 29)',
    file: 'js/dns.js',
    from: 'dmarc: 30, spf: 15, dkim: 15, dnssec: 15,',
    to: 'dmarc: 29, spf: 15, dkim: 15, dnssec: 15,',
    mustMove: ['dom', 'report', 'result'],
    mustHold: ['csv', 'trace'],
  },
  {
    label: 'reorder one array (the scoring pillars)',
    file: 'js/dns.js',
    from: "      { key: 'dmarc', pts: dmarc.pts, max: WEIGHTS.dmarc },\n      { key: 'spf', pts: calcSpfScore(spfStatus, advanced), max: WEIGHTS.spf },",
    to: "      { key: 'spf', pts: calcSpfScore(spfStatus, advanced), max: WEIGHTS.spf },\n      { key: 'dmarc', pts: dmarc.pts, max: WEIGHTS.dmarc },",
    mustMove: ['dom', 'report', 'result'],
    mustHold: ['trace'],
  },
  {
    label: 'change one issue token (spf-missing -> spf-absent)',
    file: 'js/dns.js',
    from: "issues.push({ key: 'spf-missing', sev: 'crit' });",
    to: "issues.push({ key: 'spf-absent', sev: 'crit' });",
    mustMove: ['csv', 'dom', 'report', 'result'],
    mustHold: ['trace'],
  },
  {
    label: 'drop one DNS query (the AAAA lookup at the apex)',
    file: 'js/dns.js',
    from: "      dohQuery(d, 'AAAA', queryOpts),",
    to: "      Promise.resolve([]),",
    mustMove: ['result', 'trace'],
    mustHold: [],
  },
  {
    // The R10 case, and the reason the trace surface exists at all. The result
    // is byte-identical and the fan-out changes — which is a published figure.
    label: 'narrow the cache (noCache on the DMARC walk)',
    file: 'js/dns.js',
    from: "      var response = await dohFetch(queryName, 'TXT', queryOpts);",
    to: "      var response = await dohFetch(queryName, 'TXT', Object.assign({}, queryOpts, { noCache: true }));",
    mustMove: ['trace'],
    mustHold: ['result', 'csv', 'dom'],
  },
  {
    label: 'reorder two CSV columns',
    file: 'js/app.js',
    from: "        r.score.grade, r.score.pts,",
    to: "        r.score.pts, r.score.grade,",
    mustMove: ['csv'],
    mustHold: ['result', 'trace', 'dom'],
  },
  {
    label: "weaken the exported report's own CSP",
    file: 'js/app.js',
    from: "content: \"default-src 'none'; style-src 'unsafe-inline'; img-src data:\",",
    to: "content: \"default-src 'none'; style-src 'unsafe-inline'; img-src *\",",
    mustMove: ['report'],
    mustHold: ['result', 'trace', 'csv', 'dom'],
  },
];

for (const mutation of MUTATIONS) {
  const root = makeRoot('mutant');
  const path = join(root, mutation.file);
  const source = readFileSync(path, 'utf8');
  const occurrences = source.split(mutation.from).length - 1;
  // A mutation that did not apply is a green run that proves nothing — the
  // exact shape of failure this whole file exists to prevent.
  eq(`${mutation.label}: applies exactly once`, occurrences, 1);
  writeFileSync(path, source.replace(mutation.from, mutation.to));

  const mutated = await run(root);
  const moved = movedSurfaces(first, mutated);
  eq(`${mutation.label}: moves ${mutation.mustMove.join(', ') || 'nothing'}`,
    moved, [...mutation.mustMove].sort());
  for (const surface of mutation.mustHold) {
    eq(`${mutation.label}: leaves ${surface} untouched`, moved.includes(surface), false);
  }
  rmSync(root, { recursive: true, force: true });
}

/* ── 3. The subject binding ───────────────────────────────────────────── */
section('3. A subject is a complete root');

// Changing an asset the JavaScript does not touch must still be visible. A
// runner that paired baseline JavaScript with current-branch CSS would report
// a clean diff across a stylesheet rewrite.
const cssRoot = makeRoot('css');
const cssPath = join(cssRoot, 'css', 'style.css');
writeFileSync(cssPath, readFileSync(cssPath, 'utf8') + '\n.equivalence-probe{color:red}\n');
const cssMutated = await run(cssRoot);
eq('a stylesheet-only change moves the report surface and nothing else',
  movedSurfaces(first, cssMutated), ['report']);
rmSync(cssRoot, { recursive: true, force: true });

// And the index.html the subject loads is the subject's own.
const htmlRoot = makeRoot('html');
const htmlPath = join(htmlRoot, 'index.html');
writeFileSync(htmlPath, readFileSync(htmlPath, 'utf8').replace('js/app.js', 'js/does-not-exist.js'));
let refused = false;
try { await run(htmlRoot); } catch (error) { refused = /listed in index.html but missing/.test(error.message); }
eq('a script listed in index.html but absent is refused, not skipped', refused, true);
rmSync(htmlRoot, { recursive: true, force: true });

rmSync(pristine, { recursive: true, force: true });
report();
