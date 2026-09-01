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

import { cpSync, mkdtempSync, readFileSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join } from 'node:path';

import { createSuite } from '../lib/assert.mjs';
import { serialize } from '../lib/canonical.mjs';
import { runCase, bindExecutions } from './equivalence.mjs';
import { loadSubject } from '../lib/subject.mjs';
import { readEntryPoints } from '../lib/subject.mjs';
import { build } from '../../tools/build-bundle.mjs';
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

/**
 * A subject root holding what a subject is, BUILT.
 *
 * The build is not a convenience. Since the delivery boundary moved, the runner
 * loads `dist/app.min.js`, so a mutation applied to a source file reaches
 * nothing unless the root is rebuilt — and every mutation below would report
 * "moves nothing" while looking like a clean validation. Rebuilding is what
 * keeps this file's claims about the instrument true.
 *
 * `js/` left this list at Task 6.1 with the directory itself. The copy is
 * asserted rather than filtered: a path that silently stopped being copied is
 * a subject quietly missing a source, which is the same class of failure as a
 * scan that stops reading its file.
 */
const SUBJECT_PATHS = ['index.html', 'src', 'css', 'locales', 'package.json'];
for (const path of SUBJECT_PATHS) {
  eq(`the subject includes ${path}`, existsSync(join(REPO, path)), true);
}
async function makeRoot(label) {
  const root = mkdtempSync(join(tmpdir(), `equivalence-${label}-`));
  for (const path of SUBJECT_PATHS) {
    cpSync(join(REPO, path), join(root, path), { recursive: true });
  }
  await build({ root });
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

const pristine = await makeRoot('pristine');
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
    // Followed the scoring model to its owner at Task 5.3.
    file: 'src/audit/scoring.js',
    from: 'dmarc: 30, spf: 15, dkim: 15, dnssec: 15,',
    to: 'dmarc: 30, spf: 14, dkim: 15, dnssec: 15,',
    mustMove: ['csv', 'dom', 'report', 'result'],
    mustHold: ['trace'],
  },
  {
    // The same edit to a DIFFERENT weight, and it reaches less far. Measured,
    // not assumed — this expectation was written as "csv moves too" and the
    // validator refused it. `calcDmarcScore()` builds `pts` from fixed
    // components and `WEIGHTS.dmarc` is only the pillar's `max`, so the total,
    // the grade and therefore every CSV column stay identical while the
    // breakdown the UI renders changes. (The two `js/dns.js` line numbers this
    // note used to cite went stale long before Task 5.3 moved the code; both
    // functions are in `src/audit/scoring.js` now.)
    //
    // Kept as a case because it is the clearest evidence in this file that the
    // five surfaces have genuinely different reach.
    label: 'flip a WEIGHTS value that is a ceiling only (dmarc 30 -> 29)',
    file: 'src/audit/scoring.js',
    from: 'dmarc: 30, spf: 15, dkim: 15, dnssec: 15,',
    to: 'dmarc: 29, spf: 15, dkim: 15, dnssec: 15,',
    mustMove: ['dom', 'report', 'result'],
    mustHold: ['csv', 'trace'],
  },
  {
    label: 'reorder one array (the scoring pillars)',
    file: 'src/audit/scoring.js',
    // The indentation is part of the pattern, and the move dedented these two
    // lines by two spaces. `applies exactly once` is what turns that into a
    // visible failure instead of "the mutation moved nothing".
    from: "    { key: 'dmarc', pts: dmarc.pts, max: WEIGHTS.dmarc },\n    { key: 'spf', pts: calcSpfScore(spfStatus, advanced), max: WEIGHTS.spf },",
    to: "    { key: 'spf', pts: calcSpfScore(spfStatus, advanced), max: WEIGHTS.spf },\n    { key: 'dmarc', pts: dmarc.pts, max: WEIGHTS.dmarc },",
    mustMove: ['dom', 'report', 'result'],
    mustHold: ['trace'],
  },
  {
    label: 'change one issue token (spf-missing -> spf-absent)',
    // Followed the issue builder to its owner at Task 5.4. The last probe that
    // still named `js/dns.js`.
    file: 'src/audit/issues.js',
    from: "issues.push({ key: 'spf-missing', sev: 'crit' });",
    to: "issues.push({ key: 'spf-absent', sev: 'crit' });",
    mustMove: ['csv', 'dom', 'report', 'result'],
    mustHold: ['trace'],
  },
  {
    label: 'drop one DNS query (the AAAA lookup at the apex)',
    // Followed the coordinator to its owner at Task 5.2, for the same reason
    // the DMARC walk probe was followed at 4.6: a probe naming a file the code
    // has left fails as "the mutation moved nothing", which reads as the
    // instrument being insensitive rather than as a stale path.
    file: 'src/audit/audit-domain.js',
    from: "      dohQuery(d, 'AAAA', queryOpts),",
    to: "      Promise.resolve([]),",
    mustMove: ['result', 'trace'],
    mustHold: [],
  },
  {
    // The R10 case, and the reason the trace surface exists at all. The result
    // is byte-identical and the fan-out changes — which is a published figure.
    label: 'narrow the cache (noCache on the DMARC walk)',
    // Followed the walk to its owner at Task 4.6. A mutation probe naming a
    // file the code has left does not fail loudly — it fails as "the mutation
    // moved nothing", which reads like the instrument being insensitive rather
    // than like a stale path.
    file: 'src/core/dmarc/tree-walk.js',
    from: "      var response = await dohFetch(queryName, 'TXT', queryOpts);",
    to: "      var response = await dohFetch(queryName, 'TXT', Object.assign({}, queryOpts, { noCache: true }));",
    mustMove: ['trace'],
    mustHold: ['result', 'csv', 'dom'],
  },
  {
    label: 'reorder two CSV columns',
    // Followed the CSV builder to `src/ui/report.js` at Task 5.5. The block
    // moved at its own indentation, so only the path changed.
    file: 'src/ui/report.js',
    from: "        r.score.grade, r.score.pts,",
    to: "        r.score.pts, r.score.grade,",
    mustMove: ['csv'],
    mustHold: ['result', 'trace', 'dom'],
  },
  {
    label: "weaken the exported report's own CSP",
    file: 'src/ui/report.js',
    from: "content: \"default-src 'none'; style-src 'unsafe-inline'; img-src data:\",",
    to: "content: \"default-src 'none'; style-src 'unsafe-inline'; img-src *\",",
    mustMove: ['report'],
    mustHold: ['result', 'trace', 'csv', 'dom'],
  },
];

for (const mutation of MUTATIONS) {
  const root = await makeRoot('mutant');
  const path = join(root, mutation.file);
  const source = readFileSync(path, 'utf8');
  const occurrences = source.split(mutation.from).length - 1;
  // A mutation that did not apply is a green run that proves nothing — the
  // exact shape of failure this whole file exists to prevent.
  eq(`${mutation.label}: applies exactly once`, occurrences, 1);
  writeFileSync(path, source.replace(mutation.from, mutation.to));
  // Rebuild: the mutation is in the source, and the subject loads the artifact.
  await build({ root });

  const mutated = await run(root);
  const moved = movedSurfaces(first, mutated);
  eq(`${mutation.label}: moves ${mutation.mustMove.join(', ') || 'nothing'}`,
    moved, [...mutation.mustMove].sort());
  for (const surface of mutation.mustHold) {
    eq(`${mutation.label}: leaves ${surface} untouched`, moved.includes(surface), false);
  }
  rmSync(root, { recursive: true, force: true });
}

/* ── 2b. The rebuild is what makes a mutation observable ──────────────── */
section('2b. Negative control: a mutation that is not rebuilt moves nothing');

/**
 * The control that keeps section 2 honest.
 *
 * Since the delivery boundary moved, the subject loads `dist/app.min.js`. A
 * validator that edited `js/` and did not rebuild would be measuring an
 * artifact the edit never reached — every mutation would report "moves
 * nothing", every `mustMove` assertion would fail, and if the assertions were
 * ever loosened it would go green while proving nothing at all.
 *
 * So this asserts the failure mode directly: apply the largest mutation in the
 * list, DO NOT rebuild, and require that no surface moves. If this ever starts
 * reporting movement, the subject has stopped loading the artifact and section
 * 2's rebuilds are no longer what makes it work.
 */
const staleRoot = await makeRoot('stale');
// Follows the weights, like the probes above. Task 5.3 moved the scoring model
// out of `js/dns.js`, and a control that edited a file no longer holding the
// weights would have gone green for the wrong reason — which is the exact
// failure this control exists to detect in section 2.
const stalePath = join(staleRoot, 'src', 'audit', 'scoring.js');
const staleSource = readFileSync(stalePath, 'utf8');
eq('the control mutation applies', staleSource.includes('dmarc: 30, spf: 15'), true);
writeFileSync(stalePath, staleSource.replace('dmarc: 30, spf: 15', 'dmarc: 30, spf: 1'));
// Deliberately no build({ root: staleRoot }) here.
const stale = await run(staleRoot);
eq('an unbuilt mutation moves no surface — the artifact is what is measured',
  movedSurfaces(first, stale), []);
// And the same mutation, rebuilt, does move. The pair is the evidence.
await build({ root: staleRoot });
const rebuilt = await run(staleRoot);
eq('the same mutation rebuilt moves the result surface',
  movedSurfaces(first, rebuilt).includes('result'), true);
rmSync(staleRoot, { recursive: true, force: true });

/* ── 3. The subject binding ───────────────────────────────────────────── */
section('3. A subject is a complete root');

/**
 * Input hashes are PROVENANCE, not an equivalence surface — the subject under
 * test is by definition not the one the baseline was captured from. What has
 * to hold instead is that the manifest is COMPLETE and STABLE.
 */
const manifestSubject = loadSubject(pristine, {});
const manifestPaths = manifestSubject.manifest.inputs.map(i => i.path);
const { scripts, stylesheets } = readEntryPoints(readFileSync(join(pristine, 'index.html'), 'utf8'));

eq('every script index.html references is hashed',
  scripts.map(s => s.src).filter(src => !manifestPaths.includes(src)), []);
eq('every stylesheet index.html references is hashed',
  stylesheets.filter(href => !manifestPaths.includes(href)), []);
eq('index.html itself is hashed', manifestPaths.includes('index.html'), true);
eq('and nothing else is', manifestPaths.length, scripts.length + stylesheets.length + 1);
eq('every entry carries a sha256 and a byte count',
  manifestSubject.manifest.inputs.filter(i => !/^[0-9a-f]{64}$/.test(i.sha256) || typeof i.bytes !== 'number'), []);

// Stable: the same subject read twice hashes identically.
const secondRead = loadSubject(pristine, {});
eq('re-reading the same subject produces identical hashes',
  JSON.stringify(manifestSubject.manifest.inputs), JSON.stringify(secondRead.manifest.inputs));
eq('and the same platform profile', manifestSubject.manifest.platform, secondRead.manifest.platform);

// Sensitive: a one-byte change to any input changes its hash.
const hashRoot = await makeRoot('hash');
const cssFile = join(hashRoot, 'css', 'style.css');
const beforeHash = loadSubject(hashRoot, {}).manifest.inputs.find(i => i.path === 'css/style.css').sha256;
writeFileSync(cssFile, readFileSync(cssFile, 'utf8') + ' ');
const afterHash = loadSubject(hashRoot, {}).manifest.inputs.find(i => i.path === 'css/style.css').sha256;
eq('a one-byte change to an input changes its hash', beforeHash === afterHash, false);
rmSync(hashRoot, { recursive: true, force: true });


// Changing an asset the JavaScript does not touch must still be visible. A
// runner that paired baseline JavaScript with current-branch CSS would report
// a clean diff across a stylesheet rewrite.
const cssRoot = await makeRoot('css');
const cssPath = join(cssRoot, 'css', 'style.css');
writeFileSync(cssPath, readFileSync(cssPath, 'utf8') + '\n.equivalence-probe{color:red}\n');
// No rebuild: the stylesheet is not an input to the bundle, and that is the
// point — a subject is a complete root, not its JavaScript.
const cssMutated = await run(cssRoot);
eq('a stylesheet-only change moves the report surface and nothing else',
  movedSurfaces(first, cssMutated), ['report']);
rmSync(cssRoot, { recursive: true, force: true });

// And the index.html the subject loads is the subject's own.
const htmlRoot = await makeRoot('html');
const htmlPath = join(htmlRoot, 'index.html');
writeFileSync(htmlPath, readFileSync(htmlPath, 'utf8').replace('dist/app.min.js', 'dist/does-not-exist.js'));
let refused = false;
try { await run(htmlRoot); } catch (error) { refused = /listed in index.html but missing/.test(error.message); }
eq('a script listed in index.html but absent is refused, not skipped', refused, true);
rmSync(htmlRoot, { recursive: true, force: true });

/**
 * Generated data swapped for a fixture table.
 *
 * The runner must refuse to produce surfaces at all rather than emit a baseline
 * that looks authoritative — this is the spike's failure mode moved up a level,
 * where it would poison every later comparison instead of one suite.
 *
 * The wording tolerated below covers every probe form, and deliberately: an
 * artifact that exposes the engine members is refused by the `PSL` probe, and
 * one that exposes only the facade by the `PSL artifact` probe — which is what
 * Task 6.2 turned the second form into when the last adapter took the
 * generated-data globals with it. Which form a subject gets is recorded in its
 * manifest (`subject.fixtureIdentity`), so a regex that admitted only one would
 * start passing for the wrong reason the day another appeared.
 */
const swappedRoot = await makeRoot('swapped');
writeFileSync(join(swappedRoot, 'src', 'data', 'public-suffixes.js'),
  "export const PUBLIC_SUFFIX_RULES = ['com','co.uk','*.ck','!www.ck'];\n");
await build({ root: swappedRoot });
let refusedData = false;
let refusalMessage = '';
try { await run(swappedRoot); } catch (error) {
  refusalMessage = error.message;
  refusedData = /the PSL(?: table| artifact)? binding in force is not the production one/.test(error.message) &&
    /this is exactly the fixture value/.test(error.message);
}
eq('a subject whose generated data was substituted is refused, not measured', refusedData, true);
// And it named the discriminating rule, so whoever reads the failure knows what
// was substituted rather than only that something was.
eq('and the refusal names the rule that diverged',
  /blogspot\.com/.test(refusalMessage), true);
rmSync(swappedRoot, { recursive: true, force: true });

/* ── 4. Ordering, and where its protection now lives ─────────────────── */
section('4. Module evaluation order');

/**
 * The guarantee here is an IMPORT-GRAPH dependency, not textual order in the
 * entry point. A static import's module body is evaluated before the importing
 * module's own body runs, and imports are evaluated in the order they appear —
 * so installing the generated data from an IMPORTED module is a real ordering
 * fact about the graph, while an assignment written above those imports would
 * not be.
 *
 * This section used to build an entry point that installed the generated data
 * AFTER importing its consumers — the ES-hoisting bug this project actually
 * wrote in Phase 2 — and require the artifact to fail its identity probes.
 *
 * It no longer does, and that is a result rather than a regression. Measured:
 * a deliberately hoisted entry produced **30 cases, 5 surfaces, 0 differences**,
 * because `js/dns.js` and `src/i18n/index.js` take their data as arguments
 * instead of reading globals. Task 2.6 finished the job — `js/app.js` was the
 * last reader, and `tests/contract/namespace.test.mjs` now asserts that nothing
 * left under `js/` reaches for a global at all. Nothing evaluates against one,
 * so nothing depends on when they are installed.
 *
 * Asserting a failure that cannot happen would be worse than useless, so the
 * protection lives in that contract: no module under `src/` may read or write
 * one of the 24 watched namespace properties. That catches the hazard
 * COMING BACK, which is the only way it can return.
 *
 * **The generated-data globals are gone as of Task 6.2**, and with them the
 * import this section watched. `src/data/legacy-globals.js` was the last
 * adapter; every consumer of those three names now takes its data as an
 * argument, so there is no installation left to order.
 *
 * What survives is the lesson, asserted where it still bites: the entry point
 * must construct the runtime in its BODY, after every import has evaluated.
 * That is what made the original bug a bug — textual order in an entry point
 * says nothing about evaluation order — and it is still true of anything the
 * body does.
 */
const entry = readFileSync(join(pristine, 'src', 'main.js'), 'utf8');
const lastImportAt = [...entry.matchAll(/^import\b.*$/gm)].pop().index;
const runtimeAt = entry.indexOf('createAuditRuntime({');
eq('the entry point constructs its runtime after every import',
  runtimeAt > lastImportAt, true);
// Comments first: the entry point's header names all three while explaining
// that they were retired, and a scan that counted prose would report the
// opposite of the truth. Second time that shape has bitten in Phase 6.
const entryCode = entry.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
eq('and it installs no generated-data global at all',
  /__PUBLIC_SUFFIX_RULES__|__DKIM_SELECTOR_CATALOG__|__I18N_EN__/.test(entryCode), false);
// Proven able to fire: the names ARE in the file, just not in its code.
eq('while the header does discuss them',
  /__PUBLIC_SUFFIX_RULES__/.test(entry), true);
eq('the namespace contract exists to hold the property this used to test',
  existsSync(join(REPO, 'tests/contract/namespace.test.mjs')), true);

/* ── 5. The two-execution binding, and that it can fail ───────────────── */
section('5. The cross-surface binding between the two executions');

/**
 * Spec §8 as of `1.4`: the five surfaces come from one deterministic case
 * captured by TWO isolated executions — the facade for the result, the real UI
 * controls for the other four — because `globalName` makes the bundle global an
 * export namespace that is not the engine the UI calls.
 *
 * What one process image used to guarantee for free, the binding now asserts.
 * So the binding itself needs the treatment every check in this project gets:
 * **watched failing before it is trusted.** A binding that cannot fail would
 * let two different cases be joined under one case id and report clean.
 *
 * The pairs below are built by taking a REAL pair, from the run above, and
 * damaging one side. That matters — a control assembled from hand-written
 * literals would prove the function parses its arguments, not that it discovers
 * a mismatch in the shapes this runner actually produces.
 */
const bound = first.get('enforcing-signed');
const boundCase = cases.find(c => c.id === 'enforcing-signed');

// The shape the binding reads on the UI side: the DOM, and only the DOM. See
// the rule in bindExecutions() about what may be compared there.
const uiOf = surfaces => ({ dom: surfaces.dom });
const auditsOf = surfaces => Object.values(surfaces.result).map(entry => ({
  domain: entry.domain,
  outcome: entry.outcome,
  result: entry.result,
}));

const realAudits = auditsOf(bound);
const realUi = uiOf(bound);

eq('the real pair binds cleanly', bindExecutions(boundCase, realAudits, realUi), []);
// And it is not vacuous: the pair it just approved has something to compare.
eq('and it had domains to compare', realAudits.length > 0, true);
eq('with a graded result among them',
  realAudits.some(a => a.result && a.result.score && a.result.score.grade), true);

const damaged = (mutate) => {
  const audits = JSON.parse(JSON.stringify(realAudits));
  const ui = { dom: [...realUi.dom] };
  mutate(audits, ui);
  return bindExecutions(boundCase, audits, ui);
};

eq('a result-execution grade that disagrees with the UI is caught',
  damaged(audits => { audits[0].result.score.grade = 'F'; }).some(p => /grade/.test(p)), true);
eq('a result-execution score that disagrees with the rendered one is caught',
  damaged(audits => { audits[0].result.score.pts = 1; }).some(p => /score/.test(p)), true);
eq('a domain the UI never rendered is caught',
  damaged(audits => { audits[0].domain = 'somewhere.else.test'; }).some(p => /domain sets differ/.test(p)), true);
eq('a domain the result execution never audited is caught',
  damaged(audits => { audits.pop(); }).some(p => /domain sets differ/.test(p)), true);
eq('a finding set of a different size is caught',
  damaged(audits => { audits[0].result.findings = []; }).some(p => /finding count/.test(p)), true);
eq('and a suggestion set of a different size',
  damaged(audits => { audits[0].result.suggestions = [{ key: 'invented' }]; }).some(p => /suggestion count/.test(p)), true);
// The UI side can be the wrong one too — the binding is symmetric about which
// execution drifted, because it cannot know which.
eq('a UI row whose grade moved is caught',
  damaged((audits, ui) => {
    ui.dom = ui.dom.map(line => line.replace('data-grade="A++"', 'data-grade="B"'));
  }).some(p => /grade/.test(p)), true);

/**
 * Isolation: the result execution must not warm the UI execution's cache.
 *
 * The trace surface is the observable that would move if it did — a warmed
 * cache means fewer queries — and the run above already answers it against the
 * committed baseline, which was captured when ONE execution produced all five
 * surfaces. Stated here as an assertion rather than left implicit in "0
 * differences", because cache scope is Risk R10 and a query-trace difference
 * with an identical result is a stop.
 */
const cacheCase = first.get('cache-reuse-siblings');
const baselineCache = JSON.parse(
  readFileSync(join(REPO, 'tests/fixtures/equivalence/baseline-v0.5.0.json'), 'utf8'))
  .cases.find(c => c.id === 'cache-reuse-siblings');
eq('the sibling-cache case still reports a trace', !!cacheCase.trace, true);
eq('and its total query count is what the single-execution baseline recorded',
  cacheCase.trace.total, baselineCache.trace.total);
eq('and its distinct query count too — a warmed cache would lower one and not the other',
  cacheCase.trace.distinct, baselineCache.trace.distinct);
eq('and the DMARC walk order is unchanged',
  serialize(cacheCase.trace.dmarcWalk), serialize(baselineCache.trace.dmarcWalk));

rmSync(pristine, { recursive: true, force: true });
report();
