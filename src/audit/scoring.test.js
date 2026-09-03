#!/usr/bin/env node
/**
 * The scoring model. Task 5.3.
 *
 * Two things are worth pinning here and they are different in kind.
 *
 * **The numbers**, because Gate 5's first condition is that they are
 * byte-identical to `v0.5.0`. The literals below are not typed from memory:
 * they were read out of `git show v0.5.0:js/dns.js` by the explicit diff
 * recorded in the implementation log, which compares `JSON.stringify` of each
 * constant on both sides and was proven to fail on a single changed weight
 * before it was believed.
 *
 * **The input boundary**, because it is the thing most likely to be argued
 * about later: scoring reads protocol FACTS and never records. §5 asserts that
 * directly rather than describing it.
 */

import { createSuite } from '../../tests/lib/assert.mjs';
import { POLICY_RANK } from '../core/dmarc/record.js';
import { createHash } from 'node:crypto';
import { stripComments, normalizeSource } from '../../tests/lib/source.mjs';
import {
  ANALYSIS_VERSION,
  WEIGHTS, PARKED_WEIGHTS, GRADE_THRESHOLDS,
  calcScore, calcDmarcScore, calcSpfScore, gradeFor, calcAdvScore,
} from './scoring.js';

const { eq, section, report } = createSuite();

/* ── 1. The weights, as v0.5.0 published them ─────────────────────────── */
section('1. Byte-identical to v0.5.0');

eq('the eight pillar weights are unchanged', WEIGHTS,
  { dmarc: 30, spf: 15, dkim: 15, dnssec: 15, caa: 10, mtaSts: 8, bimi: 4, tlsRpt: 3 });
eq('and they still total 100', Object.values(WEIGHTS).reduce((a, b) => a + b, 0), 100);
eq('the parked weights are unchanged', PARKED_WEIGHTS, { spf: 30, dmarc: 30, dnssec: 25, caa: 15 });
eq('and they total 100 too', Object.values(PARKED_WEIGHTS).reduce((a, b) => a + b, 0), 100);
// Not frozen, and asserted so rather than left to be assumed from `const`.
// These are legacy engine members published as plain objects; freezing them
// would be a compatibility delta wearing the word "constant".
eq('the rubric is exported as plain data, not frozen',
  [Object.isFrozen(WEIGHTS), Object.isFrozen(PARKED_WEIGHTS), Object.isFrozen(GRADE_THRESHOLDS)],
  [false, false, false]);
// Ordering is part of what matches v0.5.0: the grade tiers are scanned in
// order and the first `min` a score clears decides the grade.
eq('the pillar keys are in their published order',
  Object.keys(WEIGHTS), ['dmarc', 'spf', 'dkim', 'dnssec', 'caa', 'mtaSts', 'bimi', 'tlsRpt']);
eq('and the tiers descend', GRADE_THRESHOLDS.map(t => t.min), [85, 75, 65, 50, 30, 10, 0]);
eq('the seven grade tiers are unchanged', GRADE_THRESHOLDS, [
  { min: 85, grade: 'A++', cls: 'score-aplusplus', requiresDnssec: true },
  { min: 75, grade: 'A+', cls: 'score-aplus', requiresDnssec: true },
  { min: 65, grade: 'A', cls: 'score-a', requiresDnssec: true },
  { min: 50, grade: 'B', cls: 'score-b', requiresDnssec: false },
  { min: 30, grade: 'C', cls: 'score-c', requiresDnssec: false },
  { min: 10, grade: 'D', cls: 'score-d', requiresDnssec: false },
  { min: 0, grade: 'F', cls: 'score-f', requiresDnssec: false },
]);
// POLICY_RANK is `core/dmarc/`'s, not this module's — it moved at Task 4.6 and
// the implementation plan lists it here only because it was still in
// `js/dns.js` when the plan was written. Its value is in the same diff.
eq('the DMARC policy ranks are unchanged', POLICY_RANK, { none: 0, quarantine: 1, reject: 2 });

/* ── 2. The two asymmetric pillars ────────────────────────────────────── */
section('2. DNSSEC gates the A tier, and DMARC carries the most weight');

// An unsigned zone means every record above it can be spoofed, so DNSSEC is
// not merely additive: it is a gate on the top three tiers.
eq('an unsigned zone cannot reach A however high it scores', gradeFor(100, false).grade, 'B');
eq('while a signed one can', gradeFor(100, true).grade, 'A++');
eq('and the gate applies at every tier above B',
  [gradeFor(85, false).grade, gradeFor(75, false).grade, gradeFor(65, false).grade], ['B', 'B', 'B']);
eq('B and below are reachable unsigned',
  [gradeFor(50, false).grade, gradeFor(30, false).grade, gradeFor(10, false).grade, gradeFor(0, false).grade],
  ['B', 'C', 'D', 'F']);
eq('the class travels with the grade', gradeFor(0, false).cls, 'score-f');
eq('DMARC is the largest single pillar',
  Math.max(...Object.values(WEIGHTS)) === WEIGHTS.dmarc, true);

/* ── 3. calcDmarcScore ────────────────────────────────────────────────── */
section('3. calcDmarcScore');

const dmarc = (over = {}) => calcDmarcScore({
  status: 'ok', policy: 'reject', effectiveSp: 'reject', effectiveNp: 'reject',
  rua: ['mailto:a@e.test'], ruf: [], adkim: 's', aspf: 's', testMode: false, ...over,
});
eq('a full policy is capped at the DMARC weight', dmarc().pts <= WEIGHTS.dmarc, true);
eq('and p=none scores below p=reject', dmarc({ policy: 'none', effectiveSp: 'none', effectiveNp: 'none' }).pts < dmarc().pts, true);
eq('the breakdown names its parts',
  Object.keys(dmarc().parts).sort(), ['alignment', 'policy', 'rua', 'ruf', 'subdomain', 'uris']);
// `t=y` is the operator saying "do not act on this yet", so the subdomain
// posture collapses to the none-equivalent tier — 1 point, not 0. Probed
// before it was asserted: the obvious guess was zero, and the code does not
// say that. The three tiers are [none, quarantine, reject] = [1, 4, 6].
eq('test mode collapses the subdomain component to the none tier',
  dmarc({ testMode: true }).parts.subdomain, 1);
eq('which is what an effective none scores anyway',
  dmarc({ testMode: true }).parts.subdomain,
  dmarc({ effectiveSp: 'none', effectiveNp: 'none' }).parts.subdomain);
eq('and is less than an enforcing one', dmarc({ testMode: true }).parts.subdomain < dmarc().parts.subdomain, true);
// The weakest link, not the average: sp and np are taken at their minimum.
eq('the weaker of sp and np decides',
  dmarc({ effectiveSp: 'reject', effectiveNp: 'none' }).parts.subdomain,
  dmarc({ effectiveSp: 'none', effectiveNp: 'none' }).parts.subdomain);

/* ── 4. calcSpfScore, and the bands it does not blur ──────────────────── */
section('4. calcSpfScore');

const spf = (over = {}) => calcSpfScore({ status: 'ok', warnings: [], ...over }, null);
eq('-all earns the full pillar', spf(), WEIGHTS.spf);
eq('~all earns less', spf({ status: 'softfail' }), 10);
eq('a record that is merely present earns least', spf({ status: 'present' }), 8);
eq('no record at all earns nothing', spf({ status: 'missing' }), 0);
eq('and a permerror earns nothing', spf({ status: 'permerror' }), 0);
eq('a missing status object earns nothing rather than throwing', calcSpfScore(null, null), 0);
// A record that passes everything and permits the whole internet is worth
// nothing, which is a scoring judgement about an SPF fact.
eq('+all is worth nothing despite an ok status', spf({ warnings: ['spf-all-permit'] }), 0);
eq('and so is ?all', spf({ warnings: ['spf-neutral'] }), 0);
eq('an unrelated warning costs nothing', spf({ warnings: ['spf-softfail'] }), WEIGHTS.spf);
// A lookup count that BLEW the limit zeroes the pillar; one that is merely
// unknown does not, which is why `unprovenPillars` deliberately omits SPF.
eq('a lookup-limit error zeroes the pillar',
  calcSpfScore({ status: 'ok', warnings: [] }, { spfLookups: { error: true } }), 0);
eq('while an unknown count does not',
  calcSpfScore({ status: 'ok', warnings: [] }, { spfLookups: { unknown: true } }), WEIGHTS.spf);

/* ── 5. THE INPUT BOUNDARY: facts in, points out ──────────────────────── */
section('5. Scoring reads protocol facts, never records');

/**
 * Ruled at Task 5.3 and asserted here rather than in
 * `dns-transport.test.mjs` §3b, which protects a different thing: §3b is the
 * parsing-owner inventory, and a weight table is not a parsing rule.
 *
 * `calcSpfScore()` reading `spfStatus.warnings` is the question that prompted
 * the ruling. The tokens are `core/spf/`'s — it produced them from the record
 * — and this module interprets what they are WORTH. The owner decides what a
 * record MEANS; scoring decides what a meaning COSTS. Those are different jobs
 * and this is the second one.
 *
 * The line scoring may not cross is re-deriving a fact from a record. The
 * assertions below make that testable: the facts are fabricated, no record was
 * ever parsed to produce them, and a record attached to the same facts changes
 * nothing — including a record that flatly contradicts them.
 */

// 1. A status object no parser produced still scores. If scoring re-derived
//    anything it would have nothing to re-derive it from.
eq('scoring works on a fabricated fact with no record behind it',
  calcSpfScore({ status: 'ok', warnings: [] }, null), WEIGHTS.spf);

// 2. The record is not an input. Attaching one changes nothing...
const facts = { status: 'ok', warnings: [] };
eq('attaching the record that produced the facts changes nothing',
  calcSpfScore({ ...facts, record: 'v=spf1 -all' }, null), calcSpfScore(facts, null));
// ...and neither does attaching one that contradicts them, which is the
// assertion that would fail if this module ever read the record.
eq('and attaching a record that contradicts them changes nothing either',
  calcSpfScore({ ...facts, record: 'v=spf1 +all' }, null), WEIGHTS.spf);
eq('while the FACT for that record does', spf({ warnings: ['spf-all-permit'] }), 0);

// 3. The same, one level up: the whole audit result is scored from facts.
const scored = calcScore({
  emailProvider: 'Google Workspace',
  spfStatus: { status: 'ok', warnings: [] },
  dkimStatus: { found: true },
  dmarcStatus: { status: 'ok', policy: 'reject', effectiveSp: 'reject', effectiveNp: 'reject', rua: ['mailto:a@e.test'], ruf: [], adkim: 's', aspf: 's' },
  advanced: { caa: { found: true }, dnssec: { signed: true }, mtaSts: { present: true, policyVerified: true }, bimi: { present: true }, tlsRpt: { present: true } },
});
eq('a complete result scores out of 100', scored.max, 100);
eq('and every pillar is keyed by name',
  scored.breakdown.pillars.map(p => p.key),
  ['dmarc', 'spf', 'dkim', 'dnssec', 'caa', 'mtaSts', 'bimi', 'tlsRpt']);
eq('each pillar names the weight it is measured against',
  scored.breakdown.pillars.map(p => p.max),
  ['dmarc', 'spf', 'dkim', 'dnssec', 'caa', 'mtaSts', 'bimi', 'tlsRpt'].map(k => WEIGHTS[k]));
// Not a single record string reached any of that.
eq('no record text appears anywhere in the scored result',
  JSON.stringify(scored).includes('v=spf1'), false);

/* ── 6. The parked rubric is a different rubric ───────────────────────── */
section('6. A domain that will never send mail is scored differently');

const parked = calcScore({
  emailProvider: '@null-mx',
  spfStatus: { status: 'ok', warnings: [] },
  dkimStatus: { found: false },
  dmarcStatus: { status: 'ok', policy: 'reject', effectivePolicy: 'reject' },
  advanced: { caa: { found: true }, dnssec: { signed: true } },
});
eq('a null-MX domain is scored as parked', parked.parked, true);
eq('and its pillars are the four that can apply',
  parked.breakdown.pillars.map(p => p.key), ['spf', 'dmarc', 'dnssec', 'caa']);
eq('measured against the parked weights',
  parked.breakdown.pillars.map(p => p.max), [30, 30, 25, 15]);
eq('while an ordinary domain is not parked', scored.parked, false);

/* ── 7. calcAdvScore ──────────────────────────────────────────────────── */
section('7. calcAdvScore: an unverifiable check leaves the denominator');

eq('no advanced data is no advanced score', calcAdvScore(null), null);
eq('five checks, none done',
  calcAdvScore({ bimi: {}, mtaSts: {}, tlsRpt: {}, caa: {}, dnssec: {} }),
  { done: 0, total: 5, unknown: 0 });
eq('a done check counts',
  calcAdvScore({ bimi: { present: true }, mtaSts: {}, tlsRpt: {}, caa: {}, dnssec: {} }).done, 1);
// A check whose lookup failed is neither done nor outstanding, so it comes out
// of the denominator rather than counting against the domain.
const unknown = calcAdvScore({ bimi: { unknown: true }, mtaSts: {}, tlsRpt: {}, caa: {}, dnssec: {} });
eq('an unknown check leaves the total', unknown.total, 4);
eq('and is reported as unknown', unknown.unknown, 1);
eq('an indeterminate DNSSEC chain counts as unknown too',
  calcAdvScore({ bimi: {}, mtaSts: {}, tlsRpt: {}, caa: {}, dnssec: { state: 'indeterminate' } }).total, 4);
// MTA-STS is the one pillar scored on `policyVerified`, not `present`,
// because the policy file itself is never fetched.
eq('MTA-STS counts as done only when its policy is verified',
  calcAdvScore({ bimi: {}, mtaSts: { present: true }, tlsRpt: {}, caa: {}, dnssec: {} }).done, 0);

/* ── The analysis version and its drift guard ─────────────────────────── */
section('The analysis version (report-comparison 1.6 §2)');

eq('ANALYSIS_VERSION is a positive integer', [
  Number.isInteger(ANALYSIS_VERSION), ANALYSIS_VERSION > 0,
], [true, true]);
eq('and 0.9.0 ships version 1', ANALYSIS_VERSION, 1);

/**
 * The rubric drift guard.
 *
 * Fingerprints the rubric's own definition — the three constants as data, the
 * four scoring functions as source — so a changed weight, threshold or branch
 * fails here with an instruction rather than silently making every previously
 * exported report's score delta a lie.
 *
 * **Comments are stripped first**, per the framework rule that a check over
 * source text must, "because the file most likely to discuss a thing is the one
 * that just stopped doing it." These four functions carry 39 line comments
 * between them, so without stripping, editing a comment would demand an
 * `ANALYSIS_VERSION` bump that no score movement justifies — and a guard that
 * cries wolf gets its hash re-pinned without thought, which is the same as not
 * having one.
 *
 * **What this cannot catch, stated rather than left to be discovered:** a
 * DISCOVERY change outside this file. 0.3.0 replaced the Public Suffix List
 * with the RFC 9989 Tree Walk and moved scores with all three constants
 * untouched; a fingerprint of `scoring.js` sees nothing. That half is caught by
 * the standing backtest rule in `AGENTS.md` — a backtest showing grade or score
 * movement requires a bump in the same release. This guard is the mechanical
 * half of a two-part rule, not the whole of it.
 */


function rubricFingerprint(constants, fnSources) {
  return createHash('sha256')
    .update(constants.concat(fnSources.map(normalizeSource)).join('\n'))
    .digest('hex');
}

const RUBRIC_CONSTANTS = [
  JSON.stringify(WEIGHTS), JSON.stringify(PARKED_WEIGHTS), JSON.stringify(GRADE_THRESHOLDS),
];
const RUBRIC_FUNCTIONS = [
  calcDmarcScore.toString(), calcSpfScore.toString(),
  calcAdvScore.toString(), calcScore.toString(),
];

eq('the rubric is unchanged — if this fails, bump ANALYSIS_VERSION in scoring.js '
  + 'and record the score movement in the release notes',
rubricFingerprint(RUBRIC_CONSTANTS, RUBRIC_FUNCTIONS), '9ff1b3775ffdf0f20e706954fd6a92929b367c20fc28c6169f6ed6dc1613c80b');

/* ── The negative controls the guard ships with ───────────────────────── */
section('The drift guard, proven to fail (AGENTS.md framework rule 3)');

const REAL = rubricFingerprint(RUBRIC_CONSTANTS, RUBRIC_FUNCTIONS);

// Vacuity control first: a fingerprint that changed on every call would make
// every assertion below pass while detecting nothing.
eq('an unchanged rubric fingerprints identically',
  rubricFingerprint(RUBRIC_CONSTANTS, RUBRIC_FUNCTIONS), REAL);

// 1. A changed weight.
const bumpedWeights = [
  JSON.stringify({ ...WEIGHTS, dmarc: WEIGHTS.dmarc + 1 }),
  RUBRIC_CONSTANTS[1], RUBRIC_CONSTANTS[2],
];
eq('a changed pillar weight moves the fingerprint',
  rubricFingerprint(bumpedWeights, RUBRIC_FUNCTIONS) !== REAL, true);

// 2. A changed grade threshold.
const bumpedThresholds = [
  RUBRIC_CONSTANTS[0], RUBRIC_CONSTANTS[1],
  JSON.stringify(GRADE_THRESHOLDS.map((t, i) => (i === 0 ? { ...t, min: t.min + 1 } : t))),
];
eq('a changed grade threshold moves the fingerprint',
  rubricFingerprint(bumpedThresholds, RUBRIC_FUNCTIONS) !== REAL, true);

// 3. THE UNIQUE DETECTION. A logic change inside a function body, with every
// constant byte-identical — the class of change no other assertion in this
// suite catches, which is the entire reason the fingerprint exists. The
// statement and the comment in control 4 are injected at the SAME point in the
// SAME real function, so the pair isolates exactly one variable.
const INJECT_AT = RUBRIC_FUNCTIONS[1].indexOf('{') + 1;
const withStatement = RUBRIC_FUNCTIONS[1].slice(0, INJECT_AT)
  + '\n  var driftProbe = 1;' + RUBRIC_FUNCTIONS[1].slice(INJECT_AT);
const bodyMutated = [RUBRIC_FUNCTIONS[0], withStatement, RUBRIC_FUNCTIONS[2], RUBRIC_FUNCTIONS[3]];
eq('a function-body change moves the fingerprint',
  rubricFingerprint(RUBRIC_CONSTANTS, bodyMutated) !== REAL, true);
eq('and that case changed no constant at all',
  RUBRIC_CONSTANTS, [JSON.stringify(WEIGHTS), JSON.stringify(PARKED_WEIGHTS), JSON.stringify(GRADE_THRESHOLDS)]);

// 4. The converse control: a COMMENT at that same point must NOT move it.
const withComment = RUBRIC_FUNCTIONS[1].slice(0, INJECT_AT)
  + '\n  // a remark about scoring that changes no behaviour' + RUBRIC_FUNCTIONS[1].slice(INJECT_AT);
const commentOnly = [RUBRIC_FUNCTIONS[0], withComment, RUBRIC_FUNCTIONS[2], RUBRIC_FUNCTIONS[3]];
eq('a comment at the same point does not',
  rubricFingerprint(RUBRIC_CONSTANTS, commentOnly), REAL);
eq('and the two probes really were different text',
  withStatement !== withComment && withStatement !== RUBRIC_FUNCTIONS[1], true);

/* ── The stripper itself ──────────────────────────────────────────────── */
section('The comment stripper, and its one blind spot proven absent');

eq('it removes a line comment', normalizeSource('a; // gone\nb;').includes('gone'), false);
eq('it removes a block comment', normalizeSource('a; /* gone */ b;').includes('gone'), false);
// The bug this pair exists to prevent: a comment sits on its own line, so
// removing it must not leave the whitespace run split in two.
eq('a comment on its own line normalizes to exactly the code without it',
  normalizeSource('f() {\n  // remark\n  var x = 1;\n}'), normalizeSource('f() {\n  var x = 1;\n}'));
// The reason it is a scanner rather than a regex: a comment sequence inside a
// string literal is code, not a comment.
eq('it leaves a comment sequence inside a string alone',
  normalizeSource('var u = "http://x"; // gone').includes('http://x'), true);
eq('single, double and backtick quotes are all respected',
  ["'//a'", '"//b"', '`//c`'].map(s => normalizeSource('var x = ' + s + ';').includes('//')),
  [true, true, true]);
eq('an escaped quote does not end the string',
  normalizeSource('var x = "a\\"// still string";').includes('// still string'), true);
eq('whitespace outside a string collapses', normalizeSource('a;\n\n   b;'), 'a; b;');
eq('but whitespace inside a string is code and survives',
  normalizeSource('var x = "a   b";'), 'var x = "a   b";');
eq('normalizing is idempotent',
  RUBRIC_FUNCTIONS.map(src => normalizeSource(normalizeSource(src)) === normalizeSource(src)),
  [true, true, true, true]);
// The blind spot: a regex literal containing `//` would be mangled. Rather than
// assume none is present, assert it — if scoring ever grows one, this fails and
// the stripper gets a tokenizer.
eq('no hashed function contains a regex literal for the scanner to trip on',
  RUBRIC_FUNCTIONS.filter(src => /[=(,:[]\s*\/(?![/*])/.test(src)), []);
// And the stripped output is still real code, which a mangling stripper would
// not produce.
eq('every stripped function still parses',
  RUBRIC_FUNCTIONS.map((src) => {
    try { new Function('return (' + normalizeSource(src) + ')'); return true; } catch (e) { return false; }
  }), [true, true, true, true]);

report();
