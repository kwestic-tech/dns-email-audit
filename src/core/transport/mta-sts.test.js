#!/usr/bin/env node
/**
 * MTA-STS record validation (RFC 8461 §3.1). Task 4.4.
 *
 * Two rules pull in opposite directions and both were once wrong:
 *
 *  - the record is ORDERED and the version literal is case-SENSITIVE, so
 *    `id=abc; v=STSv1` and `v=stsv1` are unusable and both once validated;
 *  - a DUPLICATED non-repeated field is conformant — §3.1 says parsers MUST
 *    accept it and ignore all but the first — so a blanket duplicate rejection
 *    called a good record invalid, and then reported the LAST id as effective,
 *    the one every sender discards.
 *
 * Getting either wrong suppressed `mta-sts-invalid`, a finding whose entire
 * purpose is to catch a control the operator believes is working.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import {
  validateMtaStsRecord, MTA_STS_ERRORS, summarizeMtaSts,
} from './mta-sts.js';
import {
  validateMtaStsPolicy, compareMtaStsMx, mxComparisonApplies,
  policyFindingScope, MTA_STS_POLICY_SCOPES,
  MTA_STS_POLICY_ERRORS, MTA_STS_POLICY_WARNINGS,
  MTA_STS_POLICY_LINE_ENDINGS, MTA_STS_MX_COMPARE_STATES,
} from './mta-sts-policy.js';

const { eq, section, report } = createSuite();

/* ── 1. The published error vocabulary ────────────────────────────────── */
section('1. State constants');

eq('one error token', [...MTA_STS_ERRORS], ['invalid-syntax']);
eq('and it is frozen', Object.isFrozen(MTA_STS_ERRORS), true);
eq('a valid record emits nothing', validateMtaStsRecord('v=STSv1; id=20200101').errors, []);
eq('an invalid one emits the member', validateMtaStsRecord('nonsense').errors, ['invalid-syntax']);

/* ── 2. Version first, and exact ──────────────────────────────────────── */
section('2. v=STSv1');

eq('a conforming record is valid', validateMtaStsRecord('v=STSv1; id=20200101').valid, true);
eq('and reports its id', validateMtaStsRecord('v=STSv1; id=20200101').id, '20200101');
eq('lowercase v=stsv1 is not the version', validateMtaStsRecord('v=stsv1; id=a').valid, false);
eq('the version must come FIRST', validateMtaStsRecord('id=abc; v=STSv1').valid, false);
eq('an empty record is not one', validateMtaStsRecord('').valid, false);
eq('undefined is not one', validateMtaStsRecord(undefined).valid, false);
eq('a bare token is not a field list', validateMtaStsRecord('garbage').valid, false);
// `id` is required. A version alone advertises nothing a sender can use.
eq('a record with no id is invalid', validateMtaStsRecord('v=STSv1').valid, false);
eq('and an empty id is too', validateMtaStsRecord('v=STSv1; id=').valid, false);

/* ── 3. sts-id = 1*32(ALPHA / DIGIT) ──────────────────────────────────── */
section('3. The id grammar');

eq('alphanumerics are an id', validateMtaStsRecord('v=STSv1; id=abc123').valid, true);
eq('32 characters is the limit',
  validateMtaStsRecord(`v=STSv1; id=${'a'.repeat(32)}`).valid, true);
eq('33 is not', validateMtaStsRecord(`v=STSv1; id=${'a'.repeat(33)}`).valid, false);
eq('a hyphen is not an ALPHA or DIGIT',
  validateMtaStsRecord('v=STSv1; id=has-hyphen').valid, false);
eq('nor is an underscore', validateMtaStsRecord('v=STSv1; id=has_underscore').valid, false);
eq('and the bad id is still reported, so the operator can see what they published',
  validateMtaStsRecord('v=STSv1; id=has-hyphen').id, 'has-hyphen');

/* ── 4. A duplicate is conformant, and the FIRST wins ─────────────────── */
section('4. RFC 8461 §3.1 duplicate handling');

const duplicated = validateMtaStsRecord('v=STSv1; id=first; id=second');
eq('a duplicated id does NOT invalidate the record', duplicated.valid, true);
// The half that matters: reporting `second` names the id every sender throws
// away, so the effective id and the reported id would disagree.
eq('and the FIRST id is the effective one', duplicated.id, 'first');
eq('a duplicated v= is ignored rather than fatal',
  validateMtaStsRecord('v=STSv1; id=a; v=STSv1').valid, true);
// A duplicate is ignored, not excused: the first copy still has to be valid.
eq('but the first copy still has to parse',
  validateMtaStsRecord('v=STSv1; id=has-hyphen; id=good').valid, false);

/* ── 5. Extensions ────────────────────────────────────────────────────── */
section('5. Extension fields');

eq('a well-formed extension is accepted',
  validateMtaStsRecord('v=STSv1; id=a; ext=value').valid, true);
// A bare token is not an extension: the grammar requires a name AND a value,
// so it cannot be dropped silently.
eq('a bare token is not an extension',
  validateMtaStsRecord('v=STSv1; id=a; garbage').valid, false);
eq('an extension name outside the production is not one',
  validateMtaStsRecord('v=STSv1; id=a; _ext=value').valid, false);
eq('nor is a 33-character name',
  validateMtaStsRecord(`v=STSv1; id=a; ${'e'.repeat(33)}=value`).valid, false);
eq('an empty extension value is not one',
  validateMtaStsRecord('v=STSv1; id=a; ext=').valid, false);

/**
 * The value class MTA-STS and TLS-RPT share and BIMI does not. `bimi.test.js`
 * asserts the same record shape is VALID there; this is the other half, and
 * together they are why `RECORD_EXT_VALUE` stayed in `core/transport/` while
 * `EXT_NAME` moved to `core/shared/`.
 */
eq('an = inside an extension value is refused here',
  validateMtaStsRecord('v=STSv1; id=a; ext=a=b').valid, false);
eq('and so is a space', validateMtaStsRecord('v=STSv1; id=a; ext=a b').valid, false);

/* ── 6. field-delim, under strict field syntax ────────────────────────── */
section('6. Whitespace');

// The ABNF writes its fields as single literals — `%s"v=STSv1"`, `%s"id="` —
// none of which admits whitespace around the `=`.
eq('whitespace around the delimiter is the delimiter',
  validateMtaStsRecord('v=STSv1 ;  id=abc').valid, true);
eq('but whitespace around the = is not', validateMtaStsRecord('v = STSv1; id=abc').valid, false);
eq('and not on the id either', validateMtaStsRecord('v=STSv1; id = abc').valid, false);
eq('one trailing delimiter is permitted', validateMtaStsRecord('v=STSv1; id=abc;').valid, true);


/* ── The whole MTA-STS answer, moved here at Task 5.2a ────────────────── */
section('summarizeMtaSts');

const live = summarizeMtaSts(['v=STSv1; id=20260101']);
eq('a conforming record is present', live.present, true);
eq('and advertised', live.advertised, true);
// This checks the DNS record only. Fetching the policy file over HTTPS is a
// request this tool does not make, and the field keeps that visible.
eq('the policy file is never claimed as verified', live.policyVerified, false);

// RFC 8461 §3.1: not exactly one means the domain does not have the feature.
const dup = summarizeMtaSts(['v=STSv1; id=1', 'v=STSv1; id=2']);
eq('a duplicated record is not present', dup.present, false);
eq('and says so', dup.multiple, true);

// An auditor reports what is published; a sender discards it.
const trailing = summarizeMtaSts(['id=1; v=STSv1']);
eq('a version field that is not first is still shown', trailing.record, 'id=1; v=STSv1');
eq('and advertised', trailing.advertised, true);
eq('but not present', trailing.present, false);

eq('a domain with no record advertises nothing', summarizeMtaSts([]).advertised, false);
eq('a failed lookup is unknown', summarizeMtaSts(null).unknown, true);
eq('while an empty answer is not', summarizeMtaSts([]).unknown, false);

/* ── The user-supplied policy body (RFC 8461 §3.2) ───────────────────── */
section('validateMtaStsPolicy');

eq('the policy error vocabulary is frozen',
  [Object.isFrozen(MTA_STS_POLICY_ERRORS), [...MTA_STS_POLICY_ERRORS]],
  [true, [
    'malformed-line', 'blank-line',
    'invalid-version', 'invalid-mode', 'invalid-mx', 'invalid-max-age',
    'missing-version', 'missing-mode', 'missing-max-age', 'missing-mx',
  ]]);
eq('the policy warning vocabulary is frozen',
  [Object.isFrozen(MTA_STS_POLICY_WARNINGS), [...MTA_STS_POLICY_WARNINGS]],
  [true, ['duplicate-field', 'bom-present', 'wrong-case-field']]);
eq('the line-ending vocabulary is frozen',
  [Object.isFrozen(MTA_STS_POLICY_LINE_ENDINGS), [...MTA_STS_POLICY_LINE_ENDINGS]],
  [true, ['crlf', 'lf', 'mixed', 'none']]);
eq('the MX comparison vocabulary is frozen',
  [Object.isFrozen(MTA_STS_MX_COMPARE_STATES), [...MTA_STS_MX_COMPARE_STATES]],
  [true, ['compared', 'unknown', 'null-mx']]);
// `null-mx` was held out of this vocabulary until `deliveryCandidates()` in
// src/audit/artifacts.js existed to produce it, and joined in the same commit
// as that producer — never as a member no fixture could reach.
eq('null-mx is a member now that a producer derives it',
  MTA_STS_MX_COMPARE_STATES.includes('null-mx'), true);

const POLICY = [
  'version: STSv1',
  'mode: enforce',
  'mx: mail.example.test',
  'mx: *.backup.example.test',
  'max_age: 604800',
].join('\r\n');
const policy = validateMtaStsPolicy(POLICY);
eq('a conforming policy is valid', policy.valid, true);
eq('and exposes its fields',
  [policy.version, policy.mode, policy.maxAge], ['STSv1', 'enforce', 604800]);
eq('repeated mx fields survive in order', policy.mx,
  ['mail.example.test', '*.backup.example.test']);
eq('CRLF is recorded', policy.lineEndings, 'crlf');

eq('LF is valid under the normative ABNF',
  validateMtaStsPolicy(POLICY.replace(/\r\n/g, '\n')).valid, true);
eq('and mixed terminators are valid and recorded',
  validateMtaStsPolicy(POLICY.replace(/\r\n/, '\n')).lineEndings, 'mixed');
eq('version need not be first in the policy body',
  validateMtaStsPolicy('mode: none\nmax_age: 0\nversion: STSv1').valid, true);
eq('max_age zero is valid',
  validateMtaStsPolicy('version: STSv1\nmode: none\nmax_age: 0').maxAge, 0);
eq('a wrong policy version is reported specifically',
  validateMtaStsPolicy('version: stsv1\nmode: none\nmax_age: 1').errors,
  ['invalid-version']);
eq('a missing version is reported specifically',
  validateMtaStsPolicy('mode: none\nmax_age: 1').errors,
  ['missing-version']);
eq('a missing mode is reported specifically',
  validateMtaStsPolicy('version: STSv1\nmax_age: 1').errors,
  ['missing-mode']);
eq('a missing max_age is reported specifically',
  validateMtaStsPolicy('version: STSv1\nmode: none').errors,
  ['missing-max-age']);
eq('but the RFC maximum may not be exceeded',
  validateMtaStsPolicy('version: STSv1\nmode: none\nmax_age: 31557601').errors,
  ['invalid-max-age']);

const duplicateMode = validateMtaStsPolicy(
  'version: STSv1\nmode: testing\nmode: enforce\nmx: mail.example.test\nmax_age: 1');
eq('a later duplicate non-mx field is ignored', duplicateMode.valid, true);
eq('the first duplicate value wins', duplicateMode.mode, 'testing');
eq('and the duplicate is exposed as a hygiene diagnostic',
  [duplicateMode.duplicateKeys, duplicateMode.warnings], [['mode'], ['duplicate-field']]);

const extended = validateMtaStsPolicy(
  'version: STSv1\nmode: none\nmax_age: 1\nextension-name: value');
eq('a syntactically valid extension is ignored for validity', extended.valid, true);
eq('and retained for display', extended.unknownKeys, ['extension-name']);

eq('enforce requires an mx field',
  validateMtaStsPolicy('version: STSv1\nmode: enforce\nmax_age: 1').errors,
  ['missing-mx']);
eq('none does not require mx',
  validateMtaStsPolicy('version: STSv1\nmode: none\nmax_age: 1').valid, true);
eq('a wildcard is allowed only as the complete left-most label',
  validateMtaStsPolicy('version: STSv1\nmode: enforce\nmx: mail.*.test\nmax_age: 1').errors,
  ['invalid-mx']);
eq('control characters are rejected',
  validateMtaStsPolicy('version: STSv1\nmode: none\nmax_age: 1\u0000').errors,
  ['malformed-line']);
eq('an input without a terminator reports the declared none state',
  validateMtaStsPolicy('version: STSv1').lineEndings, 'none');

const withBom = validateMtaStsPolicy('\ufeffversion: STSv1\nmode: none\nmax_age: 1');
eq('a leading BOM is stripped and reported as hygiene',
  [withBom.valid, withBom.warnings, withBom.diagnostics[0]],
  [true, ['bom-present'], { token: 'bom-present', line: 1, text: '\uFEFF' }]);

const blankLine = validateMtaStsPolicy(
  'version: STSv1\n\nmode: bogus\njunk\nmax_age: 1');
eq('blank and malformed lines do not erase a separate field error',
  blankLine.errors, ['blank-line', 'invalid-mode', 'malformed-line']);
// Each diagnostic carries the line AND the offending text, so the composer can
// build evidence without re-splitting the body and re-deriving line numbers.
eq('each diagnostic retains its line and the line itself', blankLine.diagnostics, [
  { token: 'blank-line', line: 2, text: '' },
  { token: 'invalid-mode', line: 3, text: 'mode: bogus' },
  { token: 'malformed-line', line: 4, text: 'junk' },
]);
eq('a repeated diagnostic gets one entry per occurrence, in order',
  validateMtaStsPolicy('version: STSv1\n\n\nmode: none\nmax_age: 1')
    .diagnostics.filter(d => d.token === 'blank-line').map(d => d.line),
  [2, 3]);
eq('diagnostic text is bounded in code points, never split mid-character',
  (() => {
    const v = validateMtaStsPolicy('version: STSv1\nmode: ' + 'y'.repeat(195) + '\u{1F600}')
      .diagnostics.find(d => d.token === 'invalid-mode').text;
    const last = v.charCodeAt(v.length - 1);
    return last >= 0xD800 && last <= 0xDBFF;
  })(), false);
eq('a second trailing terminator is an invalid blank line',
  validateMtaStsPolicy('version: STSv1\nmode: none\nmax_age: 1\n\n').errors,
  ['blank-line']);

const wrongCase = validateMtaStsPolicy(
  'Version: STSv1\nMode: none\nMax_age: 1');
eq('a wrong-case registered field is a warning, not an error',
  [wrongCase.warnings, wrongCase.errors],
  [['wrong-case-field', 'wrong-case-field', 'wrong-case-field'],
    ['missing-version', 'missing-mode', 'missing-max-age']]);
eq('and it still carries the line it was seen on',
  wrongCase.diagnostics.map(d => d.line), [1, 2, 3]);
// They are retained, because that is what they are: `sts-policy-ext-name`
// admits them and §3.2 ignores unknown fields. The warning is the explanation,
// not a reason to hide the field from the operator reading the panel.
eq('wrong-case registered fields are still retained as the extensions they are',
  wrongCase.unknownKeys, ['Version', 'Mode', 'Max_age']);

// sts-policy-ext-name = (ALPHA / DIGIT) *31(...), so `Mode` IS a legal
// extension name and §3.2 says unknown fields SHALL be ignored. Making the
// wrong-case token an error marked this conformant policy invalid; the
// warning bucket is what keeps `valid` an RFC answer rather than a style one.
const caseExtension = validateMtaStsPolicy(
  'version: STSv1\nmode: none\nmax_age: 1\nMode: an-extension-value');
eq('a conformant policy carrying a case-variant extension stays valid',
  [caseExtension.valid, caseExtension.errors, caseExtension.warnings],
  [true, [], ['wrong-case-field']]);
eq('and it is retained for display like any other extension',
  caseExtension.unknownKeys, ['Mode']);

const twoCaseExtensions = validateMtaStsPolicy(
  'version: STSv1\nmode: none\nmax_age: 1\nMode: first\nMode: second');
eq('a repeated case-variant extension takes the ordinary duplicate rule',
  [twoCaseExtensions.duplicateKeys, twoCaseExtensions.unknownKeys],
  [['Mode'], ['Mode']]);
eq('and reports both the wrong case and the duplication',
  twoCaseExtensions.warnings,
  ['wrong-case-field', 'wrong-case-field', 'duplicate-field']);
eq('a case-variant name is a distinct field from the registered one',
  validateMtaStsPolicy('version: STSv1\nmode: none\nmax_age: 1\nMode: x').mode,
  'none');
eq('policy extension punctuation follows the policy ABNF',
  validateMtaStsPolicy('version: STSv1\nmode: none\nmax_age: 1\nfoo: a=b;c').valid,
  true);

section('compareMtaStsMx');

const compared = compareMtaStsMx(
  ['mail.example.test', '*.backup.example.test', 'unused.example.test'],
  { hosts: ['MAIL.EXAMPLE.TEST.', 'mx.backup.example.test', 'a.b.backup.example.test'] });
eq('a known MX result is compared', compared.state, 'compared');
eq('matching is case-insensitive and ignores the DNS presentation dot',
  compared.unmatchedHosts, ['a.b.backup.example.test']);
eq('the wildcard matches exactly one left-most label',
  compared.unusedPatterns, ['unused.example.test']);
eq('the wildcard does not match its own apex',
  compareMtaStsMx(['*.example.test'], { hosts: ['example.test'] }).unmatchedHosts,
  ['example.test']);
eq('an unknown MX result suppresses both mismatch classes',
  compareMtaStsMx(['mail.example.test'], { hosts: [], unknown: true }),
  { state: 'unknown', unmatchedHosts: [], unusedPatterns: [] });
eq('an empty host list is unknown: no delivery candidate is established',
  compareMtaStsMx(['mail.example.test'], { hosts: [] }),
  { state: 'unknown', unmatchedHosts: [], unusedPatterns: [] });
eq('a null-MX fact is its own state, not an empty comparison',
  compareMtaStsMx(['mail.example.test'], { hosts: [], nullMx: true }),
  { state: 'null-mx', unmatchedHosts: [], unusedPatterns: [] });

/* ── The comparator fails closed on anything that is not an established
 *    list of hostname STRINGS.
 *
 * Every case below previously returned `state: 'compared'` with an empty host
 * list, which reports EVERY pattern as unused — a healthy policy declared
 * stale. `WRONG` is that answer, asserted explicitly so these checks cannot
 * pass vacuously: if a guard is removed, the assertion that the result is not
 * `WRONG` is what fails. ────────────────────────────────────────────────── */
const PATTERNS = ['mail.example.test', '*.backup.example.test'];
const WRONG = { state: 'compared', unmatchedHosts: [], unusedPatterns: PATTERNS };
const UNKNOWN = { state: 'unknown', unmatchedHosts: [], unusedPatterns: [] };
const stale = r => JSON.stringify(r) === JSON.stringify(WRONG);

// `advanced.mxHealth` is initialised to null and only replaced when deep
// checks are on, the domain has MX records, and it is not a null MX. Above 50
// domains the interface turns deep checks off for every row.
eq('an absent MX fact is unknown, not an empty comparison',
  compareMtaStsMx(PATTERNS, null), UNKNOWN);
eq('and it is specifically not the every-pattern-is-stale answer',
  stale(compareMtaStsMx(PATTERNS, null)), false);
eq('an undefined MX fact is unknown too',
  compareMtaStsMx(PATTERNS, undefined), UNKNOWN);
eq('a fact with no hosts array at all is unknown',
  compareMtaStsMx(PATTERNS, { unknown: false }), UNKNOWN);
eq('and none of the degraded inputs claims a stale policy',
  [null, undefined, { unknown: false }, { hosts: 'mail.example.test' }]
    .map(f => stale(compareMtaStsMx(PATTERNS, f))),
  [false, false, false, false]);

// mxHealth.hosts holds audit objects; audit-domain.js already writes
// `mxHealth.hosts.map(h => h.host)` to get names out of it. Passing the raw
// audit shape stringified each entry to "[object Object]" and matched nothing.
const MX_HEALTH_SHAPE = {
  hosts: [{ host: 'mail.example.test', preference: 10, resolves: 'yes' }],
  danglingHosts: [], cnameHosts: [], duplicatePreferences: [],
  singleHost: true, ipv6Coverage: 'all', sharedPrefixes: [], unknown: false,
};
eq('the raw mxHealth audit shape is refused rather than stringified',
  compareMtaStsMx(PATTERNS, MX_HEALTH_SHAPE), UNKNOWN);
eq('no host name is ever coerced through String() on an object',
  JSON.stringify(compareMtaStsMx(PATTERNS, MX_HEALTH_SHAPE)).includes('object'),
  false);
eq('the same domain compares clean once the composer extracts hostnames',
  compareMtaStsMx(PATTERNS, { hosts: MX_HEALTH_SHAPE.hosts.map(h => h.host) }),
  { state: 'compared', unmatchedHosts: [], unusedPatterns: ['*.backup.example.test'] });

/* An entry that normalizes away is the same confident-empty comparison in a
 * different costume: `filter(Boolean)` would silently drop it and report every
 * pattern unused. Each of these must fail closed, and none may equal WRONG. */
const BAD_HOSTS = [
  ['an empty hostname', { hosts: [''] }],
  ['a whitespace-only hostname', { hosts: ['   '] }],
  ['a bare presentation dot', { hosts: ['.'] }],
  ['one bad entry beside a good one', { hosts: ['mail.example.test', ''] }],
  ['a syntactically impossible hostname', { hosts: ['not a host!'] }],
  ['a label over 63 characters', { hosts: ['a'.repeat(64) + '.example.test'] }],
  ['a non-string entry', { hosts: [{ host: 'mail.example.test' }] }],
];
BAD_HOSTS.forEach(([label, fact]) => {
  eq(`${label} fails closed to unknown`, compareMtaStsMx(PATTERNS, fact), UNKNOWN);
  eq(`${label} never claims a stale policy`, stale(compareMtaStsMx(PATTERNS, fact)), false);
});

// One bad entry fails the whole comparison rather than being dropped: partial
// host knowledge cannot tell a stale pattern from an unread one.
eq('a good entry does not rescue a bad one',
  compareMtaStsMx(['mail.example.test'], { hosts: ['mail.example.test', ''] }).state,
  'unknown');
eq('but the good entry alone still compares',
  compareMtaStsMx(['mail.example.test'], { hosts: ['mail.example.test'] }).state,
  'compared');

/* ── Whether the comparison should run at all ──────────────────────────
 *
 * The comparator answers "do these patterns cover these hosts". Two policies
 * make that question a lie, and both produce a confident wrong answer if the
 * composer asks it anyway. These fixtures pin the counterexamples, not just
 * the predicate, so the guard cannot be removed without a failure that shows
 * the false finding it prevents. ─────────────────────────────────────────── */
section('mxComparisonApplies');

const HOSTS = { hosts: ['mail.example.test'] };

const modeNone = validateMtaStsPolicy('version: STSv1\nmode: none\nmax_age: 1');
eq('a mode: none policy is valid and legitimately carries no mx',
  [modeNone.valid, modeNone.mode, modeNone.mx], [true, 'none', []]);
eq('comparing it anyway reports every MX host unmatched',
  compareMtaStsMx(modeNone.mx, HOSTS).unmatchedHosts, ['mail.example.test']);
eq('so the comparison must not run: mode: none withdraws enforcement',
  mxComparisonApplies(modeNone), false);

const partiallyParsed = validateMtaStsPolicy(
  'version: STSv1\nmode: enforce\nmax_age: 1\nmx: ok.example.test\nmx: bad_host');
eq('an invalid policy still exposes the mx lines that parsed',
  [partiallyParsed.valid, partiallyParsed.mx], [false, ['ok.example.test']]);
eq('comparing that partial list yields both mismatch classes',
  compareMtaStsMx(partiallyParsed.mx, { hosts: ['other.example.test'] }),
  { state: 'compared', unmatchedHosts: ['other.example.test'],
    unusedPatterns: ['ok.example.test'] });
eq('so the comparison must not run on a policy no sender will honour',
  mxComparisonApplies(partiallyParsed), false);

eq('enforce is eligible', mxComparisonApplies(
  validateMtaStsPolicy('version: STSv1\nmode: enforce\nmax_age: 1\nmx: a.example.test')), true);
eq('testing is eligible: the patterns still describe intended coverage',
  mxComparisonApplies(
    validateMtaStsPolicy('version: STSv1\nmode: testing\nmax_age: 1\nmx: a.example.test')), true);
eq('a missing mode is not eligible',
  mxComparisonApplies(validateMtaStsPolicy('version: STSv1\nmax_age: 1')), false);
eq('and neither is a non-result',
  [mxComparisonApplies(null), mxComparisonApplies(undefined), mxComparisonApplies('enforce')],
  [false, false, false]);

/* -- Which semantic findings each policy state may produce -----------------
 *
 * Parsing says what a document contains; it does not say which readings of it
 * are honest. The withdrawal row is the one with teeth: RFC 8461 8.3 tells an
 * operator to publish `mode: none` with "a small max_age (e.g., one day)", so
 * flagging that max_age as short would tell them to work against the
 * protocol's own removal procedure. ------------------------------------- */
section('policyFindingScope');

eq('the scope vocabulary is frozen',
  [Object.isFrozen(MTA_STS_POLICY_SCOPES), [...MTA_STS_POLICY_SCOPES]],
  [true, ['invalid', 'withdrawal', 'testing', 'enforce']]);

const P_ENFORCE = validateMtaStsPolicy(
  'version: STSv1\nmode: enforce\nmax_age: 1\nmx: a.example.test');
const P_TESTING = validateMtaStsPolicy(
  'version: STSv1\nmode: testing\nmax_age: 1\nmx: a.example.test');
const P_NONE = validateMtaStsPolicy('version: STSv1\nmode: none\nmax_age: 1');
const P_INVALID = validateMtaStsPolicy(
  'version: STSv1\nmode: enforce\nmax_age: 1\nmx: ok.example.test\nmx: bad_host');

const row = p => {
  const sc = policyFindingScope(p);
  return [sc.state, sc.modeFinding, sc.maxAgeFinding, sc.nullMxConflict, sc.mxComparison];
};

eq('an invalid policy yields parser diagnostics only',
  row(P_INVALID), ['invalid', false, false, false, false]);
eq('a withdrawal policy yields its mode finding and nothing else',
  row(P_NONE), ['withdrawal', true, false, false, false]);
eq('testing yields every semantic class',
  row(P_TESTING), ['testing', true, true, true, true]);
eq('enforce yields every class except a mode finding',
  row(P_ENFORCE), ['enforce', false, true, true, true]);
eq('a non-result is invalid, not a crash',
  [policyFindingScope(null).state, policyFindingScope(undefined).state,
    policyFindingScope('enforce').state],
  ['invalid', 'invalid', 'invalid']);
eq('every declared scope is reachable from a real parser result',
  [...new Set([P_INVALID, P_NONE, P_TESTING, P_ENFORCE].map(p => policyFindingScope(p).state))],
  [...MTA_STS_POLICY_SCOPES]);
eq('the returned scope is frozen', Object.isFrozen(policyFindingScope(P_ENFORCE)), true);

// RFC 8461 8.3's own removal example, executed. `max_age: 86400` is "one day";
// anything a withdrawing operator publishes below the max-age-short threshold
// must not be reported as weakening protection.
const withdrawal = validateMtaStsPolicy(
  'version: STSv1\nmode: none\nmax_age: 3600');
eq('the RFC 8.3 withdrawal document parses as valid',
  [withdrawal.valid, withdrawal.mode, withdrawal.maxAge], [true, 'none', 3600]);
eq('and its deliberately short max_age raises no max-age finding',
  policyFindingScope(withdrawal).maxAgeFinding, false);
eq('while the same short max_age under enforce does',
  policyFindingScope(validateMtaStsPolicy(
    'version: STSv1\nmode: enforce\nmax_age: 3600\nmx: a.example.test')).maxAgeFinding,
  true);

/* The scope is an exported boundary, so it fails closed on shapes the current
 * validator cannot produce. `enforce` is the WIDEST scope, so defaulting an
 * unrecognised mode to it would let a drifted result enable every semantic
 * class at once — the opposite of what a fall-through should do. */
const DRIFTED = [
  ['a valid result with no mode at all', { valid: true }],
  ['a mode this module does not define', { valid: true, mode: 'bogus' }],
  ['a mode that only differs in case', { valid: true, mode: 'Enforce' }],
  ['a non-boolean truthy valid', { valid: 'yes', mode: 'enforce' }],
  ['valid as 1 rather than true', { valid: 1, mode: 'testing' }],
];
DRIFTED.forEach(([label, p]) => {
  eq(`${label} takes the closed scope`, policyFindingScope(p).state, 'invalid');
  eq(`${label} enables no semantic finding`,
    [policyFindingScope(p).modeFinding, policyFindingScope(p).maxAgeFinding,
      policyFindingScope(p).nullMxConflict, policyFindingScope(p).mxComparison],
    [false, false, false, false]);
  eq(`${label} runs no MX comparison`, mxComparisonApplies(p), false);
});

// One rule, one implementation: the predicate is a view onto the matrix.
eq('mxComparisonApplies agrees with the matrix for every state',
  [P_INVALID, P_NONE, P_TESTING, P_ENFORCE].map(mxComparisonApplies),
  [P_INVALID, P_NONE, P_TESTING, P_ENFORCE].map(p => policyFindingScope(p).mxComparison));

report();
