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
  validateMtaStsPolicy, compareMtaStsMx,
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
    'malformed-line', 'blank-line', 'wrong-case-field',
    'invalid-version', 'invalid-mode', 'invalid-mx', 'invalid-max-age',
    'missing-version', 'missing-mode', 'missing-max-age', 'missing-mx',
  ]]);
eq('the policy warning vocabulary is frozen',
  [Object.isFrozen(MTA_STS_POLICY_WARNINGS), [...MTA_STS_POLICY_WARNINGS]],
  [true, ['duplicate-field', 'bom-present']]);
eq('the line-ending vocabulary is frozen',
  [Object.isFrozen(MTA_STS_POLICY_LINE_ENDINGS), [...MTA_STS_POLICY_LINE_ENDINGS]],
  [true, ['crlf', 'lf', 'mixed', 'none']]);
eq('the MX comparison vocabulary is frozen',
  [Object.isFrozen(MTA_STS_MX_COMPARE_STATES), [...MTA_STS_MX_COMPARE_STATES]],
  [true, ['compared', 'unknown', 'null-mx']]);

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
  [true, ['bom-present'], { token: 'bom-present', line: 1 }]);

const blankLine = validateMtaStsPolicy(
  'version: STSv1\n\nmode: bogus\njunk\nmax_age: 1');
eq('blank and malformed lines do not erase a separate field error',
  blankLine.errors, ['blank-line', 'invalid-mode', 'malformed-line']);
eq('each diagnostic retains its line', blankLine.diagnostics, [
  { token: 'blank-line', line: 2 },
  { token: 'invalid-mode', line: 3 },
  { token: 'malformed-line', line: 4 },
]);
eq('a second trailing terminator is an invalid blank line',
  validateMtaStsPolicy('version: STSv1\nmode: none\nmax_age: 1\n\n').errors,
  ['blank-line']);

const wrongCase = validateMtaStsPolicy(
  'Version: STSv1\nMode: none\nMax_age: 1');
eq('registered fields with the wrong case get the specific error',
  wrongCase.errors,
  ['wrong-case-field', 'wrong-case-field', 'wrong-case-field',
    'missing-version', 'missing-mode', 'missing-max-age']);
eq('wrong-case registered fields are not presented as extensions',
  wrongCase.unknownKeys, []);
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
eq('null MX is a distinct state and not a stale-policy claim',
  compareMtaStsMx(['mail.example.test'], { hosts: [], nullMx: true }),
  { state: 'null-mx', unmatchedHosts: [], unusedPatterns: [] });

report();
