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

report();
