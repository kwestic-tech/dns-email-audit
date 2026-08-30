#!/usr/bin/env node
/**
 * TLS-RPT record validation (RFC 8460 §3). Task 4.4.
 *
 * The structural difference from MTA-STS is the one worth pinning:
 * `tlsrpt-record = tlsrpt-version 1*(field-delim tlsrpt-field)` with
 * `tlsrpt-field = tlsrpt-rua / tlsrpt-extension`, so **more than one `rua`
 * field is conformant**. Rejecting the second discarded a valid record and
 * threw away the first destination as evidence.
 *
 * The other is that `rua` destinations are real URIs, not strings beginning
 * with a scheme. Prefix matching accepted `mailto:not an address`.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import {
  validateTlsRptRecord, TLS_RPT_ERRORS, summarizeTlsRpt,
} from './tls-rpt.js';

const { eq, section, report } = createSuite();
const MAILTO = 'mailto:tlsrpt@example.test';
const HTTPS = 'https://example.test/tlsrpt';

/* ── 1. The published error vocabulary ────────────────────────────────── */
section('1. State constants');

eq('one error token', [...TLS_RPT_ERRORS], ['invalid-syntax']);
eq('and it is frozen', Object.isFrozen(TLS_RPT_ERRORS), true);
eq('a valid record emits nothing', validateTlsRptRecord(`v=TLSRPTv1; rua=${MAILTO}`).errors, []);
eq('an invalid one emits the member', validateTlsRptRecord('nonsense').errors, ['invalid-syntax']);

/* ── 2. Version first, and exact ──────────────────────────────────────── */
section('2. v=TLSRPTv1');

eq('a conforming record is valid', validateTlsRptRecord(`v=TLSRPTv1; rua=${MAILTO}`).valid, true);
eq('lowercase is not the version', validateTlsRptRecord(`v=tlsrptv1; rua=${MAILTO}`).valid, false);
eq('the version must come FIRST', validateTlsRptRecord(`rua=${MAILTO}; v=TLSRPTv1`).valid, false);
eq('an empty record is not one', validateTlsRptRecord('').valid, false);
eq('undefined is not one', validateTlsRptRecord(undefined).valid, false);
// `rua` is required: a version with nowhere to report is not a report policy.
eq('a record with no rua is invalid', validateTlsRptRecord('v=TLSRPTv1').valid, false);
eq('and an empty rua is too', validateTlsRptRecord('v=TLSRPTv1; rua=').valid, false);

/* ── 3. More than one rua field is conformant ─────────────────────────── */
section('3. Repeated rua');

const two = validateTlsRptRecord(`v=TLSRPTv1; rua=${MAILTO}; rua=${HTTPS}`);
eq('two rua fields are valid', two.valid, true);
// The half that matters: rejecting the second also threw away the first.
eq('and BOTH destinations are kept', two.destinations, [MAILTO, HTTPS]);

const commaList = validateTlsRptRecord(`v=TLSRPTv1; rua=${MAILTO},${HTTPS}`);
eq('a comma-separated list inside one field is valid', commaList.valid, true);
eq('and both destinations are kept', commaList.destinations, [MAILTO, HTTPS]);
eq('whitespace around a list entry is trimmed',
  validateTlsRptRecord(`v=TLSRPTv1; rua= ${MAILTO} , ${HTTPS} `).destinations,
  [MAILTO, HTTPS]);
// An invalid destination in a repeated field invalidates the record, and the
// destinations are still reported so the operator can see which one it was.
const oneBad = validateTlsRptRecord(`v=TLSRPTv1; rua=${MAILTO}; rua=not-a-uri`);
eq('one bad destination among several invalidates the record', oneBad.valid, false);
eq('and every destination is still reported', oneBad.destinations, [MAILTO, 'not-a-uri']);

/* ── 4. A destination is a URI, not a scheme prefix ───────────────────── */
section('4. rua destinations');

eq('a mailto destination is one', validateTlsRptRecord(`v=TLSRPTv1; rua=${MAILTO}`).valid, true);
eq('an https destination is one', validateTlsRptRecord(`v=TLSRPTv1; rua=${HTTPS}`).valid, true);
// RFC 8460 imports RFC 3986 whole and adds no FQDN rule, but https IS required.
eq('http is refused', validateTlsRptRecord('v=TLSRPTv1; rua=http://example.test/r').valid, false);
eq('a single-label host is accepted — TLS-RPT adds no FQDN rule',
  validateTlsRptRecord('v=TLSRPTv1; rua=https://localhost/r').valid, true);
eq('an IPv6 literal host is accepted for the same reason',
  validateTlsRptRecord('v=TLSRPTv1; rua=https://[2001:db8::1]/r').valid, true);
eq('a scheme prefix is not a URI', validateTlsRptRecord('v=TLSRPTv1; rua=mailto:x').valid, false);
eq('nor is a bare word', validateTlsRptRecord('v=TLSRPTv1; rua=somewhere').valid, false);
eq('nor is an unsupported scheme',
  validateTlsRptRecord('v=TLSRPTv1; rua=ftp://example.test/r').valid, false);

// RFC 8460's one encoding rule: comma, exclamation and semicolon must not
// occur RAW inside a destination URI, even where RFC 3986 would allow them.
eq('a raw exclamation is refused',
  validateTlsRptRecord('v=TLSRPTv1; rua=https://example.test/a!b').valid, false);
eq('a raw comma is a list separator, so the halves are read as destinations',
  validateTlsRptRecord('v=TLSRPTv1; rua=https://example.test/a,b').valid, false);
eq('and the percent-encoded form is accepted',
  validateTlsRptRecord('v=TLSRPTv1; rua=https://example.test/a%21b').valid, true);

/* ── 5. Extensions, and the non-repeatable rule ───────────────────────── */
section('5. Extension fields');

eq('a well-formed extension is accepted',
  validateTlsRptRecord(`v=TLSRPTv1; rua=${MAILTO}; ext=value`).valid, true);
eq('an extension name outside the production is not one',
  validateTlsRptRecord(`v=TLSRPTv1; rua=${MAILTO}; _ext=value`).valid, false);
eq('a duplicated extension keeps the first and is not fatal',
  validateTlsRptRecord(`v=TLSRPTv1; rua=${MAILTO}; ext=a; ext=b`).valid, true);

// The shared-with-MTA-STS value class, and the half that BIMI does not share.
eq('an = inside an extension value is refused here, as in MTA-STS',
  validateTlsRptRecord(`v=TLSRPTv1; rua=${MAILTO}; ext=a=b`).valid, false);
eq('and a space is refused too',
  validateTlsRptRecord(`v=TLSRPTv1; rua=${MAILTO}; ext=a b`).valid, false);

/* ── 6. Whitespace, under strict field syntax ─────────────────────────── */
section('6. Whitespace');

eq('whitespace around the delimiter is the delimiter',
  validateTlsRptRecord(`v=TLSRPTv1 ;  rua=${MAILTO}`).valid, true);
eq('but whitespace around the = is not',
  validateTlsRptRecord(`v = TLSRPTv1; rua=${MAILTO}`).valid, false);
eq('one trailing delimiter is permitted',
  validateTlsRptRecord(`v=TLSRPTv1; rua=${MAILTO};`).valid, true);


/* ── The whole TLS-RPT answer, moved here at Task 5.2a ────────────────── */
section('summarizeTlsRpt');

const live = summarizeTlsRpt(['v=TLSRPTv1; rua=mailto:t@e.test']);
eq('a conforming record is present', live.present, true);
eq('and advertised', live.advertised, true);

// RFC 8460 §3, the same rule its siblings state.
const dup = summarizeTlsRpt(['v=TLSRPTv1; rua=mailto:a@e.test', 'v=TLSRPTv1; rua=mailto:b@e.test']);
eq('a duplicated record is not present', dup.present, false);
eq('and says so', dup.multiple, true);

const trailing = summarizeTlsRpt(['rua=mailto:t@e.test; v=TLSRPTv1']);
eq('a version field that is not first is still shown',
  trailing.record, 'rua=mailto:t@e.test; v=TLSRPTv1');
eq('and advertised', trailing.advertised, true);
eq('but not present', trailing.present, false);

eq('a domain with no record advertises nothing', summarizeTlsRpt([]).advertised, false);
eq('a failed lookup is unknown', summarizeTlsRpt(null).unknown, true);
eq('while an empty answer is not', summarizeTlsRpt([]).unknown, false);

report();
