#!/usr/bin/env node
/**
 * CAA policy. Spec Design §4, Task 4.1.
 *
 * The assertions that matter are the ones about DIRECTION. A CAA record set
 * is a policy, and every mistake this module has made was a policy read
 * backwards: `%%%%%` reported as an authorized certificate authority, an
 * absent `issuewild` reported as open wildcard issuance. Both are asserted
 * here with the inverted reading named beside them.
 *
 * The lookup is driven by a fake transport, because the resolver is passed:
 * that is the property Task 4.1 exists to prove for the seven owners after it.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import {
  createCaaCheck, parseCaaRecord, parseCaaIssueValue, isCaaIodefUrl,
  summarizeCaa, CAA_KNOWN_TAGS, CAA_ERRORS,
} from './caa.js';

const { eq, rejects, section, report } = createSuite();

/* ── 1. The published state constants ─────────────────────────────────── */
section('1. State constants');

eq('the known tags are the six RFC 8659 §4 and RFC 9495 §3 properties',
  [...CAA_KNOWN_TAGS],
  ['issue', 'issuewild', 'iodef', 'issuemail', 'contactemail', 'contactphone']);
eq('and the list is frozen', Object.isFrozen(CAA_KNOWN_TAGS), true);
eq('the error vocabulary is closed at six', CAA_ERRORS.length, 6);
eq('and it is frozen too', Object.isFrozen(CAA_ERRORS), true);

/**
 * The parser pushes error tokens as literals, so the constant above is a
 * SECOND statement of the same fact and could drift from it. One record per
 * token, each chosen to emit exactly that one, closes the gap.
 */
const emitters = {
  'unparseable-record': 'issue',
  'bad-flags': '999 issue "ca.test"',
  'bad-tag': '0 thisTagIsFarTooLong "x"',
  'unquoted-value': '0 issue ca.test',
  'bad-issue-value': '0 issue "%%%%%"',
  'bad-iodef-url': '0 iodef "not-a-url"',
};
for (const [token, record] of Object.entries(emitters)) {
  eq(`${token} is emitted by a record that produces it`,
    parseCaaRecord(record).errors.includes(token), true);
  eq(`and ${token} is in CAA_ERRORS`, CAA_ERRORS.includes(token), true);
}
const emitted = new Set(Object.values(emitters).flatMap(r => parseCaaRecord(r).errors));
eq('no record above emits a token the constant does not name',
  [...emitted].filter(t => !CAA_ERRORS.includes(t)), []);

/* ── 2. The issuer-domain-name, and the inversion it prevents ─────────── */
section('2. parseCaaIssueValue');

eq('a plain issuer is itself', parseCaaIssueValue('letsencrypt.org'), 'letsencrypt.org');
eq('and it is lowercased', parseCaaIssueValue('LetsEncrypt.ORG'), 'letsencrypt.org');
eq('an empty value authorizes nobody', parseCaaIssueValue(''), '');
eq('a bare semicolon authorizes nobody', parseCaaIssueValue(';'), '');
eq('surrounding whitespace is not part of the name',
  parseCaaIssueValue('  ca.test  '), 'ca.test');

// RFC 8659 §4.2 uses `%%%%%` as its own example of a malformed value and
// requires a CA to treat it as an ABSENT issuer-domain-name. Reading the text
// before the first semicolon as a CA identity reported "authorized: %%%%%" —
// a domain called open when the RFC says it is shut.
eq('the RFC\'s own malformed example does not parse', parseCaaIssueValue('%%%%%'), null);
eq('and null is not the empty string, which is the whole distinction',
  parseCaaIssueValue('%%%%%') === parseCaaIssueValue(''), false);
eq('a label with an illegal character does not parse',
  parseCaaIssueValue('ca_test.org'), null);
eq('a leading hyphen does not parse', parseCaaIssueValue('-ca.test'), null);

// Parameters: RFC 8659 §4.2.
eq('a valid parameter is accepted',
  parseCaaIssueValue('ca.test; account=12345'), 'ca.test');
eq('several are too',
  parseCaaIssueValue('ca.test; account=1; validationmethods=dns-01'), 'ca.test');
eq('a trailing semicolon with nothing after it is legal',
  parseCaaIssueValue('ca.test;'), 'ca.test');
eq('a parameter with no = does not parse', parseCaaIssueValue('ca.test; account'), null);
eq('a parameter with no name does not parse', parseCaaIssueValue('ca.test; =1'), null);
eq('a parameter value with a space does not parse',
  parseCaaIssueValue('ca.test; account=a b'), null);
eq('parameters may accompany no issuer at all',
  parseCaaIssueValue('; account=1'), '');

/* ── 3. iodef is a URL, not a scheme prefix ───────────────────────────── */
section('3. isCaaIodefUrl');

eq('a mailto destination', isCaaIodefUrl('mailto:sec@example.test'), true);
eq('an https destination', isCaaIodefUrl('https://example.test/report'), true);
eq('an http destination — iodef adds no httpsOnly rule',
  isCaaIodefUrl('http://example.test/report'), true);
eq('a scheme prefix is not a URL', isCaaIodefUrl('mailto:not an address'), false);
eq('nor is a bare word', isCaaIodefUrl('report-to-us'), false);
eq('nor is an unsupported scheme', isCaaIodefUrl('ftp://example.test/'), false);
eq('nor is an empty value', isCaaIodefUrl(''), false);

/* ── 4. One record, from its presentation form ────────────────────────── */
section('4. parseCaaRecord');

eq('a quoted issue record',
  parseCaaRecord('0 issue "letsencrypt.org"'),
  { flags: 0, critical: false, tag: 'issue', value: 'letsencrypt.org',
    known: true, issuer: 'letsencrypt.org', valid: true, errors: [] });
eq('the tag is matched case-insensitively', parseCaaRecord('0 ISSUE "ca.test"').tag, 'issue');
eq('an unquoted value is read but named', parseCaaRecord('0 issue ca.test').errors, ['unquoted-value']);
eq('and it is still a usable issuer', parseCaaRecord('0 issue ca.test').issuer, 'ca.test');
eq('an escaped quote inside the value is unescaped',
  parseCaaRecord('0 issue "ca\\"test.org"').value, 'ca"test.org');
eq('a record with no value at all parses to an empty one',
  parseCaaRecord('0 issue').value, '');
eq('a record with no tag does not parse',
  parseCaaRecord('issue').errors, ['unparseable-record']);
eq('and its valid flag is false', parseCaaRecord('issue').valid, false);

// RFC 8659 §4.1: bit 0 is Issuer Critical. A CA that does not understand a
// critical property MUST refuse to issue, so the same unknown tag is a live
// outage risk with the bit and inert without it.
eq('flag 128 is critical', parseCaaRecord('128 issue "ca.test"').critical, true);
eq('flag 0 is not', parseCaaRecord('0 issue "ca.test"').critical, false);
eq('flag 1 is not — it is not bit 0', parseCaaRecord('1 issue "ca.test"').critical, false);
eq('a flag above 255 is not a flag', parseCaaRecord('256 issue "ca.test"').errors, ['bad-flags']);
eq('and a non-numeric one is not either',
  parseCaaRecord('x issue "ca.test"').errors, ['bad-flags']);

// contactemail and contactphone are known and deliberately unvalidated: a
// false caa-malformed on a real record is worse than an unvalidated one.
eq('contactemail is a known tag', parseCaaRecord('0 contactemail "who@example.test"').known, true);
eq('and its value is not validated',
  parseCaaRecord('0 contactemail "nonsense"').errors, []);
eq('an unknown tag is not known', parseCaaRecord('0 madeup "x"').known, false);
eq('but an unknown tag is not itself an error',
  parseCaaRecord('0 madeup "x"').errors, []);

/* ── 5. The summary, where the policy is read ─────────────────────────── */
section('5. summarizeCaa');

const authorized = summarizeCaa(['0 issue "letsencrypt.org"', '0 issue "digicert.com"']);
eq('two named issuers are both authorized',
  authorized.issuers, ['letsencrypt.org', 'digicert.com']);
eq('and issuance is not blocked', authorized.issuanceBlocked, false);

// `0 issue ";"` locks out every CA. Before this, it rendered identically to
// `0 issue "letsencrypt.org"`.
const shut = summarizeCaa(['0 issue ";"']);
eq('a semicolon issue value names no issuer', shut.issuers, []);
eq('and that BLOCKS issuance rather than leaving it open', shut.issuanceBlocked, true);

// The strongest inversion: a malformed value is an absent issuer-domain-name,
// so it blocks rather than authorizing a CA whose name is nonsense.
const malformed = summarizeCaa(['0 issue "%%%%%"']);
eq('a malformed issue value authorizes nobody', malformed.issuers, []);
eq('so it blocks issuance', malformed.issuanceBlocked, true);
eq('and the raw text is reported so the operator can find it in the zone',
  malformed.malformed, ['0 issue "%%%%%"']);

// RFC 8659 §4.3: with no issuewild present, wildcard issuance is governed by
// the issue set. Reading absence as "wildcards are open" inverts the policy.
eq('an absent issuewild is not a wildcard block', authorized.wildcardBlocked, false);
eq('and it names no wildcard issuers either', authorized.wildcardIssuers, []);
const wildShut = summarizeCaa(['0 issue "ca.test"', '0 issuewild ";"']);
eq('a present issuewild that names nobody blocks wildcards', wildShut.wildcardBlocked, true);
eq('while ordinary issuance stays open', wildShut.issuanceBlocked, false);

eq('an empty record set blocks nothing', summarizeCaa([]).issuanceBlocked, false);
eq('and names nothing malformed', summarizeCaa([]).malformed, []);

const critical = summarizeCaa(['128 madeup "x"', '0 alsomadeup "y"']);
eq('only the critical unknown tag is reported', critical.unknownCritical, ['madeup']);
eq('iodef values are collected',
  summarizeCaa(['0 iodef "mailto:a@example.test"']).iodef, ['mailto:a@example.test']);

/* ── 6. The lookup, over a passed resolver ────────────────────────────── */
section('6. createCaaCheck');

/** A transport that answers from a table, and records what it was asked. */
function fakeTransport(table) {
  const asked = [];
  return {
    asked,
    dohFetch: async (name, type) => {
      asked.push(`${name}/${type}`);
      const records = table[name];
      return records
        ? { kind: 'success', answers: records.map(data => ({ type: 257, data })) }
        : { kind: 'nodata', answers: [] };
    },
  };
}
const passing = (result, name, type) => {
  if (['success', 'nodata', 'nxdomain'].includes(result.kind)) return result;
  const error = new Error(`${type} ${name}`);
  error.kind = result.kind;
  throw error;
};

const direct = fakeTransport({ 'mail.example.test': ['0 issue "ca.test"'] });
const found = await createCaaCheck({ dohFetch: direct.dohFetch, requireUsable: passing })
  ('mail.example.test');
eq('a record at the name is found', found.found, true);
eq('and atDomain names where', found.atDomain, 'mail.example.test');
eq('and the summary came with it', found.issuers, ['ca.test']);
eq('one query was enough', direct.asked, ['mail.example.test/CAA']);

// CAA is inherited from the parent, so the walk climbs until it finds a set.
const parent = fakeTransport({ 'example.test': ['0 issue "ca.test"'] });
const inherited = await createCaaCheck({ dohFetch: parent.dohFetch, requireUsable: passing })
  ('mail.example.test');
eq('a parent record is inherited', inherited.found, true);
eq('and atDomain names the parent, not the subject', inherited.atDomain, 'example.test');
eq('the walk climbed one label to get there',
  parent.asked, ['mail.example.test/CAA', 'example.test/CAA']);

// It stops before the TLD: `parts.length - 1` iterations.
const none = fakeTransport({});
const absent = await createCaaCheck({ dohFetch: none.dohFetch, requireUsable: passing })
  ('mail.example.test');
eq('no record anywhere is found: false', absent.found, false);
eq('with a null atDomain', absent.atDomain, null);
eq('and an empty summary rather than a missing one', absent.issuanceBlocked, false);
eq('the walk does not query the bare TLD',
  none.asked, ['mail.example.test/CAA', 'example.test/CAA']);

// Only type 257 answers count. A CNAME in the response is not a CAA record.
const mixed = {
  dohFetch: async () => ({ kind: 'success', answers: [{ type: 5, data: 'other.test.' }] }),
};
const ignoring = await createCaaCheck({ dohFetch: mixed.dohFetch, requireUsable: passing })
  ('example.test');
eq('a non-CAA answer does not count as a record set', ignoring.found, false);

/**
 * A resolver failure THROWS rather than becoming a stated unknown. That is
 * layer 2 doing its job: the caller's optionalCheck() fallback owns the shape
 * of the unknown, and this module never decides it.
 */
const failing = { dohFetch: async () => ({ kind: 'servfail', answers: [] }) };
await rejects('a servfail propagates as an exception',
  () => createCaaCheck({ dohFetch: failing.dohFetch, requireUsable: passing })('example.test'),
  error => error.kind === 'servfail');

// The negative control for the injection itself: this module holds no
// transport of its own, so two checks over two transports cannot interfere.
const a = fakeTransport({ 'example.test': ['0 issue "a.test"'] });
const b = fakeTransport({ 'example.test': ['0 issue "b.test"'] });
eq('two checks over two transports stay separate',
  [(await createCaaCheck({ dohFetch: a.dohFetch, requireUsable: passing })('example.test')).issuers,
    (await createCaaCheck({ dohFetch: b.dohFetch, requireUsable: passing })('example.test')).issuers],
  [['a.test'], ['b.test']]);

report();
