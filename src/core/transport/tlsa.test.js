#!/usr/bin/env node
/**
 * TLSA / DANE (RFC 6698, RFC 7671). Task 4.4.
 *
 * Two things this suite exists to hold still.
 *
 * **The presentation form is not the DS one.** Cloudflare returns TLSA as
 * `3 1 1 ( 87D109DD… )` — parenthesised, spaces inside, uppercase hex — where
 * DS comes back as four plain fields in lowercase. Splitting on whitespace the
 * way a DS parser does yields `['3','1','1','(']` and reads the association
 * data as an empty string, raising no error at all.
 *
 * **`authenticated` is three answers, not two.** `true`, `false` and `null`,
 * and the third is what stops the unsigned finding announcing "your TLSA is
 * unprotected" on a correctly signed zone purely because nothing had looked.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { optionalCheck } from '../dns/optional.js';
import { cleanAnswerData, requireUsable } from '../dns/resolver.js';
import { createTlsaCheck, parseTlsaRecord, TLSA_ERRORS } from './tlsa.js';

const { eq, section, report } = createSuite();
const SHA256 = 'a'.repeat(64);
const SHA512 = 'b'.repeat(128);

/* ── 1. The published error vocabulary ────────────────────────────────── */
section('1. State constants');

eq('seven error tokens', TLSA_ERRORS.length, 7);
eq('and the list is frozen', Object.isFrozen(TLSA_ERRORS), true);

const emitters = {
  'unparseable-record': 'not a tlsa record',
  'unbalanced-parentheses': `3 1 1 ( ${SHA256}`,
  'bad-usage': `9 1 1 ${SHA256}`,
  'bad-selector': `3 9 1 ${SHA256}`,
  'bad-matching-type': `3 1 9 ${SHA256}`,
  'bad-association-data': '3 1 1 zzzz',
  'bad-digest-length': '3 1 1 abcd',
};
for (const [token, record] of Object.entries(emitters)) {
  eq(`${token} is emitted by a record that produces it`,
    parseTlsaRecord(record).errors.includes(token), true);
  eq(`and ${token} is in TLSA_ERRORS`, TLSA_ERRORS.includes(token), true);
}
eq('no record above emits a token the constant does not name',
  [...new Set(Object.values(emitters).flatMap(r => parseTlsaRecord(r).errors))]
    .filter(t => !TLSA_ERRORS.includes(t)), []);

/* ── 2. The presentation form ─────────────────────────────────────────── */
section('2. parseTlsaRecord');

eq('four plain fields parse', parseTlsaRecord(`3 1 1 ${SHA256}`),
  { usage: 3, selector: 1, matchingType: 1, data: SHA256, valid: true, errors: [] });

// The captured Cloudflare shape. A DS-style whitespace split reads the data as
// '' and raises no error at all, which is the failure this parser exists for.
const wrapped = parseTlsaRecord(`3 1 1 ( ${SHA256.toUpperCase()} )`);
eq('a parenthesised record parses', wrapped.valid, true);
eq('the parentheses and inner spaces are stripped', wrapped.data, SHA256);
eq('and the hex is lowercased', wrapped.data, wrapped.data.toLowerCase());
eq('hex split across lines inside the wrapper rejoins',
  parseTlsaRecord(`3 1 1 ( ${SHA256.slice(0, 32)}\n  ${SHA256.slice(32)} )`).data, SHA256);

// The wrapper is either absent or one balanced outer pair. Stripping each side
// independently accepted `( ABCD…` and `ABCD… )` alike.
eq('an opening parenthesis alone is unbalanced',
  parseTlsaRecord(`3 1 1 ( ${SHA256}`).errors, ['unbalanced-parentheses']);
eq('a closing one alone is too',
  parseTlsaRecord(`3 1 1 ${SHA256} )`).errors, ['unbalanced-parentheses']);
eq('and an unbalanced record reports no data',
  parseTlsaRecord(`3 1 1 ( ${SHA256}`).data, '');
eq('but it keeps the three numeric fields, which did parse',
  parseTlsaRecord(`3 1 1 ( ${SHA256}`).usage, 3);

eq('three fields is not a record', parseTlsaRecord('3 1 1').valid, false);
eq('and says unparseable-record', parseTlsaRecord('3 1 1').errors, ['unparseable-record']);
eq('an empty string is not a record', parseTlsaRecord('').valid, false);
eq('undefined is not one', parseTlsaRecord(undefined).valid, false);

/* ── 3. The numeric fields, RFC 6698 §2.1.1–2.1.3 ─────────────────────── */
section('3. Usage, selector and matching type');

eq('usage 0 is in range', parseTlsaRecord(`0 1 1 ${SHA256}`).valid, true);
eq('usage 3 is the top of the range', parseTlsaRecord(`3 1 1 ${SHA256}`).valid, true);
eq('usage 4 is not', parseTlsaRecord(`4 1 1 ${SHA256}`).errors, ['bad-usage']);
eq('selector 0 and 1 are the range', parseTlsaRecord(`3 0 1 ${SHA256}`).valid, true);
eq('selector 2 is not', parseTlsaRecord(`3 2 1 ${SHA256}`).errors, ['bad-selector']);
eq('matching type 2 is in range', parseTlsaRecord(`3 1 2 ${SHA512}`).valid, true);
eq('matching type 3 is not', parseTlsaRecord(`3 1 3 ${SHA256}`).errors, ['bad-matching-type']);
// Several complaints at once, rather than the first one only.
eq('a record wrong in three ways reports all three',
  parseTlsaRecord('9 9 9 abcd').errors,
  ['bad-usage', 'bad-selector', 'bad-matching-type']);

/* ── 4. Association data, and the length its matching type implies ────── */
section('4. Digest lengths');

eq('matching type 1 is SHA-256, 32 bytes', parseTlsaRecord(`3 1 1 ${SHA256}`).valid, true);
eq('a SHA-512 digest under type 1 is the wrong length',
  parseTlsaRecord(`3 1 1 ${SHA512}`).errors, ['bad-digest-length']);
eq('matching type 2 is SHA-512, 64 bytes', parseTlsaRecord(`3 1 2 ${SHA512}`).valid, true);
eq('a SHA-256 digest under type 2 is the wrong length',
  parseTlsaRecord(`3 1 2 ${SHA256}`).errors, ['bad-digest-length']);
// Matching type 0 is the full certificate or SPKI, of no fixed length.
eq('type 0 accepts any even-length hex', parseTlsaRecord('3 1 0 abcdef').valid, true);
eq('and a long one too', parseTlsaRecord(`3 1 0 ${SHA512}`).valid, true);
eq('non-hex data is not association data',
  parseTlsaRecord('3 1 0 zzzz').errors, ['bad-association-data']);
eq('an odd number of hex digits is not a byte string',
  parseTlsaRecord('3 1 0 abc').errors, ['bad-association-data']);
// A length complaint is not raised on data that is not hex in the first place.
eq('bad data suppresses the length complaint',
  parseTlsaRecord('3 1 1 zzzz').errors, ['bad-association-data']);

/* ── 5. The lookup, over a passed resolver ────────────────────────────── */
section('5. createTlsaCheck');

/**
 * A transport that answers from a table and records every query, including
 * the options — because `do=1` is load-bearing and its absence is invisible
 * in the result.
 */
function fakeTransport(table) {
  const asked = [];
  return {
    asked,
    dohFetch: async (name, type, opts) => {
      asked.push({ name, type, dnssec: opts?.dnssec === true });
      const entry = table[name];
      if (!entry) return { kind: 'nodata', answers: [], ad: false };
      if (entry.kind && entry.kind !== 'success') return { kind: entry.kind, answers: [] };
      return {
        kind: 'success',
        ad: entry.ad === true,
        answers: (entry.answers || []).map(a => (typeof a === 'string'
          ? { type: 52, data: a } : a)),
      };
    },
  };
}
const check = table => {
  const t = fakeTransport(table);
  return {
    run: createTlsaCheck({
      dohFetch: t.dohFetch, requireUsable, optionalCheck, cleanAnswerData,
    }),
    asked: t.asked,
  };
};

const signed = check({
  [`_25._tcp.mx.example.test`]: { ad: true, answers: [`3 1 1 ${SHA256}`] },
});
const signedResult = await signed.run(['mx.example.test']);
eq('the query name is _25._tcp.<host>', signed.asked[0].name, '_25._tcp.mx.example.test');
eq('and the type is TLSA', signed.asked[0].type, 'TLSA');
// Without do=1 the AD bit never arrives, and "unprotected" becomes
// indistinguishable from "we did not look".
eq('the DNSSEC bit is requested', signed.asked[0].dnssec, true);
eq('a published record is present', signedResult.hosts[0].present, true);
eq('and it parsed', signedResult.hosts[0].records[0].valid, true);
eq('the AD bit is carried through', signedResult.hosts[0].authenticated, true);
eq('nothing is unknown', signedResult.hosts[0].unknown, false);
eq('anyPresent is true', signedResult.anyPresent, true);
eq('and allAuthenticated is true', signedResult.allAuthenticated, true);
eq('with no unauthenticated hosts', signedResult.unauthenticatedHosts, []);

const unsigned = await check({
  '_25._tcp.mx.example.test': { ad: false, answers: [`3 1 1 ${SHA256}`] },
}).run(['mx.example.test']);
eq('a record without AD is published unprotected', unsigned.hosts[0].authenticated, false);
eq('allAuthenticated is false', unsigned.allAuthenticated, false);
eq('and the host is named', unsigned.unauthenticatedHosts, ['mx.example.test']);

/**
 * The third answer. A lookup that did not complete claims NOTHING: not
 * present, not absent, and `authenticated: null` rather than false.
 */
const failed = await check({
  '_25._tcp.mx.example.test': { kind: 'servfail' },
}).run(['mx.example.test']);
eq('a resolver failure is unknown', failed.hosts[0].unknown, true);
eq('authenticated is null, not false', failed.hosts[0].authenticated, null);
eq('no records are claimed', failed.hosts[0].records, []);
eq('present is false without claiming absence', failed.hosts[0].present, false);
eq('and the audit reports the unknown', failed.unknown, true);
// An unknown host is not an unauthenticated one.
eq('an unknown host is not named as unauthenticated', failed.unauthenticatedHosts, []);
eq('and allAuthenticated is false because nothing is present',
  failed.allAuthenticated, false);

const absent = await check({}).run(['mx.example.test']);
eq('nodata is a completed lookup, not an unknown', absent.hosts[0].unknown, false);
eq('with no records', absent.hosts[0].present, false);
eq('and anyPresent false', absent.anyPresent, false);

/**
 * A TLSA query commonly returns a CNAME alongside the records — pointing
 * `_25._tcp.<host>` at a shared `_dane.<zone>` name is ordinary practice — and
 * handing that CNAME string to the record parser reports a malformed TLSA
 * record on a correctly configured host.
 */
const withCname = await check({
  '_25._tcp.mx.example.test': {
    ad: true,
    answers: [{ type: 5, data: '_dane.example.net.' }, { type: 52, data: `3 1 1 ${SHA256}` }],
  },
}).run(['mx.example.test']);
eq('a CNAME beside the record is filtered out', withCname.hosts[0].records.length, 1);
eq('and the TLSA record still parses', withCname.hosts[0].records[0].valid, true);

// Per host: one unreachable exchange must not discard the others.
const mixed = await check({
  '_25._tcp.a.example.test': { ad: true, answers: [`3 1 1 ${SHA256}`] },
  '_25._tcp.b.example.test': { kind: 'timeout' },
}).run(['a.example.test', 'b.example.test']);
eq('the reachable host keeps its answer', mixed.hosts[0].authenticated, true);
eq('while the other is unknown', mixed.hosts[1].unknown, true);
eq('allAuthenticated counts only hosts that PUBLISH', mixed.allAuthenticated, true);
eq('and the unknown is still reported at the top level', mixed.unknown, true);

eq('no MX hosts is an empty audit', (await check({}).run([])).hosts, []);
eq('and undefined is the same', (await check({}).run(undefined)).anyPresent, false);

// The negative control for the injection: no transport is held here.
const a = check({ '_25._tcp.m.example.test': { ad: true, answers: [`3 1 1 ${SHA256}`] } });
const b = check({ '_25._tcp.m.example.test': { ad: false, answers: [`3 1 1 ${SHA256}`] } });
eq('two checks over two transports stay separate',
  [(await a.run(['m.example.test'])).hosts[0].authenticated,
    (await b.run(['m.example.test'])).hosts[0].authenticated],
  [true, false]);

report();
