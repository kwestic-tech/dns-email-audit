#!/usr/bin/env node
/**
 * DNS transport errors. Spec Design §3, implementation Task 3.3.
 *
 * The property under test is a boundary, not a behaviour: what leaves this
 * layer as a **throw** and what leaves as a **kind** are different vocabularies,
 * and §3 forbids merging them. `DnsTypeError` in particular "is thrown at
 * js/dns.js:121, never returned. It is not a kind and must not become one."
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { dnsTypeNum, dnsError, DNS_TYPES } from './errors.js';
import { TRANSPORT_KINDS } from './doh.js';

const { eq, throws, section, report } = createSuite();

/* ── 1. The supported type table ──────────────────────────────────────── */
section('1. Record types');

eq('every type the audit uses resolves to its IANA number',
  ['A', 'NS', 'CNAME', 'PTR', 'MX', 'TXT', 'AAAA', 'DS', 'DNSKEY', 'TLSA', 'CAA'].map(dnsTypeNum),
  [1, 2, 5, 12, 15, 16, 28, 43, 48, 52, 257]);
eq('the table is closed at eleven', Object.keys(DNS_TYPES).length, 11);
eq('and frozen against a consumer adding one', Object.isFrozen(DNS_TYPES), true);

/* ── 2. An unknown type throws, and does not default ──────────────────── */
section('2. dnsTypeNum is partial on purpose');

/**
 * The defect this replaced: `?? 16` made the function total by answering every
 * unknown type with the TXT number, so a caller asking for `DS` issued a TXT
 * query, filtered for type 16, found none, and got a plausible empty array —
 * "no records published" about a type never asked for.
 */
throws('an unsupported type throws rather than defaulting to TXT',
  () => dnsTypeNum('WKS'),
  error => error.name === 'DnsTypeError' && /unsupported DNS type: WKS/.test(error.message));
eq('and it emphatically does not return the TXT number',
  (() => { try { return dnsTypeNum('WKS'); } catch { return 'threw'; } })(), 'threw');

// `hasOwnProperty`, not a bare lookup: a name colliding with Object.prototype
// would otherwise return a function, which is worse than a wrong number.
for (const inherited of ['constructor', 'toString', 'hasOwnProperty', '__proto__']) {
  throws(`an Object.prototype name (${inherited}) throws rather than returning a function`,
    () => dnsTypeNum(inherited),
    error => error.name === 'DnsTypeError');
}
throws('and so does an absent one', () => dnsTypeNum(undefined),
  error => error.name === 'DnsTypeError');

/* ── 3. The throw/kind boundary ───────────────────────────────────────── */
section('3. A throw is not a kind');

eq('DnsTypeError is not among the ten transport kinds',
  TRANSPORT_KINDS.includes('DnsTypeError'), false);
eq('nor is AbortError', TRANSPORT_KINDS.includes('AbortError'), false);
eq('nor DnsQueryError', TRANSPORT_KINDS.includes('DnsQueryError'), false);

/* ── 4. dnsError carries the kind, and names it for the policy layer ──── */
section('4. dnsError');

const servfail = dnsError('servfail', 'example.test', 'TXT');
eq('it is returned, not thrown — the call site reads as `throw dnsError(…)`',
  servfail instanceof Error, true);
eq('it carries the transport kind', servfail.kind, 'servfail');
eq('and the query it was about', [servfail.queryName, servfail.queryType], ['example.test', 'TXT']);
eq('its message names all three', servfail.message, 'servfail while querying example.test TXT');
eq('a detail is appended when given',
  dnsError('http-error', 'example.test', 'A', 'HTTP 502').message,
  'http-error while querying example.test A: HTTP 502');

/**
 * The name is what `optionalCheck()` re-throws on, so it is the field that
 * decides whether an aborted audit degrades to "unknown" or ends the run. The
 * kind stays `cancelled` either way: the kind says what happened at the
 * transport, the name says how the policy layer must treat it.
 */
const cancelled = dnsError('cancelled', 'example.test', 'NS');
eq('a cancelled query is named AbortError', cancelled.name, 'AbortError');
eq('but its kind is still cancelled', cancelled.kind, 'cancelled');
for (const kind of TRANSPORT_KINDS.filter(k => k !== 'cancelled')) {
  eq(`${kind} is named DnsQueryError`, dnsError(kind, 'n', 'A').name, 'DnsQueryError');
}

report();
