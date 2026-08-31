#!/usr/bin/env node
/**
 * The error and cancellation policy, and name existence.
 * Spec Design §3 layer 4 and its exception edge. Task 3.5.
 *
 * Both modules decide the same kind of question — what a failure MEANS — and
 * both get it wrong in the same direction if the third value collapses: a
 * resolver that would not answer must never be reported as a resolver that
 * answered "no".
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { optionalCheck, RETHROWN_ERROR_NAMES } from './optional.js';
import { createExistence, existenceFromResponse, EXISTENCE_STATES } from './existence.js';
import { dnsError } from './errors.js';
import { TRANSPORT_KINDS } from './doh.js';

const { eq, rejects, section, report } = createSuite();

/* ── 1. A failure degrades to the caller's declared unknown ───────────── */
section('1. optionalCheck degrades rather than discards');

eq('a check that succeeds returns its value',
  await optionalCheck(async () => 'real answer', 'unknown'), 'real answer');
eq('a check that fails returns the declared fallback',
  await optionalCheck(async () => { throw dnsError('servfail', 'n', 'TXT'); }, { state: 'unknown' }),
  { state: 'unknown' });

/**
 * The failure this exists to prevent: a transient SERVFAIL on one enrichment
 * lookup used to throw, and the throw discarded the whole audit — SPF, DKIM,
 * DMARC and all — for a domain whose real records had resolved perfectly.
 */
const kinds = TRANSPORT_KINDS.filter(k => k !== 'cancelled');
for (const kind of kinds) {
  eq(`a ${kind} failure degrades instead of propagating`,
    await optionalCheck(async () => { throw dnsError(kind, 'n', 'TXT'); }, 'unknown'), 'unknown');
}

// A fallback may be a function of the error, so a caller can record the cause
// alongside its declared unknown.
eq('a function fallback receives the error',
  (await optionalCheck(async () => { throw dnsError('timeout', 'n', 'A'); },
    error => ({ state: 'unknown', because: error.kind }))),
  { state: 'unknown', because: 'timeout' });

// It is not limited to DNS errors: any throw from the wrapped work degrades.
eq('an ordinary error degrades too',
  await optionalCheck(async () => { throw new TypeError('boom'); }, 'unknown'), 'unknown');

/* ── 2. Two names are re-thrown, and never degraded ───────────────────── */
section('2. The rethrow set');

eq('the set is two names', [...RETHROWN_ERROR_NAMES].sort(), ['AbortError', 'DnsTypeError']);
eq('and it is frozen', Object.isFrozen(RETHROWN_ERROR_NAMES), true);

await rejects('an aborted audit is not an unknown result',
  () => optionalCheck(async () => { throw dnsError('cancelled', 'n', 'NS'); }, 'unknown'),
  error => error.name === 'AbortError' && error.kind === 'cancelled');

const typeError = new Error('unsupported DNS type: WKS');
typeError.name = 'DnsTypeError';
await rejects('an unsupported record type is a defect, not a hiccup',
  () => optionalCheck(async () => { throw typeError; }, 'unknown'),
  error => error.name === 'DnsTypeError');

/**
 * It re-throws by NAME, not by kind. That is why dnsError() names a cancelled
 * query AbortError while leaving its kind `cancelled` — asserted here because
 * the two modules have to agree and nothing else makes them.
 */
eq('the cancelled kind reaches this policy carrying the name it keys on',
  dnsError('cancelled', 'n', 'NS').name, 'AbortError');
eq('and no other kind carries a re-thrown name',
  kinds.filter(k => RETHROWN_ERROR_NAMES.includes(dnsError(k, 'n', 'A').name)), []);

/* ── 3. Existence: three values, and the third is load-bearing ────────── */
section('3. Name existence');

eq('the set is three values', [...EXISTENCE_STATES].sort(), ['no', 'unknown', 'yes']);
eq('and it is frozen', Object.isFrozen(EXISTENCE_STATES), true);

eq('nxdomain means the name does not exist', existenceFromResponse({ kind: 'nxdomain' }), 'no');
eq('success means it does', existenceFromResponse({ kind: 'success' }), 'yes');
eq('and so does nodata — a name with no NS record still exists',
  existenceFromResponse({ kind: 'nodata' }), 'yes');

/**
 * `nxdomain ≠ nodata` is the distinction spec §3 names, and the third value is
 * what keeps a resolver failure from becoming a missing domain. An audit that
 * collapsed `unknown` into `no` would tell someone their domain is unregistered
 * because a query timed out.
 */
const notAnswers = TRANSPORT_KINDS.filter(k => !['nxdomain', 'success', 'nodata'].includes(k));
eq('seven kinds are neither an answer nor a denial', notAnswers.length, 7);
for (const failure of notAnswers) {
  eq(`${failure} is unknown, never no`, existenceFromResponse({ kind: failure }), 'unknown');
}
eq('a missing response is unknown rather than a throw', existenceFromResponse(undefined), 'unknown');
eq('and so is a null one', existenceFromResponse(null), 'unknown');

/* ── 4. domainExists asks the right question, and rethrows cancellation ─ */
section('4. domainExists');

const asked = [];
const existsOver = kind => createExistence({
  dohFetch: async (name, type, opts) => { asked.push({ name, type, opts }); return { kind, answers: [] }; },
});

eq('it maps through the same table', await existsOver('nxdomain')('gone.test', {}), 'no');
eq('it asks for NS', asked[0].type, 'NS');
eq('for the name it was given', asked[0].name, 'gone.test');

await rejects('a cancelled probe throws rather than reporting unknown',
  () => existsOver('cancelled')('example.test', {}),
  error => error.name === 'AbortError' && error.kind === 'cancelled');

/**
 * The difference that justifies the throw: `unknown` is a claim that the
 * resolver was asked and would not say. An aborted audit never got that far,
 * so reporting `unknown` would assert something that did not happen.
 */
eq('while a servfail — asked, and refused — really is unknown',
  await existsOver('servfail')('example.test', {}), 'unknown');

report();
