#!/usr/bin/env node
/**
 * The DoH transport. Spec Design §3 layer 1, implementation Task 3.1.
 *
 * Co-located per §9: one directory holds the transport and the tests that pin
 * it. What this owns is the ten-kind algebra at its construction sites, the two
 * set rules that a coarser model would flatten, and the ordering property that
 * keeps a type error from being reported as a resolver failure.
 *
 * The whole-audit behaviour of this code is covered elsewhere and deliberately
 * not duplicated here: `tools/scoring.test.mjs` drives it through the engine,
 * and the five-surface equivalence run drives it through the shipped artifact.
 * This file exists for the boundaries those cannot address directly.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import {
  createDohTransport, responseKind,
  TRANSPORT_KINDS, RETRY_TERMINAL_KINDS, CACHEABLE_KINDS,
  DOH_ENDPOINT, DOH_TIMEOUT_MS, DOH_RETRIES, MAX_DOH_CONCURRENCY,
} from './doh.js';

const { eq, rejects, section, report } = createSuite();

/* ── A platform and a cache, both minimal and both observable ─────────── */

function dnsError(kind, name, type, detail) {
  const e = new Error(`${kind} while querying ${name} ${type}${detail ? ': ' + detail : ''}`);
  e.name = kind === 'cancelled' ? 'AbortError' : 'DnsQueryError';
  e.kind = kind;
  return e;
}

const TYPES = { A: 1, NS: 2, MX: 15, TXT: 16, DS: 43, DNSKEY: 48 };
function dnsTypeNum(type) {
  if (!Object.prototype.hasOwnProperty.call(TYPES, type)) {
    const e = new Error('unsupported DNS type: ' + type);
    e.name = 'DnsTypeError';
    throw e;
  }
  return TYPES[type];
}

/** A cache that records every read and write, so the rules can be observed. */
function recordingCache() {
  const store = new Map();
  const reads = [];
  const writes = [];
  return {
    get(key) { reads.push(key); return store.get(key); },
    set(key, value) { writes.push(key); store.set(key, value); },
    store, reads, writes,
  };
}

/**
 * `fetch` is the seam, exactly as it is in production: the DoH fixture works by
 * substituting it, and nothing here reaches for the ambient one.
 */
function stubPlatform(fetchImpl) {
  return {
    fetch: fetchImpl,
    AbortController: globalThis.AbortController,
    URLSearchParams: globalThis.URLSearchParams,
    setTimeout: (...args) => globalThis.setTimeout(...args),
    clearTimeout: (...args) => globalThis.clearTimeout(...args),
  };
}

const answered = (status, answers = []) => async () => ({
  ok: true, status: 200, json: async () => ({ Status: status, Answer: answers, AD: false }),
});

function build(fetchImpl, cache = recordingCache()) {
  const calls = [];
  const wrapped = async (url, init) => { calls.push(String(url)); return fetchImpl(url, init); };
  const transport = createDohTransport({
    platform: stubPlatform(wrapped), cache, dnsError, dnsTypeNum,
  });
  return { ...transport, cache, calls };
}

/* ── 1. The closed set, and where each member is made ─────────────────── */
section('1. The ten kinds, at their construction sites');

eq('the set is ten members', TRANSPORT_KINDS.length, 10);
eq('and it is exactly the set spec §3 closes', [...TRANSPORT_KINDS].sort(),
  ['cancelled', 'dns-error', 'http-error', 'network-error', 'nodata', 'nxdomain',
    'refused', 'servfail', 'success', 'timeout']);
eq('and it is frozen against a consumer editing it', Object.isFrozen(TRANSPORT_KINDS), true);

// Six come from the response status. Asserted on the pure function, because
// that is the site, and then through a real request below.
eq('status 0 with answers is success', responseKind(0, 1), 'success');
eq('status 0 without answers is nodata', responseKind(0, 0), 'nodata');
eq('status 3 is nxdomain', responseKind(3, 0), 'nxdomain');
eq('status 2 is servfail', responseKind(2, 0), 'servfail');
eq('status 5 is refused', responseKind(5, 0), 'refused');
eq('any other status is dns-error', responseKind(4, 0), 'dns-error');
eq('and so is an unparseable one', responseKind(-1, 0), 'dns-error');

const statusCases = [[0, [{ type: 1, data: '1.2.3.4' }], 'success'], [0, [], 'nodata'],
  [3, [], 'nxdomain'], [2, [], 'servfail'], [5, [], 'refused'], [9, [], 'dns-error']];
for (const [status, answers, kind] of statusCases) {
  const t = build(answered(status, answers));
  eq(`a status ${status} response reaches the caller as ${kind}`,
    (await t.dohFetch('example.test', 'A', { retries: 0 })).kind, kind);
}

// The other four come from the request failing rather than answering.
eq('a non-ok HTTP response is http-error',
  (await build(async () => ({ ok: false, status: 502 })).dohFetch('example.test', 'A', { retries: 0 })).kind,
  'http-error');
eq('and it carries the HTTP status for the error message',
  (await build(async () => ({ ok: false, status: 502 })).dohFetch('example.test', 'A', { retries: 0 })).httpStatus,
  502);
eq('a thrown fetch is network-error',
  (await build(async () => { throw new Error('socket closed'); }).dohFetch('example.test', 'A', { retries: 0 })).kind,
  'network-error');

/**
 * Cancellation has TWO shapes, and they are not interchangeable.
 *
 * A signal that is ALREADY aborted is rejected by `acquireDohSlot()` before a
 * request is made, and that leaves as a **throw** — `AbortError`, one of §12.1's
 * thrown paths. A signal that aborts while the request is in flight is caught
 * by `fetchDohOnce()` and returns the **kind** `cancelled`.
 *
 * Both are correct and the difference is load-bearing: the first never touches
 * the network, so reporting it as a returned kind would claim a query was made.
 * Found by writing this test and watching it fail, not by reading the code.
 */
const aborted = new AbortController();
aborted.abort();
const preAborted = build(answered(0));
await rejects('a signal aborted BEFORE the call rejects, and makes no request',
  () => preAborted.dohFetch('example.test', 'A', { retries: 0, signal: aborted.signal }),
  error => error.name === 'AbortError' && error.kind === 'cancelled');
eq('and no request was attempted', preAborted.calls.length, 0);

const midFlight = new AbortController();
const during = build((url, init) => new Promise((resolve, reject) => {
  init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
  midFlight.abort();
}));
eq('a signal that aborts DURING the request returns the cancelled kind',
  (await during.dohFetch('example.test', 'A', { retries: 0, signal: midFlight.signal })).kind,
  'cancelled');
eq('and that one did reach the network', during.calls.length, 1);

// `timeout` needs the timer to fire before the response does.
const slow = build(async (url, init) => new Promise((resolve, reject) => {
  init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
}));
eq('a request the timer aborts is timeout',
  (await slow.dohFetch('example.test', 'A', { retries: 0, timeoutMs: 5 })).kind, 'timeout');

/* ── 2. Cacheable ⊂ retry-terminal, and they differ by cancelled ──────── */
section('2. The two sets, and the member that separates them');

eq('retry stops on four kinds', [...RETRY_TERMINAL_KINDS].sort(),
  ['cancelled', 'nodata', 'nxdomain', 'success']);
eq('the cache admits three', [...CACHEABLE_KINDS].sort(),
  ['nodata', 'nxdomain', 'success']);
eq('cacheable is a strict subset of retry-terminal',
  CACHEABLE_KINDS.every(k => RETRY_TERMINAL_KINDS.includes(k)), true);
eq('and the difference is exactly cancelled',
  RETRY_TERMINAL_KINDS.filter(k => !CACHEABLE_KINDS.includes(k)), ['cancelled']);

// Observed, not just declared: what actually reaches the cache.
for (const [status, answers, kind] of statusCases) {
  const t = build(answered(status, answers));
  await t.dohFetch('example.test', 'A', { retries: 0 });
  const cached = t.cache.writes.length === 1;
  eq(`${kind} ${CACHEABLE_KINDS.includes(kind) ? 'is' : 'is not'} written to the cache`,
    cached, CACHEABLE_KINDS.includes(kind));
}

const cancelController = new AbortController();
const cancelledRun = build((url, init) => new Promise((resolve, reject) => {
  init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
  cancelController.abort();
}));
eq('the cancelled kind really was produced',
  (await cancelledRun.dohFetch('example.test', 'A', { retries: 0, signal: cancelController.signal })).kind,
  'cancelled');
eq('cancelled is terminal but never cached', cancelledRun.cache.writes, []);
eq('and terminal means it was attempted exactly once', cancelledRun.calls.length, 1);

// Retry: a non-terminal kind is attempted again, a terminal one is not.
let attempts = 0;
const retrying = build(async () => { attempts++; return { ok: false, status: 500 }; });
await retrying.dohFetch('example.test', 'A', { retries: 2 });
eq('a non-terminal kind is retried to the limit', attempts, 3);

attempts = 0;
const terminal = build(async () => { attempts++; return answered(3)(); });
await terminal.dohFetch('example.test', 'A', { retries: 2 });
eq('a terminal kind stops after the first attempt', attempts, 1);

/* ── 3. The cache key, and the bits that must not collide ─────────────── */
section('3. Cache identity');

const keyed = build(answered(0, [{ type: 1, data: '1.2.3.4' }]));
await keyed.dohFetch('Example.TEST.', 'A', { retries: 0 });
eq('the name is lowercased and its trailing dot removed',
  keyed.cache.writes, ['example.test|A|0|0']);

const bits = build(answered(0, [{ type: 1, data: '1.2.3.4' }]));
await bits.dohFetch('example.test', 'A', { retries: 0 });
await bits.dohFetch('example.test', 'A', { retries: 0, dnssec: true });
await bits.dohFetch('example.test', 'A', { retries: 0, dnssec: true, checkingDisabled: true });
eq('do and cd are part of the key, so the DNSSEC probes cannot collide',
  bits.cache.writes, ['example.test|A|0|0', 'example.test|A|1|0', 'example.test|A|1|1']);
eq('and all three were really sent', bits.calls.length, 3);
eq('the second asked for DNSSEC records', bits.calls[1].includes('do=1'), true);
eq('the third also disabled checking', bits.calls[2].includes('cd=1'), true);

const reused = build(answered(0, [{ type: 1, data: '1.2.3.4' }]));
await reused.dohFetch('example.test', 'A', { retries: 0 });
await reused.dohFetch('example.test', 'A', { retries: 0 });
eq('a second identical query is served from the cache', reused.calls.length, 1);

const uncached = build(answered(0, [{ type: 1, data: '1.2.3.4' }]));
await uncached.dohFetch('example.test', 'A', { retries: 0, noCache: true });
await uncached.dohFetch('example.test', 'A', { retries: 0, noCache: true });
eq('noCache neither reads nor writes', [uncached.calls.length, uncached.cache.writes.length], [2, 0]);

/* ── 4. A throw is not a kind ─────────────────────────────────────────── */
section('4. DnsTypeError leaves as a throw');

const typed = build(answered(0));
await rejects('an unsupported type rejects rather than returning a kind',
  () => typed.dohFetch('example.test', 'WKS', { retries: 0 }),
  error => error.name === 'DnsTypeError' && /unsupported DNS type: WKS/.test(error.message));
eq('and it never became a kind', TRANSPORT_KINDS.includes('DnsTypeError'), false);

/**
 * The ordering property, and the reason it is asserted rather than assumed.
 *
 * `fetchDohOnce`'s catch turns every throw into `network-error`. If the type
 * were resolved inside the try, an unsupported type would be reported as a
 * resolver failure — a wrong answer wearing the costume of a real one. So the
 * request must never be attempted at all.
 */
eq('and no request was made for it', typed.calls.length, 0);

// It also throws on a cache hit, not only on a miss.
const warm = build(answered(0, [{ type: 1, data: '1.2.3.4' }]));
await warm.dohFetch('example.test', 'A', { retries: 0 });
await rejects('an unsupported type rejects even with a warm cache',
  () => warm.dohFetch('example.test', 'WKS', { retries: 0 }),
  error => error.name === 'DnsTypeError');

/* ── 5. Concurrency is bounded, and cancellation unblocks a waiter ─────── */
section('5. The slot pool');

let inFlight = 0;
let peak = 0;
const release = [];
const gated = build(() => new Promise(resolve => {
  inFlight++; peak = Math.max(peak, inFlight);
  release.push(() => { inFlight--; resolve({ ok: true, status: 200, json: async () => ({ Status: 0, Answer: [] }) }); });
}));
const many = Array.from({ length: MAX_DOH_CONCURRENCY + 4 },
  (_, i) => gated.dohFetch(`d${i}.test`, 'A', { retries: 0 }));
await new Promise(resolve => globalThis.setImmediate(resolve));
eq('no more than the maximum are open at once', peak, MAX_DOH_CONCURRENCY);
eq('and the rest are queued, not dropped', release.length, MAX_DOH_CONCURRENCY);
while (release.length) { release.shift()(); await new Promise(r => globalThis.setImmediate(r)); }
await Promise.all(many);
eq('every queued query eventually ran', gated.calls.length, MAX_DOH_CONCURRENCY + 4);

/* ── 6. The declared constants are the ones in force ──────────────────── */
section('6. Constants');

eq('the endpoint is Cloudflare', DOH_ENDPOINT, 'https://cloudflare-dns.com/dns-query');
eq('the default timeout is 8 s', DOH_TIMEOUT_MS, 8000);
eq('the default retry count is 1', DOH_RETRIES, 1);
eq('the concurrency ceiling is 16', MAX_DOH_CONCURRENCY, 16);

const endpointed = build(answered(0));
await endpointed.dohFetch('example.test', 'A', { retries: 0 });
eq('and the request really goes to it', endpointed.calls[0].startsWith(DOH_ENDPOINT + '?'), true);
eq('with the type as its IANA number', endpointed.calls[0].includes('type=1'), true);

report();
