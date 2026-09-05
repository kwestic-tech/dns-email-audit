#!/usr/bin/env node
/**
 * Measurement-only spike for 0.9.2's divergence procedure. NOT an implementation.
 *
 *   node docs/specs/fixtures/ptr-fan-out-spike-0.9.2.mjs
 *
 * `OQ-MXV-03` asked what 0.9.2's PTR fan-out costs, and required query traces
 * rather than an argument. Counting addresses in the v0.9.1 oracle answers only
 * how many PTR calls the algorithm would REQUEST; it cannot answer what the
 * forward-confirm step costs, because v0.9.1 holds no PTR answers from which a
 * candidate name could be selected.
 *
 * Two different numbers matter, and an earlier version of this file measured
 * only the first and then did arithmetic for the second:
 *
 *   - calls the procedure makes ABOVE the cache, and
 *   - requests that actually leave the browser, AFTER cache reuse.
 *
 * `PRIVACY.md` publishes the second. So this runs §4 through the REAL cache and
 * the REAL transport — `createDohCache()` and `createDohTransport()` as
 * production composes them, with their own key and admission rules — and puts a
 * recording `fetch` underneath. `fetch` is the production seam: `doh.js` takes
 * it from the injected platform precisely so it can be substituted. Outbound
 * requests are counted there, not inferred.
 *
 * The qualifying hosts and their addresses are read from the committed
 * `baseline-v0.9.1.json`, so the input is the real corpus and not invented. The
 * PTR and forward answers are a fixture, because no such answers exist yet;
 * each one is chosen to exercise a different branch of §4, and they are listed
 * in the capture beside this file.
 *
 * Nothing here is imported by `src/`. It is evidence, and it is reproducible.
 */

import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { createDohCache } from '../../../src/core/dns/cache.js';
import { createDohTransport } from '../../../src/core/dns/doh.js';
import { createResolver } from '../../../src/core/dns/resolver.js';
import { dnsError, dnsTypeNum, DNS_TYPES } from '../../../src/core/dns/errors.js';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const baseline = JSON.parse(
  readFileSync(join(REPO, 'tests/fixtures/equivalence/baseline-v0.9.1.json'), 'utf8'));

/* ── The fixture, one branch of §4 per domain ─────────────────────────── */

/**
 * The name a PTR is actually asked under. This is what reaches the resolver,
 * and therefore what §7.3 lists as disclosed — not the bare address.
 */
function reverseName(address) {
  if (address.includes(':')) {
    const groups = address.split('::');
    const head = groups[0] ? groups[0].split(':') : [];
    const tail = groups.length > 1 && groups[1] ? groups[1].split(':') : [];
    const full = groups.length > 1
      ? [...head, ...Array(8 - head.length - tail.length).fill('0'), ...tail]
      : head;
    const nibbles = full.map(g => g.padStart(4, '0')).join('');
    return nibbles.split('').reverse().join('.') + '.ip6.arpa';
  }
  return address.split('.').reverse().join('.') + '.in-addr.arpa';
}

const SERVFAIL = Symbol('servfail');
const PTR_ANSWERS = {
  // Divergent: provider publishes an address the customer's copy does not.
  '20.0.2.100.in-addr.arpa': ['mailfilter.provider.test'],
  '0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.1.0.a.2.ip6.arpa': ['mailfilter.provider.test'],
  // Self-hosted: the reverse name is inside the audited domain, so there is no
  // separate provider name to compare against and step 2 selects no candidate.
  '5.100.51.100.in-addr.arpa': ['mail.bravo.test'],
  // No PTR published at all — an answer, and therefore a claim of absence.
  '5.113.0.100.in-addr.arpa': [],
  // The lookup did not return. Not a claim either way.
  '9.113.0.100.in-addr.arpa': SERVFAIL,
  // A reverse name that does not forward-confirm: step 3 must stop.
  '11.113.0.100.in-addr.arpa': ['unconfirmed.provider.test'],
  // Equal address sets: confirmed, compared, and correctly reports nothing.
  '13.113.0.100.in-addr.arpa': ['equal.provider.test'],
  // Divergent again, on a second domain.
  '10.100.51.100.in-addr.arpa': ['mailfilter.provider.test'],
};
const FORWARD_ANSWERS = {
  'mailfilter.provider.test': { A: ['100.2.0.20', '100.51.100.10', '100.9.9.9'], AAAA: ['2a01:100::20'] },
  // Resolves, but to nothing the audited domain published — fails confirmation.
  'unconfirmed.provider.test': { A: ['203.0.113.200'], AAAA: [] },
  'equal.provider.test': { A: ['100.0.113.13'], AAAA: [] },
};

/* ── The real cache and transport, over a recording fetch ─────────────── */

const NUM_TO_TYPE = Object.fromEntries(
  Object.entries(DNS_TYPES).map(([name, num]) => [num, name]));

/** A DoH JSON body, in the shape `doh.js` parses. */
function dohBody(type, values) {
  return {
    ok: true,
    status: 200,
    json: async () => ({
      Status: values.length ? 0 : 3,
      Answer: values.map(data => ({ type: DNS_TYPES[type], data })),
      AD: false,
    }),
  };
}

/**
 * Production composition: recording fetch → real transport → real cache → real
 * resolver. Nothing here is a stand-in for the cache; the cache IS the
 * production one, so its key and admission rules are the ones under test.
 */
function productionStack({ ptrAnswers = PTR_ANSWERS, forwardAnswers = FORWARD_ANSWERS } = {}) {
  const outbound = [];
  const platform = {
    fetch: async (url) => {
      const params = new URL(String(url)).searchParams;
      const name = params.get('name');
      const type = NUM_TO_TYPE[Number(params.get('type'))];
      outbound.push(`${name}/${type}`);
      if (type === 'PTR') {
        const answer = ptrAnswers[name];
        if (answer === SERVFAIL) return { ok: true, status: 200, json: async () => ({ Status: 2, Answer: [], AD: false }) };
        return dohBody('PTR', answer || []);
      }
      const entry = forwardAnswers[name];
      return dohBody(type, entry ? (entry[type] || []) : []);
    },
    AbortController: globalThis.AbortController,
    URLSearchParams: globalThis.URLSearchParams,
    setTimeout: (...a) => globalThis.setTimeout(...a),
    clearTimeout: (...a) => globalThis.clearTimeout(...a),
  };
  const cache = createDohCache();
  const { dohFetch } = createDohTransport({ platform, cache, dnsError, dnsTypeNum, retries: 0 });
  const { dohQuery } = createResolver({ dohFetch });

  const above = [];
  return {
    outbound,
    above,
    async query(name, type) {
      above.push(`${name}/${type}`);
      try { return await dohQuery(name, type); } catch (e) { return null; }
    },
  };
}

/* ── §4, executed literally ───────────────────────────────────────────── */

const MAX_HOSTS = 2;          // §4, added by the 0.14 privacy review
const MAX_ADDRESSES = 4;
const MAX_CANDIDATES = 2;

async function divergenceForDomain(domain, hosts, resolver) {
  const qualifying = hosts
    .filter(h => h.inAudited && h.resolves === 'yes' && h.reachability !== 'none')
    .sort((a, b) => a.preference - b.preference)
    .slice(0, MAX_HOSTS);

  const findings = [];
  const candidates = [];
  for (const host of qualifying) {
    const names = [];
    let anyReturned = false;
    for (const address of (host.addresses || []).slice(0, MAX_ADDRESSES)) {
      const answer = await resolver.query(reverseName(address), 'PTR');
      if (answer === null) continue;              // per-address, never per-host
      anyReturned = true;
      names.push(...answer);
    }
    if (!anyReturned) continue;                   // reverseNames null: no claim
    if (!names.length) { findings.push({ domain, host: host.host, finding: 'mx.no-reverse-dns' }); continue; }

    const candidate = names.find(n =>
      n !== host.host && n !== domain && !n.endsWith('.' + domain));
    if (!candidate) continue;                     // self-hosted
    if (!candidates.includes(candidate)) {
      if (candidates.length >= MAX_CANDIDATES) continue;
      candidates.push(candidate);
    }

    const providerA = await resolver.query(candidate, 'A');
    const providerAAAA = await resolver.query(candidate, 'AAAA');
    const provider = [...(providerA || []), ...(providerAAAA || [])];
    const confirmed = (host.addresses || []).some(a => provider.includes(a));
    if (!confirmed) continue;                     // step 3 stops

    const missing = provider.filter(a => !(host.addresses || []).includes(a));
    const strictSuperset = missing.length > 0
      && (host.addresses || []).every(a => provider.includes(a));
    if (strictSuperset) findings.push({ domain, host: host.host, finding: 'mx.vanity-divergent', missing });
  }
  return findings;
}

/* ── Run it over the real corpus ──────────────────────────────────────── */

async function run({ deepChecks, stack = productionStack() }) {
  const findings = [];
  let audited = 0;
  let qualifyingHosts = 0;
  for (const testCase of baseline.cases) {
    for (const entry of testCase.result) {
      const result = entry.result;
      if (!result) continue;
      audited++;
      const mxHealth = deepChecks && result.advanced && result.advanced.mxHealth;
      if (!mxHealth) continue;
      const hosts = mxHealth.hosts || [];
      qualifyingHosts += hosts.filter(h =>
        h.inAudited && h.resolves === 'yes' && h.reachability !== 'none').length;
      findings.push(...await divergenceForDomain(result.domain, hosts, stack));
    }
  }
  return { audited, qualifyingHosts, findings, stack };
}

/* ── The accepted result, pinned exactly ──────────────────────────────── */

/**
 * Every headline figure this capture publishes, as an executable constant.
 *
 * An earlier verdict asserted only the gate, that the renamed run exceeded the
 * ordinary one, and the type probe. All three still passed when the ordinary
 * result drifted from 16/14 to 14/12 — which invalidates the capture and every
 * number in §7.2 while printing CONTROLS PASS. Relative movement does not bound
 * an accepted result; the result itself has to be stated.
 */
const EXPECTED = {
  audited: 80,
  qualifyingHosts: 7,
  ptrCalls: 8,
  forwardCalls: 8,
  callsAboveCache: 16,
  outbound: 14,
  savedByCache: 2,
  findings: [
    { domain: 'alpha.test', host: 'mail.alpha.test', finding: 'mx.vanity-divergent', missing: ['100.51.100.10', '100.9.9.9'] },
    { domain: 'delta.test', host: 'mail.delta.test', finding: 'mx.no-reverse-dns' },
    { domain: 'nowww.host.test', host: 'mail.nowww.host.test', finding: 'mx.vanity-divergent', missing: ['100.2.0.20', '100.9.9.9', '2a01:100::20'] },
  ],
  // The ordered questions that leave the browser. This is the trace reproduced
  // in ptr-fan-out-0.9.2.md; the two must agree.
  outboundTrace: [
    '20.0.2.100.in-addr.arpa/PTR',
    '0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.1.0.a.2.ip6.arpa/PTR',
    'mailfilter.provider.test/A',
    'mailfilter.provider.test/AAAA',
    '5.100.51.100.in-addr.arpa/PTR',
    '5.113.0.100.in-addr.arpa/PTR',
    '9.113.0.100.in-addr.arpa/PTR',
    '11.113.0.100.in-addr.arpa/PTR',
    'unconfirmed.provider.test/A',
    'unconfirmed.provider.test/AAAA',
    '13.113.0.100.in-addr.arpa/PTR',
    'equal.provider.test/A',
    'equal.provider.test/AAAA',
    '10.100.51.100.in-addr.arpa/PTR',
  ],
};

/** Throws unless the ordinary run is exactly the accepted result. */
function assertOrdinaryResult(result) {
  const above = result.stack.above;
  const outbound = result.stack.outbound;
  assert.equal(result.audited, EXPECTED.audited, 'audited domains');
  assert.equal(result.qualifyingHosts, EXPECTED.qualifyingHosts, 'qualifying hosts');
  assert.equal(above.filter(q => q.endsWith('/PTR')).length, EXPECTED.ptrCalls, 'PTR calls above cache');
  assert.equal(above.filter(q => !q.endsWith('/PTR')).length, EXPECTED.forwardCalls, 'forward calls above cache');
  assert.equal(above.length, EXPECTED.callsAboveCache, 'calls above cache');
  assert.equal(outbound.length, EXPECTED.outbound, 'requests that left the browser');
  assert.equal(above.length - outbound.length, EXPECTED.savedByCache, 'saved by cache reuse');
  assert.deepEqual(result.findings, EXPECTED.findings, 'findings');
  assert.deepEqual(outbound, EXPECTED.outboundTrace, 'ordered outbound trace');
}

const on = await run({ deepChecks: true });
const ptrAbove = on.stack.above.filter(q => q.endsWith('/PTR'));
const fwdAbove = on.stack.above.filter(q => !q.endsWith('/PTR'));
console.log('OBSERVED, deep checks on');
console.log(`  domains audited                      : ${on.audited}`);
console.log(`  qualifying hosts                     : ${on.qualifyingHosts}`);
console.log(`  procedure calls ABOVE the cache      : ${on.stack.above.length}  (${ptrAbove.length} PTR + ${fwdAbove.length} forward)`);
console.log(`  requests that LEFT the browser       : ${on.stack.outbound.length}`);
console.log(`  saved by page-lifetime cache reuse   : ${on.stack.above.length - on.stack.outbound.length}`);
console.log(`  outbound per audited domain          : ${(on.stack.outbound.length / on.audited).toFixed(3)}`);
console.log('  findings produced:');
for (const f of on.findings) console.log(`    ${f.finding.padEnd(22)} ${f.domain} (${f.host})${f.missing ? ' missing ' + JSON.stringify(f.missing) : ''}`);
console.log('  every request that left the browser:');
for (const q of on.stack.outbound) console.log(`    ${q}`);

/* ── Negative controls ────────────────────────────────────────────────── */

// 1. The gate. With deep checks off there is no mxHealth to read, so nothing
//    may be issued at all — otherwise the count above includes queries the gate
//    was supposed to prevent.
const off = await run({ deepChecks: false });
console.log('\nCONTROL 1 — gate off');
console.log(`  above the cache: ${off.stack.above.length}   outbound: ${off.stack.outbound.length}   findings: ${off.findings.length}   (all must be 0)`);

// 2. The reuse is the CACHE's, not an accident of the harness. The saving above
//    comes from one provider name being asked for twice. Rename it on the
//    second domain and the same procedure must go out again — if the number
//    does not move, nothing was being deduplicated in the first place.
const renamed = { ...PTR_ANSWERS, '10.100.51.100.in-addr.arpa': ['second.provider.test'] };
const renamedForward = { ...FORWARD_ANSWERS, 'second.provider.test': FORWARD_ANSWERS['mailfilter.provider.test'] };
const byName = await run({ deepChecks: true,
  stack: productionStack({ ptrAnswers: renamed, forwardAnswers: renamedForward }) });
console.log('\nCONTROL 2 — a repeated query renamed');
console.log(`  above the cache: ${byName.stack.above.length}   outbound: ${byName.stack.outbound.length}   (outbound must RISE)`);

// 3. Same, by TYPE. The cache key is name|type|dnssec|cd, so asking the same
//    name under a different type must miss.
const typeProbe = productionStack();
await typeProbe.query('mailfilter.provider.test', 'A');
const afterFirst = typeProbe.outbound.length;
await typeProbe.query('mailfilter.provider.test', 'A');      // same key: must reuse
const afterRepeat = typeProbe.outbound.length;
await typeProbe.query('mailfilter.provider.test', 'AAAA');   // different type: must miss
const afterType = typeProbe.outbound.length;
console.log('\nCONTROL 3 — the cache key includes the type');
console.log(`  first A: ${afterFirst}   repeated A: ${afterRepeat} (must not rise)   then AAAA: ${afterType} (must rise)`);

/* ── Assertions. Anything below that throws exits non-zero. ───────────── */

assertOrdinaryResult(on);

// The gate.
assert.equal(off.stack.above.length, 0, 'gate off: calls above cache');
assert.equal(off.stack.outbound.length, 0, 'gate off: outbound');
assert.equal(off.findings.length, 0, 'gate off: findings');

// The reuse is the cache's. Pinned to 16 exactly, not merely "more than 14":
// a renamed run that produced 15 would satisfy a greater-than and still mean
// the cache had absorbed a request it should not have.
assert.equal(byName.stack.above.length, 16, 'renamed: calls above cache');
assert.equal(byName.stack.outbound.length, 16, 'renamed: outbound');

// The key discriminates on type as well as name.
assert.equal(afterFirst, 1, 'first A');
assert.equal(afterRepeat, 1, 'repeated A must reuse');
assert.equal(afterType, 2, 'AAAA must miss');

/**
 * The positive check has to be able to fail, or it bounds nothing.
 *
 * This is the exact drift that passed the previous verdict: golf.test publishes
 * no PTR instead of a provider that fails forward-confirmation, which removes
 * two forward calls and two outbound requests. `assertOrdinaryResult` must
 * reject it.
 */
const drifted = await run({
  deepChecks: true,
  stack: productionStack({
    ptrAnswers: { ...PTR_ANSWERS, '11.113.0.100.in-addr.arpa': [] },
  }),
});
let rejected = false;
try { assertOrdinaryResult(drifted); } catch { rejected = true; }
console.log('\nCONTROL 4 — the pinned result rejects a drifted run');
console.log(`  drifted run: ${drifted.stack.above.length} above, ${drifted.stack.outbound.length} outbound   rejected: ${rejected}  (must be true)`);
assert.equal(rejected, true, 'a drifted ordinary result must be rejected');

/**
 * The capture beside this file reproduces the trace for a reader who is not
 * going to run the script. The spec says the trace is captured there, so the
 * two must be the same fourteen lines in the same order — otherwise the
 * document can drift from the executable silently, which is how the headline
 * figures drifted in the first place.
 */
const captureText = readFileSync(join(dirname(fileURLToPath(import.meta.url)), 'ptr-fan-out-0.9.2.md'), 'utf8');
const captureBlock = /### The ordered outbound trace[\s\S]*?```text\n([\s\S]*?)```/.exec(captureText);
assert.ok(captureBlock, 'the capture must contain an ordered outbound trace block');
const captureTrace = captureBlock[1].trim().split('\n').map(line => line.trim()).filter(Boolean);
console.log('\nCONTROL 5 — the capture reproduces the executable trace');
console.log(`  capture entries: ${captureTrace.length}   executable entries: ${EXPECTED.outboundTrace.length}`);
assert.deepEqual(captureTrace, EXPECTED.outboundTrace, 'capture trace must equal EXPECTED.outboundTrace');

console.log('\nRESULT PINNED AND CONTROLS PASS');
