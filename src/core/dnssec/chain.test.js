#!/usr/bin/env node
/**
 * DNSSEC chain evaluation. Task 4.5.
 *
 * **Two axes, kept apart.** `secure` comes only from the resolver's AD verdict;
 * local DS-to-DNSKEY arithmetic can diagnose a mismatch when AD is already
 * false but can never promote a zone to secure or demote one the resolver
 * authenticated. `servfail.nl` is why — its DS confirms its KSK by SHA-256 and
 * the zone is bogus. Those are asserted here as rule precedence, with a
 * matcher that says "confirmed" while the resolver says nothing.
 *
 * **It must never throw.** It is the only entry in the advanced-checks
 * `Promise.all` with no `optionalCheck()` wrapper, which is safe only because
 * it reads `dohFetch()`'s `.kind` instead of calling `requireUsable()`. Every
 * transport kind is driven through it below.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { TRANSPORT_KINDS } from '../dns/doh.js';
import {
  createDnssecCheck, dnssecLookupStatus,
  DNSSEC_STATES, DNSSEC_CHAIN_CLAIMS, DNSSEC_CHAIN_SOURCES, DNSSEC_EVIDENCE,
} from './chain.js';

const { eq, section, report } = createSuite();

const DOMAIN = 'example.test';
const KEY = '257 3 8 AwEAAaurq6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=';
const DS = `1234 8 2 ${'ab'.repeat(32)}`;

/**
 * A transport answering per record type, plus a separate answer for the
 * checking-disabled re-probe that rule 1 makes.
 */
function transport({ ns = {}, ds = {}, dnskey = {}, unchecked = null } = {}) {
  const asked = [];
  const answer = spec => ({
    kind: spec.kind || 'success', ad: spec.ad === true,
    answers: (spec.answers || []),
  });
  return {
    asked,
    dohFetch: async (name, type, opts) => {
      asked.push({ name, type, dnssec: opts?.dnssec === true, cd: opts?.checkingDisabled === true });
      if (type === 'DS') return answer(ds);
      if (type === 'DNSKEY') return answer(dnskey);
      if (opts?.checkingDisabled) return answer(unchecked || { kind: 'servfail' });
      return answer(ns);
    },
  };
}
const rec = (type, data) => ({ type, data });
const run = (spec, matcher) => {
  const t = transport(spec);
  const check = createDnssecCheck({
    dohFetch: t.dohFetch,
    cleanAnswerData: d => d,
    matchDsSet: matcher || (async records => ({
      ds: records.map(() => ({ match: 'unverifiable', unverifiableReason: 'invalid-ds' })),
      anchorConfirmed: false, orphanDs: [],
    })),
  });
  return { asked: t.asked, result: check(DOMAIN) };
};

/* ── 1. Published state constants ─────────────────────────────────────── */
section('1. State constants');

eq('six chain states', [...DNSSEC_STATES],
  ['secure', 'insecure', 'bogus', 'unanchored', 'mismatch', 'indeterminate']);
eq('nine chain claims', DNSSEC_CHAIN_CLAIMS.length, 9);
eq('two chain sources', [...DNSSEC_CHAIN_SOURCES], ['resolver', 'local']);
eq('three evidence levels', [...DNSSEC_EVIDENCE], ['complete', 'partial', 'none']);
for (const [name, c] of Object.entries({
  DNSSEC_STATES, DNSSEC_CHAIN_CLAIMS, DNSSEC_CHAIN_SOURCES, DNSSEC_EVIDENCE,
})) eq(`${name} is frozen`, Object.isFrozen(c), true);

/* ── 2. dnssecLookupStatus, a named raw-kind reader ───────────────────── */
section('2. dnssecLookupStatus');

// `success` or `nodata` only. NXDOMAIN on the NS probe stays indeterminate
// rather than becoming insecure: both score zero, but `indeterminate` is what
// marks the pillar UNPROVEN, and quietly moving a domain out of that set
// changes what the interface reports about a check that did not run.
eq('success is a completed lookup', dnssecLookupStatus({ kind: 'success' }).completed, true);
eq('so is nodata', dnssecLookupStatus({ kind: 'nodata' }).completed, true);
eq('nxdomain is NOT', dnssecLookupStatus({ kind: 'nxdomain' }).completed, false);
eq('nor is servfail', dnssecLookupStatus({ kind: 'servfail' }).completed, false);
eq('and the kind is carried through', dnssecLookupStatus({ kind: 'timeout' }).kind, 'timeout');
const completed = TRANSPORT_KINDS.filter(k => dnssecLookupStatus({ kind: k }).completed);
eq('exactly two of the ten kinds complete', completed, ['success', 'nodata']);

/* ── 3. The resolver decides secure, and nothing else does ────────────── */
section('3. Rules 2 and 3');

const secure = await run({ ns: { ad: true } }).result;
eq('AD true is secure', secure.state, 'secure');
eq('the claim says where it came from',
  secure.chain.find(c => c.claim === 'resolver-ad').source, 'resolver');
eq('and records the bit it read',
  secure.chain.find(c => c.claim === 'resolver-ad').detail.ad, true);

const insecure = await run({ ns: { ad: false } }).result;
eq('AD false with nothing published is insecure', insecure.state, 'insecure');

/**
 * The `servfail.nl` rule. A matcher that confirms an anchor must NOT promote a
 * zone the resolver did not authenticate — local evidence agreeing is not the
 * same as the chain validating.
 */
const confirming = async records => ({
  ds: records.map(() => ({ match: 'confirmed', unverifiableReason: null, keyTag: 1234 })),
  anchorConfirmed: true, orphanDs: [],
});
const localOnly = await run({
  ns: { ad: false }, ds: { answers: [rec(43, DS)] }, dnskey: { answers: [rec(48, KEY)] },
}, confirming).result;
eq('a confirmed anchor does NOT make an unauthenticated zone secure',
  localOnly.state === 'secure', false);
eq('it stays insecure', localOnly.state, 'insecure');
eq('while still reporting the confirmation as local evidence',
  localOnly.chain.find(c => c.claim === 'ds-confirms-dnskey').source, 'local');

/* ── 4. Rule 1 outranks everything ────────────────────────────────────── */
section('4. The validated-servfail security path');

// A SERVFAIL that RESOLVES with checking disabled is the resolver saying
// validation failed. This is the reason the raw handle is required: a SERVFAIL
// never becomes a normalized array at all.
const bogus = run({ ns: { kind: 'servfail' }, unchecked: { kind: 'success' } });
const bogusResult = await bogus.result;
eq('a servfail that resolves with cd=1 is bogus', bogusResult.state, 'bogus');
eq('and the claim is the resolver\'s', bogusResult.chain[0].claim, 'resolver-bogus');
eq('the re-probe asked with checking disabled',
  bogus.asked.some(q => q.cd === true), true);
eq('and the first three queries did not', bogus.asked.slice(0, 3).every(q => !q.cd), true);
eq('every query asked for DNSSEC records', bogus.asked.every(q => q.dnssec), true);

// A SERVFAIL that stays SERVFAIL with checking disabled is not a validation
// failure — it is a resolver that could not answer.
const stillFailing = await run({ ns: { kind: 'servfail' }, unchecked: { kind: 'servfail' } }).result;
eq('a servfail that persists with cd=1 is indeterminate', stillFailing.state, 'indeterminate');
eq('and it is NOT bogus', stillFailing.state === 'bogus', false);
eq('the claim names the unreachability',
  stillFailing.chain[0].claim, 'resolver-unreachable');
eq('and the error carries the kind', stillFailing.error, 'servfail');

// Even a confirming matcher cannot rescue a bogus verdict.
const bogusWithProof = await run({
  ns: { kind: 'servfail' }, unchecked: { kind: 'success' },
  ds: { answers: [rec(43, DS)] }, dnskey: { answers: [rec(48, KEY)] },
}, confirming).result;
eq('local confirmation cannot un-bogus a zone', bogusWithProof.state, 'bogus');

/* ── 5. It must never throw ───────────────────────────────────────────── */
section('5. Every transport kind returns a result');

for (const kind of TRANSPORT_KINDS) {
  const r = await run({ ns: { kind }, ds: { kind }, dnskey: { kind } }).result;
  eq(`${kind} produces a state rather than an exception`,
    DNSSEC_STATES.includes(r.state), true);
}
eq('an unreachable resolver is indeterminate, not insecure',
  (await run({ ns: { kind: 'timeout' }, ds: { kind: 'timeout' }, dnskey: { kind: 'timeout' } })
    .result).state, 'indeterminate');
// The one place the transport kind reaches the result, and only there.
eq('error is set only for indeterminate',
  (await run({ ns: { ad: true } }).result).error, undefined);
eq('and it is the NS kind that lands there',
  (await run({ ns: { kind: 'refused' } }).result).error, 'refused');

/* ── 6. Rules 4, 5 and 6, and the evidence behind them ────────────────── */
section('6. What the child and parent publish');

const unanchored = await run({
  ns: { ad: false }, ds: { kind: 'nodata' }, dnskey: { answers: [rec(48, KEY)] },
}).result;
eq('keys published with no DS is unanchored', unanchored.state, 'unanchored');

const mismatching = async records => ({
  ds: records.map(() => ({ match: 'digest-mismatch', unverifiableReason: null, keyTag: 1234 })),
  anchorConfirmed: false, orphanDs: [1234],
});
const mismatch = await run({
  ns: { ad: false }, ds: { answers: [rec(43, DS)] }, dnskey: { answers: [rec(48, KEY)] },
}, mismatching).result;
eq('a determinate DS set with no confirmation is a mismatch', mismatch.state, 'mismatch');
eq('and the chain names the failing tag',
  mismatch.chain.find(c => c.claim === 'ds-digest-mismatch').detail.keyTag, 1234);

// A DS set that merely could not be CHECKED falls to the residual rather than
// raising the alarm. Positive local proof only.
const unverifiable = await run({
  ns: { ad: false }, ds: { answers: [rec(43, DS)] }, dnskey: { answers: [rec(48, KEY)] },
}).result;
eq('an unverifiable DS set is not a mismatch', unverifiable.state, 'insecure');
eq('and the chain says it was unverifiable',
  unverifiable.chain.some(c => c.claim === 'ds-unverifiable'), true);

/* ── 7. Evidence, and the type filter ─────────────────────────────────── */
section('7. Evidence and filtering');

eq('both lookups completed is complete evidence', mismatch.evidence, 'complete');
eq('and exactly one link is claimed checked',
  mismatch.chain.filter(c => c.claim === 'link-checked').length, 1);

const partial = await run({
  ns: { ad: false }, ds: { kind: 'servfail' }, dnskey: { answers: [rec(48, KEY)] },
}).result;
eq('one failed lookup is partial evidence', partial.evidence, 'partial');
eq('no link is claimed checked', partial.chain.some(c => c.claim === 'link-checked'), false);
eq('and the incompleteness is stated rather than inferred',
  partial.chain.find(c => c.claim === 'lookup-incomplete').detail,
  { query: 'ds', kind: 'servfail' });
const none = await run({
  ns: { ad: false }, ds: { kind: 'servfail' }, dnskey: { kind: 'servfail' },
}).result;
eq('neither lookup completing is no evidence', none.evidence, 'none');
eq('and both are named', none.chain.filter(c => c.claim === 'lookup-incomplete').length, 2);

/**
 * The type filter. A `do=1` answer carries the RRSIG beside the record it
 * signs, and an unfiltered parser reads `DS 8 2 3600 …` as a DS record with key
 * tag NaN — no error, matching no key, and a mismatch verdict on every signed
 * domain audited.
 */
const withRrsig = await run({
  ns: { ad: false },
  ds: { answers: [rec(46, 'DS 8 2 3600 ...'), rec(43, DS)] },
  dnskey: { answers: [rec(46, 'DNSKEY 8 2 3600 ...'), rec(48, KEY)] },
}, mismatching).result;
eq('an RRSIG beside the DS is filtered out', withRrsig.ds.length, 1);
eq('and the real record is the one kept', withRrsig.ds[0].keyTag, 1234);

/* ── 8. Every produced value is in its published algebra ──────────────── */
section('8. The constants are not decoration');

const results = [secure, insecure, localOnly, bogusResult, stillFailing, unanchored,
  mismatch, unverifiable, partial, none, withRrsig];
eq('every state observed is in DNSSEC_STATES',
  results.map(r => r.state).filter(v => !DNSSEC_STATES.includes(v)), []);
eq('every claim observed is in DNSSEC_CHAIN_CLAIMS',
  [...new Set(results.flatMap(r => r.chain.map(c => c.claim)))]
    .filter(v => !DNSSEC_CHAIN_CLAIMS.includes(v)), []);
eq('every source observed is resolver or local',
  [...new Set(results.flatMap(r => r.chain.map(c => c.source)))]
    .filter(v => !DNSSEC_CHAIN_SOURCES.includes(v)), []);
eq('every evidence level observed is in DNSSEC_EVIDENCE',
  results.map(r => r.evidence).filter(v => !DNSSEC_EVIDENCE.includes(v)), []);
eq('and all three evidence levels were produced',
  [...new Set(results.map(r => r.evidence))].sort(), ['complete', 'none', 'partial']);
eq('five of the six states were produced here',
  [...new Set(results.map(r => r.state))].sort(),
  ['bogus', 'indeterminate', 'insecure', 'mismatch', 'secure', 'unanchored']
    .filter(s => results.some(r => r.state === s)));

report();
