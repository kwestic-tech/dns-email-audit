#!/usr/bin/env node
/**
 * The audit coordinator. Task 5.2.
 *
 * What is worth asserting about a coordinator is not what any record means —
 * that belongs to the protocol owners and is tested beside each of them. It is
 * WHICH checks run, WHEN they are skipped, WHAT runs concurrently, and how a
 * failure is isolated. Every collaborator here is a recording stub, so the
 * orchestration is observable directly instead of being inferred from a result.
 *
 * Two capabilities are the REAL ones, deliberately: `optionalCheck` and
 * `requireUsable` decide isolation and the usability gate, and stubbing them
 * would leave this file asserting its own fixtures. The test may import
 * `core/dns/` even though `src/audit/` may not — the edge rule is about the
 * shipped graph, and `dns-transport.test.mjs` enforces it over `src/`.
 *
 * The concurrency assertions are the ones to keep. Spec §35 and the
 * implementation plan both forbid changing concurrency in this release, and
 * "the `Promise.all` structure is preserved" is a claim that needs an
 * instrument: each stub records the moment it is CALLED and holds until the
 * whole batch has arrived, so a batch rewritten as a sequence of awaits cannot
 * complete. Every such run is raced against a **tick deadline** so that a
 * sequential regression fails in under a second with a readable diagnostic
 * instead of hanging until the suite or CI timeout.
 *
 * The three batches asserted here are the coordinator's own. DKIM's selector
 * scan is batched inside `core/dkim/` and is that module's contract to keep;
 * nothing here exercises it and nothing here claims to.
 */

import { createSuite } from '../../tests/lib/assert.mjs';
import { optionalCheck } from '../core/dns/optional.js';
import { requireUsable } from '../core/dns/resolver.js';
import { existenceFromResponse } from '../core/dns/existence.js';
import { dnsError } from '../core/dns/errors.js';
import { createAuditDomain } from './audit-domain.js';

const { eq, rejects, section, report } = createSuite();

const OK = (answers = []) => ({ kind: 'success', status: 0, answers });
const NS_OK = OK([{ type: 2, data: 'ns1.example.test.' }]);

/**
 * A coordinator over stubs that record what they were asked and when.
 *
 * `calls` is the whole instrument: an ordered log of every collaborator
 * invocation, which is what makes "these four ran concurrently" and "this one
 * never ran at all" both assertable.
 */
function build(overrides = {}) {
  const calls = [];
  const log = (name, ...args) => { calls.push({ name, args }); };
  const sentinel = name => ({ sentinel: name });

  const capabilities = {
    dohFetch: async (name, type, opts) => { log('dohFetch', name, type, opts); return NS_OK; },
    // A real MX set: `providers/` is imported by the coordinator rather than
    // injected, so `emailProvider` is a real answer here and the DKIM gate —
    // which skips `@none` and `@null-mx` — sees what production sees.
    dohQuery: async (name, type, opts) => { log('dohQuery', name, type, opts); return type === 'MX' ? ['10 mail.example.test'] : []; },
    requireUsable,
    optionalCheck,
    existenceFromResponse,
    checkDNSSEC: async d => { log('checkDNSSEC', d); return { state: 'insecure', signed: false }; },
    checkCAA: async d => { log('checkCAA', d); return sentinel('caa'); },
    checkTlsa: async hosts => { log('checkTlsa', hosts); return sentinel('tlsa'); },
    auditMxHosts: async mx => { log('auditMxHosts', mx); return { hosts: [{ host: 'mail.example.test' }] }; },
    checkDKIM: async (...args) => { log('checkDKIM', ...args); return { found: true, selectors: [] }; },
    discoverDmarc: async d => { log('discoverDmarc', d); return { applied: null, organizationalDomain: d, observed: [], terminated: null }; },
    resolveDestinationOrgDomains: async () => { log('resolveDestinationOrgDomains'); return {}; },
    checkExternalReportAuth: async () => { log('checkExternalReportAuth'); return []; },
    countSpfLookups: async () => { log('countSpfLookups'); return sentinel('lookups'); },
    auditSpfSubnets: async () => { log('auditSpfSubnets'); return sentinel('subnets'); },
    buildIssues: () => [sentinel('issues')],
    buildSuggestions: () => [sentinel('suggestions')],
    calcScore: () => sentinel('score'),
    calcAdvScore: () => sentinel('advScore'),
    ...overrides,
  };
  const { analyzeDomain } = createAuditDomain(capabilities);
  return { analyzeDomain, calls, named: name => calls.filter(c => c.name === name) };
}

const NONE = { advanced: false, dkim: false, www: false, wildcard: false, deepChecks: false };

/* ── 1. The unregistered short-circuit ────────────────────────────────── */
section('1. NXDOMAIN stops the audit');

const gone = build({ dohFetch: async () => ({ kind: 'nxdomain', status: 3, answers: [] }) });
const goneResult = await gone.analyzeDomain('Gone.Test', NONE);
eq('an unregistered domain is three fields and the normalized name',
  goneResult, { domain: 'gone.test', unregistered: true, error: false });
// The point of the early return: nothing downstream runs.
eq('and no other check runs at all',
  gone.calls.map(c => c.name).filter(n => n !== 'dohFetch'), []);
// The control that proves the assertion above is not vacuous.
const live = build();
const liveResult = await live.analyzeDomain('example.test', NONE);
eq('a registered domain does continue', liveResult.unregistered, undefined);
eq('and reaches the scorer', liveResult.score, { sentinel: 'score' });

/* ── 2. The NS servfail DNSSEC preflight ──────────────────────────────── */
section('2. The preflight, spec §3\'s audit-owned exception edge');

/** A resolver that answers SERVFAIL for NS until `cd=1` is asked for. */
function servfailUntilUnchecked(dnssecState) {
  const seen = [];
  return {
    seen,
    dohFetch: async (name, type, opts) => {
      seen.push({ type, checkingDisabled: !!(opts && opts.checkingDisabled) });
      if (type !== 'NS') return OK();
      return opts && opts.checkingDisabled ? NS_OK : { kind: 'servfail', status: 2, answers: [] };
    },
    checkDNSSEC: async () => ({ state: dnssecState, signed: dnssecState === 'bogus' }),
  };
}

const bogus = servfailUntilUnchecked('bogus');
const bogusCalls = [];
const bogusRun = build({
  dohFetch: bogus.dohFetch,
  checkDNSSEC: async (...a) => { bogusCalls.push(a); return { state: 'bogus', signed: false }; },
});
const bogusResult = await bogusRun.analyzeDomain('bogus.test', { ...NONE, advanced: true });
eq('a confirmed bogus chain retries NS with checking disabled',
  bogus.seen.filter(s => s.type === 'NS').map(s => s.checkingDisabled), [false, true]);
eq('the DNSSEC verdict still comes from the validating query — it is not re-run',
  bogusCalls.length, 1);
eq('and that verdict is what the result carries',
  bogusResult.advanced.dnssec, { state: 'bogus', signed: false });

// Not bogus: the SERVFAIL was an ordinary failure, so nothing is retried and
// the usability gate does what it always did.
const notBogus = servfailUntilUnchecked('insecure');
const plain = build({
  dohFetch: notBogus.dohFetch,
  checkDNSSEC: async () => ({ state: 'insecure', signed: false }),
});
await rejects('a SERVFAIL that is not a bogus chain still throws',
  () => plain.analyzeDomain('sf.test', { ...NONE, advanced: true }),
  error => error.kind === 'servfail');
eq('and it was not retried with checking disabled',
  notBogus.seen.filter(s => s.checkingDisabled), []);

// The preflight is gated on `advanced`. Without it there is no classifier to
// establish the verdict, so there is nothing to license the unchecked retry.
const noAdvanced = servfailUntilUnchecked('bogus');
const preflightCalls = [];
const unadvanced = build({
  dohFetch: noAdvanced.dohFetch,
  checkDNSSEC: async () => { preflightCalls.push(1); return { state: 'bogus', signed: false }; },
});
await rejects('without advanced checks a SERVFAIL simply throws',
  () => unadvanced.analyzeDomain('sf.test', NONE),
  error => error.kind === 'servfail');
eq('and the preflight never ran', preflightCalls.length, 0);

/* ── 3. Concurrency, which this release does not change ───────────────── */
section('3. The Promise.all structure is preserved');

/**
 * A stub that does not resolve until every expected call has arrived.
 *
 * If the coordinator awaited these one at a time the gate would never open, so
 * the failure mode is a HANG rather than a failed assertion. That is why every
 * run below is raced against `ticks()`.
 */
function batchProbe(expected) {
  let seen = 0;
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  return {
    arrive(value) {
      seen += 1;
      if (seen >= expected) release();
      return gate.then(() => value);
    },
    get seen() { return seen; },
  };
}

/**
 * A bounded deadline measured in EVENT-LOOP TURNS, not milliseconds.
 *
 * The question is whether the coordinator issued its calls before awaiting
 * any of them, which is a question about the event loop; a wall-clock
 * threshold would answer a different question and would be flaky on a loaded
 * machine. `setImmediate` runs in the check phase, so a chain of them lets
 * every pending promise continuation drain in between — a batch that is
 * genuinely concurrent fills within a handful of turns, and one that is
 * sequential never fills at all.
 *
 * 2,000 turns is far more than the audit needs and still resolves in
 * milliseconds, so a regression reports promptly instead of running to the
 * suite or CI timeout.
 */
const TICK_BUDGET = 2000;
function ticks(n = TICK_BUDGET) {
  let live = true;
  const promise = new Promise(resolve => {
    let left = n;
    const step = () => {
      // Stop as soon as the race is decided. Without this, every passing run
      // would leave its losing deadline scheduling turns to the end of its
      // budget — work nothing is waiting for, in a suite that runs dozens of
      // these.
      if (!live) return;
      if (left-- <= 0) return resolve('deadline');
      setImmediate(step);
    };
    setImmediate(step);
  });
  return { promise, cancel() { live = false; } };
}

/**
 * Run an audit against the deadline. Resolves 'completed' or 'deadline'.
 *
 * A REJECTED audit is neither: it rejects, and the caller sees the error.
 * Turning a rejection into 'completed' would let a fixture that throws after
 * issuing its batch satisfy the completion assertion, which is the opposite of
 * what these runs are for — the point is that the calls went out AND the audit
 * finished normally.
 */
async function within(run) {
  const deadline = ticks();
  try {
    return await Promise.race([run.then(() => 'completed'), deadline.promise]);
  } finally {
    deadline.cancel();
  }
}

// The deadline proven to fire, and proven not to fire spuriously. Without the
// first, `within()` returning 'completed' everywhere would be
// indistinguishable from a race that never times out, and every concurrency
// assertion below would be measuring nothing.
const neverFinishes = ticks(10);
eq('the deadline fires on work that never finishes',
  await Promise.race([new Promise(() => {}), neverFinishes.promise]), 'deadline');
neverFinishes.cancel();
eq('and does not fire on work that does', await within(Promise.resolve()), 'completed');
// A rejection is NOT a completion. A fixture that issued its whole batch and
// then threw would otherwise pass the assertions these runs exist to make.
await rejects('a rejected audit rejects rather than reporting completion',
  () => within(Promise.reject(new Error('boom'))),
  error => error.message === 'boom');

const core = batchProbe(4);
const concurrent = build({
  dohQuery: async (name, type, opts) => {
    concurrent.calls.push({ name: 'dohQuery', args: [name, type, opts] });
    return core.arrive([]);
  },
});
eq('the core batch completes rather than deadlocking',
  await within(concurrent.analyzeDomain('example.test', NONE)), 'completed');
eq('the four core lookups are all in flight before any of them resolves', core.seen, 4);
eq('and they are the four v0.5.0 issued',
  concurrent.named('dohQuery').map(c => c.args[1]).sort(), ['A', 'AAAA', 'MX', 'TXT']);

/**
 * The advanced batch, same instrument, and all EIGHT entries live.
 *
 * Two of them only exist when the domain has an SPF record — with none, the
 * coordinator states the zero itself rather than asking the SPF owner, which
 * section 8 asserts separately. So the apex TXT here carries one, and both SPF
 * entries are gated with the other six.
 */
const advancedProbe = batchProbe(8);
const advanced = build({
  // `default._bimi.<d>` does not begin with an underscore, so the three probes
  // are identified as "a TXT query at a name other than the apex". The apex
  // TXT is part of the CORE batch and answers immediately, with the SPF record
  // that makes the last two advanced entries reachable.
  dohQuery: async (name, type) => {
    if (type !== 'TXT') return [];
    return name === 'example.test' ? ['v=spf1 -all'] : advancedProbe.arrive([]);
  },
  checkCAA: () => advancedProbe.arrive({ sentinel: 'caa' }),
  checkDNSSEC: () => advancedProbe.arrive({ state: 'insecure' }),
  checkExternalReportAuth: () => advancedProbe.arrive([]),
  countSpfLookups: () => advancedProbe.arrive({ sentinel: 'lookups' }),
  auditSpfSubnets: () => advancedProbe.arrive({ sentinel: 'subnets' }),
});
eq('the advanced batch completes rather than deadlocking',
  await within(advanced.analyzeDomain('example.test', { ...NONE, advanced: true })), 'completed');
eq('all eight advanced checks are one batch, not a sequence', advancedProbe.seen, 8);

// The wildcard pair, which is its own Promise.all.
const wildcardProbe = batchProbe(2);
const probes = build({
  dohQuery: async (name) => (name.includes('_wildcardtest99xyz') ? wildcardProbe.arrive([]) : []),
});
eq('the wildcard pair completes rather than deadlocking',
  await within(probes.analyzeDomain('example.test', { ...NONE, wildcard: true })), 'completed');
eq('and both wildcard depths are probed together', wildcardProbe.seen, 2);

/* ── 4. Option gating ─────────────────────────────────────────────────── */
section('4. Which checks run is the options\' answer');

const off = build();
const offResult = await off.analyzeDomain('example.test', NONE);
eq('dkim: false runs no DKIM check', off.named('checkDKIM').length, 0);
eq('www: false resolves no website', offResult.hosting, '@dash');
eq('wildcard: false probes neither depth', [offResult.wildcardApex, offResult.wildcardDkim], [false, false]);
eq('advanced: false leaves every advanced slot null',
  Object.values(offResult.advanced).filter(v => v !== null), []);
eq('and reports no advanced score', offResult.advScore, null);

const on = build();
await on.analyzeDomain('example.test', { advanced: true, dkim: true, www: true, wildcard: true, deepChecks: false });
eq('dkim: true runs the DKIM check once', on.named('checkDKIM').length, 1);
eq('wildcard: true probes exactly the two depths',
  on.named('dohQuery').filter(c => c.args[0].includes('_wildcardtest99xyz')).length, 2);
eq('www: true resolves the website from www.', on.named('dohFetch').some(c => c.args[0] === 'www.example.test'), true);
eq('and advanced: true reaches CAA', on.named('checkCAA').length, 1);

/* ── 5. The deep-check gate, including the null-MX skip ───────────────── */
section('5. Deep checks scale with the domain, so they are gated separately');

const withMx = mx => build({ dohQuery: async (name, type) => (type === 'MX' ? mx : []) });

const deepOff = withMx(['10 mail.example.test']);
await deepOff.analyzeDomain('example.test', { ...NONE, advanced: true });
eq('deepChecks: false audits no MX host', deepOff.named('auditMxHosts').length, 0);

const deepOn = withMx(['10 mail.example.test']);
const deepResult = await deepOn.analyzeDomain('example.test', { ...NONE, advanced: true, deepChecks: true });
eq('deepChecks: true audits the MX hosts', deepOn.named('auditMxHosts').length, 1);
eq('and TLSA follows the hosts it found',
  deepOn.named('checkTlsa')[0].args[0], ['mail.example.test']);
eq('both land in the result', [deepResult.advanced.mxHealth !== null, deepResult.advanced.tlsa !== null], [true, true]);

// RFC 7505: the domain has declared it accepts no mail, so there is no host to
// resolve and nothing to say about TLSA.
const nullMx = withMx(['0 .']);
const nullResult = await nullMx.analyzeDomain('example.test', { ...NONE, advanced: true, deepChecks: true });
eq('a null MX skips the deep checks entirely', nullMx.named('auditMxHosts').length, 0);
eq('and leaves both slots null', [nullResult.advanced.mxHealth, nullResult.advanced.tlsa], [null, null]);

const noMx = withMx([]);
await noMx.analyzeDomain('example.test', { ...NONE, advanced: true, deepChecks: true });
eq('and so does having no MX at all', noMx.named('auditMxHosts').length, 0);

/* ── 6. Error isolation, and the three fallbacks that copy a kind ─────── */
section('6. One failed lookup degrades one check');

const failing = build({
  checkCAA: async () => { throw dnsError('servfail', 'example.test', 'CAA'); },
});
const degraded = await failing.analyzeDomain('example.test', { ...NONE, advanced: true });
eq('a CAA failure states its unknown rather than discarding the audit',
  [degraded.advanced.caa.unknown, degraded.advanced.caa.error], [true, 'servfail']);
eq('and every other advanced check still produced its answer',
  degraded.advanced.dnssec !== null, true);
eq('the audit still scores', degraded.score, { sentinel: 'score' });

// The website fallback COLLAPSES the kind to one token, where CAA lets it
// escape. Two deliberately different policies, asserted together so neither
// can be "made consistent" by accident.
const noWeb = build({
  dohFetch: async (name, type) => {
    if (type === 'CNAME') throw dnsError('timeout', name, 'CNAME');
    return NS_OK;
  },
});
const noWebResult = await noWeb.analyzeDomain('example.test', { ...NONE, www: true });
eq('a failed website lookup collapses to one token', noWebResult.hosting, '@dns-error');

// Cancellation is NOT an unknown, and the rule is optionalCheck's, not the
// coordinator's — so an abort escapes every one of those fallbacks.
const cancelled = build({
  checkCAA: async () => { throw dnsError('cancelled', 'example.test', 'CAA'); },
});
await rejects('an aborted check aborts the audit rather than degrading',
  () => cancelled.analyzeDomain('example.test', { ...NONE, advanced: true }),
  error => error.name === 'AbortError');

/* ── 7. The derived null-MX fact ─────────────────────────────────────── */
section('7. The fact audit derives, and both of its readers');

/**
 * RFC 7505's `0 .` is MX semantics, and §12 gives `providers/` an edge to
 * `core/shared/` only — so `providers/` cannot decide it and audit does,
 * once. Task 4.9 injected the PREDICATE as a stated debt; Task 5.2 pays it by
 * deriving the FACT here. Two readers, and both are asserted: provider
 * detection and the deep-check gate.
 */
const refusesMail = withMx(['0 .']);
const refused = await refusesMail.analyzeDomain('example.test', { ...NONE, advanced: true, deepChecks: true, dkim: true });
eq('the null-MX fact reaches provider detection', refused.emailProvider, '@null-mx');
eq('and the deep-check gate reads the same fact', refusesMail.named('auditMxHosts').length, 0);
// A domain that refuses mail has no DKIM to find either — the gate skips
// `@null-mx`, which is only reachable because the fact was derived correctly.
eq('and no DKIM check runs for a domain that refuses mail', refusesMail.named('checkDKIM').length, 0);

// The control: the same audit over an ordinary MX set answers differently on
// all three, so none of the assertions above passes for want of an MX record.
const acceptsMail = withMx(['10 mail.example.test']);
const accepted = await acceptsMail.analyzeDomain('example.test', { ...NONE, advanced: true, deepChecks: true, dkim: true });
eq('an ordinary MX set is not null-MX', accepted.emailProvider === '@null-mx', false);
eq('its deep checks run', acceptsMail.named('auditMxHosts').length, 1);
eq('and its DKIM check runs', acceptsMail.named('checkDKIM').length, 1);

/* ── 8. The coordinator carries answers ────────────────────────────── */
section('8. Answers are carried, not re-derived');

const identity = build();
const passed = await identity.analyzeDomain('example.test', { ...NONE, advanced: true });
// Each protocol owner's answer reaches the result as the object it returned.
eq('the CAA owner\'s answer is carried, not re-derived', passed.advanced.caa, { sentinel: 'caa' });
// With no SPF record the coordinator states the zero itself rather than asking
// the SPF owner to account for nothing — an orchestration decision, and the
// reason the batch above has six live entries rather than eight.
eq('with no SPF record the accounting is the stated zero, un-asked',
  [passed.advanced.spfLookups.count, passed.advanced.spfLookups.indeterminate], [0, false]);
eq('and the SPF owner was not called', identity.named('countSpfLookups').length, 0);

const withSpf = build({
  dohQuery: async (name, type) => (type === 'TXT' && !name.startsWith('_') ? ['v=spf1 -all'] : []),
});
const spfResult = await withSpf.analyzeDomain('example.test', { ...NONE, advanced: true });
eq('but with one, the owner\'s answer is carried unchanged',
  spfResult.advanced.spfLookups, { sentinel: 'lookups' });
eq('and its subnet audit with it', spfResult.advanced.spfSubnets, { sentinel: 'subnets' });
eq('the issues are the issue builder\'s', passed.issues, [{ sentinel: 'issues' }]);
eq('and the domain is the context\'s normalized name', passed.domain, 'example.test');

report();
