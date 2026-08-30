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
 * instrument: each stub records the moment it is CALLED, so a batch rewritten
 * as a sequence of awaits fails here rather than passing quietly with an
 * identical result.
 */

import { createSuite } from '../../tests/lib/assert.mjs';
import { optionalCheck } from '../core/dns/optional.js';
import { requireUsable } from '../core/dns/resolver.js';
import { existenceFromResponse } from '../core/dns/existence.js';
import { dnsError } from '../core/dns/errors.js';
import { createAuditDomain, startsWithCI } from './audit-domain.js';

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

/* ── 1. The audit-local record selector ───────────────────────────────── */
section('1. startsWithCI');

// Moved with the coordinator, and still an engine member. Case-insensitive
// recognition, so `V=SPF1` is not silently discarded as "no policy at all".
eq('an upper-case version field is still recognized', startsWithCI('V=SPF1 -all', 'v=spf1'), true);
eq('a non-match is rejected', startsWithCI('x=DMARC1', 'v=DMARC1'), false);
eq('and a null record is safe', startsWithCI(null, 'v=DMARC1'), false);

/* ── 2. The unregistered short-circuit ────────────────────────────────── */
section('2. NXDOMAIN stops the audit');

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

/* ── 3. The NS servfail DNSSEC preflight ──────────────────────────────── */
section('3. The preflight, spec §3\'s audit-owned exception edge');

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

/* ── 4. Concurrency, which this release does not change ───────────────── */
section('4. The Promise.all structure is preserved');

/**
 * A stub that does not resolve until every expected call has arrived. If the
 * coordinator awaited these one at a time it would deadlock rather than fail
 * an assertion — so the run is raced against a tick budget and a hang is
 * reported as a sequence, which is the failure this asserts against.
 */
function batchProbe(expected) {
  let seen = 0;
  let release;
  const gate = new Promise(resolve => { release = resolve; });
  return {
    arrive() {
      seen += 1;
      if (seen >= expected) release();
      return gate;
    },
    get seen() { return seen; },
  };
}

const core = batchProbe(4);
const concurrent = build({
  dohQuery: async (name, type, opts) => {
    concurrent.calls.push({ name: 'dohQuery', args: [name, type, opts] });
    await core.arrive();
    return [];
  },
});
await concurrent.analyzeDomain('example.test', NONE);
eq('the four core lookups are all in flight before any of them resolves', core.seen, 4);
eq('and they are the four v0.5.0 issued',
  concurrent.named('dohQuery').map(c => c.args[1]).sort(), ['A', 'AAAA', 'MX', 'TXT']);

/**
 * The advanced batch, same instrument. Six of the eight entries reach a
 * collaborator on this fixture: the three `_bimi` / `_mta-sts` / `_smtp._tls`
 * TXT probes, CAA, DNSSEC and report authorization. The two SPF entries do
 * not, because there is no SPF record to account for — which section 8 asserts
 * separately rather than hiding here.
 */
const advancedProbe = batchProbe(6);
const arrive = async value => { await advancedProbe.arrive(); return value; };
const batched = build({
  // `default._bimi.<d>` does not begin with an underscore; the three probes
  // are identified as "a TXT query at a name other than the apex".
  dohQuery: async (name, type) => (type === 'TXT' && name !== 'example.test' ? arrive([]) : []),
  checkCAA: () => arrive({ sentinel: 'caa' }),
  checkDNSSEC: () => arrive({ state: 'insecure' }),
  checkExternalReportAuth: () => arrive([]),
});
await batched.analyzeDomain('example.test', { ...NONE, advanced: true });
eq('the advanced checks are one batch, not a sequence', advancedProbe.seen, 6);

// The wildcard pair, which is its own Promise.all.
const wildcardProbe = batchProbe(2);
const probes = build({
  dohQuery: async (name) => (name.includes('_wildcardtest99xyz') ? arrive2(wildcardProbe) : []),
});
async function arrive2(probe) { await probe.arrive(); return []; }
await probes.analyzeDomain('example.test', { ...NONE, wildcard: true });
eq('and both wildcard depths are probed together', wildcardProbe.seen, 2);

/* ── 5. Option gating ─────────────────────────────────────────────────── */
section('5. Which checks run is the options\' answer');

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

/* ── 6. The deep-check gate, including the null-MX skip ───────────────── */
section('6. Deep checks scale with the domain, so they are gated separately');

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

/* ── 7. Error isolation, and the three fallbacks that copy a kind ─────── */
section('7. One failed lookup degrades one check');

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

/* ── 7b. The derived null-MX fact ─────────────────────────────────────── */
section('7b. The fact audit derives, and both of its readers');

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

/* ── 8. The coordinator interprets nothing ────────────────────────────── */
section('8. No protocol rule lives here');

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
