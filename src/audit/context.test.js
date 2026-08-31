#!/usr/bin/env node
/**
 * The audit context. Task 5.1.
 *
 * Three things belong to one audit — the options it was started with, the
 * query options those produce, and the result it is accumulating — and the
 * assertions worth holding are the ones that pin the boundary rather than the
 * plumbing: that the query options carry the signal and nothing else, that the
 * `cd=1` re-issue does not mutate options already handed to a query, that the
 * normalized name cannot be overwritten by an accumulated field, that a
 * result is isolated at the TOP LEVEL and shares its nested values by
 * identity, and that the context holds no cache, no resolver and no parsing.
 *
 * The isolation pair is asserted in both directions on purpose. `result()`
 * returns a fresh outer object and shares what it holds; deep-cloning would
 * change legacy identities and value types, so the sharing is asserted rather
 * than merely tolerated — a later attempt to "harden" this into serialization
 * has to delete a passing assertion to do it.
 *
 * Every check here is written so it can fail. The member list is asserted
 * against a fabricated context carrying a cache, which is the shape this
 * boundary exists to refuse.
 */

import { createSuite } from '../../tests/lib/assert.mjs';
import * as contextModule from './context.js';
import { createAuditContext } from './context.js';

const { eq, throws, section, report } = createSuite();

/* ── 1. The audited name ──────────────────────────────────────────────── */
section('1. Domain normalization');

const OPTS = { advanced: true, dkim: false, signal: undefined };

eq('the name is lowercased and trimmed',
  createAuditContext({ domain: '  Example.TEST  ', options: OPTS }).domain, 'example.test');
eq('an already-normal name is unchanged',
  createAuditContext({ domain: 'example.test', options: OPTS }).domain, 'example.test');
eq('interior text is not touched — only the ends are trimmed',
  createAuditContext({ domain: '\tSUB.Example.Test\n', options: OPTS }).domain, 'sub.example.test');
// The observed behaviour of `analyzeDomain()`, preserved rather than softened:
// a value with no `toLowerCase` throws, and it throws here for the same reason.
throws('a domain that is not a string throws, as it always has',
  () => createAuditContext({ domain: 42, options: OPTS }),
  error => error instanceof TypeError);
throws('and so does a missing options object',
  () => createAuditContext({ domain: 'example.test' }),
  error => error instanceof TypeError);

/* ── 2. Options in force ──────────────────────────────────────────────── */
section('2. Options in force');

const supplied = { advanced: true, dkim: true, selectors: 'a,b', dkimComprehensive: false, retries: 0 };
const withOptions = createAuditContext({ domain: 'example.test', options: supplied });
eq('the options in force are the ones supplied, not a copy the audit invented',
  withOptions.options === supplied, true);
// The two that are passed onward as VALUES. Coercing either to a boolean would
// change what `checkDKIM()` receives, which is why nothing here reinterprets.
eq('a value-carrying option keeps its value', withOptions.options.selectors, 'a,b');
eq('and a false flag stays false rather than becoming absent',
  withOptions.options.dkimComprehensive, false);

/* ── 3. Query options: the signal, and nothing else ───────────────────── */
section('3. Query options');

const signal = new AbortController().signal;
const ctx = createAuditContext({ domain: 'Example.Test', options: { advanced: true, retries: 7, signal } });

eq('the signal reaches the query options by identity', ctx.queryOptions.signal === signal, true);
// The load-bearing one. `analyzeDomain()` has always built `{ signal }`, so an
// option the caller also passed does NOT reach the transport — widening this
// would change the retry behaviour and the published DNS fan-out.
eq('and the query options carry exactly one key',
  Object.keys(ctx.queryOptions), ['signal']);
eq('so `retries` is not forwarded, however the caller supplied it',
  'retries' in ctx.queryOptions, false);

// Cancellation POLICY is not here. An already-aborted signal is constructed
// exactly like any other; the first query is where it is felt.
const aborted = AbortSignal.abort();
const abortedCtx = createAuditContext({ domain: 'example.test', options: { signal: aborted } });
eq('an already-aborted audit still builds a context — nothing here inspects it',
  abortedCtx.queryOptions.signal.aborted, true);
eq('and its result is a result like any other', abortedCtx.result(), { domain: 'example.test' });

/* ── 4. The one derived query option ──────────────────────────────────── */
section('4. Disabling DNSSEC checking');

const before = ctx.queryOptions;
const after = ctx.disableDnssecChecking();
eq('the re-issued options ask for cd=1', after.checkingDisabled, true);
eq('and keep the same signal', after.signal === signal, true);
eq('the context now hands out the re-issued options', ctx.queryOptions === after, true);
// A NEW object, deliberately: options already handed to an in-flight query
// must not change underneath it.
eq('the options a query already holds are not mutated', 'checkingDisabled' in before, false);
eq('so the two are different objects', before === after, false);
eq('and re-issuing again is still cd=1', ctx.disableDnssecChecking().checkingDisabled, true);

/* ── 5. The accumulated result ────────────────────────────────────────── */
section('5. The accumulated result');

const building = createAuditContext({ domain: 'Build.Test', options: OPTS });
eq('an audit that recorded nothing is its domain alone', building.result(), { domain: 'build.test' });

building.record({ ns: ['ns1.build.test'], mx: [] });
building.record({ score: { pts: 40 } });
eq('records accumulate across calls',
  building.result(), { domain: 'build.test', ns: ['ns1.build.test'], mx: [], score: { pts: 40 } });
// Key order is part of the observable result: the domain leads, as it always
// has in both of `analyzeDomain()`'s returns.
eq('the domain leads, and the rest follow in the order they were recorded',
  Object.keys(building.result()), ['domain', 'ns', 'mx', 'score']);

building.record({ mx: ['10 mail.build.test'] });
eq('a later record replaces an earlier field',
  building.result().mx, ['10 mail.build.test']);
eq('and does not disturb the fields around it', Object.keys(building.result()), ['domain', 'ns', 'mx', 'score']);

// Isolation, and its exact extent. Replacing a TOP-LEVEL property of a result
// cannot reach the accumulator...
const emitted = building.result();
emitted.score = 'tampered';
eq('replacing a top-level property of a result does not mutate the accumulator',
  building.result().score, { pts: 40 });
eq('and two results are not the same outer object', building.result() === emitted, false);

// ...and that is the whole of it. The properties are the SAME values the audit
// recorded, not copies of them. Deep-cloning would change legacy identities and
// value types — the result carries BigInts from the SPF subnet helpers among
// other things — so this is asserted as the contract, not left as an accident.
const scoreObject = { pts: 40, grade: 'B' };
const shared = createAuditContext({ domain: 'shared.test', options: OPTS });
shared.record({ score: scoreObject });
eq('a nested value is shared by identity — a result is not a deep copy',
  shared.result().score === scoreObject, true);
eq('and two results share it with each other', shared.result().score === shared.result().score, true);
shared.result().score.pts = 99;
eq('so mutating THROUGH a result does reach the accumulator, by design',
  shared.result().score.pts, 99);
eq('which is visible on the recorded object itself', scoreObject.pts, 99);

// The early-return shape, which is the other thing `analyzeDomain()` builds.
const unregistered = createAuditContext({ domain: 'gone.test', options: OPTS });
unregistered.record({ unregistered: true, error: false });
eq('an unregistered domain is the same accumulator, used once',
  unregistered.result(), { domain: 'gone.test', unregistered: true, error: false });

/* ── 5b. The normalized name is not a recordable field ────────────────── */
section('5b. The audited name cannot be overwritten');

// The factory's contract is that `result().domain` is the NORMALIZED name. An
// accumulated field must not be able to contradict it — a result whose
// `domain` disagreed with `ctx.domain` is a result naming a domain the audit
// did not run against.
const named = createAuditContext({ domain: '  Real.Test  ', options: OPTS });
named.record({ domain: 'wrong.test' });
eq('recording a domain does not replace the normalized name', named.result().domain, 'real.test');
eq('and the result still agrees with the context', named.result().domain, named.domain);
// The guard drops the one field, not the call it arrived in.
named.record({ domain: 'wrong.test', ns: ['ns1.real.test'] });
eq('the other fields in the same record still land', named.result().ns, ['ns1.real.test']);
eq('the name is still the normalized one', named.result().domain, 'real.test');
// Key order survives the guard: the name leads, as it does in both of
// `analyzeDomain()`'s returns.
eq('and the domain still leads', Object.keys(named.result()), ['domain', 'ns']);
// The check proven to fail: an accumulator that DID take the field produces
// the contradiction this guard exists to prevent.
eq('an unguarded accumulator would have contradicted the context',
  Object.assign({ domain: named.domain }, { domain: 'wrong.test' }).domain, 'wrong.test');

/* ── 6. The boundary itself ───────────────────────────────────────────── */
section('6. What the context does not own');

eq('the module exports one factory and nothing else',
  Object.keys(contextModule), ['createAuditContext']);

const MEMBERS = ['disableDnssecChecking', 'domain', 'options', 'queryOptions', 'record', 'result'];
eq('the context is exactly these members', Object.keys(ctx).sort(), MEMBERS);
// The check proven to fail. A context that had absorbed the DoH cache — the
// spec correction this boundary exists to hold — does not match the list, and
// neither does one missing a member.
const isTheBoundary = value => Object.keys(value).sort().join(',') === MEMBERS.join(',');
eq('the comparison recognizes the real context', isTheBoundary(ctx), true);
eq('a context carrying a cache would not match', isTheBoundary({ ...ctx, dohCache: new Map() }), false);
eq('nor would one that lost the accumulator',
  isTheBoundary(Object.fromEntries(Object.entries(ctx).filter(([k]) => k !== 'record'))), false);
// Named absences, so the responsibility table in API.md is executable rather
// than descriptive.
for (const absent of ['cache', 'dohCache', 'resolver', 'dohFetch', 'score', 'issues', 'parse']) {
  eq(`the context has no \`${absent}\``, absent in ctx, false);
}

report();
