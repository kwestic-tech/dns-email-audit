#!/usr/bin/env node
/**
 * External report authorization (RFC 9989 §5.6, RFC 9990 §4). Task 4.6.
 *
 * The rule that is easiest to get wrong, and is asserted here as the OPPOSITE
 * of the Tree Walk's: RFC 9990 §4 step 8 says "if at least one TXT resource
 * record remains in the set after parsing, then the external reporting
 * arrangement was authorized" — permissive, where §4.10 step 2 discards every
 * record when a name returns more than one. Two questions at different names,
 * by different RFCs, answered differently. Neither is a bug in the other.
 *
 * And exactly ONE name is queried. A Report Consumer that accepts reports for
 * any domain publishes a wildcard, and the resolver synthesizes it while
 * answering the constructed query — RFC 4592 §2.3 is explicit that querying
 * the asterisk owner literally gets a different question answered.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { dnsError } from '../dns/errors.js';
import { optionalCheck } from '../dns/optional.js';
import {
  createReportAuth, parseReportAuthRecord, reportDestinationHosts,
  findExternalReportDestinations, planReportDestinations,
  REPORT_AUTH_STATES, REPORT_AUTH_EXACT_KINDS, REPORT_AUTH_VIA,
} from './report-auth.js';
import { analyzeDmarc } from './record.js';

const { eq, section, report } = createSuite();

/* ── 1. Published state constants ─────────────────────────────────────── */
section('1. State constants');

eq('four states', [...REPORT_AUTH_STATES],
  ['authorized', 'unauthorized', 'unverifiable', 'override-mismatch']);
eq('THREE exact kinds, not the two the corpus once produced',
  [...REPORT_AUTH_EXACT_KINDS], ['success', 'nodata', 'nxdomain']);
eq('two via values', [...REPORT_AUTH_VIA], ['null', 'exact']);
for (const [n, c] of Object.entries({ REPORT_AUTH_STATES, REPORT_AUTH_EXACT_KINDS, REPORT_AUTH_VIA }))
  eq(`${n} is frozen`, Object.isFrozen(c), true);

/* ── 2. Destinations outside the organizational domain ────────────────── */
section('2. Which destinations need authorization');

const status = analyzeDmarc('v=DMARC1; p=reject; rua=mailto:a@vendor.test,mailto:b@example.test');
eq('every destination host is listed in order',
  reportDestinationHosts(status), ['vendor.test', 'example.test']);
eq('a destination inside the organizational domain needs no authorization',
  findExternalReportDestinations(status, 'example.test', { 'example.test': 'example.test' },
    ['example.test']), []);
eq('while one outside it does',
  findExternalReportDestinations(status, 'example.test', { 'vendor.test': 'vendor.test' },
    ['vendor.test']), ['vendor.test']);

// The cap exists because a record can name any number of destinations and
// each costs a query.
const many = analyzeDmarc(`v=DMARC1; p=none; rua=${
  Array.from({ length: 14 }, (_, i) => `mailto:r@v${i}.test`).join(',')}`);
const plan = planReportDestinations(many, 'example.test',
  Object.fromEntries(Array.from({ length: 14 }, (_, i) => [`v${i}.test`, `v${i}.test`])));
eq('the destination list is capped at ten', plan.external.length, 10);
eq('the true total is still reported', plan.total, 14);
eq('and what was dropped is named rather than silently lost',
  plan.omitted, ['v10.test', 'v11.test', 'v12.test', 'v13.test']);

/* ── 3. One record ────────────────────────────────────────────────────── */
section('3. parseReportAuthRecord');

eq('a bare v=DMARC1 authorizes', parseReportAuthRecord('v=DMARC1', 'vendor.test').valid, true);
eq('a lowercase version does not',
  parseReportAuthRecord('v=dmarc1', 'vendor.test').valid, false);
eq('the version must be first',
  parseReportAuthRecord('rua=mailto:x@y.test; v=DMARC1', 'vendor.test').valid, false);
eq('an unrelated TXT record is not an authorization',
  parseReportAuthRecord('v=spf1 -all', 'vendor.test').valid, false);
eq('an empty record is not one', parseReportAuthRecord('', 'vendor.test').valid, false);

// An override pointing at a third party means conformant receivers send to
// NEITHER URI, so reporting it as authorized would claim reports are flowing.
const crossHost = parseReportAuthRecord('v=DMARC1; rua=mailto:x@elsewhere.test', 'vendor.test');
eq('an override to a third party is flagged', crossHost.overrideReason, 'cross-host');
const sameHost = parseReportAuthRecord('v=DMARC1; rua=mailto:x@vendor.test', 'vendor.test');
eq('an override to the destination itself is not', sameHost.overrideReason, null);

/* ── 4. The lookup, over a passed resolver ────────────────────────────── */
section('4. createReportAuth');

function build(table) {
  const asked = [];
  const dohFetch = async (name, type) => {
    asked.push({ name, type });
    const spec = table[name];
    if (!spec) return { kind: 'nxdomain', answers: [] };
    if (typeof spec === 'string') return { kind: spec, answers: [] };
    return { kind: 'success', answers: spec.map(data => ({ type: 16, data })) };
  };
  const api = createReportAuth({
    dohFetch, dnsError, cleanAnswerData: d => String(d), optionalCheck,
    discoverDmarc: async () => null,
  });
  return { asked, ...api };
}

const authed = build({ 'example.test._report._dmarc.vendor.test': ['v=DMARC1'] });
const ok = (await authed.checkExternalReportAuth('example.test', ['vendor.test']))[0];
eq('a published authorization authorizes', ok.state, 'authorized');
eq('via the exact name', ok.via, 'exact');
eq('and the exact kind is carried', ok.exactKind, 'success');
// RFC 9990 §4 constructs and queries exactly ONE name.
eq('exactly one name is queried', authed.asked.length, 1);
eq('and it is the constructed one',
  authed.asked[0].name, 'example.test._report._dmarc.vendor.test');

const none = build({});
const missing = (await none.checkExternalReportAuth('example.test', ['vendor.test']))[0];
eq('an absent name is unauthorized', missing.state, 'unauthorized');
// nxdomain reaches exactKind: the inline usability gate admits it, which is
// why the algebra has three members and not the two the corpus once showed.
eq('and nxdomain reaches exactKind', missing.exactKind, 'nxdomain');

const nodata = build({ 'example.test._report._dmarc.vendor.test': 'nodata' });
eq('a name with no TXT is unauthorized carrying nodata',
  (await nodata.checkExternalReportAuth('example.test', ['vendor.test']))[0].exactKind, 'nodata');

const malformed = build({ 'example.test._report._dmarc.vendor.test': ['not a dmarc record'] });
const bad = (await malformed.checkExternalReportAuth('example.test', ['vendor.test']))[0];
eq('a TXT record that does not parse authorizes nothing', bad.state, 'unauthorized');
eq('and is distinguished from nothing at all', bad.malformed, true);
eq('while an absent name is not malformed', missing.malformed, false);

/**
 * §4 step 8, permissive — the opposite of the Tree Walk's duplicate rule, and
 * deliberately so.
 */
const several = build({
  'example.test._report._dmarc.vendor.test': ['garbage', 'v=DMARC1'],
});
const survived = (await several.checkExternalReportAuth('example.test', ['vendor.test']))[0];
eq('one valid record among several authorizes', survived.state, 'authorized');
eq('and the count is reported', survived.recordCount, 1);

const override = build({
  'example.test._report._dmarc.vendor.test': ['v=DMARC1; rua=mailto:x@elsewhere.test'],
});
eq('an override to a third party is override-mismatch, not authorized',
  (await override.checkExternalReportAuth('example.test', ['vendor.test']))[0].state,
  'override-mismatch');

/**
 * A DNS failure is `unverifiable`, never `unauthorized`. A timeout is not
 * evidence of a missing record, and calling it one sends someone chasing a
 * vendor over our own flaky lookup.
 */
const failing = build({ 'example.test._report._dmarc.vendor.test': 'servfail' });
const unsure = (await failing.checkExternalReportAuth('example.test', ['vendor.test']))[0];
eq('a resolver failure is unverifiable', unsure.state, 'unverifiable');
eq('and it is NOT unauthorized', unsure.state === 'unauthorized', false);
eq('the kind is kept as the reason', unsure.error, 'servfail');
eq('and no exactKind is claimed', unsure.exactKind, undefined);

// RFC 9990 §4 step 4: a constructed name past DNS limits cannot yield a
// positive determination. Cannot-determine and not-authorized are different.
const tooLong = build({});
const long = (await tooLong.checkExternalReportAuth(
  'a'.repeat(200), ['b'.repeat(60) + '.test']))[0];
eq('an over-long constructed name is unverifiable', long.state, 'unverifiable');
eq('with its own reason', long.error, 'name-too-long');
eq('and no query was made for it', tooLong.asked.length, 0);

// A cancelled query is re-thrown rather than degraded.
const cancelled = build({ 'example.test._report._dmarc.vendor.test': 'cancelled' });
let threw = null;
try { await cancelled.checkExternalReportAuth('example.test', ['vendor.test']); }
catch (e) { threw = e; }
eq('a cancelled check throws', threw && threw.name, 'AbortError');

// Duplicate destinations are one query.
const dupes = build({ 'example.test._report._dmarc.vendor.test': ['v=DMARC1'] });
const once = await dupes.checkExternalReportAuth('example.test',
  ['vendor.test', 'VENDOR.test.', 'vendor.test']);
eq('a repeated destination is checked once', once.length, 1);
eq('and queried once', dupes.asked.length, 1);

/* ── 5. Every produced value is in its published algebra ──────────────── */
section('5. The constants are not decoration');

const produced = [ok, missing, bad, survived, unsure, long];
eq('every state observed is in REPORT_AUTH_STATES',
  produced.map(r => r.state).filter(v => !REPORT_AUTH_STATES.includes(v)), []);
eq('every exactKind observed is in REPORT_AUTH_EXACT_KINDS',
  produced.map(r => r.exactKind).filter(v => v !== undefined)
    .filter(v => !REPORT_AUTH_EXACT_KINDS.includes(v)), []);
eq('and all three exact kinds are reachable',
  [...new Set([ok, missing, (await nodata.checkExternalReportAuth('example.test', ['vendor.test']))[0]]
    .map(r => r.exactKind))].sort(), ['nodata', 'nxdomain', 'success']);

report();
