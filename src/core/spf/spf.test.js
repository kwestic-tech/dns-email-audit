#!/usr/bin/env node
/**
 * SPF: parsing, lookup accounting, subnet classification and redundancy.
 * Task 4.8 — the last protocol owner.
 *
 * Three properties carry most of the value, and each is a place where a wrong
 * answer would be confident:
 *
 *  - **`permerror` outranks everything.** RFC 7208 §4.5 makes two `v=spf1`
 *    records a permanent error, and SPF then fails for ALL mail regardless of
 *    what either record says.
 *  - **IPv6 is not classified on the IPv4 table.** RFC 4291 §2.5.4 makes /64
 *    the standard single-subnet allocation, frequently one mail server, while
 *    the host-count reasoning that makes an IPv4 /24 worth a look would rate
 *    that same /64 as eighteen quintillion hosts.
 *  - **The ten-lookup limit is counted, not estimated**, and a macro is not a
 *    hostname.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { requireUsable, cleanAnswerData } from '../dns/resolver.js';
import {
  createSpfChecks, analyzeSpf, parseSpfTerms, cidrContains, classifySpfSubnet, classifySpfSubnets, stripSpfQualifier, spfReferencedCatalogKeys, selectSpfRecords, spfUsesMechanism,
} from './spf.js';

const { eq, section, report } = createSuite();

/* ── 1. Record status ─────────────────────────────────────────────────── */
section('1. analyzeSpf');

eq('a -all record is ok', analyzeSpf('v=spf1 -all', '@none', false).status, 'ok');
eq('a ~all record softfails', analyzeSpf('v=spf1 ~all', '@none', false).status, 'softfail');
eq('and warns about it', analyzeSpf('v=spf1 ~all', '@none', false).warnings, ['spf-softfail']);
eq('a record with no all is merely present',
  analyzeSpf('v=spf1 include:a.test', '@none', false).status, 'present');

/**
 * RFC 7208 §4.5. Two records is a permanent error and SPF fails for all mail,
 * so this outranks every other finding about the contents — including the
 * `-all` that would otherwise have made it `ok`.
 */
const multiple = analyzeSpf('v=spf1 -all', '@none', true);
eq('two records is a permerror', multiple.status, 'permerror');
eq('and it is critical', multiple.cls, 'crit');
eq('with its own warning', multiple.warnings, ['spf-multiple-records']);
eq('even though the record itself would have been ok',
  analyzeSpf('v=spf1 -all', '@none', false).status, 'ok');

/* ── 2. Term parsing ──────────────────────────────────────────────────── */
section('2. parseSpfTerms');

const terms = parseSpfTerms('v=spf1 include:a.test ip4:192.0.2.0/24 redirect=x.test ~all');
eq('the version is not a term', terms.length, 4);
eq('a mechanism is parsed', terms[0], {
  raw: 'include:a.test', name: 'include', value: 'a.test', qualifier: '+', modifier: false });
eq('a modifier is flagged as one', terms[2].modifier, true);
eq('and modifiers carry no qualifier', terms[2].qualifier, undefined);
eq('an explicit qualifier is read', terms[3].qualifier, '~');
eq('and stripped from the name', terms[3].name, 'all');
eq('a CIDR value keeps only the address half', terms[1].value, '192.0.2.0');
eq('the raw term survives for reporting', terms[1].raw, 'ip4:192.0.2.0/24');
eq('an empty record parses to nothing', parseSpfTerms(''), []);
eq('and so does undefined', parseSpfTerms(undefined), []);

eq('a qualifier is stripped', stripSpfQualifier('~include:a.test'), 'include:a.test');
eq('and an absent one changes nothing', stripSpfQualifier('include:a.test'), 'include:a.test');

/* ── 3. Subnet classification, and the two tables ─────────────────────── */
section('3. classifySpfSubnet');

// IPv4 is judged on host count: a /24 is 256 addresses and it is unusual for a
// sender to control that much space directly.
eq('an IPv4 /24 is worth reviewing', classifySpfSubnet(24, 'ipv4'), 'HIGH');
eq('a /25 less so', classifySpfSubnet(25, 'ipv4'), 'MEDIUM');
eq('and a single host is low', classifySpfSubnet(32, 'ipv4'), 'LOW');

/**
 * IPv6 must NOT reuse that table. RFC 4291 §2.5.4 makes /64 the standard
 * single-subnet allocation, frequently one mail server — and the 2^n reasoning
 * that makes an IPv4 /24 worth a look would rate that /64 as eighteen
 * quintillion hosts and scream about it. nih.gov publishes four of them and
 * they are entirely unremarkable.
 */
eq('an IPv6 /64 is LOW, not a catastrophe', classifySpfSubnet(64, 'ipv6'), 'LOW');
eq('a /48 is medium', classifySpfSubnet(48, 'ipv6'), 'MEDIUM');
eq('and a /32 is high', classifySpfSubnet(32, 'ipv6'), 'HIGH');
// The negative control for the whole two-table decision: the same prefix
// number means different things in the two families.
eq('prefix 32 is HIGH in IPv6 and LOW in IPv4 — the tables are not shared',
  [classifySpfSubnet(32, 'ipv6'), classifySpfSubnet(32, 'ipv4')], ['HIGH', 'LOW']);

const classified = classifySpfSubnets('v=spf1 ip4:192.0.2.0/24 ip6:2001:db8::/32 -all');
eq('both families are classified', classified.subnets.length, 2);
eq('and each names its mechanism',
  classified.subnets.map(s => s.mechanism), ['ip4:192.0.2.0/24', 'ip6:2001:db8::/32']);
eq('with its family', classified.subnets.map(s => s.family), ['ipv4', 'ipv6']);
// A single host is still classified — as LOW. Reporting it keeps the audit's
// account of the record complete; suppressing it would make "no subnets" mean
// two different things.
eq('a single host is classified LOW rather than omitted',
  classifySpfSubnets('v=spf1 ip4:192.0.2.1 -all').subnets.map(x => x.severity), ['LOW']);
eq('a malformed mechanism is dropped rather than throwing',
  classifySpfSubnets('v=spf1 ip4:not-an-address/24 -all').subnets, []);
eq('and the rest of the record is still audited',
  classifySpfSubnets('v=spf1 ip4:bad/24 ip4:192.0.2.0/24 -all').subnets.length, 1);

// The blocks are kept per family so an IPv4 address is never tested against an
// ip6: mechanism.
eq('blocks are separated by family',
  [classified.blocks.ipv4.length, classified.blocks.ipv6.length], [1, 1]);
eq('a v4 address inside the block is contained',
  cidrContains(classified.blocks.ipv4[0].block,
    classifySpfSubnets('v=spf1 ip4:192.0.2.5/24').blocks.ipv4[0].block.address), true);

/* ── 4. The SPF→DKIM bridge, owned here ───────────────────────────────── */
section('4. spfReferencedCatalogKeys');

eq('a named vendor is recognized',
  [...spfReferencedCatalogKeys('v=spf1 include:mail.zendesk.com -all')], ['Zendesk']);
eq('several are',
  [...spfReferencedCatalogKeys('v=spf1 include:mail.zendesk.com include:sendgrid.net -all')],
  ['Zendesk', 'Twilio SendGrid']);
eq('a redirect= counts too',
  [...spfReferencedCatalogKeys('v=spf1 redirect=sendgrid.net')], ['Twilio SendGrid']);
eq('an unknown vendor is not', [...spfReferencedCatalogKeys('v=spf1 include:nobody.test -all')], []);
eq('an empty record names nobody', [...spfReferencedCatalogKeys('')], []);
// A macro cannot be reduced to a literal hostname, so there is nothing to
// match — the same treatment countSpfLookups() gives it.
eq('a macro is not a hostname', [...spfReferencedCatalogKeys('v=spf1 include:%{d}.sendgrid.net -all')], []);
// Only the domain's OWN record counts. Following an include into its own
// includes would attribute the vendor's upstream to the audited domain.
eq('only the literal hostnames of this record are read',
  [...spfReferencedCatalogKeys('v=spf1 include:freshdesk.com -all')], ['Freshdesk / Freshworks']);

/* ── 5. Lookup accounting, over a passed resolver ─────────────────────── */
section('5. createSpfChecks');

function build(table = {}) {
  const asked = [];
  const answer = name => table[name];
  const dohFetch = async (name, type) => {
    asked.push(`${name}/${type}`);
    const spec = answer(name);
    if (typeof spec === 'string') return { kind: spec, answers: [] };
    if (!spec) return { kind: 'nodata', answers: [] };
    return { kind: 'success', answers: spec.map(data => ({ type: 16, data: `"${data}"` })) };
  };
  const dohQuery = async (name, type) => {
    const r = await dohFetch(name, type);
    return requireUsable(r, name, type).answers.map(a => cleanAnswerData(a.data, type));
  };
  return { asked, ...createSpfChecks({ dohQuery, dohFetch, requireUsable, cleanAnswerData }) };
}

const flat = build();
const none = await flat.countSpfLookups('v=spf1 -all', 'example.test', {});
eq('a record with no lookup mechanisms counts zero', none.count, 0);
eq('and reaches no queries', flat.asked.length, 0);

const one = build({ 'a.test': ['v=spf1 -all'] });
const counted = await one.countSpfLookups('v=spf1 include:a.test -all', 'example.test', {});
eq('an include costs a lookup', counted.count >= 1, true);
eq('and the included name was actually queried',
  one.asked.some(q => q.startsWith('a.test/')), true);

// RFC 7208 §4.6.4 caps the term count at ten.
const chain = {};
for (let i = 0; i < 12; i += 1) chain[`v${i}.test`] = [`v=spf1 include:v${i + 1}.test -all`];
const deep = build(chain);
const over = await deep.countSpfLookups('v=spf1 include:v0.test -all', 'example.test', {});
eq('a chain past the limit is counted past it', over.count > 10, true);
eq('and flagged as an error, not merely a warning', over.error, true);
// The warning band is 8..10; past 10 it is an error and the warning is off.
eq('so the warning band does not also fire', over.warning, false);
const eight = build({ 'w.test': ['v=spf1 a mx a mx a mx a -all'] });
const warned = await eight.countSpfLookups('v=spf1 a mx a mx a mx a mx -all', 'example.test', {});
eq('a count inside 8..10 warns without erroring',
  [warned.warning, warned.error], [true, false]);

// A cycle terminates rather than recursing forever.
const looped = build({ 'a.test': ['v=spf1 include:b.test -all'], 'b.test': ['v=spf1 include:a.test -all'] });
const cycle = await looped.countSpfLookups('v=spf1 include:a.test -all', 'example.test', {});
eq('a cycle is detected and named', cycle.cycles.length > 0, true);

/**
 * This module states NO unknown of its own. A resolver failure THROWS, and the
 * caller's `optionalCheck()` fallback factory is what copies `DnsError.kind`
 * onto `advanced.spfLookups.queryError` — one of the eleven typed propagation
 * paths, and the one whose corpus gap was found at Task 3.6.
 *
 * Asserted as a throw, because the alternative reading — that this function
 * degrades — would put the shape of the unknown in the wrong module.
 */
const failing = build({ 'a.test': 'servfail' });
let thrown = null;
try { await failing.countSpfLookups('v=spf1 include:a.test -all', 'example.test', {}); }
catch (e) { thrown = e; }
eq('a resolver failure propagates as an exception', thrown !== null, true);
eq('carrying the kind the caller will copy', thrown && thrown.kind, 'servfail');
// A name that answers with NO SPF record is a void lookup, not a failure —
// layer 3 would hand back the same empty array for both.
const voided = build({ 'a.test': ['not an spf record'] });
const withVoid = await voided.countSpfLookups('v=spf1 include:a.test -all', 'example.test', {});
eq('a name with no SPF record is a void lookup', withVoid.voidLookups, 1);
eq('and not an error at one', withVoid.error, false);

/* ── 6. Redundancy ────────────────────────────────────────────────────── */
section('6. findSpfRedundancy and auditSpfSubnets');

const blocks = classifySpfSubnets('v=spf1 ip4:192.0.2.0/24 -all').blocks;
const noHosts = build();
eq('a record naming no hosts has no redundancy',
  await noHosts.findSpfRedundancy('v=spf1 ip4:192.0.2.0/24 -all', 'example.test', blocks, {}), []);
eq('and an empty block set short-circuits',
  await noHosts.findSpfRedundancy('v=spf1 -all', 'example.test', { ipv4: [], ipv6: [] }, {}), []);

const audit = await build().auditSpfSubnets('v=spf1 ip4:192.0.2.0/24 -all', 'example.test', {});
eq('the audit carries the classification', audit.subnets.length, 1);
eq('and the redundancy list', Array.isArray(audit.redundancy), true);
eq('and states it is not unknown', audit.unknown, false);

/**
 * The negative control for the injection: no resolver is held here.
 *
 * `count` is the WRONG field to compare — both fixtures reach one include and
 * both return 1, so an assertion on it proves nothing about isolation.
 * `voidLookups` is the field that actually differs: the populated transport
 * answers with an SPF record (0), the empty one answers with none (1).
 */
const a = build({ 'x.test': ['v=spf1 -all'] });
const b = build({});
const fromA = await a.countSpfLookups('v=spf1 include:x.test -all', 'e.test', {});
const fromB = await b.countSpfLookups('v=spf1 include:x.test -all', 'e.test', {});
eq('two checks over two resolvers see different answers',
  [fromA.voidLookups, fromB.voidLookups], [0, 1]);
eq('and the lookup count alone would NOT have shown it',
  [fromA.count, fromB.count], [1, 1]);
eq('while each asked its own transport, once',
  [a.asked.length, b.asked.length], [1, 1]);


/* ── Record selection, moved here at Task 5.2a ────────────────────────── */
section('Selecting a domain\'s SPF records');

eq('the SPF record is selected out of a mixed TXT set',
  selectSpfRecords(['google-site-verification=x', 'v=spf1 -all']).record, 'v=spf1 -all');
// Recognition is case-insensitive: `V=SPF1` is a valid record, and discarding
// it would report a protected domain as having no policy at all.
eq('an upper-case version field is still an SPF record',
  selectSpfRecords(['V=SPF1 -all']).record, 'V=SPF1 -all');
eq('a domain with none has an empty record', selectSpfRecords(['x=y']).record, '');
eq('and no records to show for it', selectSpfRecords(['x=y']).records, []);
eq('a null TXT set is empty rather than a throw', selectSpfRecords(null).records, []);

/**
 * EVERY match is kept, not just the first. `record` alone made
 * `spf-multiple-records` an unevidenced accusation: the finding is critical
 * and the panel beside it showed one perfectly valid record, because the
 * second existed nowhere in the result.
 */
const two = selectSpfRecords(['v=spf1 include:a.test -all', 'v=spf1 -all']);
eq('both conflicting records are kept as evidence', two.records.length, 2);
eq('RFC 7208 §4.5: more than one is the multiple-record case', two.multiple, true);
eq('while exactly one is not', selectSpfRecords(['v=spf1 -all']).multiple, false);
eq('and neither is none', selectSpfRecords([]).multiple, false);
// The interpretation the selection feeds: multiple outranks the contents.
eq('and that is what makes the record set a permerror',
  analyzeSpf(two.record, '@none', two.multiple).status, 'permerror');

/* ── 8. spfUsesMechanism — the fact audit composes with a null MX ──────── */
section('8. spfUsesMechanism');

eq('a bare mx mechanism is a use of mx', spfUsesMechanism('v=spf1 mx -all', 'mx'), true);
eq('mx:host counts too', spfUsesMechanism('v=spf1 mx:mail.example.com -all', 'mx'), true);
eq('a qualified ~mx still counts', spfUsesMechanism('v=spf1 ~mx -all', 'mx'), true);
eq('a record without mx does not', spfUsesMechanism('v=spf1 include:_spf.google.com -all', 'mx'), false);
// A modifier is not a mechanism: redirect= names a domain, not an mx use.
eq('redirect=mx.example.com is not a use of the mx mechanism',
  spfUsesMechanism('v=spf1 redirect=mx.example.com', 'mx'), false);
// The `a` mechanism uses the same path.
eq('the a mechanism is detected the same way', spfUsesMechanism('v=spf1 a -all', 'a'), true);
eq('and an empty or missing record is never a use', spfUsesMechanism('', 'mx') || spfUsesMechanism(null, 'mx'), false);
// Proven able to distinguish: `mx` must not match a substring like `include:mx.x`.
eq('an include naming an mx host is not a use of the mx mechanism',
  spfUsesMechanism('v=spf1 include:mx.example.com -all', 'mx'), false);

report();
