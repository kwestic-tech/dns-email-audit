#!/usr/bin/env node
/**
 * MX health and host resolution. Spec Design §4, Task 4.2.
 *
 * Two properties carry most of the value and both are about NOT overclaiming:
 * a host whose lookups failed is `unknown` and never `no`, because `no` is a
 * total inbound mail outage and saying it wrongly is the worst thing this
 * check can do; and two MX records naming one exchange are one host, one point
 * of failure and one set of lookups.
 *
 * The audit is driven by a fake resolver, because both capabilities are
 * passed — the property Task 4.1 established and every owner after it keeps.
 * The POLICY, though, is the real `optionalCheck` imported from `core/dns/`:
 * the module has to work against the function it will actually be handed, and
 * a local reimplementation would only prove the test agrees with itself. A
 * test import is not a production edge, so this does not touch §12's graph —
 * `dns-transport.test.mjs` walks `*.js` and excludes `*.test.js`.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { optionalCheck } from '../dns/optional.js';
import {
  createMxAudit, isNullMx, hasNullMxConflict, parseMxRecord, reverseName,
  MX_HOST_RESOLVES, MX_IPV6_COVERAGE, MX_HOST_REACHABILITY,
} from './mx.js';

const { eq, section, report } = createSuite();

/* ── 1. The published state constants ─────────────────────────────────── */
section('1. State constants');

eq('a host resolves yes, no or unknown', [...MX_HOST_RESOLVES], ['yes', 'no', 'unknown']);
eq('and the list is frozen', Object.isFrozen(MX_HOST_RESOLVES), true);
eq('IPv6 coverage is none, some or all', [...MX_IPV6_COVERAGE], ['none', 'some', 'all']);
eq('and that list is frozen too', Object.isFrozen(MX_IPV6_COVERAGE), true);

/* ── 2. RFC 7505 null MX ──────────────────────────────────────────────── */
section('2. isNullMx');

eq('0 . is a null MX', isNullMx(['0 .']), true);
eq('with surrounding whitespace it still is', isNullMx(['  0   .  ']), true);
eq('an empty set is not one', isNullMx([]), false);
eq('a real exchange is not one', isNullMx(['10 mail.example.test.']), false);
// A null MX is exclusive by definition: RFC 7505 §3 forbids any other record.
eq('a null MX beside another record is not a null MX',
  isNullMx(['0 .', '10 mail.example.test.']), false);
eq('preference 10 with a root target is not one', isNullMx(['10 .']), false);
eq('preference 0 with a real target is not one', isNullMx(['0 mail.example.test.']), false);

/* ── 3. One record ────────────────────────────────────────────────────── */
section('3. parseMxRecord');

eq('a normal record', parseMxRecord('10 mail.example.test.'),
  { preference: 10, host: 'mail.example.test', isAddressLiteral: false });
eq('the trailing dot is dropped and the host lowercased',
  parseMxRecord('10 Mail.Example.TEST.').host, 'mail.example.test');
eq('extra whitespace is collapsed', parseMxRecord('  10   mail.example.test '),
  { preference: 10, host: 'mail.example.test', isAddressLiteral: false });
eq('preference 0 with a target is a record', parseMxRecord('0 mail.example.test').preference, 0);
eq('a non-numeric preference is not a record', parseMxRecord('ten mail.example.test'), null);
eq('a record with no target is not one', parseMxRecord('10'), null);
eq('an empty string is not one', parseMxRecord(''), null);
eq('undefined is not one', parseMxRecord(undefined), null);
eq('a bare dot target survives as a host', parseMxRecord('0 .'), null);

/* ── 4. The audit, over a passed resolver ─────────────────────────────── */
section('4. createMxAudit');

/**
 * A resolver that answers from a table and can be told to fail one lookup.
 * `null` in the table means "this query throws", which is what layer 2 does
 * for the seven non-usable transport kinds.
 */
function fakeResolver(table) {
  const asked = [];
  return {
    asked,
    dohQuery: async (name, type) => {
      asked.push(`${name}/${type}`);
      const answers = (table[name] || {})[type];
      if (answers === null) { const e = new Error('servfail'); e.kind = 'servfail'; throw e; }
      return answers || [];
    },
  };
}
const audit = table => createMxAudit({ dohQuery: fakeResolver(table).dohQuery, optionalCheck });
const auditWith = table => {
  const r = fakeResolver(table);
  return { run: createMxAudit({ dohQuery: r.dohQuery, optionalCheck }), asked: r.asked };
};

eq('no MX records is an empty audit, not a failure',
  (await audit({})([], 'example.test')).hosts, []);
eq('and it claims no unknown', (await audit({})([], 'example.test')).unknown, false);
eq('a set of unparseable records is the same empty audit',
  (await audit({})(['garbage'], 'example.test')).hosts, []);

const healthy = await audit({
  'mail.example.test': { A: ['192.0.2.1'], AAAA: ['2001:db8::1'], CNAME: [] },
})(['10 mail.example.test.'], 'example.test');
eq('a resolving host resolves yes', healthy.hosts[0].resolves, 'yes');
eq('its addresses are both families', healthy.hosts[0].addresses, ['192.0.2.1', '2001:db8::1']);
eq('IPv6 coverage is all', healthy.ipv6Coverage, 'all');
eq('one host is a single point of failure', healthy.singleHost, true);
eq('and the host is inside the audited domain', healthy.hosts[0].inAudited, true);
eq('nothing is dangling', healthy.danglingHosts, []);

/**
 * The finding this whole module exists for. An MX host that does not resolve
 * is a total inbound mail outage, and it used to read exactly like health.
 */
const dangling = await audit({
  'mail.example.test': { A: [], AAAA: [], CNAME: [] },
})(['10 mail.example.test.'], 'example.test');
eq('a host with no addresses resolves no', dangling.hosts[0].resolves, 'no');
eq('and it is reported as dangling', dangling.danglingHosts, ['mail.example.test']);
eq('IPv6 coverage over nothing resolved is none', dangling.ipv6Coverage, 'none');

/**
 * `no` is claimed ONLY when both address lookups actually returned. One failed
 * lookup and one empty answer is not evidence of absence — and a host we could
 * not check must never be counted as dangling.
 */
const partial = await audit({
  'mail.example.test': { A: null, AAAA: [], CNAME: [] },
})(['10 mail.example.test.'], 'example.test');
eq('a failed A lookup beside an empty AAAA is unknown, not no',
  partial.hosts[0].resolves, 'unknown');
eq('and an unknown host is NOT dangling', partial.danglingHosts, []);
eq('the audit says so at the top level', partial.unknown, true);

// The failure is per host: one bad target must not poison the others.
const mixed = await audit({
  'good.example.test': { A: ['192.0.2.1'], AAAA: [], CNAME: [] },
  'bad.example.test': { A: null, AAAA: null, CNAME: null },
})(['10 good.example.test.', '20 bad.example.test.'], 'example.test');
eq('the healthy target still resolves', mixed.hosts[0].resolves, 'yes');
eq('while the unreachable one is unknown', mixed.hosts[1].resolves, 'unknown');
eq('and a cname we could not read is flagged rather than assumed',
  [mixed.hosts[1].isCname, mixed.hosts[1].cnameUnknown], [false, true]);

/**
 * Two records naming one exchange are ONE host: one point of failure and one
 * set of lookups. Mapping records straight to audits queried it twice, counted
 * it twice, and suppressed `mx-single-host` on a domain that has exactly one.
 */
const duplicate = auditWith({
  'mail.example.test': { A: ['192.0.2.1'], AAAA: [], CNAME: [] },
});
const deduped = await duplicate.run(
  ['10 mail.example.test.', '20 mail.example.test.'], 'example.test');
eq('one exchange at two preferences is one host', deduped.hosts.length, 1);
eq('and it is still a single point of failure', deduped.singleHost, true);
eq('both preferences are kept as evidence', deduped.hosts[0].preferences, [10, 20]);
eq('the lowest is the one that describes it', deduped.hosts[0].preference, 10);
eq('and it was queried once per type, not twice',
  duplicate.asked, ['mail.example.test/A', 'mail.example.test/AAAA', 'mail.example.test/CNAME']);

// Duplicate PREFERENCES are about the records, not the targets.
const tied = await audit({
  'a.example.test': { A: ['192.0.2.1'], AAAA: [], CNAME: [] },
  'b.example.test': { A: ['198.51.100.1'], AAAA: [], CNAME: [] },
})(['10 a.example.test.', '10 b.example.test.'], 'example.test');
eq('two hosts at one preference is a duplicate preference',
  tied.duplicatePreferences, [10]);
eq('and they are two hosts', tied.hosts.length, 2);
eq('so it is not a single point of failure', tied.singleHost, false);

// Block concentration, via core/shared/ip.js. /24 for v4, /48 for v6.
const concentrated = await audit({
  'a.example.test': { A: ['192.0.2.1'], AAAA: [], CNAME: [] },
  'b.example.test': { A: ['192.0.2.9'], AAAA: [], CNAME: [] },
})(['10 a.example.test.', '20 b.example.test.'], 'example.test');
eq('two hosts in one /24 share a prefix',
  concentrated.sharedPrefixes,
  [{ prefix: '192.0.2.0/24', hosts: ['a.example.test', 'b.example.test'] }]);
const spread = await audit({
  'a.example.test': { A: ['192.0.2.1'], AAAA: [], CNAME: [] },
  'b.example.test': { A: ['198.51.100.1'], AAAA: [], CNAME: [] },
})(['10 a.example.test.', '20 b.example.test.'], 'example.test');
eq('hosts in different /24s share nothing', spread.sharedPrefixes, []);

/**
 * IPv6 groups at /48, not /24, and the label is rendered by a private helper
 * whose whole observable contract is this string. Both halves are load-bearing:
 * the WIDTH, because reusing the IPv4 table would group by /24 of a 128-bit
 * address and call unrelated networks one block; and the FORM, because a
 * mis-rendered label is what an operator is asked to go and look for.
 */
const v6Concentrated = await audit({
  'a.example.test': { A: [], AAAA: ['2001:db8:1::1'], CNAME: [] },
  'b.example.test': { A: [], AAAA: ['2001:db8:1:ffff::9'], CNAME: [] },
})(['10 a.example.test.', '20 b.example.test.'], 'example.test');
eq('two hosts in one /48 share a prefix',
  v6Concentrated.sharedPrefixes,
  [{ prefix: '2001:db8:1:0:0:0:0:0/48', hosts: ['a.example.test', 'b.example.test'] }]);

// One hextet further out is a different /48, which is the negative control
// for the width: at /24 of a v6 address these two would still group together.
const v6Spread = await audit({
  'a.example.test': { A: [], AAAA: ['2001:db8:1::1'], CNAME: [] },
  'b.example.test': { A: [], AAAA: ['2001:db8:2::1'], CNAME: [] },
})(['10 a.example.test.', '20 b.example.test.'], 'example.test');
eq('hosts in different /48s share nothing', v6Spread.sharedPrefixes, []);

// The two families are grouped separately and never mixed into one label.
const bothFamilies = await audit({
  'a.example.test': { A: ['192.0.2.1'], AAAA: ['2001:db8:1::1'], CNAME: [] },
  'b.example.test': { A: ['192.0.2.9'], AAAA: ['2001:db8:1::9'], CNAME: [] },
})(['10 a.example.test.', '20 b.example.test.'], 'example.test');
eq('a host pair sharing both families produces two prefixes',
  bothFamilies.sharedPrefixes.map(p => p.prefix).sort(),
  ['192.0.2.0/24', '2001:db8:1:0:0:0:0:0/48']);

// An unknown host is left OUT of the concentration analysis rather than
// counted as sharing or not sharing a block.
const unknownBlock = await audit({
  'a.example.test': { A: ['192.0.2.1'], AAAA: [], CNAME: [] },
  'b.example.test': { A: null, AAAA: null, CNAME: null },
})(['10 a.example.test.', '20 b.example.test.'], 'example.test');
eq('a host we could not resolve contributes no prefix',
  unknownBlock.sharedPrefixes, []);

// Partial IPv6.
const someV6 = await audit({
  'a.example.test': { A: ['192.0.2.1'], AAAA: ['2001:db8::1'], CNAME: [] },
  'b.example.test': { A: ['198.51.100.1'], AAAA: [], CNAME: [] },
})(['10 a.example.test.', '20 b.example.test.'], 'example.test');
eq('one of two with AAAA is some', someV6.ipv6Coverage, 'some');

const cnamed = await audit({
  'mail.example.test': { A: ['192.0.2.1'], AAAA: [], CNAME: ['real.example.net'] },
})(['10 mail.example.test.'], 'example.test');
eq('an MX target behind a CNAME is named', cnamed.cnameHosts, ['mail.example.test']);
eq('and cnameUnknown is false when the lookup returned',
  cnamed.hosts[0].cnameUnknown, false);

const outside = await audit({
  'mx.provider.test': { A: ['192.0.2.1'], AAAA: [], CNAME: [] },
})(['10 mx.provider.test.'], 'example.test');
eq('a third-party exchange is not inside the audited domain',
  outside.hosts[0].inAudited, false);

/* ── 5. Every produced value is in its published algebra ──────────────── */
section('5. The constants are not decoration');

const observed = [healthy, dangling, partial, mixed, deduped, tied, concentrated,
  spread, v6Concentrated, v6Spread, bothFamilies, unknownBlock, someV6, cnamed, outside];
eq('every resolves value observed is one of the three',
  [...new Set(observed.flatMap(a => a.hosts.map(h => h.resolves)))]
    .filter(v => !MX_HOST_RESOLVES.includes(v)), []);
eq('and all three were actually produced',
  [...new Set(observed.flatMap(a => a.hosts.map(h => h.resolves)))].sort(),
  ['no', 'unknown', 'yes']);
eq('every ipv6Coverage value observed is one of the three',
  [...new Set(observed.map(a => a.ipv6Coverage))]
    .filter(v => !MX_IPV6_COVERAGE.includes(v)), []);
eq('and all three were actually produced',
  [...new Set(observed.map(a => a.ipv6Coverage))].sort(), ['all', 'none', 'some']);

// The negative control for the injection: this module holds no resolver, so
// two audits over two resolvers cannot see each other's answers.
eq('two audits over two resolvers stay separate',
  [(await audit({ 'm.example.test': { A: ['192.0.2.1'], AAAA: [], CNAME: [] } })
    (['10 m.example.test.'], 'example.test')).hosts[0].addresses,
    (await audit({ 'm.example.test': { A: ['198.51.100.1'], AAAA: [], CNAME: [] } })
      (['10 m.example.test.'], 'example.test')).hosts[0].addresses],
  [['192.0.2.1'], ['198.51.100.1']]);

/* ── 6. 0.9.1: what the addresses are, not just how many ──────────────── */
section('6. Address scope and reachability');

// The finding this release exists for. Before it, `resolves` came from
// `addresses.length` alone, so this host read exactly like a healthy one.
const loopback = await audit({
  'lo.example.test': { A: ['127.0.0.1'], AAAA: [], CNAME: [] },
})(['10 lo.example.test.'], 'example.test');
eq('a host on loopback still resolves yes', loopback.hosts[0].resolves, 'yes');
eq('but it is not reachable', loopback.hosts[0].reachability, 'none');
eq('and it is named as unroutable', loopback.unroutableHosts, ['lo.example.test']);

const priv = await audit({
  'p.example.test': { A: ['10.0.0.4'], AAAA: ['fe80::1'], CNAME: [] },
})(['10 p.example.test.'], 'example.test');
eq('private and link-local space is unreachable too', priv.hosts[0].reachability, 'none');
eq('every address carries its own scope',
  priv.hosts[0].addressScopes.map(e => e.scope), ['private', 'link-local']);

// STUB VALUES, chosen for their scope and nothing else. This file's usual
// 192.0.2.x is RFC 5737 documentation space, which `ipScope` classifies
// `documentation` and therefore unreachable — correctly, and that is the point
// of this release — so it cannot stand in for a reachable host here. These two
// are in globally-routable class and are placeholders: they assert nothing
// about who holds them, and nothing in this suite depends on their being
// reachable in fact. Documentation addresses are still used elsewhere in the
// file as deliberate classification inputs.
const ROUTABLE_V4 = '100.200.100.200';
const ROUTABLE_V6 = '2a01:beef::1';

const routable = await audit({
  'r.example.test': { A: [ROUTABLE_V4], AAAA: [ROUTABLE_V6], CNAME: [] },
})(['10 r.example.test.'], 'example.test');
eq('a globally routable host is global', routable.hosts[0].reachability, 'global');

eq('documentation space is not globally reachable either',
  (await audit({ 'd.example.test': { A: ['192.0.2.1'], AAAA: [], CNAME: [] } })
    (['10 d.example.test.'], 'example.test')).hosts[0].reachability, 'none');

// Partial is its own state: this host takes mail from most senders and stalls
// whichever ones pick the second address.
const partlyRoutable = await audit({
  'm.example.test': { A: [ROUTABLE_V4, '10.0.0.4'], AAAA: [], CNAME: [] },
})(['10 m.example.test.'], 'example.test');
eq('one routable and one not is partial', partlyRoutable.hosts[0].reachability, 'partial');
eq('and it is listed as partial, not unroutable',
  [partlyRoutable.partiallyRoutableHosts, partlyRoutable.unroutableHosts],
  [['m.example.test'], []]);

eq('a host that did not resolve claims no reachability',
  dangling.hosts[0].reachability, 'unknown');

// An address the classifier cannot read is excluded from the verdict rather
// than counted as reachable. A resolver returning junk must not produce a
// reachability claim in either direction.
const junk = await audit({
  'j.example.test': { A: ['not-an-address'], AAAA: [], CNAME: [] },
})(['10 j.example.test.'], 'example.test');
eq('an unreadable address yields no reachability claim',
  junk.hosts[0].reachability, 'unknown');
eq('and it is neither unroutable nor partial',
  [junk.unroutableHosts, junk.partiallyRoutableHosts], [[], []]);

section('7. An address literal is not a missing address record');

const literal = auditWith({});
const literalResult = await literal.run(['10 203.0.113.5'], 'example.test');
eq('the RDATA is recognised as an address', literalResult.hosts[0].isAddressLiteral, true);
eq('it is reported as an address literal', literalResult.addressLiteralHosts, ['203.0.113.5']);
// The suppression. `mx-dangling` tells the operator to check the zone for a
// missing address record, which cannot exist for a name that is an address.
eq('and NOT as a dangling host', literalResult.danglingHosts, []);
// A saving that is only described regresses silently, so it is asserted: three
// queries per host spent proving what the RDATA already stated.
eq('no query is issued for it at all', literal.asked, []);

const v6Literal = auditWith({});
const v6LiteralResult = await v6Literal.run(['10 2001:db8::1'], 'example.test');
eq('an IPv6 literal is caught the same way',
  [v6LiteralResult.addressLiteralHosts, v6LiteralResult.danglingHosts, v6Literal.asked],
  [['2001:db8::1'], [], []]);

// The negative control: a real hostname must still be looked up.
const realHost = auditWith({ 'mail.example.test': { A: ['192.0.2.1'], AAAA: [], CNAME: [] } });
await realHost.run(['10 mail.example.test.'], 'example.test');
eq('while a real host is still queried three ways',
  realHost.asked.sort(),
  ['mail.example.test/A', 'mail.example.test/AAAA', 'mail.example.test/CNAME']);

section('8. A null MX beside a real one');

// RFC 7505 §3. Reported where v0.9.0 reported nothing: `parseMxRecord` rejects
// `0 .` because stripping the trailing dot leaves an empty host, so the
// contradiction never reached a lookup and never reached a finding either.
eq('`0 .` still does not parse', parseMxRecord('0 .'), null);
eq('a null MX beside a real host is a conflict',
  hasNullMxConflict(['0 .', '10 mail.example.test.']), true);
eq('a lone null MX is not', hasNullMxConflict(['0 .']), false);
// A duplicate of one declaration says nothing contradictory. The predicate
// needs a record that is NOT `0 .`, not merely a second array entry.
eq('two null MX answers are a duplicate, not a conflict',
  hasNullMxConflict(['0 .', '0 .']), false);
// The other record does not have to parse. `0 .` beside an attempt to name
// somewhere mail goes is contradictory however malformed that attempt is.
eq('a null MX beside an unparseable record is still a conflict',
  hasNullMxConflict(['0 .', 'garbage']), true);
eq('an ordinary set is not', hasNullMxConflict(['10 a.example.test', '20 b.example.test']), false);
eq('and neither is an empty one', hasNullMxConflict([]), false);

// isNullMx is load-bearing in the deep-check gate, in @null-mx provider
// detection and in the MTA-STS policy-on-null-mx finding. None of them may move.
eq('isNullMx is unchanged on a lone null MX', isNullMx(['0 .']), true);
eq('unchanged on a conflicted set', isNullMx(['0 .', '10 mail.example.test.']), false);
eq('unchanged on an ordinary set', isNullMx(['10 mail.example.test.']), false);

const conflicted = auditWith({ 'mail.example.test': { A: ['192.0.2.1'], AAAA: [], CNAME: [] } });
const conflictedResult = await conflicted.run(['0 .', '10 mail.example.test.'], 'example.test');
eq('the audit reports the conflict', conflictedResult.nullMxConflict, true);
eq('the real host is still audited', conflictedResult.hosts.map(h => h.host), ['mail.example.test']);
eq('nothing dangles and the pseudo-target is never queried',
  [conflictedResult.danglingHosts, conflicted.asked.filter(q => q.startsWith('./'))], [[], []]);

// No preference-range check: RFC 1035 §3.3.9 encodes the preference as an
// unsigned 16-bit integer, so a value above 65535 cannot survive a real MX
// response. Asserting one would mean handing the parser a string no resolver
// produces. Both ends of the real range parse, and that is all there is to say.
eq('0 parses', parseMxRecord('0 mail.example.test').preference, 0);
eq('65535 parses', parseMxRecord('65535 mail.example.test').preference, 65535);

section('9. The reachability constant is not decoration');

const reachObserved = [routable, dangling, loopback, priv, partlyRoutable, junk, literalResult];
eq('every reachability value observed is a declared member',
  [...new Set(reachObserved.flatMap(a => a.hosts.map(h => h.reachability)))]
    .filter(v => !MX_HOST_REACHABILITY.includes(v)), []);
eq('and all four were actually produced',
  [...new Set(reachObserved.flatMap(a => a.hosts.map(h => h.reachability)))].sort(),
  ['global', 'none', 'partial', 'unknown']);

/* ── 10. 0.9.2: the name a PTR is asked under ─────────────────────────── */
section('10. reverseName');

// This is what reaches the resolver, and therefore what the privacy review
// inventories as disclosed. It is not the address.
eq('IPv4 reverses the octets under in-addr.arpa',
  reverseName('100.2.0.20'), '20.0.2.100.in-addr.arpa');
eq('IPv6 reverses all 32 nibbles under ip6.arpa',
  reverseName('2a01:100::20'),
  '0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.1.0.a.2.ip6.arpa');
// `::` elides a run of zeroes, so the address must be expanded before it is
// reversed. Reversing the text as written would give a short, wrong name.
eq('and the elided form and the written-out form agree',
  reverseName('2a01:100::20'),
  reverseName('2a01:0100:0000:0000:0000:0000:0000:0020'));
eq('an unparseable address has no reverse name', reverseName('garbage'), null);
eq('and neither has an empty one', reverseName(''), null);

/* ── 11. 0.9.2: divergence, and every branch that reports nothing ──────── */
section('11. Vanity divergence');

const PROVIDER = 'mailfilter.provider.test';
// A vanity host: named in the audited domain, resolving into routable space.
const vanity = (over = {}) => ({
  'mail.example.test': { A: ['100.2.0.20'], AAAA: [], CNAME: [] },
  '20.0.2.100.in-addr.arpa': { PTR: [PROVIDER] },
  [PROVIDER]: { A: ['100.2.0.20', '100.9.9.9'], AAAA: [] },
  ...over,
});
const runMx = table => auditWith(table);
const oneVanity = async table => {
  const h = runMx(table);
  const result = await h.run(['10 mail.example.test.'], 'example.test');
  return { result, asked: h.asked };
};

const divergent = await oneVanity(vanity());
eq('a provider publishing an address the copy lacks is divergent',
  divergent.result.divergentHosts,
  [{ host: 'mail.example.test', provider: PROVIDER, missing: ['100.9.9.9'] }]);
eq('and the PTR is asked under the reverse zone, not the address',
  divergent.asked.includes('20.0.2.100.in-addr.arpa/PTR'), true);
eq('and the provider name is forward-confirmed before it is trusted',
  [divergent.asked.includes(PROVIDER + '/A'), divergent.asked.includes(PROVIDER + '/AAAA')],
  [true, true]);

// Equal sets: confirmed, compared, and correctly silent.
eq('an equal address set reports nothing',
  (await oneVanity(vanity({ [PROVIDER]: { A: ['100.2.0.20'], AAAA: [] } }))).result.divergentHosts, []);

// Not forward-confirmed: the reverse name is not acted on at all.
eq('a reverse name that does not forward-confirm reports nothing',
  (await oneVanity(vanity({ [PROVIDER]: { A: ['203.0.113.200'], AAAA: [] } }))).result.divergentHosts, []);

// Bidirectional divergence is deferred (RQ-MXV-06): H must be a strict subset.
eq('a set diverging in both directions reports nothing',
  (await oneVanity(vanity({
    'mail.example.test': { A: ['100.2.0.20', '100.7.7.7'], AAAA: [], CNAME: [] },
    '7.7.7.100.in-addr.arpa': { PTR: [PROVIDER] },
  }))).result.divergentHosts, []);

// Self-hosted: the reverse name is inside the audited zone, so there is no
// provider to compare against — and no forward query is spent finding out.
const selfHosted = await oneVanity(vanity({
  '20.0.2.100.in-addr.arpa': { PTR: ['mail.example.test'] },
}));
eq('a reverse name inside the audited domain reports nothing',
  selfHosted.result.divergentHosts, []);
eq('and costs no forward-confirmation query',
  selfHosted.asked.some(q => q.startsWith(PROVIDER)), false);

section('12. Reverse DNS absence, failure, and the gate');

// An answer of nothing is a claim of absence.
const noReverse = await oneVanity(vanity({ '20.0.2.100.in-addr.arpa': { PTR: [] } }));
eq('a host with no PTR published is named', noReverse.result.hostsWithoutReverse, ['mail.example.test']);
eq('and reverseNames is an empty answer, not null', noReverse.result.hosts[0].reverseNames, []);

// A lookup that does not return is not a claim of absence.
const failedReverse = await oneVanity(vanity({ '20.0.2.100.in-addr.arpa': { PTR: null } }));
eq('a PTR that did not return claims nothing', failedReverse.result.hostsWithoutReverse, []);
eq('and reverseNames stays null', failedReverse.result.hosts[0].reverseNames, null);

// Out-of-domain hosts never qualify: the operator does not control that name.
const outOfDomain = auditWith({
  'mx.provider.test': { A: ['100.2.0.20'], AAAA: [], CNAME: [] },
  '20.0.2.100.in-addr.arpa': { PTR: [PROVIDER] },
});
const outResult = await outOfDomain.run(['10 mx.provider.test.'], 'example.test');
eq('an out-of-domain MX host is not examined', outResult.divergentHosts, []);
eq('and no PTR is issued for it', outOfDomain.asked.some(q => q.endsWith('/PTR')), false);

// An unreachable host is not examined either.
const unreachable = auditWith({
  'mail.example.test': { A: ['127.0.0.1'], AAAA: [], CNAME: [] },
  '1.0.0.127.in-addr.arpa': { PTR: [PROVIDER] },
});
await unreachable.run(['10 mail.example.test.'], 'example.test');
eq('an unroutable host costs no PTR', unreachable.asked.some(q => q.endsWith('/PTR')), false);

section('13. The caps are load-bearing');

// Two lowest-preference qualifying hosts, and no more. Three in-domain hosts
// would otherwise cost twelve PTR queries on their own.
const threeHosts = auditWith({
  'a.example.test': { A: ['100.2.0.20'], AAAA: [], CNAME: [] },
  'b.example.test': { A: ['100.2.0.21'], AAAA: [], CNAME: [] },
  'c.example.test': { A: ['100.2.0.22'], AAAA: [], CNAME: [] },
  '20.0.2.100.in-addr.arpa': { PTR: [] },
  '21.0.2.100.in-addr.arpa': { PTR: [] },
  '22.0.2.100.in-addr.arpa': { PTR: [] },
});
await threeHosts.run(['10 a.example.test.', '20 b.example.test.', '30 c.example.test.'], 'example.test');
eq('only the two lowest-preference hosts are examined',
  threeHosts.asked.filter(q => q.endsWith('/PTR')).sort(),
  ['20.0.2.100.in-addr.arpa/PTR', '21.0.2.100.in-addr.arpa/PTR']);

// Four addresses per host, and no more.
const fiveAddresses = auditWith({
  'mail.example.test': { A: ['100.2.0.20', '100.2.0.21', '100.2.0.22', '100.2.0.23', '100.2.0.24'], AAAA: [], CNAME: [] },
  '20.0.2.100.in-addr.arpa': { PTR: [] }, '21.0.2.100.in-addr.arpa': { PTR: [] },
  '22.0.2.100.in-addr.arpa': { PTR: [] }, '23.0.2.100.in-addr.arpa': { PTR: [] },
  '24.0.2.100.in-addr.arpa': { PTR: [] },
});
await fiveAddresses.run(['10 mail.example.test.'], 'example.test');
eq('at most four addresses per host are reversed',
  fiveAddresses.asked.filter(q => q.endsWith('/PTR')).length, 4);

// Two candidate provider names per domain, and no more.
const threeCandidates = auditWith({
  'a.example.test': { A: ['100.2.0.20'], AAAA: [], CNAME: [] },
  'b.example.test': { A: ['100.2.0.21'], AAAA: [], CNAME: [] },
  '20.0.2.100.in-addr.arpa': { PTR: ['one.provider.test'] },
  '21.0.2.100.in-addr.arpa': { PTR: ['two.provider.test'] },
  'one.provider.test': { A: ['100.2.0.20'], AAAA: [] },
  'two.provider.test': { A: ['100.2.0.21'], AAAA: [] },
});
await threeCandidates.run(['10 a.example.test.', '20 b.example.test.'], 'example.test');
eq('two candidates are resolved, one A and one AAAA each',
  threeCandidates.asked.filter(q => /provider\.test\/(A|AAAA)$/.test(q)).length, 4);

/* ── 14. 0.9.2 review corrections ─────────────────────────────────────── */
section('14. Unknown is not absent, and confirmation is per source address');

// F1. One lookup that never returned means absence cannot be claimed, even
// though the other returned an empty answer. Unknown is not absent — and the
// recorded field has to say so, because an empty array is the encoding of a
// host that answered and published nothing.
const mixedFailure = await oneVanity({
  'mail.example.test': { A: ['100.2.0.20', '100.2.0.21'], AAAA: [], CNAME: [] },
  '20.0.2.100.in-addr.arpa': { PTR: null },
  '21.0.2.100.in-addr.arpa': { PTR: [] },
});
eq('a failed lookup beside an empty one claims no absence',
  mixedFailure.result.hostsWithoutReverse, []);
eq('and reverseNames is null, not the empty answer of a host that published none',
  mixedFailure.result.hosts[0].reverseNames, null);

// The three states are distinct, and the distinction is only visible when all
// three are read together: every address answered nothing is `[]` with the
// host named; some address did not answer and none produced a name is `null`
// with the host unnamed; a name that did return survives a sibling failure.
const bothEmpty = await oneVanity({
  'mail.example.test': { A: ['100.2.0.20', '100.2.0.21'], AAAA: [], CNAME: [] },
  '20.0.2.100.in-addr.arpa': { PTR: [] },
  '21.0.2.100.in-addr.arpa': { PTR: [] },
});
eq('every address answering nothing is an empty answer',
  [bothEmpty.result.hosts[0].reverseNames, bothEmpty.result.hostsWithoutReverse],
  [[], ['mail.example.test']]);

const failedWithName = await oneVanity({
  'mail.example.test': { A: ['100.2.0.20', '100.2.0.21'], AAAA: [], CNAME: [] },
  '20.0.2.100.in-addr.arpa': { PTR: null },
  '21.0.2.100.in-addr.arpa': { PTR: ['mail.example.test'] },
});
eq('a name that returned is kept even though a sibling lookup failed',
  [failedWithName.result.hosts[0].reverseNames, failedWithName.result.hostsWithoutReverse],
  [['mail.example.test'], []]);

// Acceptance criterion 13. One address fails, the other yields a confirmed
// provider, and divergence is still evaluated from the address that worked.
const oneFailedOneWorked = await oneVanity({
  'mail.example.test': { A: ['100.2.0.20', '100.2.0.21'], AAAA: [], CNAME: [] },
  '20.0.2.100.in-addr.arpa': { PTR: null },
  '21.0.2.100.in-addr.arpa': { PTR: [PROVIDER] },
  [PROVIDER]: { A: ['100.2.0.20', '100.2.0.21', '100.9.9.9'], AAAA: [] },
});
eq('divergence is still found from the address whose lookup returned',
  oneFailedOneWorked.result.divergentHosts,
  [{ host: 'mail.example.test', provider: PROVIDER, missing: ['100.9.9.9'] }]);

// F2. The candidate must forward-confirm against the address whose PTR named
// it — not against any address the host happens to publish.
const wrongSource = await oneVanity({
  'mail.example.test': { A: ['100.2.0.20', '100.2.0.21'], AAAA: [], CNAME: [] },
  '20.0.2.100.in-addr.arpa': { PTR: [PROVIDER] },
  '21.0.2.100.in-addr.arpa': { PTR: [] },
  [PROVIDER]: { A: ['100.2.0.21'], AAAA: [] },
});
eq('a provider confirming a different address of the same host is not confirmed',
  wrongSource.result.divergentHosts, []);
// And an unconfirmed name is never recorded as this host's provider.
eq('and neither provider field is populated',
  [wrongSource.result.hosts[0].providerName, wrongSource.result.hosts[0].providerAddresses],
  [null, null]);

section('15. Address sets, not arrays');

// F3. A provider publishing the same RR twice must not duplicate the evidence.
eq('a duplicated provider RR appears once in the missing set',
  (await oneVanity(vanity({
    [PROVIDER]: { A: ['100.2.0.20', '100.9.9.9', '100.9.9.9'], AAAA: [] },
  }))).result.divergentHosts[0].missing, ['100.9.9.9']);

// And on the host's side: a duplicated host RR must not defeat the subset test.
eq('a duplicated host RR still compares as a set',
  (await oneVanity({
    'mail.example.test': { A: ['100.2.0.20', '100.2.0.20'], AAAA: [], CNAME: [] },
    '20.0.2.100.in-addr.arpa': { PTR: [PROVIDER] },
    [PROVIDER]: { A: ['100.2.0.20', '100.9.9.9'], AAAA: [] },
  })).result.divergentHosts[0].missing, ['100.9.9.9']);

section('16. A reverse name is only built from a real address');

// F4. `999.1.1.1` matches three-digits-per-octet and is not an address.
eq('255.255.255.255 reverses', reverseName('255.255.255.255'), '255.255.255.255.in-addr.arpa');
eq('256.1.1.1 does not', reverseName('256.1.1.1'), null);
eq('999.1.1.1 does not either', reverseName('999.1.1.1'), null);
eq('and neither does a three-octet address', reverseName('1.2.3'), null);

// A host answering with one usable address and one malformed one still
// qualifies through the usable address — and must put no malformed question
// on the wire.
const partlyMalformed = auditWith({
  'mail.example.test': { A: ['100.2.0.20', '999.1.1.1'], AAAA: [], CNAME: [] },
  '20.0.2.100.in-addr.arpa': { PTR: [] },
});
await partlyMalformed.run(['10 mail.example.test.'], 'example.test');
eq('the usable address is reversed',
  partlyMalformed.asked.includes('20.0.2.100.in-addr.arpa/PTR'), true);
eq('and no malformed reverse name is ever queried',
  partlyMalformed.asked.some(q => q.includes('999')), false);

/* ── 17. An address set is a set of values, not of spellings ──────────── */
section('17. Equivalent spellings are one address');

const V6_EXPANDED = '2a01:0100:0000:0000:0000:0000:0000:0020';
const V6_SHORT = '2a01:100::20';
const V6_REVERSE =
  '0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.1.0.a.2.ip6.arpa';

// F1. The host publishes the expanded form; the provider publishes the
// compressed one. Comparing the text fails forward confirmation and the real
// divergence is reported nowhere.
const spelledDifferently = await oneVanity({
  'mail.example.test': { A: [], AAAA: [V6_EXPANDED], CNAME: [] },
  [V6_REVERSE]: { PTR: [PROVIDER] },
  [PROVIDER]: { A: [], AAAA: [V6_SHORT, '2a01:100::21'] },
});
eq('the PTR source confirms against the same address written differently',
  spelledDifferently.result.hosts[0].providerName, PROVIDER);
eq('and the divergence is found, naming only the address the host lacks',
  spelledDifferently.result.divergentHosts,
  [{ host: 'mail.example.test', provider: PROVIDER, missing: ['2a01:100::21'] }]);

// Membership, the other way round: an address the host does publish must not
// appear as missing because the provider spelled it out in full.
const providerSpellsItOut = await oneVanity({
  'mail.example.test': { A: [], AAAA: [V6_SHORT], CNAME: [] },
  [V6_REVERSE]: { PTR: [PROVIDER] },
  [PROVIDER]: { A: [], AAAA: [V6_EXPANDED] },
});
eq('an equal set in two spellings is not a divergence',
  providerSpellsItOut.result.divergentHosts, []);

// De-duplication is by identity too: one address written twice is one address,
// so it neither inflates the host's set nor breaks the subset test.
const twoSpellings = await oneVanity({
  'mail.example.test': { A: [], AAAA: [V6_SHORT, V6_EXPANDED], CNAME: [] },
  [V6_REVERSE]: { PTR: [PROVIDER] },
  [PROVIDER]: { A: [], AAAA: [V6_SHORT, '2a01:100::21'] },
});
eq('one address written twice is still one address',
  twoSpellings.result.divergentHosts,
  [{ host: 'mail.example.test', provider: PROVIDER, missing: ['2a01:100::21'] }]);
// And it costs one reverse lookup, not two identical ones.
eq('and it is reversed once',
  twoSpellings.asked.filter(q => q === V6_REVERSE + '/PTR').length, 1);

// The evidence keeps the text the zone published, not a normalized rendering.
const providerWritesItLong = await oneVanity({
  'mail.example.test': { A: [], AAAA: [V6_SHORT], CNAME: [] },
  [V6_REVERSE]: { PTR: [PROVIDER] },
  [PROVIDER]: { A: [], AAAA: [V6_SHORT, '2A01:0100:0000:0000:0000:0000:0000:0021'] },
});
eq('the missing address is quoted as the provider published it',
  providerWritesItLong.result.divergentHosts[0].missing,
  ['2A01:0100:0000:0000:0000:0000:0000:0021']);

// The two families stay apart, which is visible in the key rather than in a
// finding: an IPv4-mapped address is not the IPv4 address it embeds, and it is
// not globally reachable either, so §18 is where its behaviour is asserted.

/* ── 18. Only reachable addresses are missing redundancy ──────────────── */
section('18. The comparison is over globally reachable addresses');

// A provider address that cannot accept Internet mail is not redundancy the
// operator is missing, and telling them to publish it would contradict
// `mx.unroutable`. Each of these is a provider-only address the audit must
// refuse to turn into remediation.
const providerOnly = async extra => (await oneVanity({
  'mail.example.test': { A: ['100.2.0.20'], AAAA: [], CNAME: [] },
  '20.0.2.100.in-addr.arpa': { PTR: [PROVIDER] },
  [PROVIDER]: { A: ['100.2.0.20'].concat(extra.A || []), AAAA: extra.AAAA || [] },
})).result.divergentHosts;

eq('a private provider address is not missing redundancy',
  await providerOnly({ A: ['10.0.0.5'] }), []);
eq('nor is a documentation address',
  await providerOnly({ A: ['198.51.100.9'] }), []);
eq('nor is shared address space',
  await providerOnly({ A: ['100.64.0.9'] }), []);
eq('nor is an IPv4-mapped form of an address the host already publishes',
  await providerOnly({ AAAA: ['::ffff:100.2.0.20'] }), []);
eq('nor is text that is not an address at all',
  await providerOnly({ A: ['not-an-address'] }), []);

// And the finding still fires for the case it exists for.
eq('a missing global address is still reported',
  await providerOnly({ A: ['100.9.9.9'] }),
  [{ host: 'mail.example.test', provider: PROVIDER, missing: ['100.9.9.9'] }]);

// The suppression case. Comparing raw sets, the host's private address is
// absent from the provider's, so `H ⊄ P` reads as bidirectional divergence and
// the real missing global address is reported nowhere.
const extraPrivateOnHost = await oneVanity({
  'mail.example.test': { A: ['100.2.0.20', '10.0.0.5'], AAAA: [], CNAME: [] },
  '20.0.2.100.in-addr.arpa': { PTR: [PROVIDER] },
  '5.0.0.10.in-addr.arpa': { PTR: [] },
  [PROVIDER]: { A: ['100.2.0.20', '100.9.9.9'], AAAA: [] },
});
eq('an extra non-global host address does not suppress the finding',
  extraPrivateOnHost.result.divergentHosts,
  [{ host: 'mail.example.test', provider: PROVIDER, missing: ['100.9.9.9'] }]);

// Bidirectional divergence between two REACHABLE sets is still deferred, and
// the restriction above must not have quietly turned it into a finding.
const bothWaysGlobal = await oneVanity({
  'mail.example.test': { A: ['100.2.0.20', '100.8.8.8'], AAAA: [], CNAME: [] },
  '20.0.2.100.in-addr.arpa': { PTR: [PROVIDER] },
  '8.8.8.100.in-addr.arpa': { PTR: [] },
  [PROVIDER]: { A: ['100.2.0.20', '100.9.9.9'], AAAA: [] },
});
eq('two reachable sets diverging both ways is still not this finding',
  bothWaysGlobal.result.divergentHosts, []);

/* ── 19. The advisory says only what was checked ──────────────────────── */
section('19. The four-address cap is part of what the finding means');

// The finding names the host, and its text says the CHECKED addresses. This is
// the case that makes the difference matter: five addresses, reverse DNS on the
// fifth, and the fifth is never asked. Claiming the host publishes none would
// be false about this zone — the text says what was observed instead, and the
// cap is disclosed to the reader rather than left implicit.
const fifthHasReverse = auditWith({
  'mail.example.test': {
    A: ['100.2.0.20', '100.2.0.21', '100.2.0.22', '100.2.0.23', '100.2.0.24'],
    AAAA: [], CNAME: [],
  },
  '20.0.2.100.in-addr.arpa': { PTR: [] }, '21.0.2.100.in-addr.arpa': { PTR: [] },
  '22.0.2.100.in-addr.arpa': { PTR: [] }, '23.0.2.100.in-addr.arpa': { PTR: [] },
  '24.0.2.100.in-addr.arpa': { PTR: ['mail.example.test'] },
});
const capped = await fifthHasReverse.run(['10 mail.example.test.'], 'example.test');
eq('the fifth address is never asked', [
  fifthHasReverse.asked.filter(q => q.endsWith('/PTR')).length,
  fifthHasReverse.asked.includes('24.0.2.100.in-addr.arpa/PTR'),
], [4, false]);
eq('and the host is still named, because the checked addresses published none',
  capped.hostsWithoutReverse, ['mail.example.test']);
// The scope of the claim lives in the finding's text, which is asserted in the
// locale suite; what this file pins is that the observation itself is exactly
// "the four that were checked", never the whole published set.
eq('the recorded answer covers the checked addresses only',
  [capped.hosts[0].reverseNames, capped.hosts[0].addresses.length], [[], 5]);

// The cap is applied to one combined list, and that list is A answers followed
// by AAAA answers — not a single "order the zone returned them", which does not
// exist across two lookups. Four IPv4 answers therefore consume the whole
// budget and the host's IPv6 address is never asked about, even though it is
// the one publishing a PTR. This asserts the result AND the trace: under the
// opposite order the ip6.arpa question would be asked, the PTR would return a
// name, and both assertions below would fail.
const fourAOneAAAA = auditWith({
  'mail.example.test': {
    A: ['100.2.0.20', '100.2.0.21', '100.2.0.22', '100.2.0.23'],
    AAAA: ['2a01:100::20'], CNAME: [],
  },
  '20.0.2.100.in-addr.arpa': { PTR: [] }, '21.0.2.100.in-addr.arpa': { PTR: [] },
  '22.0.2.100.in-addr.arpa': { PTR: [] }, '23.0.2.100.in-addr.arpa': { PTR: [] },
  '0.2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.1.0.1.0.a.2.ip6.arpa':
    { PTR: ['mail.example.test'] },
});
const cappedByA = await fourAOneAAAA.run(['10 mail.example.test.'], 'example.test');
eq('the four IPv4 answers consume the budget, in resolver order',
  fourAOneAAAA.asked.filter(q => q.endsWith('/PTR')),
  ['20.0.2.100.in-addr.arpa/PTR', '21.0.2.100.in-addr.arpa/PTR',
    '22.0.2.100.in-addr.arpa/PTR', '23.0.2.100.in-addr.arpa/PTR']);
eq('and the IPv6 address is never asked about, PTR or not',
  fourAOneAAAA.asked.some(q => q.includes('ip6.arpa')), false);
// Which is exactly why the finding's text says the checked addresses: this host
// does publish reverse DNS, on an address the cap never reached.
eq('the advisory still names the host, on what was checked',
  [cappedByA.hostsWithoutReverse, cappedByA.hosts[0].reverseNames],
  [['mail.example.test'], []]);

report();
