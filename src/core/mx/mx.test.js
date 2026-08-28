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
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import {
  createMxAudit, isNullMx, parseMxRecord, bigIntToIp,
  MX_HOST_RESOLVES, MX_IPV6_COVERAGE,
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
  { preference: 10, host: 'mail.example.test' });
eq('the trailing dot is dropped and the host lowercased',
  parseMxRecord('10 Mail.Example.TEST.').host, 'mail.example.test');
eq('extra whitespace is collapsed', parseMxRecord('  10   mail.example.test '),
  { preference: 10, host: 'mail.example.test' });
eq('preference 0 with a target is a record', parseMxRecord('0 mail.example.test').preference, 0);
eq('a non-numeric preference is not a record', parseMxRecord('ten mail.example.test'), null);
eq('a record with no target is not one', parseMxRecord('10'), null);
eq('an empty string is not one', parseMxRecord(''), null);
eq('undefined is not one', parseMxRecord(undefined), null);
eq('a bare dot target survives as a host', parseMxRecord('0 .'), null);

/* ── 4. Rendering a network address back to text ──────────────────────── */
section('4. bigIntToIp');

eq('an IPv4 network', bigIntToIp(3221225984n, 'ipv4'), '192.0.2.0');
eq('the zero address', bigIntToIp(0n, 'ipv4'), '0.0.0.0');
eq('the broadcast address', bigIntToIp(4294967295n, 'ipv4'), '255.255.255.255');
eq('an IPv6 network', bigIntToIp(0x20010db8n << 96n, 'ipv6'), '2001:db8:0:0:0:0:0:0');
eq('the all-ones IPv6 address', bigIntToIp(2n ** 128n - 1n, 'ipv6'),
  'ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff');

/* ── 5. The audit, over a passed resolver ─────────────────────────────── */
section('5. createMxAudit');

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
// The real layer-4 policy, not a stub: the module must work against the
// function it will actually be handed.
const optionalCheck = async (run, fallback) => {
  try { return await run(); }
  catch (error) {
    if (error && (error.name === 'AbortError' || error.name === 'DnsTypeError')) throw error;
    return typeof fallback === 'function' ? fallback(error) : fallback;
  }
};
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

/* ── 6. Every produced value is in its published algebra ──────────────── */
section('6. The constants are not decoration');

const observed = [healthy, dangling, partial, mixed, deduped, tied, concentrated,
  spread, unknownBlock, someV6, cnamed, outside];
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

report();
