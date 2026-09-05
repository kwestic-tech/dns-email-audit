#!/usr/bin/env node
/**
 * IP address and CIDR arithmetic. Spec §12, Task 4.0.
 *
 * The properties worth pinning are the ones a plausible-looking rewrite would
 * lose: `::` expands to exactly eight hextets before any arithmetic happens,
 * every value is a BigInt so nothing above 2^53 rounds, and a malformed input
 * returns null so one bad SPF mechanism does not discard the record.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { ipv4ToBigInt, ipv6ToBigInt, parseIpCidr, ipScope, ipIdentity, IP_SCOPE } from './ip.js';

const { eq, section, report } = createSuite();

/* ── 1. IPv4 ──────────────────────────────────────────────────────────── */
section('1. ipv4ToBigInt');

eq('the zero address', ipv4ToBigInt('0.0.0.0'), 0n);
eq('a documentation address', ipv4ToBigInt('192.0.2.1'), 3221225985n);
eq('the broadcast address', ipv4ToBigInt('255.255.255.255'), 4294967295n);
eq('an octet above 255 is not an address', ipv4ToBigInt('192.0.2.256'), null);
eq('three octets are not an address', ipv4ToBigInt('192.0.2'), null);
eq('five are not either', ipv4ToBigInt('192.0.2.1.1'), null);
eq('a hex octet is not one', ipv4ToBigInt('192.0.2.0x1'), null);
eq('an empty octet is not one', ipv4ToBigInt('192.0..1'), null);
eq('a four-digit octet is not one', ipv4ToBigInt('192.0.2.0001'), null);
eq('and the result is a BigInt', typeof ipv4ToBigInt('192.0.2.1'), 'bigint');

/* ── 2. IPv6, where `::` is the whole difficulty ──────────────────────── */
section('2. ipv6ToBigInt');

eq('a full address', ipv6ToBigInt('2001:0db8:0000:0000:0000:0000:0000:0001'),
  42540766411282592856903984951653826561n);
// The same address elided. Splitting on ':' naively leaves this three groups
// short and silently misaligns every bit.
eq('and the same address with :: is the same number',
  ipv6ToBigInt('2001:db8::1'), ipv6ToBigInt('2001:0db8:0000:0000:0000:0000:0000:0001'));
eq(':: alone is the unspecified address', ipv6ToBigInt('::'), 0n);
eq('::1 is loopback', ipv6ToBigInt('::1'), 1n);
eq('a leading :: expands on the left', ipv6ToBigInt('::2001:db8'), 0x20010db8n);
eq('a trailing :: expands on the right',
  ipv6ToBigInt('2001:db8::'), ipv6ToBigInt('2001:db8:0:0:0:0:0:0'));

// RFC 4291 §2.2.3: the low 32 bits may be written dotted-quad.
eq('an embedded IPv4 is folded into two hextets',
  ipv6ToBigInt('::ffff:192.0.2.1'), ipv6ToBigInt('::ffff:c000:201'));
eq('a bad embedded IPv4 is not an address', ipv6ToBigInt('::ffff:192.0.2.256'), null);

eq(':: may appear only once', ipv6ToBigInt('2001::db8::1'), null);
eq('seven groups without :: is not an address', ipv6ToBigInt('1:2:3:4:5:6:7'), null);
eq('nine groups is not either', ipv6ToBigInt('1:2:3:4:5:6:7:8:9'), null);
eq('a five-digit hextet is not one', ipv6ToBigInt('2001:db8::12345'), null);
eq('a non-hex hextet is not one', ipv6ToBigInt('2001:db8::zz'), null);
eq('an address with no colon is not one', ipv6ToBigInt('192.0.2.1'), null);
eq('the full range is exact, not rounded',
  ipv6ToBigInt('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff'), 2n ** 128n - 1n);

/* ── 3. CIDR ──────────────────────────────────────────────────────────── */
section('3. parseIpCidr');

eq('an IPv4 block', parseIpCidr('192.0.2.0/24', 'ipv4'),
  { address: 3221225984n, prefix: 24, bits: 32 });
eq('an absent prefix is a single host', parseIpCidr('192.0.2.1', 'ipv4'),
  { address: 3221225985n, prefix: 32, bits: 32 });
eq('an IPv6 block keeps 128 bits', parseIpCidr('2001:db8::/32', 'ipv6'),
  { address: ipv6ToBigInt('2001:db8::'), prefix: 32, bits: 128 });
eq('an absent IPv6 prefix is /128', parseIpCidr('2001:db8::1', 'ipv6').prefix, 128);
eq('/0 is a legal prefix', parseIpCidr('0.0.0.0/0', 'ipv4').prefix, 0);

// A bad prefix is not a /32. The caller drops that one mechanism and audits
// the rest of the record, which only works if this says null.
eq('a prefix past the family width is not a block', parseIpCidr('192.0.2.0/33', 'ipv4'), null);
eq('a negative prefix is not one', parseIpCidr('192.0.2.0/-1', 'ipv4'), null);
eq('a non-numeric prefix is not one', parseIpCidr('192.0.2.0/abc', 'ipv4'), null);
eq('an empty prefix is not one', parseIpCidr('192.0.2.0/', 'ipv4'), null);
eq('a malformed address is not one', parseIpCidr('192.0.2.999/24', 'ipv4'), null);
eq('an unknown family is not one', parseIpCidr('192.0.2.0/24', 'ipv5'), null);
eq('an absent family is not one', parseIpCidr('192.0.2.0/24'), null);

// The family is the caller's declaration, not a guess from the text — MX and
// SPF both decide it before calling.
eq('an IPv6 address read as IPv4 is refused', parseIpCidr('2001:db8::1', 'ipv4'), null);
eq('an IPv4 address read as IPv6 is refused', parseIpCidr('192.0.2.1', 'ipv6'), null);

/* ── 4. The module holds nothing ──────────────────────────────────────── */
section('4. Pure');

eq('repeated calls agree',
  parseIpCidr('192.0.2.0/24', 'ipv4'), parseIpCidr('192.0.2.0/24', 'ipv4'));

/* ── 5. ipScope: both edges of every range, and just outside them ─────── */
section('5. ipScope, IPv4');

// Two per member, and both edges of every range. A classifier is wrong at its
// boundaries or it is not wrong anywhere, so the first and last address of each
// block is the assertion that matters.
eq('0.0.0.0 is unspecified', ipScope('0.0.0.0', 'ipv4'), 'unspecified');
eq('0.255.255.255 still is', ipScope('0.255.255.255', 'ipv4'), 'unspecified');
eq('127.0.0.1 is loopback', ipScope('127.0.0.1', 'ipv4'), 'loopback');
eq('127.0.0.0 and 127.255.255.255 bound it',
  [ipScope('127.0.0.0', 'ipv4'), ipScope('127.255.255.255', 'ipv4')],
  ['loopback', 'loopback']);
eq('10.0.0.0/8 is private at both ends',
  [ipScope('10.0.0.0', 'ipv4'), ipScope('10.255.255.255', 'ipv4')],
  ['private', 'private']);
eq('172.16.0.0/12 is private at both ends',
  [ipScope('172.16.0.0', 'ipv4'), ipScope('172.31.255.255', 'ipv4')],
  ['private', 'private']);
eq('192.168.0.0/16 is private at both ends',
  [ipScope('192.168.0.0', 'ipv4'), ipScope('192.168.255.255', 'ipv4')],
  ['private', 'private']);
eq('169.254.0.0/16 is link-local at both ends',
  [ipScope('169.254.0.0', 'ipv4'), ipScope('169.254.255.255', 'ipv4')],
  ['link-local', 'link-local']);
eq('100.64.0.0/10 is shared at both ends',
  [ipScope('100.64.0.0', 'ipv4'), ipScope('100.127.255.255', 'ipv4')],
  ['shared', 'shared']);
eq('the three documentation blocks',
  [ipScope('192.0.2.0', 'ipv4'), ipScope('198.51.100.255', 'ipv4'),
    ipScope('203.0.113.7', 'ipv4')],
  ['documentation', 'documentation', 'documentation']);
eq('198.18.0.0/15 is benchmarking at both ends',
  [ipScope('198.18.0.0', 'ipv4'), ipScope('198.19.255.255', 'ipv4')],
  ['benchmarking', 'benchmarking']);
eq('224.0.0.0/4 is multicast at both ends',
  [ipScope('224.0.0.0', 'ipv4'), ipScope('239.255.255.255', 'ipv4')],
  ['multicast', 'multicast']);
eq('240.0.0.0/4 and the broadcast address are reserved',
  [ipScope('240.0.0.0', 'ipv4'), ipScope('255.255.255.255', 'ipv4')],
  ['reserved', 'reserved']);

// The other half of a boundary test: one address below and one above each
// block is ordinary space. A matcher off by one bit passes everything above
// and fails here.
section('6. ipScope, immediately outside each IPv4 range');

eq('1.0.0.0 is global', ipScope('1.0.0.0', 'ipv4'), 'global');
eq('9.255.255.255 and 11.0.0.0 are global',
  [ipScope('9.255.255.255', 'ipv4'), ipScope('11.0.0.0', 'ipv4')],
  ['global', 'global']);
eq('172.15.255.255 and 172.32.0.0 are global',
  [ipScope('172.15.255.255', 'ipv4'), ipScope('172.32.0.0', 'ipv4')],
  ['global', 'global']);
eq('192.167.255.255 and 192.169.0.0 are global',
  [ipScope('192.167.255.255', 'ipv4'), ipScope('192.169.0.0', 'ipv4')],
  ['global', 'global']);
eq('169.253.255.255 and 169.255.0.0 are global',
  [ipScope('169.253.255.255', 'ipv4'), ipScope('169.255.0.0', 'ipv4')],
  ['global', 'global']);
eq('100.63.255.255 and 100.128.0.0 are global',
  [ipScope('100.63.255.255', 'ipv4'), ipScope('100.128.0.0', 'ipv4')],
  ['global', 'global']);
eq('192.0.1.255 and 192.0.3.0 are global',
  [ipScope('192.0.1.255', 'ipv4'), ipScope('192.0.3.0', 'ipv4')],
  ['global', 'global']);
eq('198.17.255.255 and 198.20.0.0 are global',
  [ipScope('198.17.255.255', 'ipv4'), ipScope('198.20.0.0', 'ipv4')],
  ['global', 'global']);
eq('223.255.255.255 is global', ipScope('223.255.255.255', 'ipv4'), 'global');
eq('a real mail host is global', ipScope('210.71.187.212', 'ipv4'), 'global');

section('7. ipScope, IPv6');

eq(':: is unspecified', ipScope('::', 'ipv6'), 'unspecified');
eq('::1 is loopback', ipScope('::1', 'ipv6'), 'loopback');
// A single-address block: the neighbour on each side must not be caught by it.
eq('::2 is global', ipScope('::2', 'ipv6'), 'global');
eq('fc00:: and fdff:...:ffff bound unique-local',
  [ipScope('fc00::', 'ipv6'), ipScope('fdff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'ipv6')],
  ['private', 'private']);
eq('fe80::/10 is link-local at both ends',
  [ipScope('fe80::', 'ipv6'), ipScope('febf:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'ipv6')],
  ['link-local', 'link-local']);
eq('2001:db8::/32 is documentation at both ends',
  [ipScope('2001:db8::', 'ipv6'), ipScope('2001:db8:ffff:ffff:ffff:ffff:ffff:ffff', 'ipv6')],
  ['documentation', 'documentation']);
eq('2001:2::/48 is benchmarking', ipScope('2001:2::1', 'ipv6'), 'benchmarking');
eq('ff00::/8 is multicast at both ends',
  [ipScope('ff00::', 'ipv6'), ipScope('ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff', 'ipv6')],
  ['multicast', 'multicast']);
// An AAAA holding a v4-mapped address is a specific authoring mistake, and
// naming it that is more use than calling it reserved.
eq('::ffff:0:0/96 is v4-mapped, written either way',
  [ipScope('::ffff:0:0', 'ipv6'), ipScope('::ffff:203.0.113.5', 'ipv6')],
  ['v4-mapped', 'v4-mapped']);
eq('2001:db7:: and 2001:db9:: are global',
  [ipScope('2001:db7::1', 'ipv6'), ipScope('2001:db9::1', 'ipv6')],
  ['global', 'global']);
eq('fbff:: and fe00:: are global',
  [ipScope('fbff::1', 'ipv6'), ipScope('fe00::1', 'ipv6')],
  ['global', 'global']);
eq('a real resolver address is global', ipScope('2606:4700::1111', 'ipv6'), 'global');

section('8. ipScope refuses what it cannot read');

// These come from DNS answers, which are third-party input. Reporting an
// unreadable string as globally reachable would claim reachability about
// something never parsed, so it is null and the caller must exclude it.
eq('an unparseable address is null, not global', ipScope('nonsense', 'ipv4'), null);
eq('an empty address is null', ipScope('', 'ipv4'), null);
eq('an absent address is null', ipScope(undefined, 'ipv4'), null);
eq('an unknown family is null', ipScope('192.0.2.1', 'ipv5'), null);
eq('an absent family is null', ipScope('192.0.2.1'), null);
eq('a v6 address read as v4 is null', ipScope('2001:db8::1', 'ipv4'), null);
eq('a v4 address read as v6 is null', ipScope('192.0.2.1', 'ipv6'), null);

eq('every returned scope is a declared member',
  ['0.0.0.0', '127.0.0.1', '10.0.0.1', '169.254.0.1', '100.64.0.1',
    '192.0.2.1', '198.18.0.1', '224.0.0.1', '240.0.0.1', '8.8.8.8']
    .map(function (a) { return IP_SCOPE.indexOf(ipScope(a, 'ipv4')) !== -1; })
    .every(Boolean),
  true);

section('ipIdentity: one address is one key, however it is written');

// The reason this exists: an address set compared as text makes one address
// two, and the MX subset test then reports nothing.
eq('the elided and expanded forms of one address are one key',
  ipIdentity('2a01:100::20'),
  ipIdentity('2a01:0100:0000:0000:0000:0000:0000:0020'));
eq('case does not change identity either',
  ipIdentity('2A01:100::AB'), ipIdentity('2a01:100::ab'));
eq('surrounding whitespace does not', ipIdentity(' 192.0.2.1 '), ipIdentity('192.0.2.1'));
eq('and two different addresses are two keys',
  ipIdentity('2a01:100::20') === ipIdentity('2a01:100::21'), false);

// The families are kept apart on purpose: an AAAA publishing an IPv4-mapped
// address is a different delivery path from an A publishing the same quad.
eq('an IPv4-mapped v6 address does not key as its v4 form',
  ipIdentity('::ffff:192.0.2.1') === ipIdentity('192.0.2.1'), false);
eq('and it is still a v6 key',
  ipIdentity('::ffff:192.0.2.1').startsWith('v6:'), true);

// Text that is not an address has no identity; callers decide what to do.
eq('a malformed octet is not an address', ipIdentity('999.1.1.1'), null);
eq('a hostname is not an address', ipIdentity('mail.example.test'), null);
eq('an empty string is not', ipIdentity(''), null);
eq('and neither is nothing at all', ipIdentity(undefined), null);

report();
