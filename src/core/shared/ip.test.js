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
import { ipv4ToBigInt, ipv6ToBigInt, parseIpCidr } from './ip.js';

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

report();
