/**
 * IP address and CIDR arithmetic, shared by two protocol owners. Spec §12,
 * Task 4.0.
 *
 * `parseIpCidr()` is read by `core/mx/`'s `auditMxHosts()`, which groups mail
 * hosts into /24 and /48 blocks to see how concentrated they are, and by
 * `core/spf/`'s `classifySpfSubnets()`, which sizes the space an `ip4:` or
 * `ip6:` mechanism authorizes. `ipv4ToBigInt()` and `ipv6ToBigInt()` come with
 * it: they are what it is built from, and SPF's `findSpfRedundancy()` calls
 * both directly as well.
 *
 * BigInt throughout, because 128 bits does not fit in a Number and anything
 * that rounds an IPv6 address is wrong in a way no test output makes obvious.
 *
 * ── What stayed with its one owner ──────────────────────────────────────
 *
 * `bigIntToIp()` (MX only), `cidrContains()`, `classifySpfSubnet()` and
 * `stripSpfQualifier()` (SPF only) each have exactly one caller and are NOT
 * here. Task 4.0's test is two or more protocol owners, and a helper with one
 * owner is not shared just because it is adjacent to something that is.
 *
 * The consequence is worth stating plainly: the `{ address, prefix, bits }`
 * record this module returns is an OPEN value that both owners read fields off
 * directly — MX already computes its own network address from `.bits` and
 * `.prefix`. Moving the accessors here would not have changed that, so it was
 * not a reason to move them.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s `IP_FAMILY_BITS`, `ipv4ToBigInt`, `ipv6ToBigInt` and
 * `parseIpCidr`, unchanged apart from the two-space dedent and three `export`
 * keywords. `IP_FAMILY_BITS` stays private; nothing outside read it.
 *
 * ── ipScope(), added by 0.9.1 ────────────────────────────────────────────
 *
 * `parseIpCidr()` answers how big a block is. `ipScope()` answers what kind of
 * address it holds, which nothing here could ask before: `core/mx/` computed
 * `resolves: 'yes'` from `addresses.length` alone, so an MX host answering
 * `127.0.0.1` reported as a healthy mail host that no sender can reach.
 *
 * It lives here rather than in `core/mx/` under the same test that placed
 * `parseIpCidr()` here: two protocol owners. MX reads it now; `core/spf/`
 * classifies the same address space and can read it without a new edge.
 */

var IP_FAMILY_BITS = { ipv4: 32, ipv6: 128 };

export function ipv4ToBigInt(text) {
  var parts = String(text).split('.');
  if (parts.length !== 4) return null;
  var value = 0n;
  for (var i = 0; i < 4; i++) {
    if (!/^\d{1,3}$/.test(parts[i])) return null;
    var octet = Number(parts[i]);
    if (octet > 255) return null;
    value = (value << 8n) | BigInt(octet);
  }
  return value;
}

/**
 * Parse an IPv6 literal into one 128-bit BigInt, or null if it isn't one.
 *
 * Two things make this more than a split on ':'. `::` elides a run of zero
 * hextets, so the text has to be expanded to exactly 8 groups before any
 * arithmetic — splitting naively leaves `2001:db8::1` three groups short
 * and silently misaligns every bit of the address. And 128 bits does not
 * fit in a Number, which loses precision above 53, so this is BigInt from
 * end to end rather than anything that could round.
 */
export function ipv6ToBigInt(text) {
  var str = String(text);
  if (str.indexOf(':') === -1) return null;
  // RFC 4291 §2.2.3 allows the low 32 bits in dotted-quad form
  // (::ffff:192.0.2.1). Fold it into two hextets first.
  var embedded = /(\d{1,3}(?:\.\d{1,3}){3})$/.exec(str);
  if (embedded) {
    var v4 = ipv4ToBigInt(embedded[1]);
    if (v4 === null) return null;
    str = str.slice(0, embedded.index) +
      ((v4 >> 16n) & 0xffffn).toString(16) + ':' + (v4 & 0xffffn).toString(16);
  }
  var halves = str.split('::');
  if (halves.length > 2) return null;                       // '::' may appear once
  var head = halves[0] ? halves[0].split(':') : [];
  var tail = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  var groups = head;
  if (halves.length === 2) {
    var fill = 8 - head.length - tail.length;
    if (fill < 0) return null;
    groups = head.concat(new Array(fill).fill('0'), tail);
  }
  if (groups.length !== 8) return null;
  var value = 0n;
  for (var i = 0; i < 8; i++) {
    if (!/^[0-9a-fA-F]{1,4}$/.test(groups[i])) return null;
    value = (value << 16n) | BigInt(parseInt(groups[i], 16));
  }
  return value;
}

/**
 * Parse `address` or `address/prefix` into { address, prefix, bits }.
 *
 * Returns null for anything malformed rather than throwing or guessing. A
 * bad prefix is not a /32: '/33', '/-1' and '/abc' all return null so the
 * caller drops that one mechanism and still audits the rest of the record.
 * An absent prefix is a single host — /32 for IPv4, /128 for IPv6.
 */
export function parseIpCidr(text, family) {
  var bits = IP_FAMILY_BITS[family];
  if (!bits) return null;
  var value = String(text || '');
  var prefix = bits;
  var slash = value.lastIndexOf('/');
  if (slash !== -1) {
    var suffix = value.slice(slash + 1);
    value = value.slice(0, slash);
    if (!/^\d{1,3}$/.test(suffix)) return null;
    prefix = Number(suffix);
    if (prefix > bits) return null;
  }
  var address = family === 'ipv6' ? ipv6ToBigInt(value) : ipv4ToBigInt(value);
  if (address === null) return null;
  return { address: address, prefix: prefix, bits: bits };
}

/**
 * The kinds of address `ipScope()` distinguishes. Registry algebra `ip.scope`.
 *
 * The registry behind this is RFC 6890 and the IANA special-purpose address
 * registries it establishes. Every member but `global` names space that is not
 * globally reachable, which is the only distinction MX reachability needs; they
 * are kept apart anyway because "this MX points at loopback" and "this MX points
 * at documentation space" are different mistakes and the operator fixes them
 * differently.
 */
export const IP_SCOPE = Object.freeze(['global', 'unspecified', 'loopback',
  'private', 'link-local', 'shared', 'documentation', 'benchmarking',
  'multicast', 'reserved', 'v4-mapped']);

/**
 * Special-purpose ranges, most specific first where two overlap.
 *
 * `255.255.255.255/32` sits inside `240.0.0.0/4` and both are `reserved`, so
 * their order is immaterial; it is listed for the reader rather than the
 * matcher. Nothing else here overlaps.
 */
var SPECIAL_RANGES = [
  { family: 'ipv4', cidr: '0.0.0.0/8',          scope: 'unspecified' },
  { family: 'ipv4', cidr: '127.0.0.0/8',        scope: 'loopback' },
  { family: 'ipv4', cidr: '10.0.0.0/8',         scope: 'private' },
  { family: 'ipv4', cidr: '172.16.0.0/12',      scope: 'private' },
  { family: 'ipv4', cidr: '192.168.0.0/16',     scope: 'private' },
  { family: 'ipv4', cidr: '169.254.0.0/16',     scope: 'link-local' },
  { family: 'ipv4', cidr: '100.64.0.0/10',      scope: 'shared' },
  { family: 'ipv4', cidr: '192.0.2.0/24',       scope: 'documentation' },
  { family: 'ipv4', cidr: '198.51.100.0/24',    scope: 'documentation' },
  { family: 'ipv4', cidr: '203.0.113.0/24',     scope: 'documentation' },
  { family: 'ipv4', cidr: '198.18.0.0/15',      scope: 'benchmarking' },
  { family: 'ipv4', cidr: '224.0.0.0/4',        scope: 'multicast' },
  { family: 'ipv4', cidr: '255.255.255.255/32', scope: 'reserved' },
  { family: 'ipv4', cidr: '240.0.0.0/4',        scope: 'reserved' },
  { family: 'ipv6', cidr: '::/128',             scope: 'unspecified' },
  { family: 'ipv6', cidr: '::1/128',            scope: 'loopback' },
  { family: 'ipv6', cidr: '::ffff:0:0/96',      scope: 'v4-mapped' },
  { family: 'ipv6', cidr: '2001:db8::/32',      scope: 'documentation' },
  { family: 'ipv6', cidr: '2001:2::/48',        scope: 'benchmarking' },
  { family: 'ipv6', cidr: 'fc00::/7',           scope: 'private' },
  { family: 'ipv6', cidr: 'fe80::/10',          scope: 'link-local' },
  { family: 'ipv6', cidr: 'ff00::/8',           scope: 'multicast' },
];

/** Whether `value` falls inside the parsed block `block`. */
function inBlock(value, block) {
  var shift = BigInt(block.bits - block.prefix);
  return (value >> shift) === (block.address >> shift);
}

/**
 * Classify one address as globally reachable or as the special-purpose space it
 * belongs to.
 *
 * Returns `null` — not `'global'` — for text that is not an address of that
 * family. The distinction matters: these values come from DNS answers, which
 * are third-party input, and reporting an unparseable string as globally
 * reachable would state a reachability claim about something never read. A
 * caller counting reachability must exclude a `null` rather than default it.
 *
 * `'global'` is the default for everything that parses and matches no range,
 * so a range IANA adds after this ships is reported as reachable rather than as
 * an outage. That direction of error is the safe one: this classification must
 * never invent a mail outage that is not there.
 */
export function ipScope(address, family) {
  var bits = IP_FAMILY_BITS[family];
  if (!bits) return null;
  var value = family === 'ipv6' ? ipv6ToBigInt(String(address || ''))
    : ipv4ToBigInt(String(address || ''));
  if (value === null) return null;
  for (var i = 0; i < SPECIAL_RANGES.length; i++) {
    var range = SPECIAL_RANGES[i];
    if (range.family !== family) continue;
    var block = parseIpCidr(range.cidr, family);
    if (block && inBlock(value, block)) return range.scope;
  }
  return 'global';
}

/**
 * The identity of an address, as a comparable key — or `null` if the text is
 * not an address at all.
 *
 * An address set is a set of IP **values**; DNS answers are presentation text.
 * `2a01:100::20` and `2a01:0100:0000:0000:0000:0000:0000:0020` are one address
 * written two ways, and comparing the strings makes them two — which silently
 * defeats de-duplication, forward confirmation and the `H ⊂ P` subset test
 * that the whole vanity-divergence finding rests on. Callers keep the
 * first-seen text for evidence and compare on this key.
 *
 * The family is read from the text rather than declared, because the caller is
 * comparing answers from `A` and `AAAA` in one set and has nothing else to go
 * on. **The two families do not collide:** an IPv4-mapped `::ffff:203.0.113.1`
 * keys as IPv6, because an `AAAA` publishing it is a different delivery path
 * from an `A` publishing `203.0.113.1`, and folding them together would report
 * a host as holding an address it does not publish.
 */
export function ipIdentity(text) {
  var value = String(text == null ? '' : text).trim();
  if (!value) return null;
  if (value.indexOf(':') !== -1) {
    var v6 = ipv6ToBigInt(value);
    return v6 === null ? null : 'v6:' + v6.toString(16);
  }
  var v4 = ipv4ToBigInt(value);
  return v4 === null ? null : 'v4:' + v4.toString(16);
}
