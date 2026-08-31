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
