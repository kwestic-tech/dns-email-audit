/**
 * MX health and host resolution. Spec Design §4 and §12, Task 4.2.
 *
 * **No SMTP, ever.** Everything here is inferred from DNS, so it reports what
 * is published and never what a delivery attempt would do. The finding this
 * directory exists for is an MX host that does not resolve — a total inbound
 * mail outage that, before it was checked, read in the interface exactly like
 * a healthy mail domain. The rest — CNAME targets, single points of failure,
 * address-block concentration — are hygiene notes.
 *
 * ── Two resolver capabilities, both passed ──────────────────────────────
 *
 * `dohQuery` (layer 3, normalized) and `optionalCheck` (layer 4, the error
 * policy). Neither is imported: §12 gives a protocol directory an edge to
 * `core/shared/` only. `core/caa/` names `requireUsable` for the same reason
 * and at the same boundary.
 *
 * `optionalCheck` is applied **per host**, not to the audit as a whole. A
 * resolver hiccup on one target must not turn the other targets' answers into
 * an outage report, and must never let a host we could not check be counted as
 * dangling. That is why `resolves` has three values and not two.
 *
 * ── isNullMx lives here, and providers will not import it ───────────────
 *
 * `isNullMx()` is MX semantics, so `core/mx/` owns it. Its callers today are
 * `detectEmailProvider()` and `analyzeDomain()` — neither a protocol owner,
 * and `providers/` may import `core/shared/` only. The ruling at Task 4.0 is
 * that `providers/` receives the DERIVED null-MX fact from audit rather than
 * reaching for the predicate; Task 4.9 does that. `js/dns.js` importing it
 * here is the legacy file wiring, not the target graph.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s MX health block and `isNullMx`, unchanged apart from the
 * two-space dedent, the `export` keywords, `auditMxHosts` becoming the body of
 * a factory that names its two resolver capabilities, and the two published
 * state constants. No lookup, no grouping rule and no result shape moved with
 * it.
 */

import { parseIpCidr } from '../shared/ip.js';

/** The three answers a host lookup can give. Registry algebra `mx.host.resolves`. */
export const MX_HOST_RESOLVES = Object.freeze(['yes', 'no', 'unknown']);

/**
 * How much of the resolved MX set publishes AAAA. Registry algebra
 * `mx.ipv6Coverage`.
 *
 * `none` is two different situations — nothing resolved, and everything
 * resolved without IPv6 — and they are deliberately one value, because the
 * distinction is already carried by `hosts[].resolves`.
 */
export const MX_IPV6_COVERAGE = Object.freeze(['none', 'some', 'all']);

/**
 * RFC 7505: `0 .` is a null MX, an explicit declaration that the domain
 * receives no mail. It is not an absent MX and not a broken one.
 */
export function isNullMx(mx) {
  if (mx.length !== 1) return false;
  var parts = String(mx[0]).trim().split(/\s+/);
  return parts.length === 2 && parts[0] === '0' && parts[1] === '.';
}

/* ── MX health (DNS only) ─────────────────────────────────────────────
   No SMTP, ever. Everything below is inferred from DNS, so it reports what
   is published and never what a delivery attempt would do.
   ───────────────────────────────────────────────────────────────────── */

/** Prefix width used to notice that every MX host sits in one block. */
var MX_PREFIX_BITS = { ipv4: 24, ipv6: 48 };

/**
 * Render a network address back to text, for the prefix label only.
 *
 * Private. Its only caller is the concentration grouping below, and its
 * observable contract is the `sharedPrefixes[].prefix` label — which is where
 * the tests read it. Exporting a function so a unit test can reach it widens
 * the module's API for the test's convenience, and this one was never a legacy
 * engine member either.
 */
function bigIntToIp(value, family) {
  if (family === 'ipv4') {
    return [24n, 16n, 8n, 0n].map(function (shift) { return String((value >> shift) & 0xffn); }).join('.');
  }
  var groups = [];
  for (var i = 7; i >= 0; i--) groups.push((((value >> BigInt(i * 16)) & 0xffffn)).toString(16));
  return groups.join(':');
}

/** `10 mail.example.com.` → `{ preference: 10, host: 'mail.example.com' }`. */
export function parseMxRecord(record) {
  var parts = String(record || '').trim().split(/\s+/);
  if (parts.length < 2 || !/^\d+$/.test(parts[0])) return null;
  var host = parts.slice(1).join(' ').replace(/\.$/, '').toLowerCase();
  if (!host) return null;
  return { preference: Number(parts[0]), host: host };
}

/**
 * Resolve every MX target and report what DNS alone can say about it.
 *
 * An MX host that does not resolve is a total inbound mail outage, and today
 * it reads in the interface exactly like a healthy mail domain. That is the
 * finding this function exists for; the rest — CNAME targets, single points
 * of failure, address-block concentration — are hygiene notes.
 *
 * Each host is resolved independently and a failure degrades that host to
 * `resolves: 'unknown'`. A resolver hiccup on one target must not turn the
 * other targets' answers into an outage report, and must never let a host we
 * could not check be counted as dangling. That is optionalCheck()'s rule
 * applied per host rather than to the audit as a whole.
 */
/**
 * The MX audit, over a passed resolver.
 *
 * `dohQuery` is layer 3 — normalized string arrays with no transport kind —
 * and `optionalCheck` is layer 4's policy, applied once per host and per
 * record type. Both are arguments because §12 gives a protocol directory no
 * edge to `core/dns/`.
 */
export function createMxAudit({ dohQuery, optionalCheck }) {
  async function auditMxHosts(mx, domain, queryOpts) {
    var entries = (mx || []).map(parseMxRecord).filter(Boolean);
    if (!entries.length) {
      return {
        hosts: [], danglingHosts: [], cnameHosts: [], duplicatePreferences: [],
        singleHost: false, ipv6Coverage: 'none', sharedPrefixes: [], unknown: false,
      };
    }

    // Distinct delivery targets. Two MX records naming the same exchange at
    // different preferences are one host, one point of failure and one set of
    // lookups — mapping records straight to audits queried it twice, counted it
    // twice in the CSV, and suppressed `mx-single-host` on a domain that has
    // exactly one. The records themselves stay in `entries` for the preference
    // analysis, which is about the records and not the targets.
    var targets = [];
    var byHost = Object.create(null);
    entries.forEach(function (entry) {
      var target = byHost[entry.host];
      if (target) { target.preferences.push(entry.preference); return; }
      target = { host: entry.host, preference: entry.preference, preferences: [entry.preference] };
      byHost[entry.host] = target;
      targets.push(target);
    });
    // The lowest preference is the one a sender reaches first, so it is the one
    // that describes the target.
    targets.forEach(function (target) {
      target.preference = Math.min.apply(null, target.preferences);
    });

    var hosts = await Promise.all(targets.map(async function (entry) {
      var UNKNOWN = {};
      var results = await Promise.all([
        optionalCheck(function () { return dohQuery(entry.host, 'A', queryOpts); }, UNKNOWN),
        optionalCheck(function () { return dohQuery(entry.host, 'AAAA', queryOpts); }, UNKNOWN),
        optionalCheck(function () { return dohQuery(entry.host, 'CNAME', queryOpts); }, UNKNOWN),
      ]);
      var v4 = results[0] === UNKNOWN ? null : results[0];
      var v6 = results[1] === UNKNOWN ? null : results[1];
      var cname = results[2] === UNKNOWN ? null : results[2];
      var addresses = (v4 || []).concat(v6 || []);
      return {
        host: entry.host,
        preference: entry.preference,
        // Every preference this host is published at. One host at two
        // preferences is still one host, and the duplication is evidence.
        preferences: entry.preferences,
        addresses: addresses,
        v4Count: v4 ? v4.length : 0,
        v6Count: v6 ? v6.length : 0,
        // 'no' is claimed only when both address lookups actually returned.
        // One failed lookup and one empty answer is not evidence of absence.
        resolves: addresses.length ? 'yes' : (v4 === null || v6 === null) ? 'unknown' : 'no',
        isCname: cname === null ? false : cname.length > 0,
        cnameUnknown: cname === null,
        inAudited: entry.host === domain || entry.host.endsWith('.' + domain),
      };
    }));

    var seenPreferences = Object.create(null);
    var duplicatePreferences = [];
    entries.forEach(function (entry) {
      if (seenPreferences[entry.preference]) {
        if (duplicatePreferences.indexOf(entry.preference) === -1) duplicatePreferences.push(entry.preference);
      }
      seenPreferences[entry.preference] = true;
    });

    // Only hosts whose addresses we actually read can tell us anything about
    // concentration, so an unknown host is left out rather than counted as
    // sharing or not sharing a block.
    var groups = Object.create(null);
    hosts.filter(function (h) { return h.resolves === 'yes'; }).forEach(function (h) {
      h.addresses.forEach(function (address) {
        var family = address.indexOf(':') === -1 ? 'ipv4' : 'ipv6';
        var block = parseIpCidr(address + '/' + MX_PREFIX_BITS[family], family);
        if (!block) return;
        var network = block.address >> BigInt(block.bits - block.prefix) << BigInt(block.bits - block.prefix);
        var label = bigIntToIp(network, family) + '/' + MX_PREFIX_BITS[family];
        if (!groups[label]) groups[label] = [];
        if (groups[label].indexOf(h.host) === -1) groups[label].push(h.host);
      });
    });
    var sharedPrefixes = Object.keys(groups)
      .filter(function (label) { return groups[label].length > 1; })
      .map(function (label) { return { prefix: label, hosts: groups[label] }; });

    var resolved = hosts.filter(function (h) { return h.resolves === 'yes'; });
    var withV6 = resolved.filter(function (h) { return h.v6Count > 0; });

    return {
      hosts: hosts,
      danglingHosts: hosts.filter(function (h) { return h.resolves === 'no'; }).map(function (h) { return h.host; }),
      cnameHosts: hosts.filter(function (h) { return h.isCname; }).map(function (h) { return h.host; }),
      duplicatePreferences: duplicatePreferences,
      singleHost: hosts.length === 1,
      ipv6Coverage: !resolved.length ? 'none'
        : withV6.length === resolved.length ? 'all'
          : withV6.length ? 'some' : 'none',
      sharedPrefixes: sharedPrefixes,
      unknown: hosts.some(function (h) { return h.resolves === 'unknown'; }),
    };
  }

  return auditMxHosts;
}
