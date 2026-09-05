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
 * ── isNullMx lives here, and providers does not import it ───────────────
 *
 * `isNullMx()` is MX semantics, so `core/mx/` owns it, and `providers/` may
 * import `core/shared/` only. Task 4.0's ruling was that `providers/` receives
 * the DERIVED null-MX fact rather than reaching for the predicate.
 *
 * **`src/audit/` is the only caller now.** Task 4.9 injected the predicate
 * into `createDetectors()` as a stated debt, because there was no `src/audit/`
 * to derive the fact in; Task 5.2 paid it. Audit calls this once and reads the
 * boolean twice — provider detection and its own deep-check gate.
 * `js/dns.js` importing it is the legacy file's wiring for its compatibility
 * wrapper, not the target graph, and goes with that file in Phase 6.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s MX health block and `isNullMx`, unchanged apart from the
 * two-space dedent, the `export` keywords, `auditMxHosts` becoming the body of
 * a factory that names its two resolver capabilities, and the two published
 * state constants. No lookup, no grouping rule and no result shape moved with
 * it.
 */

import { parseIpCidr, ipScope, ipIdentity, ipv4ToBigInt, ipv6ToBigInt } from '../shared/ip.js';

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
 * How much of a host's address set is reachable from the internet. Registry
 * algebra `mx.host.reachability`.
 *
 * `partial` is a real state and not a rounding of either neighbour: a host with
 * one routable and one unroutable address accepts mail from most senders and
 * stalls whichever ones select the other, which is harder to diagnose from
 * outside than total failure.
 *
 * `unknown` covers three situations that all support no claim — the host did not
 * resolve, the record was an address literal so nothing was looked up, and every
 * address returned was unparseable. Unknown is not absent.
 */
export const MX_HOST_REACHABILITY = Object.freeze(['global', 'partial', 'none', 'unknown']);

/**
 * Caps on the 0.9.2 divergence procedure. Every one is load-bearing, and none
 * was set by taste: together they bound the additional outbound work at twelve
 * queries per domain, which is what made keeping this check under the existing
 * deep-check flag proportionate rather than a widening of what the tool
 * discloses. Spec §4 and §7, measured in `fixtures/ptr-fan-out-0.9.2.md`.
 */
var MX_MAX_DIVERGENCE_HOSTS = 2;
var MX_MAX_REVERSE_ADDRESSES = 4;
var MX_MAX_CANDIDATES = 2;

/**
 * The name a `PTR` is actually asked under.
 *
 * Reverse DNS does not look up an address; it looks up a name derived from one,
 * and that derived name is what reaches the resolver — so it is also what the
 * privacy review inventories as disclosed. IPv4 reverses the octets under
 * `in-addr.arpa`. IPv6 reverses all 32 nibbles under `ip6.arpa`, which means
 * the address must be expanded first: `::` elides a run of zeroes, and
 * reversing the text as written would produce a short, wrong name.
 *
 * Returns null for anything that does not parse, which the caller treats as an
 * address it cannot ask about rather than as an absent reverse record.
 */
export function reverseName(address, family) {
  var text = String(address || '');
  if (family === 'ipv6' || text.indexOf(':') !== -1) {
    var value = ipv6ToBigInt(text);
    if (value === null) return null;
    var nibbles = [];
    for (var i = 0; i < 32; i++) nibbles.push((((value >> BigInt(i * 4)) & 0xfn)).toString(16));
    return nibbles.join('.') + '.ip6.arpa';
  }
  // Validated with the shared parser, not a shape regex: `999.1.1.1` matches
  // three-digits-per-octet and is not an address, and building a reverse name
  // from it would put a malformed question on the wire.
  if (ipv4ToBigInt(text) === null) return null;
  return text.split('.').slice().reverse().join('.') + '.in-addr.arpa';
}

/**
 * Whether an MX target is an address rather than a name.
 *
 * A dotted quad is safe to treat as an address because the DNS root delegates
 * no all-numeric top-level domain, so a name of this shape cannot resolve. A
 * colon cannot appear in a hostname at all.
 */
function looksLikeAddressLiteral(host) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(host) || host.indexOf(':') !== -1;
}

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

/**
 * `10 mail.example.com.` → `{ preference: 10, host: 'mail.example.com', … }`.
 *
 * Null and unchanged for anything malformed, which includes RFC 7505's `0 .`:
 * stripping the trailing dot leaves an empty host and the record is rejected.
 * That is why a null MX never reaches a lookup, and why a null MX published
 * beside a real one produces silence rather than a dangling host.
 * `hasNullMxConflict()` reads the record set to report what this rejection
 * hides.
 *
 * No preference-range check. RFC 1035 §3.3.9 encodes the preference as an
 * unsigned 16-bit integer in the wire format, so a value above 65535 cannot
 * survive a real MX response and cannot reach this function from the resolver.
 * A check for it could only ever be exercised by handing this parser a string
 * no resolver produces, which is the reviewed-registry stop condition in
 * `AGENTS.md` rather than a finding.
 */
export function parseMxRecord(record) {
  var parts = String(record || '').trim().split(/\s+/);
  if (parts.length < 2 || !/^\d+$/.test(parts[0])) return null;
  var host = parts.slice(1).join(' ').replace(/\.$/, '').toLowerCase();
  if (!host) return null;
  return {
    preference: Number(parts[0]),
    host: host,
    isAddressLiteral: looksLikeAddressLiteral(host),
  };
}

/** Whether one record is RFC 7505's `0 .`, in its own right. */
function isNullMxRecord(record) {
  var parts = String(record).trim().split(/\s+/);
  return parts.length === 2 && parts[0] === '0' && parts[1] === '.';
}

/**
 * RFC 7505 §3: a null MX must be the only MX record in the set.
 *
 * Deliberately not folded into `isNullMx()`, whose `mx.length !== 1` guard is
 * load-bearing in the deep-check gate, in `@null-mx` provider detection and in
 * the MTA-STS `policy-on-null-mx` finding. All three want its current meaning —
 * "this domain has declared it receives no mail" — and a domain publishing a
 * contradictory set has declared nothing coherent, so it correctly fails that
 * predicate and correctly raises this one.
 */
export function hasNullMxConflict(mx) {
  var records = mx || [];
  var nulls = 0;
  var others = 0;
  records.forEach(function (record) {
    if (isNullMxRecord(record)) nulls++; else others++;
  });
  // Both halves are required. Two `0 .` answers are a duplicate of one
  // declaration and say nothing contradictory, so they are not a conflict. A
  // `0 .` beside anything else is, including beside a record too malformed to
  // parse into a host: the domain has published "no mail here" alongside an
  // attempt to name somewhere mail goes, and no sender can honour both.
  return nulls > 0 && others > 0;
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
/**
 * The comparable identity of an address, never its spelling.
 *
 * Everything §4 does with addresses — de-duplicating an answer, confirming a
 * PTR against the address it came from, testing `H ⊂ P` — is set membership
 * over IP values. Text that is not an address keys as itself so that a
 * malformed answer still de-duplicates rather than silently multiplying.
 */
function addressKey(text) {
  var key = ipIdentity(text);
  return key === null ? 'text:' + String(text == null ? '' : text).trim().toLowerCase() : key;
}

/**
 * First-seen-order de-duplication, by identity rather than by text. §4 compares
 * address SETS; DNS answers are multisets, and a zone publishing the same RR
 * twice — or the same address in two legal spellings — must not change either
 * the comparison or the evidence rendered from it. The text kept is the first
 * spelling seen, because the evidence should read as the zone published it.
 */
function uniqueAddresses(list) {
  var out = [];
  var seen = [];
  (list || []).forEach(function (a) {
    var key = addressKey(a);
    if (seen.indexOf(key) !== -1) return;
    seen.push(key);
    out.push(a);
  });
  return out;
}

/** A thunk for `optionalCheck`, named so the loop above stays readable. */
function makeQuery(dohQuery, name, type, queryOpts) {
  return function () { return dohQuery(name, type, queryOpts); };
}

export function createMxAudit({ dohQuery, optionalCheck }) {
  async function auditMxHosts(mx, domain, queryOpts) {
    var entries = (mx || []).map(parseMxRecord).filter(Boolean);
    // Read from the records, not from `entries`: the record this reports on is
    // exactly the one `parseMxRecord()` rejects.
    var nullMxConflict = hasNullMxConflict(mx);
    if (!entries.length) {
      return {
        hosts: [], danglingHosts: [], cnameHosts: [], duplicatePreferences: [],
        singleHost: false, ipv6Coverage: 'none', sharedPrefixes: [], unknown: false,
        addressLiteralHosts: [], unroutableHosts: [], partiallyRoutableHosts: [],
        nullMxConflict: nullMxConflict, divergentHosts: [], hostsWithoutReverse: [],
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
      target = {
        host: entry.host, preference: entry.preference, preferences: [entry.preference],
        isAddressLiteral: entry.isAddressLiteral,
      };
      byHost[entry.host] = target;
      targets.push(target);
    });
    // The lowest preference is the one a sender reaches first, so it is the one
    // that describes the target.
    targets.forEach(function (target) {
      target.preference = Math.min.apply(null, target.preferences);
    });

    var hosts = await Promise.all(targets.map(async function (entry) {
      // An address literal cannot resolve, and three queries per host spent
      // proving what the RDATA already stated are three queries wasted. The
      // record is reported for what it is instead.
      if (entry.isAddressLiteral) {
        return {
          host: entry.host, preference: entry.preference, preferences: entry.preferences,
          addresses: [], v4Count: 0, v6Count: 0,
          resolves: 'no', isCname: false, cnameUnknown: false,
          inAudited: entry.host === domain || entry.host.endsWith('.' + domain),
          isAddressLiteral: true, addressScopes: [], reachability: 'unknown',
          reverseNames: null, providerName: null, providerAddresses: null, missingAddresses: [],
        };
      }
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
      // One entry per address, `scope: null` included. An address the classifier
      // could not read is excluded from the reachability verdict below rather
      // than counted as reachable — these are third-party DNS answers, and
      // calling an unreadable one 'global' would state a claim never checked.
      var addressScopes = addresses.map(function (address) {
        return {
          address: address,
          scope: ipScope(address, address.indexOf(':') === -1 ? 'ipv4' : 'ipv6'),
        };
      });
      var classified = addressScopes.filter(function (entry) { return entry.scope !== null; });
      var globalCount = classified.filter(function (entry) { return entry.scope === 'global'; }).length;
      var resolves = addresses.length ? 'yes' : (v4 === null || v6 === null) ? 'unknown' : 'no';
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
        resolves: resolves,
        isCname: cname === null ? false : cname.length > 0,
        cnameUnknown: cname === null,
        inAudited: entry.host === domain || entry.host.endsWith('.' + domain),
        isAddressLiteral: false,
        // 0.9.2 fills these for qualifying hosts only. `null` means "not
        // asked" and is not the same as `[]`, which is an answer.
        reverseNames: null,
        providerName: null,
        providerAddresses: null,
        missingAddresses: [],
        addressScopes: addressScopes,
        reachability: resolves !== 'yes' || !classified.length ? 'unknown'
          : globalCount === classified.length ? 'global'
            : globalCount ? 'partial' : 'none',
      };
    }));

    /* ── 0.9.2: vanity divergence, and the reverse-DNS advisory ─────────
       Only for hosts named INSIDE the audited domain that resolved to
       something reachable. A provider-named MX has no vanity copy to have
       fallen behind, and a name the operator does not control is not theirs to
       fix. The three caps below are the privacy review's, not taste: together
       they bound the additional outbound work at twelve queries per domain. */
    var divergentHosts = [];
    var hostsWithoutReverse = [];
    var candidates = [];
    var qualifying = hosts
      .filter(function (h) {
        return h.inAudited && h.resolves === 'yes' && h.reachability !== 'none';
      })
      .slice()
      .sort(function (a, b) { return a.preference - b.preference; })
      .slice(0, MX_MAX_DIVERGENCE_HOSTS);

    for (var qi = 0; qi < qualifying.length; qi++) {
      var qHost = qualifying[qi];
      // Each reverse name is kept with the address that returned it. The
      // candidate has to be confirmed against THAT address: a provider name
      // that resolves to some other address of the same host has not been
      // confirmed for the address whose PTR produced it.
      var found = [];
      var attempted = 0;
      var returned = 0;
      var hostAddresses = uniqueAddresses(qHost.addresses);
      var reverseTargets = hostAddresses.slice(0, MX_MAX_REVERSE_ADDRESSES);

      for (var ai = 0; ai < reverseTargets.length; ai++) {
        var addr = reverseTargets[ai];
        var rName = reverseName(addr, addr.indexOf(':') === -1 ? 'ipv4' : 'ipv6');
        // An address with no valid reverse name is not a lookup that was made,
        // so it neither counts toward absence nor puts a question on the wire.
        if (!rName) continue;
        attempted++;
        var UNKNOWN_PTR = {};
        var answer = await optionalCheck(
          makeQuery(dohQuery, rName, 'PTR', queryOpts), UNKNOWN_PTR);
        if (answer === UNKNOWN_PTR) continue;
        returned++;
        for (var xi = 0; xi < answer.length; xi++) {
          var clean = String(answer[xi] || '').trim().replace(/\.$/, '').toLowerCase();
          if (!clean) continue;
          if (!found.some(function (f) { return f.name === clean; })) {
            found.push({ name: clean, source: addr });
          }
        }
      }

      var names = found.map(function (f) { return f.name; });

      // Three states, and `[]` is the narrow one. It means every attempted
      // lookup returned and none published a PTR — the only state that supports
      // the absence finding. A host where one lookup failed and another
      // answered empty is NOT that state, and encoding it as `[]` would claim
      // in the result what the finding correctly refused to claim.
      //
      // Names that did return are kept whatever else failed: per-address
      // aggregation is not conditional on the other addresses succeeding.
      if (names.length) qHost.reverseNames = names;
      else if (attempted > 0 && returned === attempted) qHost.reverseNames = [];
      else qHost.reverseNames = null;

      if (!names.length) {
        if (qHost.reverseNames !== null) hostsWithoutReverse.push(qHost.host);
        continue;
      }

      // A reverse name inside the audited zone is the self-hosted case: no
      // separate provider name exists to compare against.
      var pick = null;
      for (var ni = 0; ni < found.length; ni++) {
        var n = found[ni].name;
        if (n === qHost.host || n === domain || n.endsWith('.' + domain)) continue;
        pick = found[ni];
        break;
      }
      if (!pick) continue;
      var candidate = pick.name;
      if (candidates.indexOf(candidate) === -1) {
        if (candidates.length >= MX_MAX_CANDIDATES) continue;
        candidates.push(candidate);
      }

      var UNKNOWN_FWD = {};
      var forward = await Promise.all([
        optionalCheck(makeQuery(dohQuery, candidate, 'A', queryOpts), UNKNOWN_FWD),
        optionalCheck(makeQuery(dohQuery, candidate, 'AAAA', queryOpts), UNKNOWN_FWD),
      ]);
      var pv4 = forward[0] === UNKNOWN_FWD ? null : forward[0];
      var pv6 = forward[1] === UNKNOWN_FWD ? null : forward[1];
      if (pv4 === null && pv6 === null) continue;
      var provider = uniqueAddresses((pv4 || []).concat(pv6 || []));

      // Forward confirmation, against the address whose PTR named this
      // candidate. A PTR is authored by whoever holds the reverse zone and
      // nothing forces it to name a service, so an unconfirmed name is never
      // acted on and is never recorded as this host's provider.
      var providerKeys = provider.map(addressKey);
      if (providerKeys.indexOf(addressKey(pick.source)) === -1) continue;

      qHost.providerName = candidate;
      qHost.providerAddresses = provider;

      // Sets, not arrays: a provider publishing the same RR twice must not
      // duplicate the evidence. Strict subset only, H ⊂ P — divergence in both
      // directions is a different finding and is deferred (RQ-MXV-06).
      var hostKeys = hostAddresses.map(addressKey);
      var missing = provider.filter(function (a) { return hostKeys.indexOf(addressKey(a)) === -1; });
      var strictSubset = missing.length > 0
        && hostKeys.every(function (k) { return providerKeys.indexOf(k) !== -1; });
      if (strictSubset) {
        qHost.missingAddresses = missing;
        divergentHosts.push({ host: qHost.host, provider: candidate, missing: missing });
      }
    }

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
      // An address literal resolves to nothing, but reporting it as dangling
      // sends the operator to look for a missing address record that can never
      // exist. It has its own finding; this one stays for real dangling hosts.
      danglingHosts: hosts.filter(function (h) { return h.resolves === 'no' && !h.isAddressLiteral; })
        .map(function (h) { return h.host; }),
      addressLiteralHosts: hosts.filter(function (h) { return h.isAddressLiteral; })
        .map(function (h) { return h.host; }),
      unroutableHosts: hosts.filter(function (h) { return h.reachability === 'none'; })
        .map(function (h) { return h.host; }),
      partiallyRoutableHosts: hosts.filter(function (h) { return h.reachability === 'partial'; })
        .map(function (h) { return h.host; }),
      nullMxConflict: nullMxConflict,
      divergentHosts: divergentHosts,
      hostsWithoutReverse: hostsWithoutReverse,
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
