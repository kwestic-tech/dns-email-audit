/**
 * SPF: parsing, lookup accounting, subnet classification and redundancy.
 * Spec Design §4 and §12, Task 4.8 — the last protocol owner.
 *
 * ── The one grammar ─────────────────────────────────────────────────────
 *
 * `parseSpfTerms()` is the only SPF term parser in this repository, and Task
 * 4.0's ruling exists to keep it that way. `core/dkim/` needs the vendors a
 * domain's SPF record names in order to widen its selector scan, and §12 gives
 * a protocol directory no edge to a sibling protocol. The answer was never a
 * second parser.
 *
 * So `spfReferencedCatalogKeys()` lives HERE, with the grammar it reads, and
 * the composition root imports it and injects it into `createDkimCheck()`.
 * `checkDKIM()`'s signature is unchanged — still an SPF record string.
 *
 * **That injection is transitional, and the direction of the eventual fix is
 * recorded rather than left to be rediscovered.** Cross-protocol composition
 * belongs to the audit layer: Phase 5 derives the catalog keys there and
 * passes the derived input, and this export stops being reached across the
 * composition root. What must NOT happen in the meantime is a
 * `core/dkim → core/spf` import, which is why the helper is exported for a
 * caller that already exists rather than for a sibling that must not have it.
 *
 * ── Its own `startsWithCI` ──────────────────────────────────────────────
 *
 * Three lines, duplicated deliberately. The other reader is `analyzeDomain()`
 * in the audit layer, and §12 gives `src/audit/` no edge to `core/shared/` —
 * Task 4.0's finding 5, ruled: a genuinely audit-local helper stays local,
 * duplicated if need be, and the matrix is amended only for a real
 * architectural need. One protocol owner and one audit reader is not that.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s SPF blocks, unchanged apart from the two-space dedent, the
 * `export` keywords, and the resolver-using half becoming the body of a
 * factory. No lookup count, no classification threshold and no redundancy rule
 * moved with it.
 */

import { parseIpCidr, ipv4ToBigInt, ipv6ToBigInt } from '../shared/ip.js';

/**
 * Record selection is case-insensitive, and this is SPF's own copy.
 *
 * RFC 7208 tag names are case-insensitive, so `V=SPF1` is a valid record that a
 * case-sensitive `startsWith()` would silently discard — reporting a protected
 * domain as having none. False negatives are the worse error for a security
 * tool, so match liberally here and validate the contents later.
 */
function startsWithCI(value, prefix) {
  return String(value || '').slice(0, prefix.length).toLowerCase() === prefix.toLowerCase();
}

// locale files and in the "Show me" explainer content.
export function analyzeSpf(spf, emailProvider, multiple) {
  // RFC 7208 §4.5: more than one v=spf1 record is a permerror. SPF fails for
  // ALL mail regardless of what the records say, so this outranks every other
  // finding about the record's contents.
  if (multiple) return { status: 'permerror', cls: 'crit', warnings: ['spf-multiple-records'] };
  if (!spf) return { status: 'missing', cls: 'crit', warnings: [] };
  const warnings = [];
  const lower = spf.toLowerCase();
  if (emailProvider === 'Google Workspace' && !lower.includes('_spf.google.com') && !lower.includes('google.com')) warnings.push('spf-missing-google');
  if (emailProvider === 'Apple iCloud' && !lower.includes('icloud')) warnings.push('spf-missing-icloud');
  if (emailProvider === 'Microsoft 365' && !lower.includes('protection.outlook')) warnings.push('spf-missing-microsoft');
  if (/(?:^|\s)\+all(?:\s|$)/i.test(spf)) warnings.push('spf-all-permit');
  if (/(?:^|\s)\?all(?:\s|$)/i.test(spf)) warnings.push('spf-neutral');
  if (warnings.length) return { status: 'warn', cls: 'warn', warnings };
  if (/(?:^|\s)-all(?:\s|$)/i.test(spf)) return { status: 'ok', cls: 'ok', warnings: [] };
  if (/(?:^|\s)~all(?:\s|$)/i.test(spf)) return { status: 'softfail', cls: 'warn', warnings: ['spf-softfail'] };
  return { status: 'present', cls: 'ok', warnings: [] };
}

export function parseSpfTerms(spf) {
  return String(spf || '').trim().split(/\s+/).slice(1).map(function (raw) {
    var term = raw.toLowerCase();
    var qualifier = /^[+\-~?]/.test(term) ? term[0] : '+';
    if (qualifier !== '+') term = term.slice(1);
    var modifierAt = term.indexOf('=');
    if (modifierAt !== -1) return { raw: raw, name: term.slice(0, modifierAt), value: term.slice(modifierAt + 1), modifier: true };
    var mechanism = term.split(/[:/]/, 1)[0];
    var value = term.indexOf(':') === -1 ? '' : term.slice(term.indexOf(':') + 1).split('/')[0];
    return { raw: raw, name: mechanism, value: value, qualifier: qualifier, modifier: false };
  });
}


/* ── SPF subnet size & redundancy ───────────────────────────────────────
   Two advisory checks over the ip4:/ip6:/a/mx mechanisms written directly
   into one record: how much address space each block authorizes, and which
   a/mx mechanisms only restate something a block already covers.

   Both are deliberately ownership-blind. Whether a /20 belongs to the
   domain owner or to a shared host is not answerable over DoH, and guessing
   would be worse than saying nothing, so this reports size and leaves the
   context to the reader. That is why nothing here reaches calcScore: it is
   reported, not graded.

   Sized against live records while this was written — irs.gov, github.com,
   bbc.co.uk and cloudflare.com all publish their own large blocks and all
   land in the top tier — so the top tier is worded as "review this", not
   as a fault.
   ──────────────────────────────────────────────────────────────────────── */

/** Is `address` inside `block`? Compare only the prefix bits of each. */
export function cidrContains(block, address) {
  if (block.prefix === 0) return true;
  var shift = BigInt(block.bits - block.prefix);
  return (block.address >> shift) === (address >> shift);
}

/**
 * Severity for one authorized block, by family.
 *
 * IPv4 is judged on host count, because blocks that size really are handed
 * to single organizations: a /24 is 256 addresses and it is unusual for a
 * sender to control that much space directly.
 *
 * IPv6 must NOT reuse that table. Allocation there is tier-based, not
 * host-count-based — RFC 4291 §2.5.4 makes /64 the standard single-subnet
 * allocation, frequently one mail server — while the 2^n reasoning that
 * makes an IPv4 /24 worth a look would rate that same /64 as eighteen
 * quintillion hosts and scream about it. nih.gov publishes four of them and
 * they are entirely unremarkable, which is the whole argument for a
 * separate table.
 */
export function classifySpfSubnet(prefix, family) {
  if (family === 'ipv6') {
    if (prefix >= 64) return 'LOW';      // /64 or tighter — one subnet at most
    if (prefix >= 48) return 'MEDIUM';   // multi-subnet / small site block
    return 'HIGH';                       // /47 and shorter — ISP/RIR scale
  }
  if (prefix >= 29) return 'LOW';        // 1–8 addresses
  if (prefix >= 25) return 'MEDIUM';     // 9–128 addresses
  return 'HIGH';                         // /24 and shorter — 256+
}

var SPF_IP_MECHANISM = /^(ip4|ip6):(.+)$/i;
// `a` and `mx`, with the optional host and the optional dual-CIDR suffix
// RFC 7208 §5.3 allows on both: a, mx, a:host, mx:host, a/24, mx:host//64.
var SPF_HOST_MECHANISM = /^(a|mx)(?::([^/]+))?((?:\/\/?\d+)*)$/i;

export function stripSpfQualifier(raw) {
  var text = String(raw || '');
  return /^[+\-~?]/.test(text) ? text.slice(1) : text;
}

/**
 * Classify every ip4:/ip6: block in a record. Pure — no DNS, never throws.
 *
 * Split out from the redundancy half deliberately: a resolver failure
 * during redundancy resolution must not take the size findings down with
 * it, and these need no network at all.
 */
export function classifySpfSubnets(spf) {
  var blocks = { ipv4: [], ipv6: [] };
  var subnets = [];
  String(spf || '').trim().split(/\s+/).slice(1).forEach(function (raw) {
    var match = SPF_IP_MECHANISM.exec(stripSpfQualifier(raw));
    if (!match) return;
    var family = match[1].toLowerCase() === 'ip6' ? 'ipv6' : 'ipv4';
    var block = parseIpCidr(match[2], family);
    // A malformed mechanism drops itself out of the audit instead of
    // aborting it — the rest of the record is still worth reporting on.
    if (!block) return;
    blocks[family].push({ mechanism: raw, block: block });
    subnets.push({
      type: 'SPF_LARGE_SUBNET',
      severity: classifySpfSubnet(block.prefix, family),
      mechanism: raw,
      family: family,
      prefix: block.prefix,
    });
  });
  return { subnets: subnets, blocks: blocks };
}




//
// Each hostname below is the vendor's documented SPF include target, and was
// confirmed to serve a live `v=spf1` record when this table was written.
// Keys must match DKIM_CATALOG.providers exactly.
var DKIM_SPF_INCLUDE_PROVIDERS = [
  { pattern: /(^|\.)mail\.zendesk\.com$/i, catalogKey: 'Zendesk' },
  { pattern: /(^|\.)sendgrid\.net$/i, catalogKey: 'Twilio SendGrid' },
  { pattern: /(^|\.)mailgun\.org$/i, catalogKey: 'Mailgun' },
  { pattern: /(^|\.)servers\.mcsv\.net$/i, catalogKey: 'Mailchimp / Mandrill' },
  { pattern: /(^|\.)mandrillapp\.com$/i, catalogKey: 'Mailchimp / Mandrill' },
  { pattern: /(^|\.)spf\.mtasv\.net$/i, catalogKey: 'Postmark (ActiveCampaign)' },
  { pattern: /(^|\.)cust-spf\.exacttarget\.com$/i, catalogKey: 'Salesforce / Marketing Cloud' },
  { pattern: /(^|\.)hubspot(email)?\.(com|net)$/i, catalogKey: 'HubSpot' },
  { pattern: /(^|\.)atlassian\.net$/i, catalogKey: 'Atlassian Jira / Service Desk' },
  { pattern: /(^|\.)freshdesk\.com$/i, catalogKey: 'Freshdesk / Freshworks' },
];

// Only the literal include:/redirect= hostnames of the domain's own record
// count. Following an included record into its own includes would attribute
// the vendor's upstream to the audited domain — freshdesk.com's SPF includes
// sendgrid.net, which says nothing about who signs the domain's mail — and
// would cost DNS lookups this function deliberately does not make.
export function spfReferencedCatalogKeys(spf) {
  var keys = new Set();
  if (!spf) return keys;
  parseSpfTerms(spf).forEach(function (term) {
    if (term.modifier ? term.name !== 'redirect' : term.name !== 'include') return;
    // A macro can't be reduced to a literal hostname, so there is nothing to
    // match — the same treatment countSpfLookups() gives it.
    if (!term.value || term.value.indexOf('%{') !== -1) return;
    var host = term.value.replace(/\.$/, '');
    DKIM_SPF_INCLUDE_PROVIDERS.forEach(function (entry) {
      if (entry.pattern.test(host)) keys.add(entry.catalogKey);
    });
  });
  return keys;
}

/**
 * The resolver-driven half: lookup accounting and redundancy.
 *
 * Capabilities are arguments — §12 gives a protocol directory no edge to
 * `core/dns/`. `dohQuery` is layer 3 for the ordinary lookups;
 * `countSpfLookups()` walks with the raw `dohFetch` and applies
 * `requireUsable` itself, because it filters answers by type and keeps the
 * TXT records that begin `v=spf1` — a void lookup (a name that answers with no
 * SPF record) is counted differently from one that failed, and layer 3 hands
 * back the same empty array for both.
 *
 * **This module states no unknown of its own.** `countSpfLookups()` THROWS on
 * a resolver failure, and the caller's `optionalCheck()` fallback factory is
 * what copies `DnsError.kind` onto `advanced.spfLookups.queryError` — one of
 * the eleven typed propagation paths. The fallback owns the shape of the
 * unknown; spec §3 is explicit, and `spf.test.js` asserts the throw rather
 * than a degraded return.
 */
export function createSpfChecks(capabilities) {
  // Destructured in the BODY, matching core/dnssec and core/dkim: a
  // destructured PARAMETER is not a declaration to platform.test.mjs's
  // lexical ambient scan.
  const { dohQuery, dohFetch, requireUsable, cleanAnswerData } = capabilities;

  async function countSpfLookups(spf, domain, queryOpts) {
    var visited = new Set();
    var cycles = [];
    var voidLookups = 0;
    var indeterminate = false;

    async function walk(record, recordDomain, depth) {
      if (depth > 20) { indeterminate = true; return 0; }
      var terms = parseSpfTerms(record);
      var count = 0;
      for (var i = 0; i < terms.length; i++) {
        var term = terms[i];
        var causesLookup = (!term.modifier && ['include', 'a', 'mx', 'ptr', 'exists'].includes(term.name)) ||
          (term.modifier && term.name === 'redirect');
        if (!causesLookup) continue;
        count++;

        if ((term.name === 'include' || term.name === 'redirect') && term.value) {
          if (term.value.includes('%{')) { indeterminate = true; continue; }
          var child = term.value.toLowerCase().replace(/\.$/, '');
          var edge = recordDomain + '>' + child;
          if (visited.has(edge)) { cycles.push(child); continue; }
          visited.add(edge);
          var result = requireUsable(await dohFetch(child, 'TXT', queryOpts), child, 'TXT');
          var txts = result.answers.filter(function (a) { return a.type === 16; })
            .map(function (a) { return cleanAnswerData(a.data, 'TXT'); });
          var records = txts.filter(function (v) { return startsWithCI(v, 'v=spf1'); });
          if (!records.length) { voidLookups++; continue; }
          if (records.length > 1) { indeterminate = true; continue; }
          count += await walk(records[0], child, depth + 1);
        }
      }
      return count;
    }

    var count = await walk(spf, domain, 0);
    return {
      count: count,
      warning: count >= 8 && count <= 10,
      error: count > 10 || voidLookups > 2,
      voidLookups: voidLookups,
      cycles: cycles,
      indeterminate: indeterminate,
    };
  }

  /**
   * Find a/mx mechanisms whose resolved addresses an ip4:/ip6: block in the
   * same record already authorizes.
   *
   * Costs no DNS at all unless the record contains at least one ip4:/ip6:
   * block — with no block present nothing can be contained in one, so the
   * whole resolution phase is skipped. That keeps records built purely from
   * include: (google.com, apple.com, most of the sample) free.
   *
   * Scope is one record: nested IPs inside include: are not followed, and
   * ptr: is ignored outright (RFC 7208 §5.5 discourages its use).
   */
  async function findSpfRedundancy(spf, domain, blocks, queryOpts) {
    if (!blocks.ipv4.length && !blocks.ipv6.length) return [];

    var mechanisms = [];
    String(spf || '').trim().split(/\s+/).slice(1).forEach(function (raw) {
      var match = SPF_HOST_MECHANISM.exec(stripSpfQualifier(raw));
      // A dual-CIDR suffix widens the mechanism beyond the addresses it
      // resolves to — `mx/24` authorizes a /24 around every MX host — so
      // containment of the bare addresses would not prove it redundant.
      if (!match || match[3]) return;
      mechanisms.push({
        mechanism: raw,
        name: match[1].toLowerCase(),
        host: (match[2] || '').toLowerCase().replace(/\.$/, ''),
      });
    });

    var findings = [];
    var seen = new Set();
    for (var i = 0; i < mechanisms.length; i++) {
      var mech = mechanisms[i];
      // Bare `a`/`mx` and `a:host`/`mx:host` are separate checks, so the key
      // is the mechanism as written, not the name it happens to resolve.
      var key = mech.name + ':' + mech.host;
      if (seen.has(key)) continue;
      seen.add(key);

      var targets;
      if (mech.host) {
        targets = [mech.host];
      } else if (mech.name === 'a') {
        targets = [domain];
      } else {
        var mxRecords = await dohQuery(domain, 'MX', queryOpts);
        targets = mxRecords.map(function (record) {
          var parts = String(record).trim().split(/\s+/);
          return parts[parts.length - 1].replace(/\.$/, '').toLowerCase();
        }).filter(function (name) { return name && name !== '.'; });  // null MX authorizes nothing
      }

      var resolved = [];
      for (var j = 0; j < targets.length; j++) {
        var answers = await Promise.all([
          dohQuery(targets[j], 'A', queryOpts),
          dohQuery(targets[j], 'AAAA', queryOpts),
        ]);
        answers[0].forEach(function (text) { resolved.push({ family: 'ipv4', text: text }); });
        answers[1].forEach(function (text) { resolved.push({ family: 'ipv6', text: text }); });
      }
      if (!resolved.length) continue;

      var coveredBy = [];
      var covered = 0;
      resolved.forEach(function (entry) {
        var address = entry.family === 'ipv6' ? ipv6ToBigInt(entry.text) : ipv4ToBigInt(entry.text);
        if (address === null) return;
        // Families never cross-check: an IPv4 address is tested only against
        // ip4: blocks and an IPv6 address only against ip6:.
        var hit = blocks[entry.family].find(function (candidate) {
          return cidrContains(candidate.block, address);
        });
        if (!hit) return;
        covered++;
        if (coveredBy.indexOf(hit.mechanism) === -1) coveredBy.push(hit.mechanism);
      });

      if (!covered) continue;
      findings.push({
        type: 'SPF_REDUNDANCY',
        severity: 'LOW',
        mechanism: mech.mechanism,
        covered: covered,
        total: resolved.length,
        // This equality *is* the dual-stack rule: `full` requires every
        // resolved address in both families to have matched a same-family
        // block. A hostname with an AAAA record in a record carrying no ip6:
        // mechanism can never reach it, so "remove this" can never be advice
        // that silently drops IPv6 authorization.
        full: covered === resolved.length,
        coveredBy: coveredBy,
      });
    }
    return findings;
  }

  async function auditSpfSubnets(spf, domain, queryOpts) {
    var classified = classifySpfSubnets(spf);
    var redundancy = await findSpfRedundancy(spf, domain, classified.blocks, queryOpts);
    return { subnets: classified.subnets, redundancy: redundancy, unknown: false };
  }

  return { countSpfLookups, findSpfRedundancy, auditSpfSubnets };
}
