/**
 * External report authorization (RFC 9989 §5.6, RFC 9990 §3.5). Spec §12,
 * Task 4.6.
 *
 * Sending reports to a domain you do not control requires the RECEIVING domain
 * to publish `<source>._report._dmarc.<destination>`. Until it does,
 * conformant receivers discard those reports — so the operator gets silence
 * and assumes everything is fine. That is the whole reason this check exists,
 * and why it is kept out of `record.js`, which stays pure and
 * domain-agnostic.
 *
 * ── A named raw-kind reader ─────────────────────────────────────────────
 *
 * `checkExternalReportAuth()` is one of spec §3's six allowed raw-kind
 * readers, moved here from `js/dns.js` by Task 4.6. It keeps the EXACT
 * response kind on `exactKind` — `success`, `nodata` or `nxdomain`, three
 * reachable members — and converts failed kinds at the protocol boundary.
 *
 * Like `discoverDmarc()`, it **inlines the usability gate** rather than
 * calling `requireUsable()`, and its `catch` is internal under a static `[]`
 * fallback rather than an `optionalCheck()` fallback factory. Both are
 * deliberate, both are unchanged, and spec §3 asserts them as three distinct
 * mechanisms.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s report-authorization block, unchanged apart from the two-space
 * dedent, the `export` keywords, and the two async functions becoming the body
 * of a factory that names its capabilities.
 */

import {
  emptyDmarcStatus, parseDmarcTag, parseDmarcUriList, validateDmarcVersion,
} from './record.js';

/** `checkExternalReportAuth()[].state`. Registry algebra `dmarc.reportAuth.state`. */
export const REPORT_AUTH_STATES = Object.freeze([
  'authorized', 'unauthorized', 'unverifiable', 'override-mismatch',
]);

/**
 * `checkExternalReportAuth()[].exactKind`. Registry algebra
 * `dmarc.reportAuth.exactKind`.
 *
 * THREE members, not the two the corpus had been observed to produce before
 * spec 1.6. The inline usability gate admits `success`, `nodata` and
 * `nxdomain` alike, so an absent authorization name reaches the unauthorized
 * branch carrying its kind. Defining a two-member algebra from corpus
 * observation would be the same mistake as an empty `resultPaths` list.
 */
export const REPORT_AUTH_EXACT_KINDS = Object.freeze(['success', 'nodata', 'nxdomain']);

/** `checkExternalReportAuth()[].via`. Registry algebra `dmarc.reportAuth.via`. */
export const REPORT_AUTH_VIA = Object.freeze(['null', 'exact']);

/**
 * Report destinations outside the audited domain's organizational domain.
 *
 * RFC 9989 §5.6: sending reports to a domain you do not control requires the
 * receiving domain to publish `<source>._report._dmarc.<destination>`. Until
 * it does, conformant receivers discard those reports — so the operator gets
 * silence and assumes everything is fine. Kept separate from analyzeDmarc so
 * that function stays pure and domain-agnostic.
 */
/** Every report destination host a record names, in RFC 9990 §3.5's order. */
export function reportDestinationHosts(dmarcStatus) {
  var seen = new Set();
  return []
    .concat(dmarcStatus && dmarcStatus.ruaUris ? dmarcStatus.ruaUris.domains : [])
    .concat(dmarcStatus && dmarcStatus.rufUris ? dmarcStatus.rufUris.domains : [])
    .filter(function (dest) {
      if (!dest || seen.has(dest)) return false;
      seen.add(dest);
      return true;
    });
}

/**
 * Decide which destinations this audit will examine, and record how many it
 * declined to.
 *
 * The truncation is surfaced rather than silent: showing ten verdicts for a
 * record naming twenty destinations would imply every URI had been checked,
 * which is the same "unknown presented as known" error this codebase refuses
 * everywhere else.
 */
export function planReportDestinations(dmarcStatus, policyDomain, orgDomains) {
  var all = reportDestinationHosts(dmarcStatus);
  var checked = all.slice(0, MAX_REPORT_DESTINATIONS);
  return {
    external: findExternalReportDestinations(dmarcStatus, policyDomain, orgDomains, checked),
    total: all.length,
    omitted: all.slice(MAX_REPORT_DESTINATIONS),
  };
}

export function findExternalReportDestinations(dmarcStatus, policyDomain, orgDomains, hosts) {
  if (!dmarcStatus || !policyDomain) return [];
  // RFC 9990 §4 defines the externality test against the ORGANIZATIONAL
  // DOMAIN on both sides, which after this release means the Tree Walk
  // result rather than the Public Suffix List. `orgDomains` carries the
  // walked answers; an absent entry falls back to the name itself, which is
  // the §4.10.2 fallback and never the PSL.
  var lookup = function (name) {
    var found = orgDomains && (typeof orgDomains.get === 'function' ? orgDomains.get(name) : orgDomains[name]);
    return found || name;
  };
  var org = lookup(policyDomain);
  return (hosts || reportDestinationHosts(dmarcStatus)).filter(function (dest) {
    return dest !== org && lookup(dest) !== org;
  });
}

/**
 * Parse one external-authorization TXT record per RFC 9990 §4 step 6.
 *
 * > For each record returned, parse the result as a series of "tag=value"
 * > pairs, i.e., the same overall format as the DMARC Policy Record (see
 * > Section 4.7 of [RFC9989]).  In particular, the "v=DMARC1" tag is
 * > mandatory and MUST appear first in the list.  Discard any that do not
 * > pass this test.  A trailing ";" is optional.
 *
 * The `v=DMARC1` test is necessary and NOT sufficient: "parse the result as
 * a series of tag=value pairs" is part of the same step, so a record whose
 * remaining syntax is not tag=value must be discarded before step 8 counts
 * the survivors. Checking only the version tag accepted
 * `v=DMARC1; this-is-not-a-tag-value-pair` as an authorization.
 *
 * Step 9 lets the Report Consumer override the report destination, but "the
 * overriding URI MUST use the same destination host from the first step".
 * This tool never sends reports, so the override changes no verdict — it is
 * captured because an "authorized" result that silently dropped it would be
 * incomplete evidence about where conformant receivers actually deliver.
 */
export function parseReportAuthRecord(record, destinationHost) {
  var text = String(record || '');
  if (!validateDmarcVersion(text).valid) return { valid: false, reason: 'version' };
  var segments = text.split(';');
  // "A trailing ';' is optional" — so one empty tail segment is allowed, but
  // an empty segment anywhere else is a syntax error rather than a courtesy.
  if (segments.length && segments[segments.length - 1].trim() === '') segments.pop();
  var wellFormed = segments.every(function (segment) {
    return /^\s*[A-Za-z][A-Za-z0-9_-]*\s*=\s*[^;]*$/.test(segment);
  });
  if (!wellFormed) return { valid: false, reason: 'syntax' };

  var rua = parseDmarcTag(text, 'rua');
  var override = null;
  var overrideValid = true;
  var overrideReason = null;
  if (rua !== null) {
    var parsed = parseDmarcUriList(rua);
    var hosts = parsed.uris.filter(function (u) { return u.valid; }).map(function (u) { return u.domain; });
    override = rua;
    /* Step 9 lets the Report Consumer override the destination, but "the
       overriding URI MUST use the same destination host from the first
       step", and the paragraph after the algorithm says what a violation
       costs:

       > Further, if the confirming record includes a URI whose host is again
       > different than the domain publishing that override, the Mail
       > Receiver generating the report MUST NOT generate a report to either
       > the original or the override URI.

       So a cross-host override does not merely void itself — it makes the
       whole arrangement unusable, and neither URI receives anything. That is
       a different fact from "the destination never authorized you", and it
       has a different fix, so it gets its own state rather than being folded
       into `unauthorized`.

       A merely malformed override is not the same case. RFC 9990 §3.5 says
       of reporting URIs that "if any of the URIs are malformed, they SHOULD
       be ignored" — ignored, not escalated — so the authorization stands and
       the override is dropped. */
    if (parsed.count > 0 && hosts.length && !hosts.every(function (h) { return h === destinationHost; })) {
      overrideValid = false;
      overrideReason = 'cross-host';
    } else if (!parsed.valid || parsed.count === 0) {
      overrideValid = false;
      overrideReason = 'malformed';
    }
  }
  return {
    valid: true, reason: null,
    override: override, overrideValid: overrideValid, overrideReason: overrideReason,
  };
}

/**
 * Resolve the Organizational Domain of every candidate report destination
 * with a Tree Walk, so the externality test in RFC 9990 §4 is answered by
 * DNS rather than by the vendored Public Suffix List.
 *
 * This is the query cost `OQ-DMARC-04` accepted knowingly: the externality
 * test now walks the destination's tree as well as the audited domain's. The
 * dohFetch() cache absorbs most of it across a run, because report
 * destinations repeat heavily (a few reporting vendors serve most domains).
 * A destination that already equals the policy domain's Organizational
 * Domain is settled by string comparison and never walked.
 */
// A record's rua=/ruf= list is written by whoever controls the domain being
// audited, and parseDmarcUriList() caps nothing — so without a bound here the
// query count for one audit is set by that record's own content.
//
// The bound has to cover the WHOLE destination-driven workflow. Capping only
// the Organizational Domain walks left the authorization lookups uncapped, so
// twenty destinations still produced forty authorization queries and the
// "bound" was not one. RFC 9990 §3.5 sanctions a limit explicitly — reports
// go to every URI "up to the Receiver's limits on supported URIs" — and fixes
// the order to apply it in: receivers "MUST evaluate the provided reporting
// URIs (see [RFC9989]) in the order given".
var MAX_REPORT_DESTINATIONS = 10;

/**
 * The report-authorization checks, over a passed resolver.
 *
 * `dohFetch` is the RAW handle — `checkExternalReportAuth()` keeps the exact
 * response kind, which layer 2 throws away — plus `dnsError` for cancellation,
 * `cleanAnswerData` for the TXT answers it kept, `optionalCheck` for the
 * per-destination walk, and ONE collaborator: `discoverDmarc`, from a factory
 * the caller has already built.
 *
 * `getOrganizationalDomain` is deliberately NOT here. It was accepted, passed
 * and documented in the Task 4.6 extraction and never read — the destination
 * org domains this module resolves come from `discoverDmarc()`'s own walk, not
 * from the PSL. A capability that is declared and unused is a false statement
 * about what a module can reach, so it is gone. `org-domain.js` and its
 * runtime construction are untouched; PSL retirement is a separately recorded
 * finding and is not this.
 */
export function createReportAuth({
  dohFetch, dnsError, cleanAnswerData, optionalCheck, discoverDmarc,
}) {

  async function resolveDestinationOrgDomains(dmarcStatus, policyDomain, policyOrgDomain, queryOpts) {
    var orgDomains = new Map();
    orgDomains.set(policyDomain, policyOrgDomain);
    var candidates = reportDestinationHosts(dmarcStatus)
      .slice(0, MAX_REPORT_DESTINATIONS)
      .filter(function (dest) { return dest !== policyOrgDomain; });
    await Promise.all(candidates.map(async function (dest) {
      var discovery = await optionalCheck(function () { return discoverDmarc(dest, queryOpts); }, null);
      // A walk that failed leaves the destination's Organizational Domain
      // unknown. Falling back to the name itself keeps the comparison honest:
      // it can only ever make the destination look external, which produces a
      // "verify this" notice rather than a silent pass.
      orgDomains.set(dest, (discovery && discovery.organizationalDomain) || dest);
    }));
    return orgDomains;
  }

  /**
   * Verify that each external report destination has authorized this domain.
   *
   * RFC 9990 §4: when a destination's organizational domain differs from the
   * policy domain's, the receiver queries
   *
   *   <policy-domain>._report._dmarc.<destination-host>
   *
   * and requires a TXT record whose FIRST tag is `v=DMARC1`. A wildcard form,
   * `*._report._dmarc.<destination-host>`, authorizes every domain at once and
   * is what most reporting vendors publish rather than a record per customer.
   *
   * Authorization is evaluated per URI: an unauthorized destination is dropped
   * on its own. It does not invalidate the DMARC record and it does not affect
   * the other destinations, which is why this returns a verdict per destination
   * rather than one verdict for the record.
   *
   * A DNS failure is reported as 'unverifiable' rather than 'unauthorized' —
   * a timeout is not evidence of a missing record, and calling it one would
   * send someone chasing a vendor over our own flaky lookup.
   */

  async function checkExternalReportAuth(domain, destinations, queryOpts) {
    var policyDomain = String(domain || '').toLowerCase().replace(/\.$/, '');
    var unique = [];
    var seen = new Set();
    (destinations || []).forEach(function (d) {
      var host = String(d || '').toLowerCase().replace(/\.$/, '');
      if (host && !seen.has(host)) { seen.add(host); unique.push(host); }
    });

    return Promise.all(unique.map(async function (host) {
      var exact = policyDomain + '._report._dmarc.' + host;
      // RFC 9990 §4 step 4: "If the length of the constructed name exceed DNS
      // limits, a positive determination of the external reporting
      // relationship cannot be made; stop." Cannot-determine and
      // not-authorized are different facts.
      if (exact.length > 253) {
        return {
          destination: host, state: 'unverifiable', via: null, queryName: exact,
          record: '', error: 'name-too-long',
        };
      }
      try {
        /* RFC 9990 §4 constructs and queries exactly ONE name (steps 2, 3 and
           5). A Report Consumer willing to receive reports for any domain
           publishes `*._report._dmarc.<host>`, and the resolver synthesizes
           that RRset while answering this query — there is no second lookup to
           make. Querying the asterisk owner literally is not the algorithm and
           gets a different question answered: RFC 4592 §2.3 is explicit that
           "when a wildcard domain name appears in a message's query section, no
           special processing occurs", so such a query retrieves the literal
           wildcard node rather than exercising synthesis.

           That distinction changes verdicts, which is why this is not merely a
           saved query. Wildcard synthesis is suppressed when the queried name
           already exists, so a destination whose exact owner holds unrelated or
           malformed TXT data is NOT authorized under RFC 9990 — while a
           literal wildcard lookup would find `v=DMARC1` and wrongly authorize
           it. Verified against three live reporting vendors: the constructed
           query already returns the synthesized answer. */
        var response = await dohFetch(exact, 'TXT', queryOpts);
        if (response.kind === 'cancelled') throw dnsError('cancelled', exact, 'TXT');
        if (response.kind !== 'success' && response.kind !== 'nodata' && response.kind !== 'nxdomain') {
          throw dnsError(response.kind, exact, 'TXT', response.httpStatus ? 'HTTP ' + response.httpStatus : '');
        }
        var records = response.answers.filter(function (a) { return a.type === 16; })
          .map(function (a) { return cleanAnswerData(a.data, 'TXT'); });
        var parsed = records.map(function (r) { return parseReportAuthRecord(r, host); });
        var authorizedAt = parsed.findIndex(function (p) { return p.valid; });

        /* Step 8, verbatim: "If at least one TXT resource record remains in the
           set after parsing, then the external reporting arrangement was
           authorized by the Report Consumer."

           Permissive, and deliberately the opposite of the DMARC policy
           duplicate rule in discoverDmarc(), where RFC 9989 §4.10 step 2
           discards every record when more than one is returned. The two
           questions are asked at different names, for different purposes, by
           different RFCs, and they answer them differently. Do not "fix"
           either one to match the other. */
        if (authorizedAt !== -1) {
          var winner = parsed[authorizedAt];
          // An arrangement whose override points at a third party is not a
          // usable reporting destination: conformant receivers send to neither
          // URI. Reporting it as `authorized` would tell the operator their
          // reports are flowing when nothing is being sent at all.
          var crossHost = winner.overrideReason === 'cross-host';
          return {
            destination: host,
            state: crossHost ? 'override-mismatch' : 'authorized',
            via: 'exact', queryName: exact,
            record: records[authorizedAt],
            recordCount: parsed.filter(function (p) { return p.valid; }).length,
            exactKind: response.kind,
            override: winner.override || null,
            overrideValid: winner.override ? winner.overrideValid : null,
            overrideReason: winner.overrideReason || null,
          };
        }
        // A TXT record that exists but does not parse authorizes nothing —
        // worth distinguishing from nothing at all, because it usually means a
        // truncated or hand-mangled record.
        return {
          destination: host, state: 'unauthorized', via: null, queryName: exact,
          record: records[0] || '', malformed: records.length > 0,
          exactKind: response.kind,
        };
      } catch (e) {
        if (e && e.name === 'AbortError') throw e;
        return { destination: host, state: 'unverifiable', via: null, queryName: exact, record: '', error: e && e.kind };
      }
    }));
  }

  return { resolveDestinationOrgDomains, checkExternalReportAuth };
}
