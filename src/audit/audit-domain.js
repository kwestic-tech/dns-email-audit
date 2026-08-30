/**
 * The audit coordinator. Spec Design §5, implementation Task 5.2.
 *
 * `analyzeDomain()` owns WHICH checks run, in what order, which may run
 * concurrently, how a failure is isolated, and how the answers become one
 * result. It parses nothing: every rule about what a record MEANS belongs to a
 * `core/<protocol>/` owner, and this file reads their answers.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s `analyzeDomain()`, its three audit-local helpers and
 * `resolveWebsite()`, at the same indentation and in the same order. **The
 * `Promise.all` structure is byte-identical** — the four core lookups, the
 * two wildcard probes, the eight advanced checks and the DKIM scan batch are
 * exactly the concurrency `v0.5.0` had. Spec §35 and the implementation plan
 * both forbid changing concurrency and moving code in the same phase, and this
 * release changes it nowhere.
 *
 * ── What is imported, and what is passed ────────────────────────────────
 *
 * §12 gives `src/audit/` an edge to `core/<protocol>/`, `providers/` and its
 * own siblings — and NOT to `core/dns/`. So the split is not a style choice:
 *
 * | Reached by import | Passed as a capability |
 * | --- | --- |
 * | The PURE protocol functions — `analyzeSpf`, `analyzeDmarc`, `applyInheritance`, the three record validators, `isNullMx`, `classifySpfSubnets`, `planReportDestinations` | Everything built over the resolver — `dohFetch`, `dohQuery`, `requireUsable`, `optionalCheck`, and every protocol check constructed with them |
 * | The sibling `context.js` | `existenceFromResponse`, which is `core/dns/`'s and cannot be imported here |
 *
 * Injecting a pure function would be a false capability; importing a resolver
 * would be a forbidden edge. Each of the two lists is the other's answer.
 *
 * ── The four audit members this file does not own yet ───────────────────
 *
 * `buildIssues`, `buildSuggestions`, `calcScore` and `calcAdvScore` are
 * `audit/` siblings that have not been extracted. They arrive as arguments
 * until Tasks 5.3 and 5.4 move them here, and then become imports. They are
 * listed apart in the destructuring below so the temporary set is visible
 * rather than mixed in with the resolver's.
 *
 * ── The one raw-kind read ───────────────────────────────────────────────
 *
 * The NS `servfail` DNSSEC preflight reads `nsResult.kind` directly, which is
 * spec §3's audit-owned exception edge. It was the last raw-kind reader
 * outside an owning directory; `tests/contract/transport-edges.test.mjs` names
 * it by owner and now locates it in this file.
 */
import { createAuditContext } from './context.js';
import { isNullMx } from '../core/mx/mx.js';
import { validateBimiRecord } from '../core/bimi/bimi.js';
import { validateMtaStsRecord } from '../core/transport/mta-sts.js';
import { validateTlsRptRecord } from '../core/transport/tls-rpt.js';
import { analyzeSpf, classifySpfSubnets, spfReferencedCatalogKeys } from '../core/spf/spf.js';
import { analyzeDmarc, emptyDmarcStatus } from '../core/dmarc/record.js';
import { applyInheritance } from '../core/dmarc/tree-walk.js';
import { planReportDestinations } from '../core/dmarc/report-auth.js';

// Record selection must be case-insensitive. RFC 7489 and RFC 7208 tag names
// are case-insensitive, so `V=DMARC1` and `V=SPF1` are valid records that a
// case-sensitive startsWith() would silently discard — reporting a protected
// domain as having no policy at all. False negatives are the worse error for
// a security tool, so match liberally here and validate the contents later.
export function startsWithCI(value, prefix) {
  return String(value || '').slice(0, prefix.length).toLowerCase() === prefix.toLowerCase();
}
/**
 * Build the coordinator over this runtime's resolver and protocol checks.
 *
 * Capabilities are destructured in the BODY rather than in the parameter list:
 * `platform.test.mjs`'s ambient scan does not recognize a destructured factory
 * parameter as a declaration, and `core/dns/doh.js` set the pattern.
 */
export function createAuditDomain(capabilities) {
  const {
    // The resolver handle. §12: passed, never imported.
    dohFetch, dohQuery, requireUsable, optionalCheck, existenceFromResponse,
    // Protocol checks, each already constructed over that resolver.
    checkDNSSEC, checkCAA, checkTlsa, auditMxHosts, checkDKIM,
    discoverDmarc, resolveDestinationOrgDomains, checkExternalReportAuth,
    countSpfLookups, auditSpfSubnets,
    // Provider detection.
    detectDNSProvider, detectEmailProvider, detectHosting,
    // TEMPORARY — audit siblings awaiting Tasks 5.3 and 5.4, then imports.
    buildIssues, buildSuggestions, calcScore, calcAdvScore,
  } = capabilities;

  /**
   * Records at a protocol's dedicated owner that MENTION its version field.
   *
   * Recognition is case-insensitive and order-independent on purpose, while
   * validation stays exact. That is the point: a record has to be recognizable
   * as a candidate before it can be diagnosed as a malformed one.
   */
  function versionCandidates(records, token) {
    var pattern = new RegExp('(^|;)\\s*v\\s*=\\s*' + token + '\\s*(;|$)', 'i');
    return (records || []).filter(function (record) { return pattern.test(String(record || '')); });
  }

  /** Records a conforming sender keeps before applying the full validator. */
  function leadingVersionMatches(records, token) {
    // The version literal itself is exact and case-sensitive. The delimiter,
    // however, is `*WSP ";" *WSP` in MTA-STS/TLS-RPT (and tolerated by the
    // BIMI parser), so valid whitespace before the semicolon must not make a
    // sender-compatible record disappear from the effective set.
    var pattern = new RegExp('^v=' + token + '[ \\t]*(?:;|$)');
    return (records || []).filter(function (record) { return pattern.test(String(record || '')); });
  }

  async function resolveWebsite(domain, queryOpts) {
    var current = 'www.' + domain;
    var visited = new Set();
    var chain = [];
    for (var depth = 0; depth < 12; depth++) {
      if (visited.has(current)) return { loop: true, chain: chain, addresses: [] };
      visited.add(current);
      var result = requireUsable(await dohFetch(current, 'CNAME', queryOpts), current, 'CNAME');
      var cnames = result.answers.filter(function (a) { return a.type === 5; })
        .map(function (a) { return a.data.replace(/\.$/, '').toLowerCase(); });
      if (!cnames.length) {
        var addresses = await Promise.all([dohQuery(current, 'A', queryOpts), dohQuery(current, 'AAAA', queryOpts)]);
        return { loop: false, chain: chain, addresses: addresses[0].concat(addresses[1]) };
      }
      current = cnames[0];
      chain.push(current);
    }
    return { loop: true, chain: chain, addresses: [] };
  }

  /* ── Orchestrated per-domain audit ──────────────────────────────────── */

  async function analyzeDomain(domain, opts) {
    // Task 5.1. The state that belongs to THIS audit — the options in force,
    // the query options they produce, and the result being accumulated — is
    // the context's. Everything else below is still this function's, including
    // the Promise.all structure Task 5.2 moves. `queryOpts` keeps its name, so
    // no query call site changed.
    const ctx = createAuditContext({ domain, options: opts });
    const d = ctx.domain;
    let queryOpts = ctx.queryOptions;
    let dnssecPreflight = null;

    // Probe NS first — NXDOMAIN (Status 3) means the domain isn't registered
    let nsResult = await dohFetch(d, 'NS', queryOpts);
    // A validating resolver deliberately returns SERVFAIL for a bogus chain.
    // Treating that like an ordinary core-query failure made the critical
    // `dnssec-bogus` finding unreachable in the application: the audit threw
    // here before the DNSSEC classifier ran. When advanced checks are enabled,
    // establish that verdict first and, only for a confirmed bogus chain,
    // retrieve the remaining diagnostic records with checking disabled. The
    // DNSSEC result still comes from the validating query; cd=1 merely lets the
    // rest of the row exist so the operator can see the failure and its data.
    if (nsResult.kind === 'servfail' && ctx.options.advanced) {
      dnssecPreflight = await checkDNSSEC(d, queryOpts);
      if (dnssecPreflight.state === 'bogus') {
        queryOpts = ctx.disableDnssecChecking();
        nsResult = await dohFetch(d, 'NS', queryOpts);
      }
    }
    requireUsable(nsResult, d, 'NS');
    const ns = nsResult.answers.filter(a => a.type === 2).map(a => a.data.replace(/^"|"$/g, '').trim());
    if (nsResult.status === 3) {
      ctx.record({ unregistered: true, error: false });
      return ctx.result();
    }

    const [mx, txt, aRec, aaaaRec] = await Promise.all([
      dohQuery(d, 'MX', queryOpts),
      dohQuery(d, 'TXT', queryOpts),
      dohQuery(d, 'A', queryOpts),
      dohQuery(d, 'AAAA', queryOpts),
    ]);

    const dnsProvider = detectDNSProvider(ns, d);
    const emailProvider = detectEmailProvider(mx, d, aRec.concat(aaaaRec));
    // Count matches rather than .find() — every one of these record types
    // fails closed when more than one exists (see the multiple-record checks
    // in buildIssues), so the count is part of the signal, not noise.
    const spfMatches = txt.filter(v => startsWithCI(v, 'v=spf1'));
    const spfRecord = spfMatches[0] || '';
    const spfMultiple = spfMatches.length > 1;
    // Every matching record is kept, not just the first. `spfRecord` alone made
    // `spf-multiple-records` an unevidenced accusation: the finding is critical
    // and correct, and the panel beside it showed one perfectly valid record,
    // because the second was discarded here and existed nowhere in the result.
    // An operator could not see which records conflicted or where to look, and
    // the honest conclusion from that screen is that the tool is wrong.
    const spfRecords = spfMatches;
    const spfStatus = analyzeSpf(spfRecord, emailProvider, spfMultiple);
    const verifications = txt.filter(v => startsWithCI(v, 'google-site-verification') || startsWithCI(v, 'apple-domain'));

    // RFC 9989 §4.10 Tree Walk. This replaces the two-query PSL approximation:
    // one query at _dmarc.<domain>, and on a miss one more at the name the
    // vendored Public Suffix List picked. No DMARC decision consults the PSL
    // after this release (OQ-DMARC-04); the vendored list stays only for the
    // hosting and provider heuristics.
    const dmarcDiscovery = await discoverDmarc(d, queryOpts, { apexTxt: txt });
    // §3.2.13 and Appendix A.4: existence is a property of the name. The NS
    // response above already answers it — NXDOMAIN returned early as
    // unregistered, so anything reaching here resolved without one — so this
    // costs no extra query.
    const dmarcExistence = existenceFromResponse(nsResult);
    const dmarcRecord = dmarcDiscovery.applied ? dmarcDiscovery.applied.record : '';
    const dmarcAtDomain = dmarcDiscovery.applied ? dmarcDiscovery.applied.foundAt : d;
    const organizationalDomain = dmarcDiscovery.organizationalDomain;
    // Duplicates are no longer a policy verdict. RFC 9989 §4.10 step 2 discards
    // them and the walk continues, so a record higher in the tree still
    // applies; the duplicate survives as `observed[]` evidence and buildIssues
    // raises it from there, still critical. `multiple` therefore stays false
    // here — passing true would resurrect the permerror it replaces.
    // A walk that ended in a transient DNS error examined nothing conclusive:
    // the record could not be read, so the honest verdict is 'unknown'. Letting
    // it fall through to analyzeDmarc('') would report 'missing' — telling the
    // operator their domain is spoofable on the strength of our own failed
    // lookup. This is optionalCheck()'s rule applied to the core path.
    const dmarcUnverified = dmarcDiscovery.terminated === 'error' && !dmarcDiscovery.applied;
    const dmarcStatus = dmarcUnverified
      ? emptyDmarcStatus('unknown')
      : applyInheritance(analyzeDmarc(dmarcRecord, false), dmarcDiscovery, dmarcExistence);
    // The externality test in RFC 9990 §4 is defined against Organizational
    // Domains, which now means walked ones on both sides.
    // The walked map exists to answer RFC 9990 §4's externality test. Compare
    // against the Organizational Domain of the name the policy was FOUND at,
    // not the audited name's — under a PSD those differ, and pairing a policy
    // domain with someone else's organizational domain records a relationship
    // that does not hold.
    const policyOrgDomain = dmarcDiscovery.applied && dmarcDiscovery.applied.inherited
      ? (await optionalCheck(function () { return discoverDmarc(dmarcAtDomain, queryOpts); }, null) || {}).organizationalDomain || organizationalDomain
      : organizationalDomain;
    const dmarcOrgDomains = await resolveDestinationOrgDomains(
      dmarcStatus, dmarcAtDomain, policyOrgDomain, queryOpts
    );
    const reportPlan = planReportDestinations(dmarcStatus, dmarcAtDomain, dmarcOrgDomains);
    const externalReportDestinations = reportPlan.external;

    // Wildcard TXT synthesis is measured at both depths that matter, because
    // only the deeper one predicts harm. The apex probe (one label) shows a
    // `* IN TXT` record exists. The _domainkey probe (two labels) shows whether
    // that synthesis actually reaches DKIM selector names — the only lookup a
    // wildcard can poison, because selector names are unpredictable and carry
    // no version prefix to filter on. Every other check here matches a version
    // prefix (v=DMARC1, v=STSv1, v=BIMI1, v=spf1) and discards a stray wildcard
    // string on its own.
    //
    // The depth is measured rather than inferred. RFC 4592 2.2.1 stops
    // synthesis below an existing node, which protects any domain publishing
    // _domainkey, but not every nameserver honours that — so only the probe is
    // authoritative.
    //
    // A failed probe must not read as "no wildcard", so each depth stays false
    // until its own probe returns.
    let wildcardApex = false;
    let wildcardDkim = false;
    let wildcardDkimRecords = [];
    if (ctx.options.wildcard) {
      const [apexProbe, dkimProbe] = await Promise.all([
        optionalCheck(() => dohQuery(`_wildcardtest99xyz.${d}`, 'TXT', queryOpts), null),
        optionalCheck(() => dohQuery(`_wildcardtest99xyz._domainkey.${d}`, 'TXT', queryOpts), null),
      ]);
      wildcardApex = apexProbe !== null && apexProbe.length > 0;
      wildcardDkim = dkimProbe !== null && dkimProbe.length > 0;
      wildcardDkimRecords = wildcardDkim ? dkimProbe : [];
    }

    let dkimStatus = { found: false, selectors: [], testedSelectors: [], confidence: 'not-checked', note: '' };
    if (ctx.options.dkim && emailProvider !== '@none' && emailProvider !== '@null-mx') {
      // The DERIVED fact, not the record. An `include:` is the domain saying a
      // vendor sends mail for it, which is as good a reason to probe that
      // vendor's selectors as MX is for the inbound provider — but reading it
      // needs SPF's term grammar, and §12 gives `core/dkim/` no edge to
      // `core/spf/`. Task 4.8 injected SPF's helper into DKIM as a stated debt;
      // this is where it is paid. Audit is the layer that composes protocols,
      // so it parses the references once, here, and passes the catalog KEYS.
      const spfCatalogKeys = spfReferencedCatalogKeys(spfRecord);
      dkimStatus = await checkDKIM(d, { dkim: wildcardDkim, records: wildcardDkimRecords }, ctx.options.selectors, emailProvider, ctx.options.dkimComprehensive, spfCatalogKeys, queryOpts);
    }

    let hosting = '@dash';
    if (ctx.options.www) {
      const website = await optionalCheck(
        () => resolveWebsite(d, queryOpts),
        error => ({ loop: false, chain: [], addresses: [], error: (error && error.kind) || 'dns-error' })
      );
      hosting = website.error ? '@dns-error'
        : website.loop ? '@cname-loop'
          : detectHosting(website.addresses, website.chain, d);
    }

    // ── Advanced checks ──
    let advanced = { bimi: null, mtaSts: null, tlsRpt: null, caa: null, dnssec: null, spfLookups: null, spfSubnets: null, reportAuth: null, mxHealth: null, tlsa: null };
    if (ctx.options.advanced) {
      // Every entry is wrapped independently. Promise.all rejects on the first
      // failure, so without this one unlucky lookup would take the other six
      // down with it and abort the audit.
      const [bimiTxt, mtaStsTxt, tlsRptTxt, caaResult, dnssecResult, spfLookups, spfSubnets, reportAuth] = await Promise.all([
        optionalCheck(() => dohQuery(`default._bimi.${d}`, 'TXT', queryOpts), null),
        optionalCheck(() => dohQuery(`_mta-sts.${d}`, 'TXT', queryOpts), null),
        optionalCheck(() => dohQuery(`_smtp._tls.${d}`, 'TXT', queryOpts), null),
        optionalCheck(() => checkCAA(d, queryOpts),
          error => ({ found: false, records: [], atDomain: null, unknown: true, error: (error && error.kind) || 'dns-error' })),
        dnssecPreflight ? Promise.resolve(dnssecPreflight) : checkDNSSEC(d, queryOpts),
        spfRecord
          ? optionalCheck(() => countSpfLookups(spfRecord, d, queryOpts),
            error => ({ count: 0, warning: false, error: false, voidLookups: 0, cycles: [], indeterminate: true, unknown: true, queryError: (error && error.kind) || 'dns-error' }))
          : Promise.resolve({ count: 0, warning: false, error: false, voidLookups: 0, cycles: [], indeterminate: false }),
        // The size half of this needs no DNS, so a resolver failure during
        // the redundancy half falls back to the size findings alone rather
        // than discarding both.
        spfRecord
          ? optionalCheck(() => auditSpfSubnets(spfRecord, d, queryOpts),
            () => ({ subnets: classifySpfSubnets(spfRecord).subnets, redundancy: [], unknown: true }))
          : Promise.resolve({ subnets: [], redundancy: [], unknown: false }),
        optionalCheck(() => checkExternalReportAuth(dmarcAtDomain, externalReportDestinations, queryOpts), []),
      ]);

      // All three specs say the same thing: filter to the versioned records,
      // and if the result isn't exactly one, treat the domain as not having
      // the feature at all (RFC 8461 §3.1, RFC 8460 §3, BIMI draft §7.2).
      // So `present` is false when duplicated — the operator believes the
      // control is active when it is not, which is worth saying out loud.
      // A null here is a lookup that failed, not a domain without the record.
      // `unknown` carries that distinction through to scoring and the UI so an
      // unverified control is never presented as an absent one.
      const bimiMatches = leadingVersionMatches(bimiTxt, 'BIMI1');
      const mtaMatches = leadingVersionMatches(mtaStsTxt, 'STSv1');
      const tlsMatches = leadingVersionMatches(tlsRptTxt, 'TLSRPTv1');

      // A sender discards a record that does not BEGIN with the version field,
      // and `present` follows that rule exactly. An auditor must not: the
      // record exists, at an owner name dedicated to this protocol, and
      // "nothing is published" and "what is published is not an active policy"
      // are different facts. Filtering the malformed candidate away before
      // validation is what suppressed the very findings the strict validators
      // were added to raise — `l=…; v=BIMI1` simply vanished.
      const bimiCandidates = versionCandidates(bimiTxt, 'BIMI1');
      const mtaCandidates = versionCandidates(mtaStsTxt, 'STSv1');
      const tlsCandidates = versionCandidates(tlsRptTxt, 'TLSRPTv1');

      // Show the sender-compatible record when there is one, and otherwise the
      // malformed candidate — which is the evidence the operator needs.
      const bimiRecord = bimiMatches[0] || bimiCandidates[0] || '';
      const mtaRecord = mtaMatches[0] || mtaCandidates[0] || '';
      const tlsRecord = tlsMatches[0] || tlsCandidates[0] || '';
      const bimiValidation = validateBimiRecord(bimiRecord);
      const mtaValidation = validateMtaStsRecord(mtaRecord);
      const tlsValidation = validateTlsRptRecord(tlsRecord);

      advanced = {
        // `present` means an indicator is actually asserted. A valid record with
        // an empty `l=` is the draft's explicit declination to publish one —
        // conformant, deliberate, and not a configured BIMI logo. Counting it
        // as present would report an indicator the operator said they do not
        // have; counting it as invalid would report a correct record as broken.
        bimi: { present: bimiMatches.length === 1 && bimiValidation.valid && !bimiValidation.declined, declined: bimiMatches.length === 1 && bimiValidation.declined, advertised: bimiCandidates.length > 0, record: bimiRecord, candidates: bimiCandidates, validation: bimiValidation, multiple: bimiMatches.length > 1, unknown: bimiTxt === null },
        mtaSts: { present: mtaMatches.length === 1 && mtaValidation.valid, advertised: mtaCandidates.length > 0, policyVerified: false, record: mtaRecord, candidates: mtaCandidates, validation: mtaValidation, multiple: mtaMatches.length > 1, unknown: mtaStsTxt === null },
        tlsRpt: { present: tlsMatches.length === 1 && tlsValidation.valid, advertised: tlsCandidates.length > 0, record: tlsRecord, candidates: tlsCandidates, validation: tlsValidation, multiple: tlsMatches.length > 1, unknown: tlsRptTxt === null },
        caa: caaResult,
        dnssec: dnssecResult,
        spfLookups,
        spfSubnets,
        reportAuth,
        mxHealth: null,
        tlsa: null,
      };

      // ── Deep protocol checks ──
      // Gated separately from `advanced` because these are the only checks in
      // the audit whose cost scales with the domain's own configuration: three
      // queries per MX host for the health audit and one more for TLSA, so a
      // five-MX domain adds twenty on its own. Everything above is a fixed
      // handful per domain. See OQ-DEPTH-03 — the interface turns this off
      // above 50 domains, and the engine simply does what it is told.
      //
      // A null MX (RFC 7505) is skipped: the domain has declared it accepts no
      // mail, so there is no host to resolve and nothing to say about TLSA.
      if (ctx.options.deepChecks && mx.length && !isNullMx(mx)) {
        const mxHealth = await optionalCheck(() => auditMxHosts(mx, d, queryOpts),
          () => ({ hosts: [], danglingHosts: [], cnameHosts: [], duplicatePreferences: [], singleHost: false, ipv6Coverage: 'none', sharedPrefixes: [], unknown: true }));
        const tlsaHosts = mxHealth.hosts.map(h => h.host);
        const tlsa = await optionalCheck(() => checkTlsa(tlsaHosts, queryOpts),
          () => ({ hosts: [], anyPresent: false, allAuthenticated: false, unauthenticatedHosts: [], unknown: true }));
        advanced.mxHealth = mxHealth;
        advanced.tlsa = tlsa;
      }
    }

    const issues = buildIssues({ emailProvider, spfStatus, spfRecords, dkimStatus, dmarcStatus, dmarcDiscovery, dmarcExistence, externalReportDestinations, reportPlan, wildcardApex, wildcardDkim, hosting, advanced, domain: d });
    const suggestions = buildSuggestions({ emailProvider, spfStatus, dkimStatus, dmarcStatus, advanced });
    const score = calcScore({ emailProvider, spfStatus, dkimStatus, dmarcStatus, advanced });
    const advScore = ctx.options.advanced ? calcAdvScore(advanced) : null;

    ctx.record({
      ns, mx, txt, aRec, aaaaRec, dnsProvider, emailProvider,
      spfRecord, spfRecords, spfStatus, dmarcRecord, dmarcStatus, dmarcDiscovery, dmarcExistence,
      // Retained as an alias of dmarcDiscovery.applied.foundAt for one release
      // so the CSV export and the saved report keep working, then removed.
      dmarcAtDomain, organizationalDomain, dkimStatus,
      wildcardApex, wildcardDkim, hosting, verifications, advanced, advScore,
      issues, suggestions, score,
    });
    return ctx.result();
  }

  return { analyzeDomain };
}
