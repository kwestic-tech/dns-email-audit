/**
 * The audit coordinator. Spec Design §5, implementation Task 5.2.
 *
 * `analyzeDomain()` owns WHICH checks run, in what order, which may run
 * concurrently, how a failure is isolated, and how the answers become one
 * result. Every rule about which records are a protocol's, and about what they
 * mean, belongs to a `core/<protocol>/` owner; this file asks and reads the
 * answers.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s `analyzeDomain()` and `resolveWebsite()`, at the same
 * indentation and in the same order. **The `Promise.all` structure is
 * byte-identical** — the four core lookups, the two wildcard probes, the eight
 * advanced checks and the DKIM scan batch are exactly the concurrency `v0.5.0`
 * had. Spec §35 and the implementation plan both forbid changing concurrency
 * and moving code in the same phase, and this release changes it nowhere.
 *
 * ── What this file does NOT parse ───────────────────────────────────────
 *
 * Gate 5: *the coordinator holds no parsing rule.* Selecting a protocol's
 * records out of a TXT set is a parsing rule, so each owner does its own —
 * `selectSpfRecords`, `summarizeBimi`, `summarizeMtaSts`, `summarizeTlsRpt`,
 * `selectVerifications`. Task 5.2a moved them out of here, along with
 * `startsWithCI`, `versionCandidates` and `leadingVersionMatches`, which went
 * to `core/shared/record-selection.js` once they had two protocol readers
 * each. `dns-transport.test.mjs` §6 asserts none of them is declared here.
 *
 * ── What is imported, and what is passed ────────────────────────────────
 *
 * §12 gives `src/audit/` an edge to `core/<protocol>/`, `providers/` and its
 * own siblings — and NOT to `core/dns/`. So the split is not a style choice:
 *
 * | Reached by import | Passed as a capability |
 * | --- | --- |
 * | The PURE protocol functions — `selectSpfRecords`, `analyzeSpf`, `classifySpfSubnets`, `spfReferencedCatalogKeys`, `analyzeDmarc`, `applyInheritance`, `planReportDestinations`, the three summarizers, `isNullMx`, and `providers/`'s detectors and `selectVerifications` | Everything built over the resolver — `dohFetch`, `dohQuery`, `requireUsable`, `optionalCheck`, and every protocol check constructed with them |
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
import { summarizeBimi } from '../core/bimi/bimi.js';
import { summarizeMtaSts } from '../core/transport/mta-sts.js';
import { summarizeTlsRpt } from '../core/transport/tls-rpt.js';
import {
  analyzeSpf, classifySpfSubnets, selectSpfRecords, spfReferencedCatalogKeys,
} from '../core/spf/spf.js';
import { analyzeDmarc, emptyDmarcStatus } from '../core/dmarc/record.js';
import { applyInheritance } from '../core/dmarc/tree-walk.js';
import { planReportDestinations } from '../core/dmarc/report-auth.js';
import {
  detectDNSProvider, detectEmailProvider, detectHosting, selectVerifications,
} from '../providers/detectors.js';

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
    // TEMPORARY — audit siblings awaiting Tasks 5.3 and 5.4, then imports.
    buildIssues, buildSuggestions, calcScore, calcAdvScore,
  } = capabilities;

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
    // RFC 7505's `0 .` is MX semantics, and §12 gives `providers/` an edge to
    // `core/shared/` only — so the fact is derived HERE, once, and read twice:
    // by provider detection and by the deep-check gate below. Task 4.0 finding
    // 4's end state, and what retires the predicate `providers/` was injected
    // with at Task 4.9.
    const nullMx = isNullMx(mx);
    const emailProvider = detectEmailProvider(mx, d, aRec.concat(aaaaRec), nullMx);
    // Which TXT records are SPF records, and whether there is more than one,
    // is SPF's question and `core/spf/` answers it. Every match is kept, not
    // just the first: the count is part of the signal, and the records are the
    // evidence `spf-multiple-records` points at.
    const { records: spfRecords, record: spfRecord, multiple: spfMultiple } = selectSpfRecords(txt);
    const spfStatus = analyzeSpf(spfRecord, emailProvider, spfMultiple);
    const verifications = selectVerifications(txt);

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

      // Each owner takes its own TXT records and returns its own answer. The
      // three rules that used to be written out here — select the versioned
      // records, keep the malformed candidate an auditor must still report,
      // and treat anything other than exactly one as not having the feature
      // (RFC 8461 §3.1, RFC 8460 §3, BIMI draft §7.2) — are protocol rules, so
      // they live with the protocols. `null` in means the lookup failed rather
      // than the record being absent, and each summary carries that as
      // `unknown`.
      advanced = {
        bimi: summarizeBimi(bimiTxt),
        mtaSts: summarizeMtaSts(mtaStsTxt),
        tlsRpt: summarizeTlsRpt(tlsRptTxt),
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
      if (ctx.options.deepChecks && mx.length && !nullMx) {
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
