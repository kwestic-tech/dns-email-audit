/* ──────────────────────────────────────────────────────────────────────────
   DNS querying and analysis.

   This file is deliberately free of user-facing English. Anything a person
   reads is represented here as a stable identifier — '@none', 'spf-missing',
   'noteWildcard' — and turned into words by js/app.js via the i18n layer.
   That keeps the audit logic and the translations independent: a translator
   never has to touch this file, and a bug fix here never breaks a locale.

   Tokens that stand in for translatable text are prefixed with '@'.
   Provider names that are proper nouns ('Cloudflare', 'Google Workspace')
   are passed through untranslated by design.
   ────────────────────────────────────────────────────────────────────────── */

/**
 * Build the DNS engine over its supplied inputs.
 *
 * A WRAPPER conversion, and deliberately nothing more. The IIFE opener became
 * this function, the closing `global.DnsAudit = {…}` became a `return`, and the
 * three `global.…` reads became the three parameters. **No function below moved,
 * was renamed, or changed behaviour, and the body is not reindented** — 5,704
 * lines changing their wrapper is reviewable; 5,704 lines changing wrapper and
 * indentation is not, and a moved function in that diff would mean it was done
 * wrong. Phases 3 and 4 are where this file is decomposed.
 *
 * Everything it needs is PASSED. The two generated tables were `global.…` reads
 * and are arguments now; the ambient primitives it used to find on `window` are
 * destructured from `platform` below. That is what lets a test hand this engine
 * a four-rule public suffix list and a fixture `fetch` — the module cannot
 * reach past its arguments for the real ones, so a fixture cannot be silently
 * replaced by production data.
 *
 * `platform` is the temporary object literal Task 2.2 introduced; Task 2.4
 * replaces it with `src/platform/browser.js` and the complete §11 primitive set.
 */
import { createDohTransport, DOH_ENDPOINT } from '../src/core/dns/doh.js';
import { createDohCache } from '../src/core/dns/cache.js';
import { dnsTypeNum, dnsError, DNS_TYPES } from '../src/core/dns/errors.js';
import { createResolver } from '../src/core/dns/resolver.js';
import { optionalCheck } from '../src/core/dns/optional.js';
import { createExistence, existenceFromResponse } from '../src/core/dns/existence.js';
// core/shared/ is down to one import here. uri.js and record-fields.js went
// with their call sites at Task 4.4; base64.js followed at 4.5 and 4.7 and the
// import outlived its last reader until Task 5.2 noticed. Only the three IP
// helpers are still read from this file, and only as engine members.
import { ipv4ToBigInt, ipv6ToBigInt, parseIpCidr } from '../src/core/shared/ip.js';
import { createCaaCheck, parseCaaRecord, summarizeCaa } from '../src/core/caa/caa.js';
import { createMxAudit, isNullMx, parseMxRecord } from '../src/core/mx/mx.js';
import { validateBimiRecord } from '../src/core/bimi/bimi.js';
import { validateMtaStsRecord } from '../src/core/transport/mta-sts.js';
import { validateTlsRptRecord } from '../src/core/transport/tls-rpt.js';
import { createTlsaCheck, parseTlsaRecord } from '../src/core/transport/tlsa.js';
import {
  parseDnskey, parseDs, dnskeyRdata, dnskeyKeyTag, dnsWireName, dnskeyStructure,
  dnssecAlgorithmEligibility, dnssecDigestEligibility, dnssecDigestName,
  DNSSEC_ALGORITHMS, DNSSEC_ZONE_SIGNING, DNSSEC_DIGESTS,
} from '../src/core/dnssec/records.js';
import {
  createDsMatcher, anchorFactsUsable, dnskeyCanAnchor, matchConfirmsAnchor,
  DNSSEC_DIGEST_WEBCRYPTO,
} from '../src/core/dnssec/matching.js';
import { createDnssecCheck } from '../src/core/dnssec/chain.js';
import { createOrgDomain } from '../src/core/dmarc/org-domain.js';
import {
  analyzeDmarc, parseDmarcTag, parseDmarcUriList,
  validateDmarcVersion, POLICY_RANK, DMARC_TAGS_RFC9989, DMARC_TAGS_REMOVED,
} from '../src/core/dmarc/record.js';
import {
  createDmarcDiscovery, dmarcWalkTargets, isDmarcPolicyRecord, diagnoseDmarcRecord,
  selectOrganizationalDomain, selectAppliedRecord, applyInheritance,
} from '../src/core/dmarc/tree-walk.js';
import {
  createReportAuth, findExternalReportDestinations, reportDestinationHosts,
  planReportDestinations, parseReportAuthRecord,
} from '../src/core/dmarc/report-auth.js';
import {
  createDkimCheck, analyzeDkimKey, DKIM_SELECTORS,
} from '../src/core/dkim/dkim.js';
import {
  createSpfChecks, analyzeSpf, parseSpfTerms, cidrContains, classifySpfSubnet,
  classifySpfSubnets, spfReferencedCatalogKeys,
} from '../src/core/spf/spf.js';
import { detectDNSProvider, detectEmailProvider, detectHosting } from '../src/providers/detectors.js';
import { createAuditDomain } from '../src/audit/audit-domain.js';
// The scoring model, Task 5.3. Byte-identical to v0.5.0 and verified as such
// against the tag; these are legacy engine members and the coordinator imports
// them itself.
import {
  calcScore, calcDmarcScore, calcSpfScore, gradeFor,
  WEIGHTS, PARKED_WEIGHTS, GRADE_THRESHOLDS,
} from '../src/audit/scoring.js';
// Findings and remediation tips, Task 5.4 — the last substantive behaviour to
// leave this file. Both are legacy engine members.
import { buildIssues, buildSuggestions } from '../src/audit/issues.js';
// A legacy engine member. It lives in core/shared/ since Task 5.2a — Gate 5
// forbids the coordinator holding a parsing rule, so record selection went to
// the protocol owners and this went to the module they share.
import { startsWithCI } from '../src/core/shared/record-selection.js';

export function createDnsEngine({ publicSuffixRules, dkimSelectorCatalog, platform }) {
  // Named, not reached for. `fetch` is the load-bearing one: the DoH fixture
  // works by substituting it, and a module that resolved `fetch` from Node's
  // globals would quietly query the real internet from a unit test.
  const { fetch, crypto, AbortController, URLSearchParams, setTimeout, clearTimeout } = platform;
  /**
   * ONE cache, for this engine and therefore for this runtime.
   *
   * Spec Design §5. `createAuditRuntime()` builds one engine per call and
   * `src/main.js` builds one runtime per page, so this is the page-lifetime
   * cache v0.5.0 had. Narrowing it would raise the DNS fan-out `PRIVACY.md`
   * publishes, which makes the scope a privacy decision rather than a detail.
   */
  const dohCache = createDohCache();
  /* ── DNS-over-HTTPS core ────────────────────────────────────────────── */

  /**
   * The transport, built over this runtime's platform and this runtime's cache.
   *
   * `dohFetch` is the same function it always was — spec Design §3 layer 1,
   * ten kinds, cache and retry rules unchanged — living in
   * `src/core/dns/doh.js` as of Task 3.1. Everything below still calls it by
   * name, so no call site moved.
   *
   * ONE transport per engine, and therefore one per runtime: the cache and the
   * concurrency limiter are its state, and `createAuditRuntime()` builds one
   * engine per call. `tools/scoring.test.mjs:1888-1891` asserts the sibling
   * reuse that lifetime produces and `PRIVACY.md` publishes the fan-out, so
   * narrowing it is a privacy change rather than a refactor.
   */
  const { dohFetch } = createDohTransport({ platform, cache: dohCache, dnsError, dnsTypeNum });

  /**
   * Layers 2 and 3, over this engine's transport.
   *
   * `requireUsable` gates; `dohQuery` and `dohAll` normalize and drop the kind.
   * `checkConnectivity` is a named exception edge that reads the kind directly.
   * Every call site below still uses these by name.
   */
  const { requireUsable, dohQuery, dohAll, checkConnectivity, cleanAnswerData } =
    createResolver({ dohFetch });

  /**
   * RFC 9989 §3.2.13 and Appendix A.4: existence is a property of the NAME,
   * not of any record type. "if any RR exists for a domain, then the domain
   * exists"; an NXDOMAIN response means the name does not exist, while a
   * NODATA response (NOERROR, no records of the queried type) means the name
   * exists but that type does not.
   *
   * So a NOERROR of either shape is 'yes', and a transient failure is
   * 'unknown' — never 'no'. Reading a timeout as non-existence would apply the
   * np= branch of a policy to a name that is plainly there.
   *
   * analyzeDomain() derives this from the NS response it already holds rather
   * than calling here; this exists for the destinations and fixtures that have
   * no such response to hand.
   */
  const domainExists = createExistence({ dohFetch });

  /**
   * Provider detection, Task 4.9, with its collaborator retired at Task 5.2.
   *
   * `providers/` is three pure functions now: audit derives the RFC 7505
   * null-MX boolean with `core/mx/`'s predicate and passes the FACT, which is
   * Task 4.0 finding 4's stated end state. The legacy three-argument member is
   * this wrapper — it performs the old derivation and delegates, because
   * `tools/scoring.test.mjs` asserts that form directly. An adapter, not
   * architecture; Phase 6 removes it with this file.
   */
  const legacyDetectEmailProvider = (mx, domain, addressRecords) =>
    detectEmailProvider(mx, domain, addressRecords, isNullMx(mx));

  // SPF, Task 4.8. Two of the three checks need the RAW handle as well as
  // layer 3, because countSpfLookups()'s fallback copies DnsError.kind.
  const { countSpfLookups, findSpfRedundancy, auditSpfSubnets } = createSpfChecks({
    dohQuery, dohFetch, requireUsable, cleanAnswerData,
  });

  // DKIM, Task 4.7. The catalog is generated data and the crypto is the
  // platform's, so both are passed — and that is now the whole list. Task
  // 4.8's injected `spfReferencedCatalogKeys` was retired at Task 5.2: audit
  // derives the catalog keys with SPF's own helper and passes them, so there
  // is still no core/dkim -> core/spf edge and still one SPF grammar. The
  // string-taking legacy members are the wrappers below.
  const {
    checkDKIM, catalogSelectors, spfSelectorSources, buildDkimSelectorList,
    isRecognizedDkimSelector, inspectDkimSelector, summarizeDkimKeys,
    validateDkimKeyStructure, dkimKeyRecords, dkimRecordSet,
  } = createDkimCheck({
    dohFetch, requireUsable, cleanAnswerData, crypto, dkimSelectorCatalog,
  });

  /**
   * The legacy engine surface for the four SPF-aware DKIM members.
   *
   * Thin compatibility wrappers, and exactly what the Phase-5 ruling
   * authorizes. The TARGET path — `src/audit/` — derives the catalog keys with
   * SPF's own helper and passes the KEYS, which is what retires the
   * `core/dkim` → `core/spf` composition from the real audit. The observed
   * legacy signatures still take an SPF record STRING, and
   * `tools/scoring.test.mjs` asserts them directly, so each wrapper performs
   * the old derivation and delegates to the fact-taking API.
   *
   * Adapters, not architecture. Phase 6 removes them with this file.
   */
  const legacyCatalogSelectors = (emailProvider, comprehensive, spfRecord) =>
    catalogSelectors(emailProvider, comprehensive, spfReferencedCatalogKeys(spfRecord));
  const legacySpfSelectorSources = (selectors, emailProvider, comprehensive, spfRecord) =>
    spfSelectorSources(selectors, emailProvider, comprehensive, spfReferencedCatalogKeys(spfRecord));
  const legacyBuildDkimSelectorList = (selectors, emailProvider, comprehensive, spfRecord) =>
    buildDkimSelectorList(selectors, emailProvider, comprehensive, spfReferencedCatalogKeys(spfRecord));
  const legacyCheckDKIM = (domain, wildcard, selectors, emailProvider, comprehensive, spfRecord, queryOpts) =>
    checkDKIM(domain, wildcard, selectors, emailProvider, comprehensive,
      spfReferencedCatalogKeys(spfRecord), queryOpts);

  // DMARC, Task 4.6. The PSL is generated data and is PASSED to its own
  // factory; the walk and the report-authorization checks each name the
  // resolver capabilities they read. Report authorization takes the walk as a
  // collaborator rather than reaching for it, because a protocol directory has
  // no edge to core/dns/ or to src/data/.
  const getOrganizationalDomain = createOrgDomain({ publicSuffixRules });
  const discoverDmarc = createDmarcDiscovery({ dohFetch, dnsError, cleanAnswerData });
  const { resolveDestinationOrgDomains, checkExternalReportAuth } = createReportAuth({
    dohFetch, dnsError, cleanAnswerData, optionalCheck, discoverDmarc,
  });

  /* ── Advanced checks ────────────────────────────────────────────────── */

  // CAA moved to src/core/caa/ at Task 4.1, MX health to src/core/mx/ at 4.2
  // and TLSA to src/core/transport/ at 4.4. Each names the resolver
  // capabilities it reads, because a protocol directory has no edge to
  // core/dns/. TLSA takes four: it needs the raw response for the AD bit and
  // the type-52 filter, so it does layer 3's cleaning itself.
  const checkCAA = createCaaCheck({ dohFetch, requireUsable });
  const auditMxHosts = createMxAudit({ dohQuery, optionalCheck });
  const checkTlsa = createTlsaCheck({ dohFetch, requireUsable, optionalCheck, cleanAnswerData });
  // DNSSEC, Task 4.5. The matcher is constructed here and PASSED to the chain
  // check: the crypto belongs to the module that computes digests, and the
  // module that decides `state` must not be able to reach it. Both matcher
  // functions are engine members in their own right.
  const { matchDsToDnskeys, matchDsSet } = createDsMatcher({ crypto });
  const checkDNSSEC = createDnssecCheck({ dohFetch, cleanAnswerData, matchDsSet });

  /**
   * The audit coordinator, Task 5.2.
   *
   * `analyzeDomain()` and its helpers live in `src/audit/audit-domain.js` now.
   * What it needs is handed to it here, because this file is still the
   * transitional composition root: the resolver handle §12 forbids `audit/`
   * from importing, and every protocol check already built over that resolver.
   *
   * That is now the WHOLE list. Tasks 5.3 and 5.4 took the scorers and the
   * issue builders off it — they are `audit/` siblings, so the coordinator
   * imports them — and what remains is exactly the set §12 says must be
   * passed. Nothing temporary is left here.
   */
  const { analyzeDomain } = createAuditDomain({
    dohFetch, dohQuery, requireUsable, optionalCheck, existenceFromResponse,
    checkDNSSEC, checkCAA, checkTlsa, auditMxHosts, checkDKIM,
    discoverDmarc, resolveDestinationOrgDomains, checkExternalReportAuth,
    countSpfLookups, auditSpfSubnets,
  });


  return {
    // Re-exported rather than dropped. Nothing in the repository reads it, but
    // it is one of the engine's members and Task 3.1 is a move: a member
    // disappearing would be a surface change riding along with one.
    DOH: DOH_ENDPOINT,
    DKIM_SELECTORS,
    // The four SPF-aware members keep their observed string-taking form
    // through the compatibility wrappers above; the audit path uses the
    // fact-taking API directly.
    buildDkimSelectorList: legacyBuildDkimSelectorList,
    catalogSelectors: legacyCatalogSelectors,
    spfSelectorSources: legacySpfSelectorSources,
    spfReferencedCatalogKeys,
    isRecognizedDkimSelector,
    checkDKIM: legacyCheckDKIM,
    dkimKeyRecords,
    dkimRecordSet,
    analyzeDkimKey,
    validateDkimKeyStructure,
    summarizeDkimKeys,
    parseCaaRecord,
    summarizeCaa,
    parseMxRecord,
    auditMxHosts,
    parseTlsaRecord,
    checkTlsa,
    checkDNSSEC,
    dnsTypeNum,
    // Exported so the test harness can assert its own type map has not drifted
    // from this one. A fixture keyed for a type the transport cannot query is
    // unreachable; a transport type the harness does not know is answered as
    // TXT and silently mis-keyed. Both are the failure dnsTypeNum() throws to
    // prevent, arriving through the tests instead of through production.
    DNS_TYPES,
    parseDnskey,
    parseDs,
    dnskeyRdata,
    dnskeyKeyTag,
    dnsWireName,
    DNSSEC_ALGORITHMS,
    DNSSEC_ZONE_SIGNING,
    DNSSEC_DIGESTS,
    dnssecAlgorithmEligibility,
    dnskeyStructure,
    dnskeyCanAnchor,
    anchorFactsUsable,
    matchConfirmsAnchor,
    dnssecDigestEligibility,
    dnssecDigestName,
    matchDsToDnskeys,
    matchDsSet,
    DNSSEC_DIGEST_WEBCRYPTO,
    analyzeDomain,
    checkConnectivity,
    dohFetch,
    // exported for unit testing / reuse
    detectDNSProvider,
    detectEmailProvider: legacyDetectEmailProvider,
    isNullMx,
    detectHosting,
    getOrganizationalDomain,
    analyzeSpf,
    analyzeDmarc,
    parseDmarcTag,
    validateDmarcVersion,
    parseDmarcUriList,
    findExternalReportDestinations,
    reportDestinationHosts,
    planReportDestinations,
    parseReportAuthRecord,
    resolveDestinationOrgDomains,
    checkExternalReportAuth,
    discoverDmarc,
    dmarcWalkTargets,
    isDmarcPolicyRecord,
    diagnoseDmarcRecord,
    selectOrganizationalDomain,
    selectAppliedRecord,
    applyInheritance,
    domainExists,
    optionalCheck,
    startsWithCI,
    countSpfLookups,
    parseSpfTerms,
    ipv4ToBigInt,
    ipv6ToBigInt,
    parseIpCidr,
    cidrContains,
    classifySpfSubnet,
    classifySpfSubnets,
    findSpfRedundancy,
    auditSpfSubnets,
    checkCAA,
    validateMtaStsRecord,
    validateTlsRptRecord,
    validateBimiRecord,
    calcScore,
    calcDmarcScore,
    calcSpfScore,
    gradeFor,
    buildIssues,
    buildSuggestions,
    WEIGHTS,
    PARKED_WEIGHTS,
    GRADE_THRESHOLDS,
    POLICY_RANK,
    DMARC_TAGS_RFC9989,
    DMARC_TAGS_REMOVED,
  };
}
