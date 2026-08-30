/* ──────────────────────────────────────────────────────────────────────────
   The `v0.5.0` engine surface, reconstructed for the tests that assert it.

   **This is a test harness, not application code.** Nothing under `src/`
   imports it and it is not in the bundle: `src/runtime.js` builds the DNS
   layer and `src/audit/create-audit.js` builds the protocol checks, and the
   supported browser API is the two-member facade `src/main.js` exports.

   ── What it is for ──────────────────────────────────────────────────────

   `tools/scoring.test.mjs` is 1,535 assertions that reach 95 engine members by
   name, and `tools/backtest.mjs` runs the same surface against live DNS. Both
   predate the refactor and both are the reason the refactor could be trusted:
   an assertion count that never moved across six phases is the strongest
   evidence that no behaviour did. Rewriting them to import forty modules
   directly would have retired the instrument that was measuring the work.

   So the surface moved here, where its nature is visible. It was `js/dns.js`
   until Task 6.1; the file is the same composition, with `../src/` become
   `../../src/` and nothing else changed.

   ── The five compatibility wrappers ─────────────────────────────────────

   `checkDKIM`, `buildDkimSelectorList`, `catalogSelectors`,
   `spfSelectorSources` and `detectEmailProvider` keep their observed `v0.5.0`
   signatures here — the string-taking and three-argument forms. The
   application uses the fact-taking APIs directly; these exist so that the
   assertions written against the old shapes still mean what they meant.
   ────────────────────────────────────────────────────────────────────────── */

import { createDohTransport, DOH_ENDPOINT } from '../../src/core/dns/doh.js';
import { createDohCache } from '../../src/core/dns/cache.js';
import { dnsTypeNum, dnsError, DNS_TYPES } from '../../src/core/dns/errors.js';
import { createResolver } from '../../src/core/dns/resolver.js';
import { optionalCheck } from '../../src/core/dns/optional.js';
import { createExistence, existenceFromResponse } from '../../src/core/dns/existence.js';
// core/shared/ is down to one import here. uri.js and record-fields.js went
// with their call sites at Task 4.4; base64.js followed at 4.5 and 4.7 and the
// import outlived its last reader until Task 5.2 noticed. Only the three IP
// helpers are still read from this file, and only as engine members.
import { ipv4ToBigInt, ipv6ToBigInt, parseIpCidr } from '../../src/core/shared/ip.js';
import { parseCaaRecord, summarizeCaa } from '../../src/core/caa/caa.js';
import { isNullMx, parseMxRecord } from '../../src/core/mx/mx.js';
import { validateBimiRecord } from '../../src/core/bimi/bimi.js';
import { validateMtaStsRecord } from '../../src/core/transport/mta-sts.js';
import { validateTlsRptRecord } from '../../src/core/transport/tls-rpt.js';
import { parseTlsaRecord } from '../../src/core/transport/tlsa.js';
import {
  parseDnskey, parseDs, dnskeyRdata, dnskeyKeyTag, dnsWireName, dnskeyStructure,
  dnssecAlgorithmEligibility, dnssecDigestEligibility, dnssecDigestName,
  DNSSEC_ALGORITHMS, DNSSEC_ZONE_SIGNING, DNSSEC_DIGESTS,
} from '../../src/core/dnssec/records.js';
import {
  anchorFactsUsable, dnskeyCanAnchor, matchConfirmsAnchor,
  DNSSEC_DIGEST_WEBCRYPTO,
} from '../../src/core/dnssec/matching.js';
import {
  analyzeDmarc, parseDmarcTag, parseDmarcUriList,
  validateDmarcVersion, POLICY_RANK, DMARC_TAGS_RFC9989, DMARC_TAGS_REMOVED,
} from '../../src/core/dmarc/record.js';
import {
  dmarcWalkTargets, isDmarcPolicyRecord, diagnoseDmarcRecord,
  selectOrganizationalDomain, selectAppliedRecord, applyInheritance,
} from '../../src/core/dmarc/tree-walk.js';
import {
  findExternalReportDestinations, reportDestinationHosts,
  planReportDestinations, parseReportAuthRecord,
} from '../../src/core/dmarc/report-auth.js';
import {
  analyzeDkimKey, DKIM_SELECTORS,
} from '../../src/core/dkim/dkim.js';
import {
  analyzeSpf, parseSpfTerms, cidrContains, classifySpfSubnet,
  classifySpfSubnets, spfReferencedCatalogKeys,
} from '../../src/core/spf/spf.js';
import { detectDNSProvider, detectEmailProvider, detectHosting } from '../../src/providers/detectors.js';
import { createAudit } from '../../src/audit/create-audit.js';
// The scoring model, Task 5.3. Byte-identical to v0.5.0 and verified as such
// against the tag; these are legacy engine members and the coordinator imports
// them itself.
import {
  calcScore, calcDmarcScore, calcSpfScore, gradeFor,
  WEIGHTS, PARKED_WEIGHTS, GRADE_THRESHOLDS,
} from '../../src/audit/scoring.js';
// Findings and remediation tips, Task 5.4 — the last substantive behaviour to
// leave this file. Both are legacy engine members.
import { buildIssues, buildSuggestions } from '../../src/audit/issues.js';
// A legacy engine member. It lives in core/shared/ since Task 5.2a — Gate 5
// forbids the coordinator holding a parsing rule, so record selection went to
// the protocol owners and this went to the module they share.
import { startsWithCI } from '../../src/core/shared/record-selection.js';

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
   * Every protocol check, and the coordinator over them.
   *
   * Constructed by `src/audit/create-audit.js` since Task 6.1 — the layer §12
   * gives the `core/<protocol>/` and `providers/` edges to. This file builds
   * the DNS layer above and hands over the handle, which is what the runtime
   * does too; the two differ only in what they assemble on top.
   */
  const audit = createAudit({
    dohFetch, dohQuery, requireUsable, cleanAnswerData, optionalCheck,
    existenceFromResponse, dnsError,
    crypto, publicSuffixRules, dkimSelectorCatalog,
  });
  const {
    analyzeDomain,
    countSpfLookups, findSpfRedundancy, auditSpfSubnets,
    checkDKIM, catalogSelectors, spfSelectorSources, buildDkimSelectorList,
    isRecognizedDkimSelector, inspectDkimSelector, summarizeDkimKeys,
    validateDkimKeyStructure, dkimKeyRecords, dkimRecordSet,
    getOrganizationalDomain, discoverDmarc,
    resolveDestinationOrgDomains, checkExternalReportAuth,
    checkCAA, auditMxHosts, checkTlsa,
    matchDsToDnskeys, matchDsSet, checkDNSSEC,
  } = audit;

  /**
   * The four SPF-aware DKIM members and provider detection, in their observed
   * legacy shapes. Thin compatibility wrappers over the fact-taking APIs; the
   * audit path uses those directly. Phase 6 removes them with this file.
   */
  const legacyDetectEmailProvider = (mx, domain, addressRecords) =>
    detectEmailProvider(mx, domain, addressRecords, isNullMx(mx));
  const legacyCatalogSelectors = (emailProvider, comprehensive, spfRecord) =>
    catalogSelectors(emailProvider, comprehensive, spfReferencedCatalogKeys(spfRecord));
  const legacySpfSelectorSources = (selectors, emailProvider, comprehensive, spfRecord) =>
    spfSelectorSources(selectors, emailProvider, comprehensive, spfReferencedCatalogKeys(spfRecord));
  const legacyBuildDkimSelectorList = (selectors, emailProvider, comprehensive, spfRecord) =>
    buildDkimSelectorList(selectors, emailProvider, comprehensive, spfReferencedCatalogKeys(spfRecord));
  const legacyCheckDKIM = (domain, wildcard, selectors, emailProvider, comprehensive, spfRecord, queryOpts) =>
    checkDKIM(domain, wildcard, selectors, emailProvider, comprehensive,
      spfReferencedCatalogKeys(spfRecord), queryOpts);


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
