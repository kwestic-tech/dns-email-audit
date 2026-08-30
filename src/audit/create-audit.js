/**
 * The audit composition root. Spec §12, implementation Task 6.1.
 *
 * Every protocol owner, constructed over one resolver handle, and the
 * coordinator built on top of them. This is the layer §12 puts the
 * `core/<protocol>/` and `providers/` edges on — `src/runtime.js` has neither,
 * and `src/audit/` has no edge to `core/dns/`, so the composition splits here
 * exactly where the matrix says it should:
 *
 * | Built by | From |
 * | --- | --- |
 * | `runtime.js` | the cache, the transport and the resolver — its `core/dns/` edge |
 * | this file | every protocol check, over the resolver handle it is handed |
 *
 * Neither can do the other's job without an edge the matrix forbids, which is
 * what makes this split structural rather than stylistic.
 *
 * ── The three things that are PASSED ────────────────────────────────────
 *
 * The resolver handle, the two generated tables, and the platform's crypto.
 * Generated data is injected and never imported by its consumer: the spike
 * measured a four-rule public suffix fixture being silently replaced by the
 * real 10,239-rule list while 1,535 assertions still passed. A consumer that
 * imports its own data can never be handed different data by a test.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s protocol composition, unchanged — same factories, same
 * capabilities, same order. Task 6.1 moved it out of the last file under
 * `js/`; nothing about what is constructed or how changed with it.
 */
import { createCaaCheck } from '../core/caa/caa.js';
import { createMxAudit } from '../core/mx/mx.js';
import { createTlsaCheck } from '../core/transport/tlsa.js';
import { createDsMatcher } from '../core/dnssec/matching.js';
import { createDnssecCheck } from '../core/dnssec/chain.js';
import { createOrgDomain } from '../core/dmarc/org-domain.js';
import { createDmarcDiscovery } from '../core/dmarc/tree-walk.js';
import { createReportAuth } from '../core/dmarc/report-auth.js';
import { createDkimCheck } from '../core/dkim/dkim.js';
import { createSpfChecks } from '../core/spf/spf.js';
import { createAuditDomain } from './audit-domain.js';

/**
 * Build the audit over one resolver.
 *
 * Returns the coordinator plus the constructed parts, which the legacy engine
 * surface and the contract tests reach by name. Capabilities are destructured
 * in the BODY: `platform.test.mjs`'s ambient scan does not recognize a
 * destructured parameter as a declaration, and `crypto` is one of the names it
 * looks for.
 */
export function createAudit(capabilities) {
  const {
    // The resolver handle. §12: passed, never imported — this directory has no
    // edge to `core/dns/`.
    dohFetch, dohQuery, requireUsable, cleanAnswerData, optionalCheck,
    existenceFromResponse, dnsError,
    // The platform's crypto, and the two generated tables.
    crypto, publicSuffixRules, dkimSelectorCatalog,
  } = capabilities;

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
    analyzeDomain,
    // The constructed parts. Not the audit's public surface — `analyzeDomain`
    // is — but the names the legacy engine surface and the contract tests
    // reach by. Phase 6 retires the former; the latter are how a protocol
    // owner is exercised over a real transport.
    countSpfLookups, findSpfRedundancy, auditSpfSubnets,
    checkDKIM, catalogSelectors, spfSelectorSources, buildDkimSelectorList,
    isRecognizedDkimSelector, inspectDkimSelector, summarizeDkimKeys,
    validateDkimKeyStructure, dkimKeyRecords, dkimRecordSet,
    getOrganizationalDomain, discoverDmarc,
    resolveDestinationOrgDomains, checkExternalReportAuth,
    checkCAA, auditMxHosts, checkTlsa,
    matchDsToDnskeys, matchDsSet, checkDNSSEC,
  };
}
