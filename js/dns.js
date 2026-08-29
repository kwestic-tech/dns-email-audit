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
// uri.js and record-fields.js are no longer imported here: CAA, BIMI,
// MTA-STS and TLS-RPT own every call site, and Task 4.4 moved the last of
// them. Only DKIM/DNSSEC (base64) and MX/SPF (ip) still read core/shared/
// from this file.
import { base64ToBytes } from '../src/core/shared/base64.js';
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
  analyzeDmarc, emptyDmarcStatus, parseDmarcTag, parseDmarcUriList,
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
  createDkimCheck, analyzeDkimKey, parseDkimKeyTagList, validDkimSelector,
  DKIM_SELECTORS, DKIM_SCAN_BATCH_SIZE,
} from '../src/core/dkim/dkim.js';
import {
  createSpfChecks, analyzeSpf, parseSpfTerms, cidrContains, classifySpfSubnet,
  classifySpfSubnets, stripSpfQualifier, spfReferencedCatalogKeys,
} from '../src/core/spf/spf.js';
import { createDetectors } from '../src/providers/detectors.js';
import { createAuditContext } from '../src/audit/context.js';

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

  // Record selection must be case-insensitive. RFC 7489 and RFC 7208 tag names
  // are case-insensitive, so `V=DMARC1` and `V=SPF1` are valid records that a
  // case-sensitive startsWith() would silently discard — reporting a protected
  // domain as having no policy at all. False negatives are the worse error for
  // a security tool, so match liberally here and validate the contents later.
  function startsWithCI(value, prefix) {
    return String(value || '').slice(0, prefix.length).toLowerCase() === prefix.toLowerCase();
  }

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

  // Provider detection, Task 4.9. `isNullMx` is MX semantics owned by
  // core/mx/, and §12 gives providers/ an edge to core/shared/ only — so the
  // composition root injects it rather than letting providers import it.
  // Task 4.0 finding 4's end state is audit passing the derived BOOLEAN;
  // that needs src/audit/, so Phase 5 finishes it.
  const { detectDNSProvider, detectEmailProvider, detectHosting } =
    createDetectors({ isNullMx });

  // SPF, Task 4.8. Two of the three checks need the RAW handle as well as
  // layer 3, because countSpfLookups()'s fallback copies DnsError.kind.
  const { countSpfLookups, findSpfRedundancy, auditSpfSubnets } = createSpfChecks({
    dohQuery, dohFetch, requireUsable, cleanAnswerData,
  });

  // DKIM, Task 4.7. The catalog is generated data and the crypto is the
  // platform's, so both are passed. `spfReferencedCatalogKeys` is a
  // TRANSITIONAL collaborator, and since Task 4.8 it is SPF-OWNED: this
  // composition root imports it from core/spf/ and injects it, because §12
  // forbids a core/dkim -> core/spf edge and Task 4.0's ruling forbids copying
  // the grammar. checkDKIM()'s signature is unchanged. Phase 5 replaces this
  // with audit-derived input, which is where cross-protocol composition
  // belongs.
  const {
    checkDKIM, catalogSelectors, spfSelectorSources, buildDkimSelectorList,
    isRecognizedDkimSelector, inspectDkimSelector, summarizeDkimKeys,
    validateDkimKeyStructure, dkimKeyRecords, dkimRecordSet,
  } = createDkimCheck({
    dohFetch, requireUsable, cleanAnswerData, crypto, dkimSelectorCatalog,
    spfReferencedCatalogKeys,
  });

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

  /* ── Scoring model ──────────────────────────────────────────────────────
     One weighted 0–100 rubric. Weights live here as data so they can be
     inspected, tested and tuned without touching the logic.

     Two pillars are deliberately asymmetric:
      • DMARC carries the most weight — it is the richest signal available and
        the only one that makes SPF and DKIM enforceable.
      • DNSSEC counts for points AND gates the A tier. An unsigned zone means
        every record above it can be spoofed, so it is not merely additive.
     ───────────────────────────────────────────────────────────────────────── */

  var WEIGHTS = {
    dmarc: 30, spf: 15, dkim: 15, dnssec: 15,
    caa: 10, mtaSts: 8, bimi: 4, tlsRpt: 3,
  };

  // Parked domains (an explicit null MX) are scored on a different rubric: DKIM, BIMI,
  // MTA-STS and TLS-RPT are meaningless without mail flow, so the weight
  // redistributes onto the checks that actually harden an unused domain.
  var PARKED_WEIGHTS = { spf: 30, dmarc: 30, dnssec: 25, caa: 15 };

  var GRADE_THRESHOLDS = [
    { min: 85, grade: 'A++', cls: 'score-aplusplus', requiresDnssec: true },
    { min: 75, grade: 'A+', cls: 'score-aplus', requiresDnssec: true },
    { min: 65, grade: 'A', cls: 'score-a', requiresDnssec: true },
    { min: 50, grade: 'B', cls: 'score-b', requiresDnssec: false },
    { min: 30, grade: 'C', cls: 'score-c', requiresDnssec: false },
    { min: 10, grade: 'D', cls: 'score-d', requiresDnssec: false },
    { min: 0, grade: 'F', cls: 'score-f', requiresDnssec: false },
  ];

  /**
   * DMARC sub-score, 0–30 (RFC 9989). Returns the component breakdown so the
   * UI can explain the number rather than just assert it.
   *
   * Changed from the RFC 7489 rubric: `pct` no longer earns points, because
   * RFC 9989 removed the tag and conformant receivers ignore it. Its four
   * points moved to `policy` (+2), `rua` (+1) and a new `uris` component (+1)
   * that pays for report destinations receivers can actually deliver to —
   * reporting is now standards-track in its own right (RFC 9990 / 9991), and
   * a record whose rua= is malformed is a monitoring blind spot.
   *
   * Test mode (`t=y`) scores at the `none` tier regardless of what p= says,
   * because receivers are explicitly told not to apply the policy.
   */
  function calcDmarcScore(d) {
    var parts = { policy: 0, subdomain: 0, rua: 0, alignment: 0, ruf: 0, uris: 0 };
    // 'present' = a record receivers cannot act on (bad v=, unrecognised p=,
    // duplicate tags). Worth no more than having no record at all.
    if (!d || d.status === 'missing' || d.status === 'present'
      || d.status === 'permerror' || d.status === 'unknown') {
      return { pts: 0, parts: parts };
    }

    // Score what receivers will actually do, not what the record claims.
    parts.policy = { reject: 12, quarantine: 8, none: 3 }[d.effectivePolicy || d.policy] || 0;

    // Score the EFFECTIVE subdomain posture, not whether sp/np are written out.
    // Absent tags inherit p, so `p=reject` alone protects subdomains fully.
    // Take the weaker of the two branches — security is the weakest link.
    // Test mode collapses the whole record to none, subdomains included.
    var subRank = d.testMode ? 0 : Math.min(
      POLICY_RANK[d.effectiveSp] !== undefined ? POLICY_RANK[d.effectiveSp] : 0,
      POLICY_RANK[d.effectiveNp] !== undefined ? POLICY_RANK[d.effectiveNp] : 0
    );
    parts.subdomain = [1, 4, 6][subRank] || 0;

    if (d.rua) parts.rua = 6;
    if (d.adkim === 's') parts.alignment += 1.5;
    if (d.aspf === 's') parts.alignment += 1.5;
    if (d.ruf) parts.ruf = 2;

    // Deliverable report destinations. Nothing published earns nothing; a
    // published-but-unparseable destination earns nothing either, which is the
    // point — it looks configured and silently is not.
    if (d.ruaUris && d.ruaUris.valid && (!d.ruf || (d.rufUris && d.rufUris.valid))) parts.uris = 1;

    var total = parts.policy + parts.subdomain + parts.rua + parts.alignment + parts.ruf + parts.uris;
    return { pts: Math.round(Math.min(WEIGHTS.dmarc, total)), parts: parts };
  }

  /**
   * SPF sub-score, 0–15.
   *
   * A record that exceeds the 10-lookup limit evaluates to permerror, which
   * receivers treat as a failure — so it scores zero regardless of how strict
   * the qualifier looks. Likewise `+all` and `?all` authorise everyone and are
   * worth nothing, while a missing provider include is a real record one line
   * short and keeps partial credit.
   */
  function calcSpfScore(spfStatus, advanced) {
    if (!spfStatus || spfStatus.status === 'missing' || spfStatus.status === 'permerror') return 0;
    if (advanced && advanced.spfLookups && advanced.spfLookups.error) return 0;

    var warnings = spfStatus.warnings || [];
    var worthless = warnings.indexOf('spf-all-permit') !== -1 || warnings.indexOf('spf-neutral') !== -1;
    if (worthless) return 0;

    if (spfStatus.status === 'ok') return WEIGHTS.spf;        // -all
    if (spfStatus.status === 'softfail') return 10;           // ~all
    return 8;                                                 // present, or missing include
  }

  function gradeFor(pts, dnssecSigned) {
    for (var i = 0; i < GRADE_THRESHOLDS.length; i++) {
      var tier = GRADE_THRESHOLDS[i];
      if (pts < tier.min) continue;
      if (tier.requiresDnssec && !dnssecSigned) continue;
      return { grade: tier.grade, cls: tier.cls };
    }
    return { grade: 'F', cls: 'score-f' };
  }

  function calcAdvScore(adv) {
    if (!adv) return null;
    const checks = [
      adv.bimi?.present,
      adv.mtaSts?.policyVerified,
      adv.tlsRpt?.present,
      adv.caa?.found,
      adv.dnssec?.signed,
    ];
    // A check whose lookup failed is neither done nor outstanding, so it comes
    // out of the denominator rather than counting against the domain.
    const unknown = [
      adv.bimi?.unknown,
      adv.mtaSts?.unknown,
      adv.tlsRpt?.unknown,
      adv.caa?.unknown,
      adv.dnssec?.state === 'indeterminate',
    ].filter(Boolean).length;
    return { done: checks.filter(Boolean).length, total: 5 - unknown, unknown: unknown };
  }

  /* ── Issues & suggestions ───────────────────────────────────────────── */

  // Each issue carries a key (→ locale lookup) and optional `args` used to
  // fill {0} placeholders in the translated message.
  function buildIssues({ emailProvider, spfStatus, spfRecords, dkimStatus, dmarcStatus, dmarcDiscovery, dmarcExistence, externalReportDestinations, reportPlan, wildcardApex, wildcardDkim, hosting, advanced, domain }) {
    const issues = [];

    // Reported by the depth that was actually measured. A wildcard only the
    // apex probe sees never reaches DKIM, and is often deliberate: Apple
    // publishes `*.apple.com IN TXT "v=spf1 redirect=_spf.apple.com"` so mail
    // from an invented subdomain meets a real SPF policy instead of none. Worth
    // reporting, not worth penalising.
    if (wildcardDkim) issues.push({ key: 'wildcard-txt-dkim', sev: 'warn' });
    else if (wildcardApex) issues.push({ key: 'wildcard-txt-apex', sev: 'info' });
    if (hosting === '@cname-loop') issues.push({ key: 'dns-loop', sev: 'crit' });
    if (emailProvider === '@none') issues.push({ key: 'no-mx', sev: 'crit' });
    if (emailProvider === '@implicit-mx') issues.push({ key: 'implicit-mx', sev: 'warn' });
    // Multiple-record failures come first: the fix ("delete the duplicate")
    // differs from the missing-record fix ("publish one"), and a domain in this
    // state must not also be told its record is absent.
    // The count is part of the evidence: "Multiple SPF records found" with a
    // single valid-looking record beside it reads as a bug in this tool, which
    // is how it was reported. Saying "2" costs nothing and matches how
    // `dkim-multiple-records` already names its selectors.
    if (spfStatus.status === 'permerror') {
      issues.push({ key: 'spf-multiple-records', sev: 'crit', args: [(spfRecords || []).length || 2] });
    }
    else if (spfStatus.status === 'missing') issues.push({ key: 'spf-missing', sev: 'crit' });

    // Content warnings are moot on a permerror — the record never evaluates, and
    // 'spf-multiple-records' is already raised above as critical. Re-pushing it
    // here would list the same finding twice at two severities.
    if (spfStatus.status !== 'permerror') {
      spfStatus.warnings.forEach(key => {
        issues.push({ key, sev: 'warn' });
      });
    }

    if (!dkimStatus.found && dkimStatus.confidence !== 'not-checked' && emailProvider !== '@none' && emailProvider !== '@null-mx' && emailProvider !== '@porkbun-forwarding') {
      // The note strings take the completed and failed selector counts. Carry
      // them on the issue: without them the renderer emits the raw "{0}"/"{1}"
      // placeholders, and a failed lookup now makes that note far more common.
      var testedCount = (dkimStatus.testedSelectors || []).length;
      var failedCount = (dkimStatus.failedSelectors || []).length;
      issues.push({
        key: dkimStatus.confidence === 'sampled' ? 'dkim-unverified' : 'dkim-missing',
        // An unfound selector now costs the full DKIM weight, so it is a
        // warning either way — 'info' was only defensible while the sampled
        // case went unscored.
        sev: 'warn',
        noteKey: dkimStatus.note,
        noteArgs: [testedCount - failedCount, failedCount],
      });
    }

    // Turning off "Check DKIM selectors" is a deliberate opt-out, so the guard
    // above correctly refuses to call it a missing record. But the pillar still
    // scores zero, and 15 points vanishing with nothing said about them is
    // worse than the grade range this replaced. Name the trade instead.
    if (dkimStatus.confidence === 'not-checked' && emailProvider !== '@none' && emailProvider !== '@null-mx' && emailProvider !== '@porkbun-forwarding') {
      issues.push({ key: 'dkim-not-checked', sev: 'info' });
    }
    /* Duplicate records are no longer a policy verdict, so the finding is
       raised from the walk's own evidence rather than from a `permerror`
       status that the Tree Walk never produces. It stays CRITICAL: publishing
       two records at one name makes every receiver ignore both, and an auditor
       that reported only "no DMARC record" would be describing the symptom
       instead of the cause.

       What changes is that the message must not lie. When a record higher in
       the tree still governs, the finding says the duplicate is ignored AND
       names the policy that actually applies — never "no DMARC policy
       applies", because one does. That is the entire point of the corrected
       walk. Hence two keys rather than one. */
    var observed = (dmarcDiscovery && dmarcDiscovery.observed) || [];
    var observedWhere = function (why) { return observed.filter(function (o) { return o.why === why; }); };
    var duplicates = observedWhere('multiple-at-step');
    if (duplicates.length) {
      issues.push(dmarcStatus.status === 'missing' || dmarcStatus.status === 'permerror'
        ? { key: 'dmarc-multiple-records', sev: 'crit', args: [duplicates[0].queryName] }
        : {
          key: 'dmarc-multiple-records-inherited', sev: 'crit',
          args: [duplicates[0].queryName, dmarcDiscovery.applied.foundAt, dmarcStatus.effectivePolicy || dmarcStatus.policy],
        });
    }
    if (dmarcStatus.status === 'unknown') {
      issues.push({
        key: 'dmarc-unverified', sev: 'warn',
        args: [(dmarcDiscovery && dmarcDiscovery.error) || 'dns-error'],
      });
    } else if (dmarcStatus.status === 'permerror' && !duplicates.length) issues.push({ key: 'dmarc-multiple-records', sev: 'crit', args: ['_dmarc.' + domain] });
    else if (dmarcStatus.status === 'missing' && !duplicates.length) issues.push({ key: 'dmarc-missing', sev: 'warn' });

    /* A misplaced or miscased v= tag is now diagnosed as misplaced rather than
       reported as absent. These never change the policy verdict — the record
       genuinely is not one a receiver will read — they change the message from
       "you have no DMARC record" to "you have a DMARC record that no receiver
       will read, and here is why". */
    var governed = !!(dmarcDiscovery && dmarcDiscovery.applied);
    var DIAGNOSIS_KEYS = {
      'version-not-first': 'dmarc-version-not-first',
      'version-bad-case': 'dmarc-version-bad-value',
      'version-absent': 'dmarc-version-missing',
    };
    Object.keys(DIAGNOSIS_KEYS).forEach(function (why) {
      var hits = observedWhere(why);
      // Name the DNS name the broken record is actually at. The walk visits up
      // to eight names, so the defect may well be at a parent the operator does
      // not control, and an unlocated "your record is malformed" sends them
      // looking in the wrong zone.
      if (hits.length) issues.push({ key: DIAGNOSIS_KEYS[why], sev: 'crit', args: [hits[0].queryName] });
    });

    /* A record on the apex is only critical when it is the operator's ONLY
       DMARC record. Alongside a working `_dmarc` record it is a leftover copy —
       untidy, not dangerous — and the critical text asserting that "the domain
       is treated as having no DMARC policy at all" would simply be false. Same
       rule as the duplicate finding above: the message must never claim no
       policy applies when one does. */
    var apex = observedWhere('at-apex-not-underscore');
    if (apex.length) {
      issues.push(governed
        ? { key: 'dmarc-at-apex-ignored', sev: 'info', args: [dmarcDiscovery.applied.foundAt] }
        : { key: 'dmarc-at-apex', sev: 'crit' });
    }
    if (dmarcStatus.status === 'warn' && dmarcStatus.policy === 'none') issues.push({ key: 'dmarc-none', sev: 'warn' });
    // p=quarantine is real enforcement, so this is a nudge rather than a defect —
    // reject is the end state, and nothing else surfaces that gap.
    if (dmarcStatus.status === 'ok' && dmarcStatus.policy === 'quarantine') issues.push({ key: 'dmarc-quarantine', sev: 'info' });
    // Test mode without reporting is the one combination that makes no sense
    // at all: t=y exists so you can watch the reports before enforcing.
    if ((dmarcStatus.status === 'ok' || dmarcStatus.testMode) && !dmarcStatus.rua) {
      issues.push({ key: 'dmarc-no-rua', sev: 'info' });
    }

    // Subdomain gaps only matter where the effective policy is genuinely weaker
    // than the organizational one — an absent sp/np inherits p and is fine.
    if (dmarcStatus.enforcing && POLICY_RANK[dmarcStatus.effectiveSp] < POLICY_RANK[dmarcStatus.policy]) {
      issues.push({ key: 'dmarc-weak-sp', sev: 'warn', args: [dmarcStatus.effectiveSp, dmarcStatus.policy] });
    }
    if (dmarcStatus.enforcing && POLICY_RANK[dmarcStatus.effectiveNp] < POLICY_RANK[dmarcStatus.policy]) {
      issues.push({ key: 'dmarc-weak-np', sev: 'warn', args: [dmarcStatus.effectiveNp, dmarcStatus.policy] });
    }

    /* ── RFC 9989 conformance ──────────────────────────────────────────────
       Severity here tracks consequence, not spec pedantry. A record receivers
       must ignore is critical; a policy that silently is not being applied is
       a warning; a tag that has simply stopped meaning anything is info.
       ───────────────────────────────────────────────────────────────────── */

    // v= absent, not first, or not exactly 'DMARC1' → the whole record MUST be
    // ignored (RFC 9989 §4.7). Since the Tree Walk's strict pass is
    // validateDmarcVersion() itself, no record with a bad v= is ever applied,
    // so that case now arrives through the diagnosis block above instead. What
    // is left here is a record receivers WILL read and cannot act on.
    if (dmarcStatus.status === 'present' && dmarcStatus.duplicateTags && dmarcStatus.duplicateTags.length) {
      issues.push({ key: 'dmarc-duplicate-tags', sev: 'crit', args: [dmarcStatus.duplicateTags.join(', ')] });
    } else if (dmarcStatus.status === 'present') {
      issues.push({ key: 'dmarc-invalid-policy', sev: 'crit' });
    }

    // t=y: receivers are told not to apply the policy. `p=reject; t=y` offers
    // exactly as much protection as p=none, so this is the headline finding
    // for such a record, not a footnote.
    if (dmarcStatus.testMode && dmarcStatus.status !== 'missing' && dmarcStatus.status !== 'permerror') {
      issues.push({ key: 'dmarc-test-mode', sev: dmarcStatus.policy === 'none' ? 'info' : 'warn', args: [dmarcStatus.policy] });
    }
    if (dmarcStatus.tValid === false) issues.push({ key: 'dmarc-bad-t', sev: 'warn' });

    /* Tag values that parse but are not what the operator wrote.
       normalizePolicy() and the alignment defaults both fall back silently,
       which is the correct RECEIVER behaviour and a poor auditor one: an
       `sp=rejcet` inherits p= and looks deliberate in the record. Report the
       divergence and name the value, without changing what receivers do. */
    if (dmarcStatus.spState === 'invalid') issues.push({ key: 'dmarc-bad-sp', sev: 'warn', args: [dmarcStatus.spRaw] });
    if (dmarcStatus.npState === 'invalid') issues.push({ key: 'dmarc-bad-np', sev: 'warn', args: [dmarcStatus.npRaw] });
    if (dmarcStatus.adkimState === 'invalid') issues.push({ key: 'dmarc-bad-adkim', sev: 'warn', args: [dmarcStatus.adkimRaw] });
    if (dmarcStatus.aspfState === 'invalid') issues.push({ key: 'dmarc-bad-aspf', sev: 'warn', args: [dmarcStatus.aspfRaw] });

    /* np= applies to NON-EXISTENT subdomains of the Organizational Domain
       (RFC 9989 §4.10.1). It was previously carried into the audited name's
       verdict without ever testing whether that name exists — and it plainly
       does, or the NS lookup would have returned NXDOMAIN. Say so, so the
       reported policy is explicable: the record's np= is real, it is simply
       not the branch that governs here. */
    if (dmarcStatus.inherited && dmarcExistence === 'yes' && dmarcStatus.npState !== 'absent'
      && POLICY_RANK[dmarcStatus.effectiveNp] !== POLICY_RANK[dmarcStatus.effectiveSp]) {
      issues.push({ key: 'dmarc-np-not-applied', sev: 'info', args: [dmarcStatus.effectiveNp, dmarcStatus.effectiveSp] });
    }

    // pct= was removed by RFC 9989. "This tag is obsolete, remove it" is advice
    // rather than a defect, so it is raised as a recommendation (see
    // buildSuggestions) and not repeated here. What DOES belong here is the
    // subset with a live consequence: a pct that receivers still on RFC 7489
    // will act on differently from receivers that have migrated.
    if (dmarcStatus.pctPresent && dmarcStatus.enforcing && dmarcStatus.pctValid && dmarcStatus.pct < 100) {
      issues.push({ key: 'dmarc-partial-pct', sev: 'warn', args: [dmarcStatus.pct, 100 - dmarcStatus.pct] });
    }
    if (dmarcStatus.status !== 'missing' && !dmarcStatus.pctValid) {
      issues.push({ key: 'dmarc-bad-pct', sev: 'warn' });
    }

    // Report destinations that will not receive anything.
    if (dmarcStatus.rua && dmarcStatus.ruaUris && !dmarcStatus.ruaUris.valid) {
      issues.push({ key: 'dmarc-rua-invalid', sev: 'warn', args: [dmarcStatus.ruaUris.invalid.join(', ')] });
    }
    if (dmarcStatus.ruf && dmarcStatus.rufUris && !dmarcStatus.rufUris.valid) {
      issues.push({ key: 'dmarc-ruf-invalid', sev: 'warn', args: [dmarcStatus.rufUris.invalid.join(', ')] });
    }
    // fo= is defined only alongside ruf=; without it, receivers MUST ignore it.
    if (dmarcStatus.foPresent && !dmarcStatus.ruf) issues.push({ key: 'dmarc-fo-without-ruf', sev: 'info' });
    if (dmarcStatus.foValid === false) issues.push({ key: 'dmarc-bad-fo', sev: 'warn' });

    /* Reports sent outside the organizational domain need the destination to
       authorize them (RFC 9990 §4), or conformant receivers drop them
       silently. Authorization is per URI, so this reports per destination —
       one unauthorized vendor does not invalidate the record or stop reports
       reaching the other destinations.

       When the lookup ran, say only what it found: a domain whose vendor has
       published the record correctly should hear nothing at all. The blanket
       "verify this" notice is the fallback for when the check did not run. */
    // Resolved by analyzeDomain with a Tree Walk per destination (RFC 9990 §4).
    // The fallback keeps buildIssues callable on its own in tests, where no
    // walk has run and every destination is compared against the bare name.
    var externalReports = externalReportDestinations || findExternalReportDestinations(dmarcStatus, domain);
    if (externalReports.length) {
      var reportAuth = advanced && advanced.reportAuth;
      if (reportAuth && reportAuth.length) {
        var unauthorized = reportAuth.filter(function (r) { return r.state === 'unauthorized'; });
        var unverifiable = reportAuth.filter(function (r) { return r.state === 'unverifiable'; });
        var mismatched = reportAuth.filter(function (r) { return r.state === 'override-mismatch'; });
        if (mismatched.length) {
          issues.push({
            key: 'dmarc-external-override-mismatch', sev: 'warn',
            args: [
              mismatched.map(function (r) { return r.destination; }).join(', '),
              mismatched.map(function (r) { return r.override; }).join(', '),
            ],
          });
        }
        if (unauthorized.length) {
          issues.push({
            key: 'dmarc-external-unauthorized', sev: 'warn',
            args: [unauthorized.map(function (r) { return r.destination; }).join(', ')],
          });
        }
        if (unverifiable.length) {
          issues.push({
            key: 'dmarc-external-unverifiable', sev: 'info',
            args: [unverifiable.map(function (r) { return r.destination; }).join(', ')],
          });
        }
      } else {
        issues.push({ key: 'dmarc-external-reporting', sev: 'info', args: [externalReports.join(', ')] });
      }
    }

    if (reportPlan && reportPlan.omitted && reportPlan.omitted.length) {
      issues.push({
        key: 'dmarc-report-destinations-truncated', sev: 'info',
        args: [reportPlan.total - reportPlan.omitted.length, reportPlan.total, reportPlan.omitted.join(', ')],
      });
    }

    if (dmarcStatus.psdValid === false) issues.push({ key: 'dmarc-bad-psd', sev: 'warn' });
    /* `dmarc-psd-invalid` was removed here. It asked the Public Suffix List
       whether a psd=y declaration was justified, which broke OQ-DMARC-04's
       invariant that no DMARC decision consults the PSL — and, worse, it asked
       about the AUDITED name rather than the name carrying the applied record.
       A domain inheriting the valid `_dmarc.gov` PSD record (psd=y, applied
       from `gov`) is its own PSL organizational domain, so the check fired and
       called a correct CISA-operated declaration invalid: a false positive on
       the exact inherited-PSD case this release adds. There is no DNS-only test
       that disproves a psd= declaration — the declaration is the protocol's own
       source of truth — and a vendored list snapshot is not evidence strong
       enough for "this domain is not a public suffix". `dmarc-bad-psd` above
       still checks the value vocabulary, which is protocol-defined.
       Reconsidered for 0.6.0, it would have to be explicitly heuristic,
       informational, and evaluated at `dmarcDiscovery.applied.foundAt`. */
    if (dmarcStatus.removedTags && dmarcStatus.removedTags.length) {
      var stillRemoved = dmarcStatus.removedTags.filter(function (k) { return k !== 'pct'; });
      if (stillRemoved.length) issues.push({ key: 'dmarc-removed-tags', sev: 'info', args: [stillRemoved.join(', ')] });
    }
    if (dmarcStatus.unknownTags && dmarcStatus.unknownTags.length) {
      issues.push({ key: 'dmarc-unknown-tags', sev: 'info', args: [dmarcStatus.unknownTags.join(', ')] });
    }
    if (emailProvider === '@porkbun-forwarding') issues.push({ key: 'porkbun-forward', sev: 'warn' });

    // Silently-inactive controls: configured, believed working, not working.
    if (advanced?.mtaSts?.multiple) issues.push({ key: 'mta-sts-multiple-records', sev: 'warn' });
    else if (advanced?.mtaSts?.advertised && !advanced.mtaSts.present) issues.push({ key: 'mta-sts-invalid', sev: 'warn' });
    else if (advanced?.mtaSts?.present && !advanced.mtaSts.policyVerified) issues.push({ key: 'mta-sts-policy-unverified', sev: 'info' });
    if (advanced?.tlsRpt?.multiple) issues.push({ key: 'tls-rpt-multiple-records', sev: 'warn' });
    else if (advanced?.tlsRpt?.advertised && !advanced.tlsRpt.present) issues.push({ key: 'tls-rpt-invalid', sev: 'warn' });
    if (advanced?.bimi?.multiple) issues.push({ key: 'bimi-multiple-records', sev: 'warn' });
    // A declination is a valid record that asserts no indicator, so it is
    // neither present nor invalid.
    else if (advanced?.bimi?.advertised && !advanced.bimi.present && !advanced.bimi.declined) issues.push({ key: 'bimi-invalid', sev: 'warn' });
    if (dkimStatus?.duplicated?.length) {
      issues.push({ key: 'dkim-multiple-records', sev: 'warn', args: [dkimStatus.duplicated.join(', ')] });
    }

    if (advanced?.spfLookups?.error) {
      issues.push({ key: 'spf-over-limit', sev: 'crit', args: [advanced.spfLookups.count] });
    } else if (advanced?.spfLookups?.warning) {
      issues.push({ key: 'spf-near-limit', sev: 'warn', args: [advanced.spfLookups.count] });
    }
    if (advanced?.spfLookups?.cycles?.length) issues.push({ key: 'spf-cycle', sev: 'crit', args: [advanced.spfLookups.cycles.join(', ')] });

    // Advisory only — none of this moves the score (see calcScore). Severity
    // here is deliberately below the spec's own HIGH/MEDIUM labels, which the
    // structured findings still carry: a large block is a thing to look at,
    // not a misconfiguration. irs.gov, github.com, bbc.co.uk and
    // cloudflare.com all publish one, and putting them on the same line as
    // "no SPF record" would teach people to ignore the critical list.
    //
    // Grouped one line per tier rather than one per mechanism. Per-mechanism
    // lines drown the report: stanford.edu publishes 15 ip4: mechanisms and
    // nih.gov six medium blocks, and the single-host ones say nothing at all,
    // so the LOW tier is classified but never surfaced as an issue.
    if (advanced?.spfSubnets) {
      const subnets = advanced.spfSubnets.subnets || [];
      const large = subnets.filter(s => s.severity === 'HIGH').map(s => s.mechanism);
      const medium = subnets.filter(s => s.severity === 'MEDIUM').map(s => s.mechanism);
      if (large.length) issues.push({ key: 'spf-large-subnet', sev: 'warn', args: [large.join(', ')] });
      if (medium.length) issues.push({ key: 'spf-medium-subnet', sev: 'info', args: [medium.join(', ')] });

      // Removing one a/mx mechanism frees exactly one of the 10 lookups, so
      // the advice is worth much more next to the current count than alone.
      const lookups = advanced.spfLookups;
      const counted = lookups && !lookups.unknown && !lookups.indeterminate ? lookups.count : null;
      (advanced.spfSubnets.redundancy || []).forEach(finding => {
        if (!finding.full) {
          issues.push({ key: 'spf-partial-coverage', sev: 'info', args: [finding.covered, finding.total, finding.mechanism] });
        } else if (counted === null) {
          issues.push({ key: 'spf-redundant-mechanism-nocount', sev: 'info', args: [finding.mechanism, finding.coveredBy.join(', ')] });
        } else {
          issues.push({ key: 'spf-redundant-mechanism', sev: 'info', args: [finding.mechanism, finding.coveredBy.join(', '), counted, counted - 1] });
        }
      });
    }
    if (advanced?.spfLookups?.indeterminate) issues.push({ key: 'spf-indeterminate', sev: 'info' });

    /* ── DKIM key strength (RFC 8301, RFC 6376, RFC 8463) ──────────────────
       Grouped one line per condition rather than one per selector: a domain
       running six selectors at 1024 bits would otherwise contribute six
       identical informational lines and bury everything else.

       The 1024-bit line is INFORMATIONAL on purpose, and that was decided by
       counting rather than arguing (OQ-DEPTH-05). Across the 40-domain
       backtest sample, 35 of 66 keys are RSA-1024 — on 21 of the 27 domains
       that publish DKIM at all, Microsoft, GitHub, Apple, PayPal, Stripe and
       the EFF among them. A warning firing on ~78% of audited domains is not
       a signal, it is a thing people learn to scroll past, and it would take
       the genuinely critical sub-1024 line down with it.
       ───────────────────────────────────────────────────────────────────── */
    var dkimKeys = (dkimStatus?.selectors || []).filter(function (entry) { return entry.key; });
    var byCondition = function (predicate) {
      return dkimKeys.filter(function (entry) { return predicate(entry.key); })
        .map(function (entry) { return entry.sel; });
    };
    // Syntax evidence is wider than usable signing keys. Revoked, service-
    // scoped and missing-p= candidates can all be malformed too; restricting
    // these findings to `selectors` made the most broken records disappear
    // from the very diagnostics intended to explain them.
    var dkimEvidence = dkimKeys
      .concat(dkimStatus?.unusableSelectors || [])
      .concat(dkimStatus?.revokedSelectors || [])
      .concat(dkimStatus?.malformedSelectors || []);
    var evidenceByCondition = function (predicate) {
      return Array.from(new Set(dkimEvidence.filter(function (entry) {
        return entry.key && predicate(entry.key);
      }).map(function (entry) { return entry.sel; })));
    };

    var weakKeys = dkimKeys.filter(function (e) { return typeof e.key.keyBits === 'number' && e.key.keyBits < 1024; });
    if (weakKeys.length) {
      issues.push({ key: 'dkim-key-weak', sev: 'crit', args: [
        weakKeys.map(function (e) { return e.sel + ' (' + e.key.keyBits + ')'; }).join(', '),
      ] });
    }
    var thousandKeys = byCondition(function (k) { return k.keyBits === 1024; });
    if (thousandKeys.length) issues.push({ key: 'dkim-key-1024', sev: 'info', args: [thousandKeys.join(', ')] });

    // Published at a selector, and not a key this domain's ordinary email can be
    // verified with — an unrecognized `k=`, or an `s=` scoped to another
    // service such as RFC 8460's `tlsrpt`. Informational because the record is
    // conformant and very likely deliberate; it is here so that a domain whose
    // only DKIM records are inapplicable is told why the audit found none,
    // rather than being told nothing exists at a name they configured.
    if (dkimStatus?.unusableSelectors?.length) {
      issues.push({ key: 'dkim-key-not-email', sev: 'info', args: [
        dkimStatus.unusableSelectors.map(function (r) { return r.sel; }).join(', '),
      ] });
    }

    if (dkimStatus?.revokedSelectors?.length) {
      issues.push({ key: 'dkim-key-revoked', sev: 'warn', args: [
        dkimStatus.revokedSelectors.map(function (r) { return r.sel; }).join(', '),
      ] });
    }

    // 'unparseable-key' is the truncated-p= case, which is a completely silent
    // DKIM failure: the record is present, the selector is found, and no
    // verifier can use it. 'key-structure-invalid' is the same outcome by a
    // different route. A key we could not check because the browser has no
    // Web Crypto is NOT here, and must never be — that is cryptoValidated:
    // null, and it means we said nothing, not that the key is bad.
    var DECODE_ERRORS = ['unparseable-key', 'key-structure-invalid', 'bad-ed25519-length'];
    var hasDecodeError = function (k) {
      return k.errors.some(function (e) { return DECODE_ERRORS.indexOf(e) !== -1; });
    };
    var brokenKeys = evidenceByCondition(hasDecodeError);
    if (brokenKeys.length) issues.push({ key: 'dkim-key-unparseable', sev: 'warn', args: [brokenKeys.join(', ')] });

    // Every other way a key record can be invalid. Without this, a record the
    // analyzer itself marks `valid: false` — an empty `h=`, a duplicated tag, a
    // bad version — counted as a found key and said nothing at all, so the
    // audit reported DKIM present on the strength of a record it knew was
    // malformed.
    var malformedKeys = evidenceByCondition(function (k) { return !k.valid && !hasDecodeError(k); });
    if (malformedKeys.length) issues.push({ key: 'dkim-key-malformed', sev: 'warn', args: [malformedKeys.join(', ')] });

    var testingKeys = byCondition(function (k) { return k.testing; });
    if (testingKeys.length) issues.push({ key: 'dkim-key-testing', sev: 'info', args: [testingKeys.join(', ')] });

    // Only when sha1 is the ONLY hash offered. `h=sha256:sha1` lets a verifier
    // choose SHA-256 and is not a finding; RFC 8301 deprecates sha1 as a
    // signing hash, not as an entry in a list.
    var sha1Keys = byCondition(function (k) {
      return k.hashAlgorithms.length > 0 && k.hashAlgorithms.every(function (h) { return h === 'sha1'; });
    });
    if (sha1Keys.length) issues.push({ key: 'dkim-key-sha1', sev: 'warn', args: [sha1Keys.join(', ')] });

    if (dkimStatus?.keyProfile?.mixed) {
      issues.push({ key: 'dkim-key-mixed', sev: 'info', args: [dkimStatus.keyProfile.minBits, dkimStatus.keyProfile.maxBits] });
    }

    /* ── CAA policy (RFC 8659, RFC 9495) ──────────────────────────────── */
    if (advanced?.caa?.found) {
      if (advanced.caa.issuanceBlocked) {
        issues.push({ key: 'caa-blocks-all-issuance', sev: 'warn', args: [advanced.caa.atDomain] });
      }
      // RFC 8659 §4.1: a CA that does not recognize a critical property MUST
      // refuse to issue. So this is an issuance outage waiting for the next
      // renewal, not a tidiness note — and it is invisible until then.
      if (advanced.caa.unknownCritical?.length) {
        issues.push({ key: 'caa-unknown-critical-tag', sev: 'warn', args: [advanced.caa.unknownCritical.join(', ')] });
      }
      if (advanced.caa.malformed?.length) {
        issues.push({ key: 'caa-malformed', sev: 'warn', args: [advanced.caa.malformed.join(', ')] });
      }
      if (!advanced.caa.iodef?.length) issues.push({ key: 'caa-no-iodef', sev: 'info' });
      // Distinct issuers, not record count: `issue` and `issuewild` for the
      // same CA is one issuer, and counting records would call it two.
      var caaIssuers = (advanced.caa.issuers || []).concat(advanced.caa.wildcardIssuers || [])
        .filter(function (v, i, all) { return all.indexOf(v) === i; });
      if (caaIssuers.length === 1 && !advanced.caa.issuanceBlocked) {
        issues.push({ key: 'caa-single-issuer', sev: 'info', args: [caaIssuers[0]] });
      }
    }

    /* ── MX health ────────────────────────────────────────────────────── */
    if (advanced?.mxHealth?.hosts?.length) {
      var mxHealth = advanced.mxHealth;
      // Critical, and the only critical finding in this group: an MX host that
      // does not resolve accepts no mail at all. Hosts we could not check are
      // 'unknown' and are deliberately not in this list.
      if (mxHealth.danglingHosts.length) {
        issues.push({ key: 'mx-dangling', sev: 'crit', args: [mxHealth.danglingHosts.join(', ')] });
      }
      // RFC 2181 §10.3 and RFC 5321 §5.1 both forbid it. It frequently works
      // anyway, which is why it survives in the wild and why it is a warning
      // rather than an error — it breaks in specific, hard-to-diagnose ways.
      if (mxHealth.cnameHosts.length) {
        issues.push({ key: 'mx-cname-target', sev: 'warn', args: [mxHealth.cnameHosts.join(', ')] });
      }
      if (mxHealth.singleHost) issues.push({ key: 'mx-single-host', sev: 'info', args: [mxHealth.hosts[0].host] });
      if (mxHealth.ipv6Coverage === 'none') issues.push({ key: 'mx-no-ipv6', sev: 'info' });
      mxHealth.sharedPrefixes.forEach(function (group) {
        issues.push({ key: 'mx-same-prefix', sev: 'info', args: [group.prefix, group.hosts.join(', ')] });
      });
      if (mxHealth.duplicatePreferences.length) {
        issues.push({ key: 'mx-duplicate-preference', sev: 'info', args: [mxHealth.duplicatePreferences.join(', ')] });
      }
    }

    /* ── TLSA / DANE ──────────────────────────────────────────────────── */
    if (advanced?.tlsa?.anyPresent) {
      var tlsa = advanced.tlsa;
      // Gated on the per-host AD bit, which is the only chain fact that
      // applies to a name in someone else's zone. The audited domain's own
      // DNSSEC state is deliberately NOT consulted here: it would tell a
      // correctly signed zone that its DANE is unprotected, or the reverse,
      // on evidence about an unrelated zone.
      if (tlsa.unauthenticatedHosts.length) {
        issues.push({ key: 'tlsa-published-unsigned', sev: 'warn', args: [tlsa.unauthenticatedHosts.join(', ')] });
      }
      var malformedTlsa = tlsa.hosts.filter(function (h) {
        return h.records.some(function (r) { return !r.valid; });
      }).map(function (h) { return h.host; });
      if (malformedTlsa.length) issues.push({ key: 'tlsa-malformed', sev: 'warn', args: [malformedTlsa.join(', ')] });

      // Only over hosts actually checked — a host whose lookup failed is not
      // evidence of missing coverage.
      var checked = tlsa.hosts.filter(function (h) { return !h.unknown; });
      var covered = checked.filter(function (h) { return h.present; });
      if (covered.length && covered.length < checked.length) {
        issues.push({ key: 'tlsa-partial-coverage', sev: 'info', args: [covered.length, checked.length] });
      }
    }

    /* ── DNSSEC ───────────────────────────────────────────────────────
       The state findings are mutually exclusive and follow the classifier's
       own order, so a domain is told one thing about its chain rather than
       three. `unanchored` and `mismatch` are the two this release exists to
       expose: both rendered as "DNSSEC not detected" before it, which told an
       operator who had signed their zone that they had not.
       ─────────────────────────────────────────────────────────────────── */
    var dnssec = advanced?.dnssec;
    if (dnssec?.state === 'bogus') issues.push({ key: 'dnssec-bogus', sev: 'crit' });
    else if (dnssec?.state === 'indeterminate') issues.push({ key: 'dnssec-indeterminate', sev: 'warn' });
    else if (dnssec?.state === 'mismatch') issues.push({ key: 'dnssec-mismatch', sev: 'crit' });
    else if (dnssec?.state === 'unanchored') issues.push({ key: 'dnssec-unanchored', sev: 'warn' });

    if (dnssec) {
      // Informational, and deliberately so. RFC 6840 §5.11 permits a DS whose
      // key is absent from the DNSKEY RRset, and `paypal.com` publishes one
      // beside a confirming DS while validating perfectly. Reported because an
      // operator usually wants to tidy it; never as a fault.
      if (dnssec.anchorConfirmed && dnssec.orphanDs?.length) {
        issues.push({ key: 'dnssec-ds-orphan', sev: 'info', args: [dnssec.orphanDs.join(', ')] });
      }
      if (dnssec.deprecatedAlgorithms?.length) {
        issues.push({
          key: 'dnssec-deprecated-algorithm', sev: 'warn',
          args: [dnssec.deprecatedAlgorithms.map(function (a) { return DNSSEC_ALGORITHMS[a] || a; }).join(', ')],
        });
      }
      if (dnssec.deprecatedDigests?.length) {
        issues.push({
          key: 'dnssec-deprecated-digest', sev: 'info',
          args: [dnssec.deprecatedDigests.map(function (d) { return DNSSEC_DIGESTS[d] || d; }).join(', ')],
        });
      }

      // Facts about a key a DS actually confirmed. Each is a reason the
      // delegation does not anchor despite the digest matching, and each is
      // reported separately because they have different remedies — except the
      // REVOKE flag, which is reported and concluded from nowhere.
      var confirmed = (dnssec.ds || []).filter(function (d) { return d.match === 'confirmed'; });
      var pushKeyFinding = function (key, predicate, severity) {
        var tags = confirmed.filter(predicate).map(function (d) { return d.matchedKeyTag; });
        if (tags.length) issues.push({ key: key, sev: severity, args: [tags.join(', ')] });
      };
      pushKeyFinding('dnssec-key-algorithm-ineligible',
        function (d) { return d.matchedKeyAlgorithmEligibility === 'ineligible'; }, 'warn');
      pushKeyFinding('dnssec-key-not-zone-key',
        function (d) { return d.matchedKeyHasZoneFlag === false; }, 'warn');
      pushKeyFinding('dnssec-key-malformed',
        function (d) { return d.matchedKeyStructure === 'invalid'; }, 'warn');

      // RFC 5011 §2.1 makes a key revoked only when a resolver sees it in a
      // self-signed RRset with the bit set. This release does not validate
      // RRSIGs, so the finding names the flag and stops there.
      var revoked = (dnssec.keys || []).filter(function (k) { return k.hasRevokeFlag; })
        .map(function (k) { return k.keyTag; });
      if (revoked.length) issues.push({ key: 'dnssec-revoke-flag', sev: 'info', args: [revoked.join(', ')] });
    }

    // Name the checks that could not be completed. An audit that quietly omits
    // a control looks identical to one where the control is fine, so the gap
    // has to be stated rather than left to the reader to notice. These now
    // score zero rather than sitting outside the grade, which is why this is a
    // warning: points were actually lost, and a re-run is what recovers them.
    var unverified = [];
    if (advanced?.caa?.unknown) unverified.push('CAA');
    if (advanced?.mtaSts?.unknown) unverified.push('MTA-STS');
    if (advanced?.tlsRpt?.unknown) unverified.push('TLS-RPT');
    if (advanced?.bimi?.unknown) unverified.push('BIMI');
    if (advanced?.spfLookups?.unknown) unverified.push('SPF');
    if (advanced?.mxHealth?.unknown) unverified.push('MX');
    if (advanced?.tlsa?.unknown) unverified.push('TLSA');
    if (hosting === '@dns-error') unverified.push('Website');
    if (unverified.length) {
      issues.push({ key: 'checks-unverified', sev: 'warn', args: [unverified.join(', ')] });
    }

    return issues;
  }

  // `guide` names the Learn more page to link to (see locales → learnMore).
  function buildSuggestions({ emailProvider, spfStatus, dkimStatus, dmarcStatus, advanced }) {
    const tips = [];

    // Deliberately ahead of the `advanced` guard: this one is derived from the
    // DMARC record alone, so it must still surface when the advanced checks
    // are switched off. RFC 9989 removed pct= outright — there is no valid
    // value any more, so the recommendation is always "remove it", whatever
    // the number says.
    if (dmarcStatus && dmarcStatus.pctPresent && dmarcStatus.status !== 'missing') {
      tips.push({ key: 'dmarc-pct-obsolete', guide: 'dmarc-rfc9989' });
    }

    if (!advanced) return tips;

    const hasEmail = emailProvider !== '@none' && emailProvider !== '@null-mx';
    const dmarcEnforced = dmarcStatus.status === 'ok' && (dmarcStatus.policy === 'quarantine' || dmarcStatus.policy === 'reject');

    // Every tip below says "you do not have this — add it". None of them may
    // fire on a check whose lookup failed, because we do not know whether the
    // record is there. Telling someone to publish a record they already have
    // is worse than saying nothing.
    if (advanced.bimi?.unknown) { /* not verified — cannot advise */ }
    else if (advanced.bimi?.declined) { /* the domain said no on purpose — do not sell it */ }
    else if (advanced.bimi?.multiple) { /* duplicate already raised as an issue */ }
    else if (!advanced.bimi?.present && dmarcEnforced && dkimStatus.found) tips.push({ key: 'bimiEligible', guide: 'bimi' });
    else if (!advanced.bimi?.present && hasEmail) tips.push({ key: 'bimiPrereq', guide: 'bimi' });

    // Skip the "not configured" tip when the record exists but is duplicated —
    // buildIssues already raises the duplicate, and telling someone to publish
    // a record they already have twice is actively confusing.
    if (!advanced.mtaSts?.unknown && !advanced.mtaSts?.present && !advanced.mtaSts?.multiple && hasEmail) tips.push({ key: 'mta-sts', guide: 'mta-sts' });
    if (!advanced.tlsRpt?.unknown && !advanced.tlsRpt?.present && !advanced.tlsRpt?.multiple && hasEmail) tips.push({ key: 'tls-rpt', guide: 'tls-rpt' });
    if (!advanced.caa?.unknown && !advanced.caa?.found) tips.push({ key: 'caa', guide: 'caa' });
    // "Enable DNSSEC" is wrong advice for a zone that is already signed. An
    // `unanchored` or `mismatch` domain has signed and has a specific finding
    // telling it what to finish, so the generic tip would contradict it.
    if (advanced.dnssec?.state === 'insecure') tips.push({ key: 'dnssec', guide: 'dnssec' });

    return tips;
  }

  /* ── Scoring ────────────────────────────────────────────────────────── */

  /**
   * Pillars that scored zero because this audit could not verify them, rather
   * than because the control is genuinely absent.
   *
   * This changes no score. The zero stands, the grade is a single letter, and
   * `pts` is unaffected — it exists so the UI can mark the grade as resting on
   * a check that a re-run or an extra selector could still settle. Without it
   * that fact lives only inside the expanded detail panel, which nobody opens
   * across a 200-domain table.
   *
   * SPF is deliberately absent: an unknown lookup *count* does not zero the SPF
   * pillar (see calcSpfScore), so there is no lost point to recover there.
   */
  function unprovenPillars(dkimStatus, advanced, dmarcStatus) {
    var out = [];
    // A DMARC pillar zeroed because the walk could not complete is unproven,
    // not absent. Without this the grade rests on a check that never ran and
    // says so nowhere — the exact gap 'dkim-unverified' exists to close.
    if (dmarcStatus && dmarcStatus.status === 'unknown') out.push('dmarc');
    if (dkimStatus && !dkimStatus.found &&
      (dkimStatus.confidence === 'sampled' || dkimStatus.confidence === 'not-checked')) out.push('dkim');
    if (advanced && advanced.dnssec && advanced.dnssec.state === 'indeterminate') out.push('dnssec');
    if (advanced && advanced.caa && advanced.caa.unknown) out.push('caa');
    if (advanced && advanced.mtaSts && advanced.mtaSts.unknown) out.push('mtaSts');
    if (advanced && advanced.bimi && advanced.bimi.unknown) out.push('bimi');
    if (advanced && advanced.tlsRpt && advanced.tlsRpt.unknown) out.push('tlsRpt');
    return out;
  }

  function calcScore({ emailProvider, spfStatus, dkimStatus, dmarcStatus, advanced }) {
    // A wildcard TXT record no longer scores an instant F. The furthest it can
    // reach is DKIM discovery, and SPF, DMARC, DNSSEC and CAA stay perfectly
    // measurable underneath it. A poisoned _domainkey leaves DKIM unproven,
    // which scores zero like every other unproven control here.
    var dnssecSigned = !!(advanced && advanced.dnssec && advanced.dnssec.signed);
    var dmarc = calcDmarcScore(dmarcStatus);

    // ── Parked / no-email domain ────────────────────────────────────────
    // Scored on PARKED_WEIGHTS: a domain that will never send mail is hardened
    // by refusing it outright (null MX + SPF -all + DMARC reject), so it can
    // legitimately reach the A tier. DKIM/BIMI/MTA-STS/TLS-RPT are excluded
    // because they cannot apply.
    if (emailProvider === '@null-mx') {
      var parkedSpf = 0;
      if (spfStatus.status === 'ok') parkedSpf = PARKED_WEIGHTS.spf;          // -all blocks
      else if (spfStatus.status !== 'missing') parkedSpf = 15;                // record, not blocking

      // Test mode collapses to none here too — a parked domain publishing
      // p=reject; t=y is not actually refusing anything.
      var parkedDmarc = { reject: 30, quarantine: 20, none: 8 }[dmarcStatus.effectivePolicy || dmarcStatus.policy] || 0;
      if (dmarcStatus.status === 'missing') parkedDmarc = 0;

      var parkedPillars = [
        { key: 'spf', pts: parkedSpf, max: PARKED_WEIGHTS.spf },
        { key: 'dmarc', pts: parkedDmarc, max: PARKED_WEIGHTS.dmarc },
        { key: 'dnssec', pts: dnssecSigned ? PARKED_WEIGHTS.dnssec : 0, max: PARKED_WEIGHTS.dnssec },
        { key: 'caa', pts: (advanced && advanced.caa && advanced.caa.found) ? PARKED_WEIGHTS.caa : 0, max: PARKED_WEIGHTS.caa },
      ];
      var parkedPts = parkedPillars.reduce(function (sum, p) { return sum + p.pts; }, 0);
      var parkedGrade = gradeFor(parkedPts, dnssecSigned);
      var parkedKeys = parkedPillars.map(function (p) { return p.key; });

      return {
        grade: parkedGrade.grade, cls: parkedGrade.cls,
        pts: parkedPts, max: 100, parked: true,
        // DKIM is not a parked pillar, so an unproven DKIM check cannot mark a
        // parked grade — there were no points to lose.
        unproven: unprovenPillars(dkimStatus, advanced, dmarcStatus).filter(function (k) { return parkedKeys.indexOf(k) !== -1; }),
        breakdown: { pillars: parkedPillars, dmarc: dmarc.parts },
      };
    }

    // ── Active email domain ─────────────────────────────────────────────
    // A control this audit could not prove scores zero, exactly like a control
    // that is genuinely absent. The alternative — leaving it unscored and
    // reporting a floor–ceiling grade range — reads as an error rather than a
    // result, and the two-letter grade told nobody what to do next. The cost of
    // that honesty is that a failed lookup now costs real points, so every
    // unproven control has an issue attached saying so and how to fix it:
    // 'dkim-unverified', 'dkim-not-checked', 'dnssec-indeterminate' and
    // 'checks-unverified' in buildIssues().
    var pillars = [
      { key: 'dmarc', pts: dmarc.pts, max: WEIGHTS.dmarc },
      { key: 'spf', pts: calcSpfScore(spfStatus, advanced), max: WEIGHTS.spf },
      { key: 'dkim', pts: dkimStatus && dkimStatus.found ? WEIGHTS.dkim : 0, max: WEIGHTS.dkim },
      { key: 'dnssec', pts: dnssecSigned ? WEIGHTS.dnssec : 0, max: WEIGHTS.dnssec },
      { key: 'caa', pts: (advanced && advanced.caa && advanced.caa.found) ? WEIGHTS.caa : 0, max: WEIGHTS.caa },
      { key: 'mtaSts', pts: (advanced && advanced.mtaSts && advanced.mtaSts.present && advanced.mtaSts.policyVerified !== false) ? WEIGHTS.mtaSts :
        (advanced && advanced.mtaSts && advanced.mtaSts.present) ? WEIGHTS.mtaSts / 2 : 0, max: WEIGHTS.mtaSts },
      { key: 'bimi', pts: (advanced && advanced.bimi && advanced.bimi.present) ? WEIGHTS.bimi : 0, max: WEIGHTS.bimi },
      { key: 'tlsRpt', pts: (advanced && advanced.tlsRpt && advanced.tlsRpt.present) ? WEIGHTS.tlsRpt : 0, max: WEIGHTS.tlsRpt },
    ];

    var pts = pillars.reduce(function (sum, p) { return sum + (p.pts || 0); }, 0);
    var graded = gradeFor(pts, dnssecSigned);

    return {
      grade: graded.grade, cls: graded.cls,
      pts: pts, max: 100, parked: false,
      unproven: unprovenPillars(dkimStatus, advanced, dmarcStatus),
      breakdown: { pillars: pillars, dmarc: dmarc.parts },
    };
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
      dkimStatus = await checkDKIM(d, { dkim: wildcardDkim, records: wildcardDkimRecords }, ctx.options.selectors, emailProvider, ctx.options.dkimComprehensive, spfRecord, queryOpts);
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

  return {
    // Re-exported rather than dropped. Nothing in the repository reads it, but
    // it is one of the engine's members and Task 3.1 is a move: a member
    // disappearing would be a surface change riding along with one.
    DOH: DOH_ENDPOINT,
    DKIM_SELECTORS,
    buildDkimSelectorList,
    catalogSelectors,
    spfSelectorSources,
    spfReferencedCatalogKeys,
    isRecognizedDkimSelector,
    checkDKIM,
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
    detectEmailProvider,
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
