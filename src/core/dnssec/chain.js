/**
 * DNSSEC chain evaluation. Spec Design §4 and §12, Task 4.5.
 *
 * ── Two axes, and keeping them apart is the whole design ────────────────
 *
 * `secure` comes ONLY from the resolver's AD verdict. The DS-to-DNSKEY
 * arithmetic in `matching.js` can diagnose a definite mismatch when AD is
 * already false, but it can never promote a zone to secure or demote one the
 * resolver authenticated. `servfail.nl` is why: its DS confirms its KSK by
 * SHA-256, its DNSKEY set is published, and the zone is bogus. Local evidence
 * agreeing is not the same as the chain validating.
 *
 * That is also why the matcher is PASSED in rather than constructed here: this
 * module decides state, and it must not be able to reach the crypto that could
 * tempt someone to derive state from it.
 *
 * ── A named raw-kind reader, and why ────────────────────────────────────
 *
 * `dnssecLookupStatus()` and `checkDNSSEC()` are two of spec §3's six allowed
 * raw-kind readers, moved here from `js/dns.js` by Task 4.5. They take
 * `dohFetch` WITHOUT `requireUsable`, deliberately:
 *
 * **`checkDNSSEC()` must never throw.** It is the only entry in the
 * `Promise.all` at the advanced-checks call site with no `optionalCheck()`
 * wrapper, and that is safe only because it reads `dohFetch()`'s `.kind`
 * rather than calling `requireUsable()`. Keep it that way, or add the wrapper
 * — `optionalCheck()` re-throws `DnsTypeError`, so a typo in a record type
 * still fails loudly either way.
 *
 * The validated-`servfail` path is the security reason the raw handle is
 * required and not merely convenient: a SERVFAIL that resolves with checking
 * disabled is the resolver saying validation FAILED, and that outranks every
 * local observation. A normalized array cannot express it, because a SERVFAIL
 * never becomes an array at all.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s `dnssecLookupStatus` and `checkDNSSEC`, unchanged apart from
 * the two-space dedent, the `export` keywords, and `checkDNSSEC` becoming the
 * body of a factory that names its three capabilities. Every rule, its order
 * and its evidence are byte-identical.
 */

import { dnskeyCanAnchor, matchConfirmsAnchor } from './matching.js';
import {
  parseDnskey, parseDs,
  DEPRECATED_DNSSEC_ALGORITHMS, DEPRECATED_DNSSEC_DIGESTS,
} from './records.js';

/** `checkDNSSEC().state`. Registry algebra `dnssec.state`. */
export const DNSSEC_STATES = Object.freeze([
  'secure', 'insecure', 'bogus', 'unanchored', 'mismatch', 'indeterminate',
]);

/** `checkDNSSEC().chain[].claim`. Registry algebra `dnssec.chain.claim`. */
export const DNSSEC_CHAIN_CLAIMS = Object.freeze([
  'resolver-bogus', 'resolver-unreachable', 'resolver-ad', 'link-checked',
  'ds-confirms-dnskey', 'ds-no-matching-key', 'ds-digest-mismatch',
  'ds-unverifiable', 'lookup-incomplete',
]);

/**
 * `checkDNSSEC().chain[].source`. Registry algebra `dnssec.chain.source`.
 *
 * Every claim says where it came from, because `resolver` and `local` are not
 * equally authoritative and a reader must be able to tell them apart.
 */
export const DNSSEC_CHAIN_SOURCES = Object.freeze(['resolver', 'local']);

/** `checkDNSSEC().evidence`. Registry algebra `dnssec.evidence`. */
export const DNSSEC_EVIDENCE = Object.freeze(['complete', 'partial', 'none']);

/**
 * A definite answer, as opposed to one that never arrived.
 *
 * `success` or `nodata` only, which is exactly what 0.4.0's `checkDNSSEC()`
 * accepted before rule 2 below inherited it. NXDOMAIN on the NS probe stays
 * `indeterminate` rather than becoming `insecure`: both score zero, but
 * `indeterminate` is what marks the DNSSEC pillar unproven in
 * `unprovenPillars()`, and quietly moving a domain out of that set would
 * change what the interface reports about a check that did not run.
 */
export function dnssecLookupStatus(result) {
  return {
    completed: result.kind === 'success' || result.kind === 'nodata',
    kind: result.kind,
  };
}

/**
 * The chain check, over a passed resolver and a passed matcher.
 *
 * Three capabilities, all arguments: §12 gives a protocol directory no edge to
 * `core/dns/`. `dohFetch` is the RAW handle — see the module note above;
 * `cleanAnswerData` because this module does layer 3's cleaning itself on the
 * answers its type filters kept; `matchDsSet` from `createDsMatcher()`, so the
 * crypto stays in the module that computes and out of the one that decides.
 */
export function createDnssecCheck({ dohFetch, cleanAnswerData, matchDsSet }) {
  /**
   * DNSSEC chain state, and the evidence behind it.
   *
   * Two axes, and keeping them apart is the whole design. `secure` comes only
   * from the resolver's AD verdict. The DS-to-DNSKEY arithmetic can diagnose
   * a definite mismatch when AD is already false, but it can never promote a
   * zone to secure or demote one the resolver authenticated.
   * `servfail.nl` is why: its DS confirms its KSK by SHA-256, its DNSKEY set is
   * published, and the zone is bogus. Local evidence agreeing is not the same
   * as the chain validating.
   *
   * **This function must never throw.** It is the only entry in the
   * `Promise.all` at the advanced-checks call site with no `optionalCheck()`
   * wrapper, and that is safe only because it reads `dohFetch()`'s `.kind`
   * rather than calling `requireUsable()`. Keep it that way, or add the
   * wrapper — `optionalCheck()` re-throws `DnsTypeError`, so a typo in a
   * record type still fails loudly either way.
   */
  async function checkDNSSEC(domain, queryOpts) {
    var dnssecOpts = Object.assign({}, queryOpts, { dnssec: true });
    // The DS record is owned by the child name and served by the parent zone,
    // so one query at the child name is the correct and only lookup.
    var answers = await Promise.all([
      dohFetch(domain, 'NS', dnssecOpts),
      dohFetch(domain, 'DS', dnssecOpts),
      dohFetch(domain, 'DNSKEY', dnssecOpts),
    ]);
    var validated = answers[0];
    var dsAnswer = answers[1];
    var keyAnswer = answers[2];

    var lookups = {
      ns: dnssecLookupStatus(validated),
      ds: dnssecLookupStatus(dsAnswer),
      dnskey: dnssecLookupStatus(keyAnswer),
    };

    // Filter on the numeric type. A `do=1` answer carries the RRSIG beside the
    // record it signs, and an unfiltered parser reads `DS 8 2 3600 …` as a DS
    // record with key tag NaN — no error, matching no key, and a mismatch
    // verdict on every signed domain audited.
    var keys = keyAnswer.answers.filter(function (a) { return a.type === 48; })
      .map(function (a) { return parseDnskey(cleanAnswerData(a.data, 'DNSKEY')); });
    var dsRecords = dsAnswer.answers.filter(function (a) { return a.type === 43; })
      .map(function (a) { return parseDs(cleanAnswerData(a.data, 'DS')); });

    var matched = await matchDsSet(dsRecords, keys, domain);
    // The published `ds` array is the parse and the verdict together, so a
    // reader never has to join two lists by index to see why a record was
    // judged the way it was.
    var ds = dsRecords.map(function (record, i) { return Object.assign({}, record, matched.ds[i]); });

    var chain = [];
    var state = null;

    // ── Rule 1: bogus ────────────────────────────────────────────────────
    // A SERVFAIL that resolves with checking disabled is the resolver saying
    // validation failed, which outranks every local observation below.
    // `dnssec-failed.org` satisfies rules 1, 2 and 5 at once.
    if (validated.kind === 'servfail') {
      var unchecked = await dohFetch(domain, 'NS',
        Object.assign({}, dnssecOpts, { checkingDisabled: true }));
      if (unchecked.kind === 'success' || unchecked.kind === 'nodata') {
        state = 'bogus';
        chain.push({ claim: 'resolver-bogus', source: 'resolver', detail: { kind: validated.kind } });
      }
    }

    // ── Rules 2 and 3: the resolver's own verdict ────────────────────────
    if (state === null && !lookups.ns.completed) {
      state = 'indeterminate';
      chain.push({ claim: 'resolver-unreachable', source: 'resolver', detail: { kind: validated.kind } });
    }
    if (state === null) {
      chain.push({ claim: 'resolver-ad', source: 'resolver', detail: { ad: validated.ad === true } });
      if (validated.ad === true) state = 'secure';
    }

    // ── Rules 4, 5 and 6: what the child and parent publish ──────────────
    // Reachable only when AD is false, which is what makes `signed` identical
    // to 0.4.0 by construction rather than by measurement.
    if (state === null) {
      var determinate = ds.filter(function (m) {
        return m.match === 'confirmed' || m.match === 'digest-mismatch' || m.match === 'no-matching-key';
      });
      var anyConfirmed = ds.some(function (m) { return m.match === 'confirmed'; });

      if (lookups.dnskey.completed && keys.length && lookups.ds.completed && !dsRecords.length) {
        state = 'unanchored';
      } else if (lookups.ds.completed && lookups.dnskey.completed &&
        dsRecords.length && keys.length && determinate.length && !anyConfirmed) {
        // Positive local proof only. A DS set that merely could not be checked,
        // or one whose only confirmation was against a key that cannot anchor,
        // falls to the residual below rather than raising the alarm.
        state = 'mismatch';
      } else {
        state = 'insecure';
      }
    }

    // ── Attribution ──────────────────────────────────────────────────────
    // OQ-SEC9-03: exactly one link is checked when both answers arrived, and
    // the chain says which one. If either lookup failed, claiming the link was
    // checked would contradict the `lookup-incomplete` evidence below.
    if (lookups.ds.completed && lookups.dnskey.completed) {
      chain.push({ claim: 'link-checked', source: 'local', detail: { child: domain, link: 'child-dnskey-to-parent-ds' } });
    }
    ds.forEach(function (record) {
      if (record.match === 'confirmed') {
        chain.push({
          claim: 'ds-confirms-dnskey', source: 'local',
          detail: { keyTag: record.keyTag, digestName: record.digestName, anchors: matchConfirmsAnchor(record) },
        });
      } else if (record.match === 'no-matching-key' || record.match === 'digest-mismatch') {
        chain.push({ claim: 'ds-' + record.match, source: 'local', detail: { keyTag: record.keyTag } });
      } else {
        chain.push({
          claim: 'ds-unverifiable', source: 'local',
          detail: { keyTag: record.keyTag, match: record.match, reason: record.unverifiableReason },
        });
      }
    });
    // Missing evidence is stated rather than left to be inferred from an empty
    // array. This is what keeps the residual rule honest: an `insecure` proved
    // by two empty answers and an `insecure` where neither query returned are
    // the same verdict from different amounts of evidence.
    ['ds', 'dnskey'].forEach(function (query) {
      if (!lookups[query].completed) {
        chain.push({ claim: 'lookup-incomplete', source: 'local', detail: { query: query, kind: lookups[query].kind } });
      }
    });

    var deprecatedAlgorithms = [];
    keys.concat(ds).forEach(function (record) {
      if (record.deprecated && record.algorithm !== null &&
        deprecatedAlgorithms.indexOf(record.algorithm) === -1 &&
        DEPRECATED_DNSSEC_ALGORITHMS.indexOf(record.algorithm) !== -1) {
        deprecatedAlgorithms.push(record.algorithm);
      }
    });
    var deprecatedDigests = [];
    ds.forEach(function (record) {
      if (DEPRECATED_DNSSEC_DIGESTS.indexOf(record.digestType) !== -1 &&
        deprecatedDigests.indexOf(record.digestType) === -1) {
        deprecatedDigests.push(record.digestType);
      }
    });

    var evidence = lookups.ds.completed && lookups.dnskey.completed ? 'complete'
      : lookups.ds.completed || lookups.dnskey.completed ? 'partial' : 'none';

    return {
      // Unchanged contract: `signed` is true exactly when the resolver
      // authenticated the answer, so every consumer from calcScore() to the
      // CSV reads what it read at 0.4.0.
      signed: state === 'secure',
      state: state,
      resolverValidated: validated.ad === true,
      keys: keys,
      ds: ds,
      anchorConfirmed: matched.anchorConfirmed,
      orphanDs: matched.orphanDs,
      chain: chain,
      deprecatedAlgorithms: deprecatedAlgorithms,
      deprecatedDigests: deprecatedDigests,
      lookups: lookups,
      evidence: evidence,
      error: state === 'indeterminate' ? validated.kind : undefined,
    };
  }

  return checkDNSSEC;
}
