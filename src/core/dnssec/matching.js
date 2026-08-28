/**
 * Local DS-to-DNSKEY matching (RFC 4034 §5.1.4). Spec §12, Task 4.5.
 *
 * **The one piece of this release that computes rather than reports**, which
 * is why it is the only module here that takes the platform's crypto — and why
 * it is a separate file from `chain.js`.
 *
 * ── What this module's output can and cannot do ─────────────────────────
 *
 * It feeds findings, AND it feeds the classifier: `chain.js` selects
 * `mismatch` over the residual `insecure` from the verdicts below. Saying it
 * "never reaches the state classifier" was an overclaim, and correcting it is
 * the point of stating the boundary precisely instead.
 *
 * What it can do: establish `mismatch` when the resolver's AD verdict is
 * already false.
 *
 * What it can never do: promote a zone to `secure`, override a validated
 * `bogus`, or demote a zone the resolver authenticated. `servfail.nl` is the
 * case that settles the last of those — its DS confirms its KSK by SHA-256 and
 * the zone is bogus, so local agreement is not the chain validating.
 *
 * ── Crypto is passed, and only as a capability ──────────────────────────
 *
 * `createDsMatcher({ crypto })` takes the platform's `crypto`, not the
 * platform: §12 gives a protocol directory no edge to `src/platform/` either.
 * Capability is tested by EXECUTING, never asserted in advance — the 1.0 spec
 * declined SHA-1 on a belief about browser support that was simply false. A
 * runtime that rejects an algorithm, or has no `crypto.subtle` at all,
 * produces `unverifiable` with reason `runtime-unavailable`. It must never
 * produce `digest-mismatch`, because "our environment could not hash this" and
 * "your zone is broken" are different sentences.
 *
 * Every failure path lands on `unverifiable`. A mismatch verdict tells an
 * operator their DNSSEC is broken, and the only thing entitled to say that is
 * arithmetic that actually ran.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s DS-to-DNSKEY block, unchanged apart from the two-space dedent,
 * the `export` keywords, and `matchDsToDnskeys`/`matchDsSet` becoming the body
 * of a factory that names the one capability they need. `bytesToHex` and
 * `dnssecDigestHex` stay private; neither was an engine member.
 */

import { dnskeyRdata, dnsWireName } from './records.js';

/** `matchDsToDnskeys().match`. Registry algebra `dnssec.ds.match`. */
export const DS_MATCH_STATES = Object.freeze([
  'unverifiable', 'unverifiable-digest-type', 'no-matching-key', 'confirmed',
  'digest-mismatch',
]);

/**
 * `matchDsToDnskeys().unverifiableReason`. Registry algebra
 * `dnssec.ds.unverifiableReason`.
 *
 * Five reasons rather than one flag, because they are not the same problem:
 * `runtime-unavailable` is about US, the other three are about the records.
 */
export const DS_UNVERIFIABLE_REASONS = Object.freeze([
  'null', 'invalid-ds', 'invalid-owner', 'runtime-unavailable', 'unbuildable-key',
]);

/* ── Local DS-to-DNSKEY matching (RFC 4034 §5.1.4) ─────────────────────
   The one piece of this release that computes rather than reports. Its
   output feeds findings AND the classifier — `chain.js` reads these verdicts
   to choose `mismatch` over the residual `insecure`. What it cannot do is
   overturn the resolver: §4's rules take `secure` and `bogus` from the AD
   verdict alone, so nothing here can promote a zone, override a validated
   `bogus`, or demote one Cloudflare authenticated. `servfail.nl` is why — its
   DS confirms its KSK by SHA-256 and the zone is bogus.

   Every failure path lands on `unverifiable`, never on `digest-mismatch`.
   A mismatch verdict tells an operator their DNSSEC is broken, and the only
   thing entitled to say that is arithmetic that actually ran.
   ───────────────────────────────────────────────────────────────────── */

/**
 * Digest types this build can actually compute, mapped to their Web Crypto
 * names. SHA-1 is here deliberately: it is a registered `SubtleCrypto.digest`
 * algorithm available in every current engine, and declining to compute a
 * digest the runtime handles perfectly well would report an unknown where a
 * known was available — inside the honesty mechanism itself.
 *
 * Absent, and therefore `unverifiable-digest-type`: 3 (GOST R 34.11-94),
 * 5 (GOST R 34.11-2012) and 6 (SM3), none of which Web Crypto implements,
 * and 0, which IANA reserves. Reserved is not the same as unassigned, so it
 * is named rather than carried as a possible future type — but RFC 3658
 * reserves the value without stating that a DS using it is invalid, so it is
 * not rejected either. Not computable is the whole claim.
 */
export const DNSSEC_DIGEST_WEBCRYPTO = { 1: 'SHA-1', 2: 'SHA-256', 4: 'SHA-384' };

function bytesToHex(bytes) {
  var out = '';
  for (var i = 0; i < bytes.length; i++) {
    out += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
  }
  return out;
}

/**
 * Can this key anchor a delegation, setting the digest aside?
 *
 * Three facts, each from its own authority, and none of them the digest:
 * the IANA Zone Signing column, RFC 4034 §2.1.1's zone bit, and whether the
 * key material is structurally possible for its algorithm. The REVOKE flag
 * is deliberately absent — RFC 5011 §2.1 needs a validated self-signature
 * this release does not compute, so the flag is reported and concluded from
 * nowhere.
 */
export function anchorFactsUsable(algorithmEligibility, hasZoneFlag, keyStructure) {
  return algorithmEligibility === 'eligible' && hasZoneFlag === true && keyStructure !== 'invalid';
}

export function dnskeyCanAnchor(key) {
  return !!key && anchorFactsUsable(key.algorithmEligibility, key.hasZoneFlag, key.keyStructure);
}

/**
 * Does this DS match actually anchor the delegation?
 *
 * The whole rule in one place. `dnskeyCanAnchor()` is the same rule read off
 * a key object; both defer to `anchorFactsUsable()` for the key half. Stated
 * twice they drift — a mutation disqualifying a REVOKE-flagged key was once
 * caught by only one of the two.
 */
export function matchConfirmsAnchor(match) {
  return !!match && match.match === 'confirmed' &&
    match.digestEligibility !== 'ineligible' &&
    anchorFactsUsable(match.matchedKeyAlgorithmEligibility,
      match.matchedKeyHasZoneFlag, match.matchedKeyStructure);
}

/**
 * The DS-to-DNSKEY matcher, over the platform's crypto.
 *
 * `crypto` is an argument, not an import: §12 gives a protocol directory no
 * edge to `src/platform/`, and passing the capability rather than the platform
 * is what lets a test hand this a runtime with no `subtle` at all and watch
 * every path land on `unverifiable`.
 *
 * `dnssecDigestHex` is defined here rather than at module scope — it is the
 * only function that touches the capability, and it moved down a few lines in
 * the extraction so the three functions that need it are contiguous. Nothing
 * else about it changed, including the `typeof crypto` guard, which is now
 * always true for a parameter and left in place rather than tidied.
 */
export function createDsMatcher(capabilities) {
  // Destructured in the BODY, not in the parameter list. `platform.test.mjs`
  // scans for a bare ambient name and recognizes `const { … }` as a
  // declaration but not a destructured parameter — a stated limit of a lexical
  // scan, and `core/dns/doh.js` already takes its primitives this way. Adjusted
  // to the scan rather than adjusting the scan mid-extraction.
  const { crypto } = capabilities;
  /**
   * Hash, or say we could not. Never throws.
   *
   * Capability is tested by executing, not asserted in advance — the 1.0 spec
   * declined SHA-1 on a belief about browser support that was simply false. A
   * runtime that rejects an algorithm, or has no `crypto.subtle` at all,
   * produces null here and `unverifiable` above. It must never produce a
   * mismatch, because "our environment could not hash this" and "your zone is
   * broken" are different sentences.
   */
  async function dnssecDigestHex(webCryptoName, input) {
    var subtle = typeof crypto !== 'undefined' && crypto && crypto.subtle;
    if (!subtle) return null;
    try {
      var digest = await subtle.digest(webCryptoName, input);
      return bytesToHex(new Uint8Array(digest));
    } catch (e) {
      return null;
    }
  }

  /**
   * Match one DS record against the child's DNSKEY set.
   *
   * RFC 4034 §5.1.4: the digest is taken over the canonical owner name in wire
   * format followed by the DNSKEY RDATA. Both sides of the comparison are
   * lowercase hex — Cloudflare returns the digest lowercase and dns.google
   * returns it uppercase, and a case-sensitive compare would report mismatch
   * on every domain if the resolver were ever made configurable.
   *
   * A key tag is not unique. Every DNSKEY sharing the tag and algorithm is
   * tried, and the DS confirms if any of them hashes correctly.
   *
   * **The order of the checks is part of the contract.** Candidate selection
   * comes before digest capability, because "no key carries that tag and
   * algorithm" is established without hashing anything: deciding capability
   * first reported `unverifiable-digest-type` for an orphan DS whose digest
   * this build cannot compute, hiding orphan evidence behind a local
   * limitation and changing the verdict on an absent key according to what
   * hashes happen to be implemented.
   *
   * **A proven confirmation is never revoked.** A digest failure on a later
   * candidate used to return `unverifiable` even when an earlier candidate had
   * already confirmed, which made the verdict depend on array order. The
   * precedence is now fixed and total: any confirmation wins; failing that a
   * computation failure is `unverifiable`; `digest-mismatch` requires that
   * every candidate which could be rebuilt was hashed and none matched.
   */
  async function matchDsToDnskeys(ds, keys, domain) {
    var result = {
      keyTag: ds ? ds.keyTag : null,
      algorithm: ds ? ds.algorithm : null,
      digestType: ds ? ds.digestType : null,
      digestEligibility: ds ? ds.digestEligibility : 'unknown',
      matchedKeyTag: null,
      matchedKeyIndex: null,
      match: 'unverifiable',
      unverifiableReason: null,
      matchedKeyAlgorithmEligibility: null,
      matchedKeyHasZoneFlag: null,
      matchedKeyStructure: null,
      matchedKeyHasRevokeFlag: null,
      computedLocally: true,
    };

    // A DS that did not parse, and an owner name the encoder refused, are both
    // statements about our own inputs. Neither is evidence about the zone, and
    // each says which it was — four different failures shared one token before
    // this, and a detail panel could not tell an operator which had happened.
    if (!ds || !ds.valid) {
      result.unverifiableReason = 'invalid-ds';
      return result;
    }
    var owner = dnsWireName(domain);
    if (!owner) {
      result.unverifiableReason = 'invalid-owner';
      return result;
    }

    // Candidates are selected on tag and algorithm alone. An ineligible or
    // malformed key stays a candidate on purpose: "a DS confirms a key that
    // cannot anchor" is a finding this release owes the operator, and it is
    // unreachable if such keys are filtered out before hashing.
    var candidates = [];
    for (var c = 0; c < (keys || []).length; c++) {
      var key = keys[c];
      if (key && key.valid && key.keyTag === ds.keyTag && key.algorithm === ds.algorithm) {
        candidates.push({ key: key, index: c });
      }
    }
    if (!candidates.length) {
      result.match = 'no-matching-key';
      result.unverifiableReason = null;
      return result;
    }

    var webCryptoName = DNSSEC_DIGEST_WEBCRYPTO[ds.digestType];
    if (!webCryptoName) {
      result.match = 'unverifiable-digest-type';
      return result;
    }

    var confirming = [];
    var digestsComputed = 0;
    var computationFailed = false;
    for (var i = 0; i < candidates.length; i++) {
      var rdata = dnskeyRdata(candidates[i].key);
      // A candidate whose RDATA cannot be rebuilt is not evidence of anything.
      // It is skipped, and the counters below stop the skip becoming a verdict.
      if (!rdata) continue;
      var input = new Uint8Array(owner.length + rdata.length);
      input.set(owner, 0);
      input.set(rdata, owner.length);
      var computed = await dnssecDigestHex(webCryptoName, input);
      // The runtime refused the algorithm it advertised. Recorded, not
      // returned: an earlier candidate may already have proved the match, and
      // a completed proof cannot be undone by failing to inspect another key.
      if (computed === null) { computationFailed = true; continue; }
      digestsComputed++;
      if (computed === ds.digest) confirming.push(candidates[i]);
    }

    if (confirming.length) {
      // On a key tag collision, report the key that could actually anchor.
      // Both hashed correctly; saying so about the usable one is the stronger
      // true statement, and it is what keeps `anchorConfirmed` honest.
      var chosen = confirming.filter(function (entry) { return dnskeyCanAnchor(entry.key); })[0] || confirming[0];
      result.match = 'confirmed';
      result.matchedKeyTag = chosen.key.keyTag;
      // The tag alone cannot identify which candidate was selected — every key
      // in a collision set shares it by definition, and RFC 4034 Appendix B
      // says so explicitly. The index into the DNSKEY set is what points at
      // the key that actually supplied the eligibility facts below.
      result.matchedKeyIndex = chosen.index;
      result.matchedKeyAlgorithmEligibility = chosen.key.algorithmEligibility;
      result.matchedKeyHasZoneFlag = chosen.key.hasZoneFlag;
      result.matchedKeyStructure = chosen.key.keyStructure;
      result.matchedKeyHasRevokeFlag = chosen.key.hasRevokeFlag;
      return result;
    }

    // Nothing confirmed. Everything from here is a reason, and only the last
    // one is a statement about the operator's zone.
    if (computationFailed) {
      result.unverifiableReason = 'runtime-unavailable';
      return result;
    }
    if (!digestsComputed) {
      result.unverifiableReason = 'unbuildable-key';
      return result;
    }
    result.match = 'digest-mismatch';
    result.unverifiableReason = null;
    return result;
  }

  async function matchDsSet(dsRecords, keys, domain) {
    var matches = [];
    for (var i = 0; i < (dsRecords || []).length; i++) {
      matches.push(await matchDsToDnskeys(dsRecords[i], keys, domain));
    }
    return {
      ds: matches,
      // The same rule as dnskeyCanAnchor(), read off the published match
      // fields rather than off the key object. Both call anchorFactsUsable()
      // rather than restating the three conditions: written twice, they drift,
      // and a mutation that disqualified a REVOKE-flagged key was caught by
      // only one of the two before they were joined.
      anchorConfirmed: matches.some(matchConfirmsAnchor),
      orphanDs: matches.filter(function (m) { return m.match === 'no-matching-key'; })
        .map(function (m) { return m.keyTag; }),
    };
  }

  return { matchDsToDnskeys, matchDsSet };
}
