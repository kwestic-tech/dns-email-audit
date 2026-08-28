/**
 * DNSSEC record parsing (RFC 4034). Spec Design §4 and §12, Task 4.5.
 *
 * Pure. No resolver, no crypto, no state — the IANA tables, the two record
 * parsers, and the three eligibility questions that read them.
 *
 * ── Why three modules and not one ───────────────────────────────────────
 *
 * Spec §3's tree names two responsibilities for this directory — "chain
 * evaluation, DS↔DNSKEY matching" — and they need different capabilities:
 * `matching.js` computes digests and so takes the platform's crypto,
 * `chain.js` does lookups and so takes the resolver. This file is the
 * substrate both read, and it takes neither. Splitting on the capability
 * boundary is what lets the parsers be tested with no injection at all, and
 * what keeps the crypto out of the module that decides the chain state.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s DNSSEC record-parsing block, unchanged apart from the
 * two-space dedent, the `export` keywords and the published state constants.
 * `bytesToHex`, `splitRdataFields` and the length/validation-use tables stay
 * private: they are implementation, and none was an engine member.
 *
 * The two DEPRECATION tables are exported for `chain.js`, which reads them to
 * build `deprecatedAlgorithms` and `deprecatedDigests`. That is a sibling
 * import, not a public API — and it is exported because the extraction needs
 * it, not because a test wanted it. It was found by reading the moved code:
 * `chain.js` referenced both by name with nothing to bind them, and a fixture
 * that produced no records ran green over the hole.
 */

import { base64ToBytes } from '../shared/base64.js';

/** `parseDnskey().errors` tokens. Registry algebra `dnssec.dnskey.errors`. */
export const DNSKEY_ERRORS = Object.freeze([
  'unparseable-record', 'unbalanced-parentheses', 'bad-flags', 'bad-protocol',
  'bad-algorithm', 'empty-key', 'bad-key-encoding',
]);

/** `parseDs().errors` tokens. Registry algebra `dnssec.ds.errors`. */
export const DS_ERRORS = Object.freeze([
  'unparseable-record', 'unbalanced-parentheses', 'bad-key-tag', 'bad-algorithm',
  'bad-digest-type', 'empty-digest', 'bad-digest', 'bad-digest-length',
]);

/**
 * `dnssecAlgorithmEligibility()`. Registry algebra
 * `dnssec.algorithmEligibility`.
 *
 * `unknown` is not `ineligible`. An algorithm the IANA table does not carry is
 * one this build has not been taught, and reporting that as "cannot sign"
 * would be a verdict about the operator's zone drawn from a gap in our data.
 */
export const DNSSEC_ALGORITHM_ELIGIBILITY = Object.freeze(['eligible', 'ineligible', 'unknown']);

/** `dnssecDigestEligibility()`. Registry algebra `dnssec.digestEligibility`. */
export const DNSSEC_DIGEST_ELIGIBILITY = Object.freeze(['eligible', 'ineligible', 'unknown']);

/**
 * `dnskeyStructure()`. Registry algebra `dnssec.keyStructure`.
 *
 * Separate from `parseDnskey().valid` on purpose. `valid` says the RECORD
 * parsed; this says whether the key material is structurally possible for its
 * declared algorithm. Collapsing them is how a recognized name gets accepted
 * without its registered value grammar.
 */
export const DNSKEY_STRUCTURE_STATES = Object.freeze(['valid', 'invalid', 'unknown']);

/* ── DNSSEC record parsing (RFC 4034) ──────────────────────────────────
   Two presentation forms from one resolver, and they must not share a
   normalizer. A DS digest is hex, so folding its case is free. A DNSKEY
   public key is base64 — case-carrying, with `+`, `/` and `=` in it — and
   folding its case destroys it silently: every digest then fails to match
   and a perfectly healthy zone is reported as a broken chain. That is the
   most damaging verdict this tool can produce, so the two parsers are
   written apart rather than factored together.

   These parsers read the numeric presentation form this project's one
   resolver returns, captured before any of this was written in
   docs/specs/fixtures/dnssec-live-states-0.5.0.md. RFC 4034 also permits
   algorithm mnemonics in zone-file presentation format; Cloudflare's JSON
   never emits them, and rather than accept a grammar nothing here can
   produce, an alphabetic algorithm field is reported as unparseable. That is
   a deliberate scope statement, not an oversight.

   A note on what `valid` means. It is a statement about the RECORD — the
   fields parsed, the protocol is 3, the base64 decoded. It is NOT a
   statement that the key is usable. Whether the key material is even
   structurally possible for its declared algorithm is `keyStructure`, and
   whether the key may verify RRsets at all is the zone flag. Collapsing
   those into one boolean is how a recognized name gets accepted without its
   registered value grammar, which is the failure 0.4.0 spent three review
   rounds removing from CAA, MTA-STS and DKIM in turn.
   ───────────────────────────────────────────────────────────────────── */

/**
 * IANA DNS Security Algorithm Numbers, current as of 2026-08-26. Protocol
 * identifiers, not prose — the localization contract lists them among the
 * terms that are never translated.
 *
 * 18 (MLDSA44) is an early allocation held by an Internet-Draft rather than
 * an RFC. It is carried because the registry carries it: a resolver could
 * return it, and reporting the number with no name is worse than reporting
 * the name the registry gives.
 */
export const DNSSEC_ALGORITHMS = {
  0: 'DELETE', 1: 'RSAMD5', 2: 'DH', 3: 'DSA', 5: 'RSASHA1',
  6: 'DSA-NSEC3-SHA1', 7: 'RSASHA1-NSEC3-SHA1', 8: 'RSASHA256',
  10: 'RSASHA512', 12: 'ECC-GOST', 13: 'ECDSAP256SHA256',
  14: 'ECDSAP384SHA384', 15: 'ED25519', 16: 'ED448', 17: 'SM2SM3',
  18: 'MLDSA44', 23: 'ECC-GOST12',
  252: 'INDIRECT', 253: 'PRIVATEDNS', 254: 'PRIVATEOID',
};

/**
 * The IANA registry's Zone Signing column is a separate protocol fact from
 * whether this build recognizes an algorithm's key grammar. The complete
 * named registry is recorded here: false is an affirmative prohibition,
 * while an absent value remains unknown for an unassigned future number.
 * Only algorithms marked true may contribute usable anchoring evidence.
 */
export const DNSSEC_ZONE_SIGNING = {
  0: false, 1: false, 2: false, 3: true, 5: true, 6: true, 7: true,
  8: true, 10: true, 12: true, 13: true, 14: true, 15: true, 16: true,
  17: true, 18: true, 23: true, 252: false, 253: true, 254: true,
};

export function dnssecAlgorithmEligibility(algorithm) {
  if (!Object.prototype.hasOwnProperty.call(DNSSEC_ZONE_SIGNING, algorithm)) return 'unknown';
  return DNSSEC_ZONE_SIGNING[algorithm] ? 'eligible' : 'ineligible';
}

/**
 * Deprecated for signing. RFC 9905 §3.1 obsoletes RFC 8624's algorithm
 * table: RSAMD5, DSA and both DSA/RSASHA1-NSEC3 variants are MUST NOT, and
 * RSASHA1 is likewise no longer permitted for new signing. RFC 9906
 * deprecates the GOST R 34.10-2001 algorithm and its digest.
 *
 * ECC-GOST12 (23) is NOT here: RFC 9558 registers it as a current
 * replacement for 12, not as a deprecated algorithm.
 */
export const DEPRECATED_DNSSEC_ALGORITHMS = [1, 3, 5, 6, 7, 12];

/**
 * IANA DS digest algorithms, current as of 2026-08-26. Types 5 and 6 were
 * missing here, which meant a one-octet digest declaring type 6 was accepted
 * as a valid record with no name — a currently registered digest parsed
 * without its registered grammar, which is exactly what the unknown-value
 * fallback is NOT for.
 */
export const DNSSEC_DIGESTS = {
  // 0 is reserved by RFC 3658 and marked "Not for use" by IANA. Named so it
  // reads as reserved rather than as an unassigned future type, and NOT
  // rejected: RFC 3658 reserves the value without saying a DS carrying it is
  // invalid, and inventing that rule is not this parser's to invent.
  0: 'RESERVED',
  1: 'SHA-1', 2: 'SHA-256', 3: 'GOST-R-34.11-94', 4: 'SHA-384',
  5: 'GOST-R-34.11-2012', 6: 'SM3',
};
var DNSSEC_DIGEST_LENGTHS = { 1: 20, 2: 32, 3: 32, 4: 48, 5: 32, 6: 32 };

/**
 * The IANA DS registry's **"Use for DNSSEC Validation"** column.
 *
 * That column, and not the delegation one, is the applicable fact here. This
 * tool inspects delegations that already exist; it does not create them. The
 * two columns genuinely disagree — SHA-1 is `MUST NOT` for creating a
 * delegation and `RECOMMENDED` for validating one, with "Implement for
 * DNSSEC Validation: MUST" beside it — so reading the delegation column would
 * mark every SHA-1 anchor in use as prohibited and contradict §3's whole
 * argument for computing SHA-1 in the first place.
 *
 * Affirmative `MUST NOT` is the only thing recorded as a prohibition: 0
 * (reserved) and 3 (GOST R 34.11-94, deprecated by RFC 9906). Everything
 * assigned and permitted at any strength — RECOMMENDED or MAY — is eligible.
 * Unassigned, reserved and private-use values are `unknown`, because the
 * registry makes no per-value determination for them.
 */
var DNSSEC_DIGEST_VALIDATION_USE = { 0: false, 1: true, 2: true, 3: false, 4: true, 5: true, 6: true };

export function dnssecDigestEligibility(digestType) {
  if (!Object.prototype.hasOwnProperty.call(DNSSEC_DIGEST_VALIDATION_USE, digestType)) return 'unknown';
  return DNSSEC_DIGEST_VALIDATION_USE[digestType] ? 'eligible' : 'ineligible';
}

/**
 * Name the ranges as well as the assignments, so a reserved or private-use
 * value cannot read as a possible future assignment. RFC 9904 reserves
 * 128–252 and sets 253–254 aside for private use; 7–127 and 255 are genuinely
 * unassigned and are the only values that get no name at all.
 */
export function dnssecDigestName(digestType) {
  if (Object.prototype.hasOwnProperty.call(DNSSEC_DIGESTS, digestType)) return DNSSEC_DIGESTS[digestType];
  if (digestType >= 128 && digestType <= 252) return 'RESERVED';
  if (digestType >= 253 && digestType <= 254) return 'PRIVATE-USE';
  return null;
}

/**
 * SHA-1 is "deprecated for delegation" per RFC 9905 and the IANA registry —
 * it must not be used for NEW delegations but remains required for
 * validating existing ones. GOST R 34.11-94 is deprecated outright by
 * RFC 9906. Both are reported; neither is a reason to refuse to compute.
 */
export const DEPRECATED_DNSSEC_DIGESTS = [1, 3];

// RFC 4034 §2.1.1 and RFC 5011 §7. Each of these names a BIT, and the
// parser reports the bit rather than a role — see parseDnskey().
var DNSKEY_FLAG_SEP = 0x0001;      // bit 15: secure entry point, advisory only
var DNSKEY_FLAG_ZONE = 0x0100;     // bit 7: this key may verify RRsets in the zone
var DNSKEY_FLAG_REVOKE = 0x0080;   // bit 8: RFC 5011 revocation, half of a proof

/**
 * Public key lengths that are fixed by their algorithm's specification.
 * RFC 6605 §4 (ECDSA Q is the uncompressed point x|y, so 64 and 96) and
 * RFC 8080 §3 (Ed25519 32 octets, Ed448 57).
 */
var DNSKEY_FIXED_KEY_LENGTHS = { 13: 64, 14: 96, 15: 32, 16: 57 };

// RFC 3110 §2 exponent-and-modulus encoding, used by every RSA algorithm.
var RSA_DNSSEC_ALGORITHMS = [1, 5, 7, 8, 10];

/**
 * Minimum modulus in octets, per the RFC that defines each algorithm.
 *
 * RFC 3110 §3 sets 512 bits for the RSA/SHA-1 family, and RFC 5702 §2.1
 * repeats it for RSA/SHA-256 — but **§2.2 raises the floor to 1024 bits for
 * RSA/SHA-512**, and a single shared minimum silently drops that. It is the
 * permissive direction, so it breaks no real zone; it is also the same shape
 * as every finding this review series has produced — a recognized algorithm
 * accepted without the value constraint its own specification states. The
 * ceiling is 4096 bits everywhere.
 */
var RSA_MIN_MODULUS_BYTES = { 1: 64, 5: 64, 7: 64, 8: 64, 10: 128 };
var RSA_MAX_MODULUS_BYTES = 512;

/**
 * Is this key material structurally possible for the algorithm it declares?
 *
 * Three answers, and the third is the point. `'invalid'` means a recognized
 * algorithm carrying material it cannot possibly be — a one-octet Ed25519
 * key. `'unknown'` means this build does not know the algorithm's key
 * grammar, which is an honest thing to say about DSA, GOST, SM2 and ML-DSA
 * and must never be read as a fault: a DS digest is computed over the raw
 * RDATA, so a parent and child can agree perfectly about a key whose
 * internals nothing here can parse.
 *
 * Only `'invalid'` disqualifies. Rejecting `'unknown'` would refuse zones
 * signed to a specification newer than this build, which is the opposite
 * failure and the one three of 0.4.0's eight rounds were spent undoing.
 */
export function dnskeyStructure(algorithm, bytes) {
  if (!bytes) return 'unknown';
  var fixed = DNSKEY_FIXED_KEY_LENGTHS[algorithm];
  if (fixed !== undefined) return bytes.length === fixed ? 'valid' : 'invalid';
  if (RSA_DNSSEC_ALGORITHMS.indexOf(algorithm) === -1) return 'unknown';

  // RFC 3110 §2: lengths 1–255 use the one-octet form; only longer
  // exponents use zero plus a two-octet length. Exponent and modulus are
  // unsigned integers with no leading zero octets, and each is limited to
  // 4096 bits. The modulus floor is per-algorithm — see
  // RSA_MIN_MODULUS_BYTES, where RFC 5702 §2.2 raises RSA/SHA-512 to 1024.
  if (bytes.length < 1) return 'invalid';
  var exponentLength = bytes[0];
  var offset = 1;
  if (exponentLength === 0) {
    if (bytes.length < 3) return 'invalid';
    exponentLength = (bytes[1] << 8) | bytes[2];
    offset = 3;
    if (exponentLength <= 255) return 'invalid';
  }
  if (exponentLength === 0 || exponentLength > 512) return 'invalid';
  if (offset + exponentLength >= bytes.length) return 'invalid';
  var modulusOffset = offset + exponentLength;
  var modulusLength = bytes.length - modulusOffset;
  var minimumModulus = RSA_MIN_MODULUS_BYTES[algorithm] || 64;
  if (modulusLength < minimumModulus || modulusLength > RSA_MAX_MODULUS_BYTES) return 'invalid';
  if (bytes[offset] === 0 || bytes[modulusOffset] === 0) return 'invalid';
  return 'valid';
}

/**
 * Split a record into its fixed leading integers and one trailing blob,
 * unwrapping the optional parenthesis pair around the blob.
 *
 * The balanced-pair rule is `parseTlsaRecord()`'s, and for the same reason:
 * stripping each side independently accepts `( ABCD` and `ABCD )` alike,
 * which defeats the point of a parser written for a presentation form. What
 * is deliberately NOT shared is case folding — see the block comment above.
 */
function splitRdataFields(presentationString, leadingFields) {
  var text = String(presentationString || '').trim();
  var pattern = new RegExp('^' + new Array(leadingFields + 1).join('(\\d+)\\s+') + '([\\s\\S]+)$');
  var match = pattern.exec(text);
  if (!match) return null;
  var body = match[leadingFields + 1].trim();
  var opened = body.charAt(0) === '(';
  var closed = body.length > 1 && body.charAt(body.length - 1) === ')';
  if (opened !== closed) return { unbalanced: true };
  if (opened) body = body.slice(1, -1);
  return {
    numbers: match.slice(1, leadingFields + 1).map(Number),
    body: body.replace(/\s+/g, ''),
  };
}

/**
 * A domain name in DNS wire format: each label prefixed by its length byte,
 * lowercased, terminated by a zero byte. RFC 4034 §5.1.4 hashes this ahead
 * of the DNSKEY RDATA, so an error here is an error in every digest.
 *
 * Returns null rather than guessing. A label over 63 octets, a name over 255,
 * or a byte outside ASCII cannot be encoded correctly, and writing the wrong
 * bytes anyway would produce a mismatch verdict about the operator's zone
 * that is really a statement about our own encoder.
 *
 * ASCII is checked BEFORE case folding, and the order is load-bearing.
 * JavaScript's toLowerCase() is Unicode case conversion, not the ASCII-only
 * folding RFC 4034 §6.2 defines: U+212A KELVIN SIGN lowercases to plain
 * 'k'. Folding first therefore turned a name this function must refuse into
 * one it accepts, and computed a digest for `k.example` when the caller
 * asked about `K.example` — a different owner name, which is a different
 * zone.
 */
export function dnsWireName(domain) {
  var raw = String(domain || '').replace(/\.$/, '');
  if (!raw) return new Uint8Array([0]);
  // Reject anything outside ASCII before any transformation touches it.
  if (!/^[\x00-\x7f]*$/.test(raw)) return null;
  var name = raw.toLowerCase();
  var labels = name.split('.');
  var total = 1;
  for (var i = 0; i < labels.length; i++) {
    if (!labels[i].length || labels[i].length > 63) return null;
    total += 1 + labels[i].length;
  }
  if (total > 255) return null;
  var bytes = new Uint8Array(total);
  var out = 0;
  for (var j = 0; j < labels.length; j++) {
    bytes[out++] = labels[j].length;
    for (var k = 0; k < labels[j].length; k++) {
      bytes[out++] = labels[j].charCodeAt(k);
    }
  }
  bytes[out] = 0;
  return bytes;
}

/** RFC 4034 §2.1: flags(2) || protocol(1) || algorithm(1) || public key. */
export function dnskeyRdata(key) {
  if (!key || !key.valid) return null;
  var publicKey = base64ToBytes(key.publicKey);
  if (!publicKey) return null;
  var rdata = new Uint8Array(4 + publicKey.length);
  rdata[0] = (key.flags >> 8) & 0xff;
  rdata[1] = key.flags & 0xff;
  rdata[2] = key.protocol;
  rdata[3] = key.algorithm;
  rdata.set(publicKey, 4);
  return rdata;
}

/**
 * The key tag, which is what links a DS to a DNSKEY. An off-by-one here does
 * not fail loudly — it reports a spurious mismatch on a healthy zone, which
 * the spec calls the worst defect this project could ship. Checked against
 * the reference key in RFC 4034 §5.4, whose stated tag is 60485.
 *
 * The general case is RFC 4034 Appendix B. Algorithm 1 is NOT: Appendix B.1
 * is erroneous, and **RFC 6840 §5.5 is the normative text**. B.1 correctly
 * says the tag is the most significant 16 of the least significant 24 bits
 * of the modulus and then names the wrong octets for it — "fourth-to-last
 * and third-to-last", where §5.5 corrects it to the third-to-last and
 * second-to-last. Implementing the appendix as written would produce a tag
 * one octet out on every RSAMD5 key, which is to say a mismatch verdict on
 * every zone still using one.
 *
 * The modulus ends the RDATA under RFC 3110's encoding, so the last octets
 * of the RDATA are the last octets of the modulus.
 */
export function dnskeyKeyTag(rdata, algorithm) {
  if (!rdata) return null;
  if (algorithm === 1) return rdata.length < 3 ? 0 : (rdata[rdata.length - 3] << 8) + rdata[rdata.length - 2];
  var accumulator = 0;
  for (var i = 0; i < rdata.length; i++) {
    accumulator += (i & 1) ? rdata[i] : rdata[i] << 8;
  }
  accumulator += (accumulator >> 16) & 0xffff;
  return accumulator & 0xffff;
}

/**
 * Parse one DNSKEY presentation string.
 *
 * Every flag is reported as the bit it is, never as the role it suggests.
 * `hasSep` is the SEP bit and not "this is the KSK": RFC 6840 §6.2 says the
 * bit "has no effect on how a DNSKEY may be used" and that validation is
 * prohibited from consulting it, so a key without SEP may be the only secure
 * entry point a zone has. `hasRevokeFlag` is the REVOKE bit and not "this
 * key is revoked": RFC 5011 §2.1 makes a key revoked when a resolver sees it
 * in a SELF-SIGNED RRset with the bit set, and this release does not
 * validate RRSIGs, so it holds one half of a two-part proof.
 *
 * `hasZoneFlag` is the one flag that does carry a normative consequence —
 * RFC 4034 §2.1.1 says a key without it MUST NOT verify RRsets — and even
 * that is reported here and applied where matching happens.
 *
 * `publicKey` stays the base64 text rather than becoming a byte array. It is
 * the evidence the resolver returned, it survives export and comparison
 * intact, and a 2048-bit key as a Uint8Array serializes into a 259-entry
 * object in every report this result reaches. `dnskeyRdata()` decodes it
 * where bytes are actually needed.
 */
export function parseDnskey(presentationString) {
  var blank = {
    flags: null, protocol: null, algorithm: null, algorithmName: null,
    algorithmEligibility: 'unknown',
    publicKey: '', keyBytes: 0, keyTag: null, keyStructure: 'unknown',
    hasSep: false, hasZoneFlag: false, hasRevokeFlag: false,
    deprecated: false, valid: false, errors: ['unparseable-record'],
  };
  var fields = splitRdataFields(presentationString, 3);
  if (!fields) return blank;
  if (fields.unbalanced) return Object.assign({}, blank, { errors: ['unbalanced-parentheses'] });

  var flags = fields.numbers[0];
  var protocol = fields.numbers[1];
  var algorithm = fields.numbers[2];
  var errors = [];

  if (!(flags >= 0 && flags <= 0xffff)) errors.push('bad-flags');
  // RFC 4034 §2.1.2: the protocol field MUST have value 3, and a DNSKEY with
  // any other value MUST be treated as invalid.
  if (protocol !== 3) errors.push('bad-protocol');
  if (!(algorithm >= 0 && algorithm <= 255)) errors.push('bad-algorithm');

  var publicKey = fields.body;
  var bytes = publicKey ? base64ToBytes(publicKey) : null;
  if (!publicKey) errors.push('empty-key');
  else if (!bytes) errors.push('bad-key-encoding');

  var valid = errors.length === 0;
  // Reserved flag bits are ignored on receipt (RFC 4034 §2.1.1). A record
  // carrying one is parseable, and nothing here rejects it for that.
  var parsed = {
    flags: flags,
    protocol: protocol,
    algorithm: algorithm,
    // An unregistered algorithm number is not an error. The registry grows,
    // and a resolver may return a key this build has never heard of; the
    // honest report is the number with no name beside it.
    algorithmName: DNSSEC_ALGORITHMS[algorithm] || null,
    algorithmEligibility: dnssecAlgorithmEligibility(algorithm),
    publicKey: publicKey,
    keyBytes: bytes ? bytes.length : 0,
    keyTag: null,
    keyStructure: valid ? dnskeyStructure(algorithm, bytes) : 'unknown',
    hasSep: valid && (flags & DNSKEY_FLAG_SEP) !== 0,
    hasZoneFlag: valid && (flags & DNSKEY_FLAG_ZONE) !== 0,
    hasRevokeFlag: valid && (flags & DNSKEY_FLAG_REVOKE) !== 0,
    deprecated: DEPRECATED_DNSSEC_ALGORITHMS.indexOf(algorithm) !== -1,
    valid: valid,
    errors: errors,
  };
  if (valid) parsed.keyTag = dnskeyKeyTag(dnskeyRdata(parsed), algorithm);
  return parsed;
}

/** Parse one DS presentation string. RFC 4034 §5.1. */
export function parseDs(presentationString) {
  var blank = {
    keyTag: null, algorithm: null, algorithmName: null,
    algorithmEligibility: 'unknown',
    digestType: null, digestName: null, digestEligibility: 'unknown', digest: '',
    deprecated: false, valid: false, errors: ['unparseable-record'],
  };
  var fields = splitRdataFields(presentationString, 3);
  if (!fields) return blank;
  if (fields.unbalanced) return Object.assign({}, blank, { errors: ['unbalanced-parentheses'] });

  var keyTag = fields.numbers[0];
  var algorithm = fields.numbers[1];
  var digestType = fields.numbers[2];
  var errors = [];

  if (!(keyTag >= 0 && keyTag <= 0xffff)) errors.push('bad-key-tag');
  if (!(algorithm >= 0 && algorithm <= 255)) errors.push('bad-algorithm');
  if (!(digestType >= 0 && digestType <= 255)) errors.push('bad-digest-type');

  // Hex, so folding the case is safe and necessary: Cloudflare returns this
  // lowercase and dns.google returns it uppercase, and the comparison this
  // feeds is a string equality.
  var digest = fields.body.toLowerCase();
  if (!digest) errors.push('empty-digest');
  else if (!/^[0-9a-f]+$/.test(digest) || digest.length % 2 !== 0) errors.push('bad-digest');
  else {
    var expected = DNSSEC_DIGEST_LENGTHS[digestType];
    // Every REGISTERED digest type has its length checked, including the two
    // this build cannot compute. A registered type parsed without its
    // registered grammar is not forward compatibility, it is a gap. Only a
    // genuinely unassigned or private-use value is carried unjudged.
    if (expected !== undefined && digest.length / 2 !== expected) errors.push('bad-digest-length');
  }

  return {
    keyTag: keyTag,
    algorithm: algorithm,
    algorithmName: DNSSEC_ALGORITHMS[algorithm] || null,
    algorithmEligibility: dnssecAlgorithmEligibility(algorithm),
    digestType: digestType,
    digestName: dnssecDigestName(digestType),
    // The registry's own determination, kept beside the digest rather than
    // folded into whether this build happens to implement the hash. An
    // affirmative prohibition must never be reported as "we could not
    // compute it" — that is R2-F1's defect in the digest registry.
    digestEligibility: dnssecDigestEligibility(digestType),
    digest: digest,
    deprecated: DEPRECATED_DNSSEC_DIGESTS.indexOf(digestType) !== -1,
    valid: errors.length === 0,
    errors: errors,
  };
}
