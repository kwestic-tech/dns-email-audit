/**
 * DKIM: selector discovery, the catalog, and key decoding. Spec Design §4 and
 * §12, Task 4.7.
 *
 * ── What is injected, and why each ──────────────────────────────────────
 *
 * | Capability | Why it cannot be imported |
 * | --- | --- |
 * | `dohFetch`, `requireUsable`, `cleanAnswerData` | §12 gives a protocol directory no edge to `core/dns/`. The RAW handle is needed: `inspectDkimSelector()` walks CNAMEs and reads the answer chain, which a normalized array does not carry. |
 * | `crypto` | The platform's, not the platform. Web Crypto validation is OPTIONAL — see below. |
 * | `dkimSelectorCatalog` | Generated data. §12 gives no edge to `src/data/`, and the fixture-identity probes work by handing this a substitute catalog. |
 * | `spfReferencedCatalogKeys` | **TEMPORARY.** See below. |
 *
 * ── The temporary SPF collaborator ──────────────────────────────────────
 *
 * `catalogSelectors()` widens the selector scan using the vendors a domain's
 * SPF record names, which needs SPF's term grammar. §12 gives DKIM no edge to
 * `core/spf/`, and the ruling at Task 4.0 was explicit about the three things
 * this must NOT become: DKIM does not import `core/spf/`, does not copy
 * `parseSpfTerms()`, and does not grow a second SPF grammar.
 *
 * So `spfReferencedCatalogKeys()` lives with the grammar it reads. Since Task
 * 4.8 that is `core/spf/`, and the COMPOSITION ROOT imports it from there and
 * injects it here.
 *
 * That is still a **transitional capability, not the target shape**.
 * Cross-protocol composition belongs to the audit layer: **Phase 5** replaces
 * this string-taking collaborator with audit-derived input — audit parses the
 * references once and passes the derived catalog keys — after which this
 * parameter goes away. Nothing here should be built to depend on the
 * arrangement lasting.
 *
 * `checkDKIM()`'s signature is unchanged — it still receives the SPF record as
 * a STRING — because changing it is the composition decision this task is
 * explicitly not making.
 *
 * ── Optional Web Crypto validation ──────────────────────────────────────
 *
 * `cryptoValidated` is `null` / `true` / `false`, and the three are different
 * sentences. `null` means we did not check — no `crypto.subtle`, or an
 * algorithm the runtime declined. It must never collapse into `false`, which
 * says the operator's key is broken. The mutation semantics are preserved
 * exactly: validation runs where it can and stays silent where it cannot.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s DKIM constants, parsers, DER reader and discovery, unchanged
 * apart from the two-space dedent, the `export` keywords, and the discovery
 * half becoming the body of a factory. `DKIM_SCAN_BATCH_SIZE` is 24 and moves
 * unchanged, the CNAME-walk depth is unchanged, and selector ordering and
 * attribution are byte-identical. No concurrency changed.
 */

import { base64ToBytes } from '../shared/base64.js';

/** The base list, tried on every domain regardless of provider. */
export const DKIM_SELECTORS = ['google', 'default', 'mail', 's1', 's2', 'selector1', 'selector2', 'dkim', 'sig1', 'odoo'];

/**
 * How many selectors are queried AT ONCE.
 *
 * 24, unchanged. It bounds BATCHING and therefore maximum concurrency; it does
 * NOT change how many selector queries an audit makes — `checkDKIM()` slices
 * the same list either way, so the query total is the same at any batch size.
 * `PRIVACY.md`'s 41/61 figures do not depend on it.
 *
 * It is preserved because Phase 4 forbids concurrency changes and the
 * equivalence trace observes concurrency and batch size directly. Changing it
 * moves a surface this refactor is measured against.
 */
export const DKIM_SCAN_BATCH_SIZE = 24;

export function validDkimSelector(selector) {
  return /^[a-z0-9][a-z0-9_-]{0,62}$/.test(selector);
}



/* ── DKIM public key analysis (RFC 6376 3.6.1, RFC 8463) ──────────────
   Everything here is pure and synchronous. The size of an RSA modulus is
   the single most actionable fact about a DKIM key and it must not depend
   on a secure context, so it is read with a DER length walk rather than
   with Web Crypto (OQ-DEPTH-02). Web Crypto validates the structure on top,
   where it exists, and its absence is recorded as an unknown — never as a
   bad key. A browser that cannot check a key has said nothing about it.
   ───────────────────────────────────────────────────────────────────── */

var DKIM_KEY_TAGS = ['v', 'h', 'k', 'n', 'p', 's', 't'];
// RFC 6376 §3.6.1 registers these hash names; a verifier that supports
// neither has nothing to verify with.
var DKIM_SUPPORTED_HASHES = ['sha1', 'sha256'];
// hyphenated-word = ALPHA *(ALPHA / DIGIT / "-") — the extension token shape
// shared by the h=, s= and t= vocabularies.
var DKIM_TOKEN = /^[a-z](?:[a-z0-9-]*[a-z0-9])?$/i;

/**
 * Parse the complete RFC 6376 §3.2 tag-list grammar used by a DKIM key.
 *
 * This is deliberately not the permissive `parseTagList()` helper used by
 * protocols that merely want a map. A key verifier must reject a bare
 * fragment, an illegal tag name, bad folding, or a version tag in the wrong
 * position. Silently skipping those pieces makes `dkim-key-malformed`
 * impossible to emit because the analyzer has already forgotten the error.
 */
export function parseDkimKeyTagList(record) {
  var source = String(record === undefined || record === null ? '' : record);
  var errors = [];
  // FWS permits CRLF only when followed by WSP. Unfold it while retaining
  // the following WSP; every other control is outside tag-value grammar.
  var unfolded = source.replace(/\r\n(?=[ \t])/g, '');
  if (/[\r\n]|[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(unfolded)) errors.push('invalid-tag-list');

  var parts = unfolded.split(';');
  if (parts.length > 1 && /^[ \t]*$/.test(parts[parts.length - 1])) parts.pop();
  var tags = Object.create(null);
  var duplicates = [];
  var order = [];
  parts.forEach(function (part) {
    if (!part || /^[ \t]*$/.test(part)) { errors.push('invalid-tag-list'); return; }
    var equals = part.indexOf('=');
    if (equals === -1) { errors.push('invalid-tag-list'); return; }
    var left = part.slice(0, equals);
    if (!/^[ \t]*[a-z][a-z0-9_]*[ \t]*$/i.test(left)) {
      errors.push('invalid-tag-list'); return;
    }
    var name = left.trim();
    var value = part.slice(equals + 1).replace(/^[ \t]+|[ \t]+$/g, '');
    if (!/^(?:[\x21-\x3a\x3c-\x7e]|[ \t])*$/.test(value)) {
      errors.push('invalid-tag-list'); return;
    }
    order.push(name);
    if (Object.prototype.hasOwnProperty.call(tags, name)) duplicates.push(name);
    else tags[name] = value;
  });
  if (!order.length) errors.push('invalid-tag-list');
  if (duplicates.length) errors.push('duplicate-tags');
  return { tags: tags, duplicates: duplicates, order: order, errors: Array.from(new Set(errors)) };
}

/**
 * Split a colon-separated DKIM tag list, or null if it is not one.
 *
 * A PRESENT tag with an empty value is malformed — `h=` and `s=` are lists of
 * at least one entry, and an empty one says nothing while looking like a
 * restriction. An ABSENT tag is a different thing entirely and never reaches
 * here: `s=` defaults to `*`, and `h=` defaults to every algorithm.
 */
function parseDkimTagList(value, allowStar) {
  var entries = String(value === undefined || value === null ? '' : value).split(':')
    .map(function (part) { return part.trim().toLowerCase(); });
  if (!entries.length || entries.some(function (entry) { return entry === ''; })) return null;
  for (var i = 0; i < entries.length; i++) {
    if (allowStar && entries[i] === '*') continue;
    if (!DKIM_TOKEN.test(entries[i])) return null;
  }
  return entries;
}

/** RFC 6376's DKIM-Quoted-Printable used by the human-readable n= tag. */
function isDkimQuotedPrintable(value) {
  var text = String(value === undefined || value === null ? '' : value).replace(/[ \t]/g, '');
  for (var i = 0; i < text.length; i++) {
    var code = text.charCodeAt(i);
    if (text.charAt(i) === '=') {
      if (!/^[0-9A-F]{2}$/.test(text.slice(i + 1, i + 3))) return false;
      i += 2;
    } else if (!((code >= 0x21 && code <= 0x3a) || code === 0x3c || (code >= 0x3e && code <= 0x7e))) {
      return false;
    }
  }
  return true;
}

/**
 * Read one DER tag-length-value at `pos`. Returns null for anything that is
 * not well-formed, which is the whole point: a `p=` value truncated by a TXT
 * chunking mistake decodes to bytes that are not a key, and that must read as
 * "unparseable" rather than as a key of whatever size the garbage implies.
 */
function derReadTlv(bytes, pos) {
  if (pos + 2 > bytes.length) return null;
  var tag = bytes[pos];
  var lengthByte = bytes[pos + 1];
  var start, length;
  if (lengthByte < 0x80) {
    length = lengthByte;
    start = pos + 2;
  } else {
    var count = lengthByte & 0x7f;
    // 0 is BER indefinite length, which DER forbids; over 4 bytes is a
    // length no DKIM key has and a sign the input is not DER at all.
    if (count === 0 || count > 4) return null;
    if (pos + 2 + count > bytes.length) return null;
    // X.690 10.1: the definite length must use the FEWEST possible octets.
    // A leading zero octet is never the fewest, and neither is the long form
    // for a value the short form can express. Accepting either let BER
    // encodings through a walk this release calls authoritative DER — and
    // two encodings of one key is one more than a canonical form allows.
    if (bytes[pos + 2] === 0x00) return null;
    length = 0;
    for (var i = 0; i < count; i++) length = (length * 256) + bytes[pos + 2 + i];
    if (length < 0x80) return null;
    start = pos + 2 + count;
  }
  if (start + length > bytes.length) return null;
  return { tag: tag, start: start, length: length, end: start + length };
}

/**
 * Bit length of a DER INTEGER that must be positive, non-zero and minimally
 * encoded — which is what RFC 8017 3.1 requires of both RSA fields. Returns
 * null for anything else, so a value that is merely tagged INTEGER cannot
 * pass as a modulus.
 *
 * The length is counted from the highest set bit of the first significant
 * octet, not from the encoded byte width. Those differ whenever the top octet
 * is below 0x80, and the difference lands on the wrong side of this release's
 * own threshold: a 128-byte modulus whose leading significant octet is 0x01 is
 * a 1017-bit key, and reporting it as 1024 both prints a false number and
 * swaps the critical `dkim-key-weak` finding for the informational 1024-bit
 * one.
 *
 * Real RSA keys have the top bit of the modulus set, so for every key in the
 * backtest sample every rule here is satisfied and the two bit-length answers
 * agree — which is exactly why all of this had to be established by
 * construction rather than waited for.
 */
function derPositiveInteger(bytes, tlv) {
  var start = tlv.start;
  var length = tlv.length;
  if (length < 1) return null;                                  // empty INTEGER
  // X.690 8.3.2 encodes sign in the first octet's high bit, so anything with
  // it set is negative — and RSA has no negative values.
  if ((bytes[start] & 0x80) !== 0) return null;
  if (length === 1 && bytes[start] === 0x00) return null;       // zero
  // Minimal form: a leading 0x00 exists only to keep a high-bit-set value
  // positive. Any other leading zero is padding DER does not permit, and
  // silently stripping it would report a size for a non-conformant encoding.
  if (length > 1 && bytes[start] === 0x00 && (bytes[start + 1] & 0x80) === 0) return null;
  if (bytes[start] === 0x00) { start++; length--; }             // the one sign octet
  var top = bytes[start];
  var topBits = 0;
  while (top) { topBits++; top >>= 1; }
  // The significant range is returned as well as the size, because comparing
  // two of these needs the octets and not just their width.
  return { start: start, length: length, bits: (length - 1) * 8 + topBits };
}

/**
 * Compare two positive integers by their significant octets: -1, 0 or 1.
 *
 * Both are already minimally encoded with any sign octet stripped, so the
 * wider value is the larger one and equal widths compare lexicographically.
 * That is an exact comparison of arbitrarily large values using nothing but
 * byte reads — an earlier version compared bit lengths instead and called it
 * the best available without bignum arithmetic, which was simply wrong: it
 * accepted `e == n` and any same-width `e > n`.
 */
function compareDerMagnitude(bytes, left, right) {
  if (left.length !== right.length) return left.length < right.length ? -1 : 1;
  for (var i = 0; i < left.length; i++) {
    if (bytes[left.start + i] !== bytes[right.start + i]) {
      return bytes[left.start + i] < bytes[right.start + i] ? -1 : 1;
    }
  }
  return 0;
}

// rsaEncryption, OID 1.2.840.113549.1.1.1 — the nine content octets of the
// AlgorithmIdentifier's OBJECT IDENTIFIER.
var RSA_ENCRYPTION_OID = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

/**
 * Does this AlgorithmIdentifier SEQUENCE name rsaEncryption, correctly?
 *
 * RFC 3279 2.3.1 requires the parameters field to be ASN.1 NULL for this
 * algorithm, and RFC 8017 A.1 says the same. Matching the OID and stopping
 * there accepted an AlgorithmIdentifier carrying arbitrary parameters — an
 * OCTET STRING, or nothing at all — which is not the structure the OID
 * promises.
 */
function isRsaAlgorithmIdentifier(bytes, algorithm) {
  var oid = derReadTlv(bytes, algorithm.start);
  if (!oid || oid.tag !== 0x06 || oid.length !== RSA_ENCRYPTION_OID.length) return false;
  for (var i = 0; i < RSA_ENCRYPTION_OID.length; i++) {
    if (bytes[oid.start + i] !== RSA_ENCRYPTION_OID[i]) return false;
  }
  var parameters = derReadTlv(bytes, oid.end);
  if (!parameters || parameters.tag !== 0x05 || parameters.length !== 0) return false;
  // NULL must also END the AlgorithmIdentifier: no trailing members.
  return parameters.end === algorithm.end;
}

/**
 * Read `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`
 * out of a SEQUENCE already located, and return the modulus bit length.
 *
 * One helper for both envelopes on purpose. The bare PKCS#1 path checked the
 * exponent and its boundary while the SPKI path checked neither, so an SPKI
 * key whose exponent tag had been altered walked cleanly and reported a size —
 * leaving an optional browser API as the only thing that would reject
 * malformed DER, in a function documented as authoritative without it.
 *
 * **Where this stops, deliberately.** The walk establishes that the encoding
 * is canonical DER and that the values satisfy the cheap NECESSARY conditions
 * RFC 8017 3.1 states: positive, minimally encoded, both odd, and
 * 3 <= e < n. It does not establish that they are SUFFICIENT. Proving `n` is
 * a product of two distinct primes, or that gcd(e, lambda(n)) is 1, needs the
 * private factors, which a public key does not carry — and factoring a
 * 2048-bit modulus is not a thing a DNS audit does in a browser. So a key
 * that passes here is well-formed, not proven usable. Web Crypto confirms
 * further where it can, for SPKI only, and its silence is never a verdict.
 */
function derReadRsaPublicKey(bytes, sequence) {
  var modulus = derReadTlv(bytes, sequence.start);
  if (!modulus || modulus.tag !== 0x02) return null;
  var exponent = derReadTlv(bytes, modulus.end);
  if (!exponent || exponent.tag !== 0x02) return null;
  // The exponent must end the sequence: no trailing content, no third member.
  if (exponent.end !== sequence.end) return null;

  // Both fields are values, not just tags. RFC 8017 3.1 defines `n` and `e`
  // as positive integers with 3 <= e < n; checking the tag alone accepted an
  // empty exponent and a negative modulus.
  var modulusValue = derPositiveInteger(bytes, modulus);
  var exponentValue = derPositiveInteger(bytes, exponent);
  if (!modulusValue || !exponentValue) return null;
  // Both are odd. RFC 8017 3.1 makes `n` a product of distinct odd primes,
  // so an even modulus is not an RSA modulus at all; and `e` must be coprime
  // to lambda(n), which is even. The exponent was checked here from the
  // start and the modulus was not — the same condition, two lines apart.
  if ((bytes[modulusValue.start + modulusValue.length - 1] & 1) === 0) return null;
  if ((bytes[exponentValue.start + exponentValue.length - 1] & 1) === 0) return null;
  // At least 3. A single content octet is the only way to encode a value
  // below 128, so nothing wider needs comparing.
  if (exponentValue.length === 1 && bytes[exponentValue.start] < 3) return null;
  // And strictly below the modulus — compared exactly, octet by octet. This
  // says nothing about the modulus's factors and needs no arithmetic beyond
  // byte reads.
  if (compareDerMagnitude(bytes, exponentValue, modulusValue) >= 0) return null;
  return modulusValue.bits;
}

/**
 * Walk an RSA public key to its modulus. Returns { bits, encoding } or null.
 *
 * BOTH envelopes are valid DKIM key encodings and both are accepted:
 *
 *   pkcs1  RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
 *   spki   SEQUENCE { AlgorithmIdentifier, BIT STRING { RSAPublicKey } }
 *
 * RFC 6376 3.6.1 describes the `p=` value as a DER-encoded `RSAPublicKey`,
 * and the errata clarify that it MAY be wrapped in a SubjectPublicKeyInfo.
 * So a bare PKCS#1 key is conformant, not a curiosity to be tolerated.
 *
 * An earlier version of this function refused the bare form so that the walk
 * and Web Crypto could never disagree. That had the dependency backwards:
 * `crypto.subtle.importKey` accepts 'spki' and not 'pkcs1', and letting an
 * implementation's import surface decide what the protocol permits would have
 * reported a perfectly valid published key as unparseable. The DER walk is
 * authoritative for the size; Web Crypto confirms only what it can express.
 *
 * Returns null for anything that is not one of these two structures, and null
 * is reported as unparseable rather than guessed at.
 */
function rsaPublicKeyShape(bytes) {
  if (!bytes) return null;
  var outer = derReadTlv(bytes, 0);
  if (!outer || outer.tag !== 0x30) return null;
  // DER encodes exactly one top-level value. Trailing bytes mean this is not
  // a key, and without this check a truncated blob whose prefix happens to
  // parse would yield a confident size for something unusable.
  if (outer.end !== bytes.length) return null;

  var first = derReadTlv(bytes, outer.start);
  if (!first) return null;

  // Bare PKCS#1: the outer SEQUENCE *is* the RSAPublicKey.
  if (first.tag === 0x02) {
    var pkcs1Bits = derReadRsaPublicKey(bytes, outer);
    return pkcs1Bits === null ? null : { bits: pkcs1Bits, encoding: 'pkcs1' };
  }

  // SPKI: SEQUENCE { AlgorithmIdentifier, BIT STRING { RSAPublicKey } }.
  // Every container boundary is checked, so no nesting level may carry
  // trailing content, and the algorithm is confirmed to be RSA rather than
  // assumed from the shape.
  if (first.tag !== 0x30) return null;
  if (!isRsaAlgorithmIdentifier(bytes, first)) return null;
  var bitString = derReadTlv(bytes, first.end);
  if (!bitString || bitString.tag !== 0x03 || bitString.length < 1) return null;
  if (bitString.end !== outer.end) return null;
  // First content octet of a BIT STRING counts the unused trailing bits. A
  // key is a whole number of bytes, so anything but zero means this is not
  // the structure we think it is.
  if (bytes[bitString.start] !== 0x00) return null;
  var inner = derReadTlv(bytes, bitString.start + 1);
  if (!inner || inner.tag !== 0x30 || inner.end !== bitString.end) return null;
  var spkiBits = derReadRsaPublicKey(bytes, inner);
  return spkiBits === null ? null : { bits: spkiBits, encoding: 'spki' };
}

/**
 * Analyze one DKIM key record. Pure, synchronous, no DNS, no Web Crypto.
 *
 * `errors` carries tokens, never English — js/dns.js does not speak to the
 * user. `cryptoValidated` starts null meaning "not attempted"; only
 * inspectDkimSelector() moves it to true or false, and false never on its
 * own makes a key invalid.
 */
export function analyzeDkimKey(txtValue) {
  var parsed = parseDkimKeyTagList(txtValue);
  var tags = parsed.tags;
  var errors = parsed.errors.slice();

  var version = null;
  if (Object.prototype.hasOwnProperty.call(tags, 'v')) {
    if (tags.v === 'DKIM1') version = 'DKIM1';
    else errors.push('bad-version');
    if (parsed.order[0] !== 'v') errors.push('version-not-first');
  }

  // Reasons a well-formed record still cannot sign this domain's email.
  // Kept apart from `errors` on purpose: none of these is a malformed record,
  // and telling an operator their key is broken when they deliberately scoped
  // it to another service would be the same false verdict in a new place.
  var restrictions = [];

  var rawKeyType = Object.prototype.hasOwnProperty.call(tags, 'k') ? tags.k.trim() : 'rsa';
  var keyType = rawKeyType.toLowerCase();
  if (!DKIM_TOKEN.test(rawKeyType)) errors.push('invalid-key-type');
  if (keyType !== 'rsa' && keyType !== 'ed25519') {
    keyType = 'unknown';
    // RFC 6376 §3.6.1: "Unrecognized key types MUST be ignored." Ignored is
    // not malformed — the record may be perfectly valid for a verifier that
    // knows the type. It simply cannot be counted as a key we can use.
    restrictions.push('unsupported-key-type');
  }

  var hasP = Object.prototype.hasOwnProperty.call(tags, 'p');
  var rawKey = hasP ? tags.p : '';
  // RFC 6376 3.6.1: "An empty value means that this public key has been
  // revoked." Revocation is a deliberate act and a complete record, so it is
  // reported as such and not as a parse failure.
  var revoked = hasP && rawKey.replace(/\s+/g, '').length === 0;
  if (!hasP) errors.push('missing-p');

  var bytes = null;
  var keyBytes = null;
  var keyBits = null;
  var keyEncoding = null;
  if (hasP && !revoked) {
    bytes = base64ToBytes(rawKey);
    if (bytes === null) {
      errors.push('unparseable-key');
    } else {
      keyBytes = bytes.length;
      if (keyType === 'ed25519') {
        // RFC 8463 3: the value is the raw 32-byte Ed25519 public key, not
        // an SPKI structure, so there is no modulus and keyBits stays null.
        if (keyBytes !== 32) errors.push('bad-ed25519-length');
      } else if (keyType === 'rsa') {
        var shape = rsaPublicKeyShape(bytes);
        if (shape === null) errors.push('unparseable-key');
        else {
          keyBits = shape.bits;
          keyEncoding = shape.encoding;
        }
      }
    }
  }

  // Each list tag is validated only when PRESENT. An unknown but well-formed
  // token is an extension and stays in the reported list rather than being
  // called malformed — RFC 6376 is explicit that the vocabularies are
  // extensible.
  var hashAlgorithms = [];
  if (Object.prototype.hasOwnProperty.call(tags, 'h')) {
    hashAlgorithms = parseDkimTagList(tags.h, false) || [];
    if (!hashAlgorithms.length) errors.push('invalid-tag-list');
    else if (!hashAlgorithms.some(function (h) { return DKIM_SUPPORTED_HASHES.indexOf(h) !== -1; })) {
      // Well-formed, and it offers this verifier nothing to work with.
      restrictions.push('no-supported-hash');
    }
  }

  var serviceTypes = [];
  if (Object.prototype.hasOwnProperty.call(tags, 's')) {
    serviceTypes = parseDkimTagList(tags.s, true) || [];
    if (!serviceTypes.length) errors.push('invalid-tag-list');
    // RFC 6376 §3.6.1: a verifier MUST ignore a key record whose service
    // type list does not include the service being verified. `s=tlsrpt`
    // (RFC 8460) is a legitimate restriction and a perfectly good record —
    // it is simply not a key for ordinary email, and counting it as one is
    // how this audit came to report DKIM found where none applies.
    else if (serviceTypes.indexOf('email') === -1 && serviceTypes.indexOf('*') === -1) {
      restrictions.push('service-not-email');
    }
  }

  var flags = [];
  if (Object.prototype.hasOwnProperty.call(tags, 't')) {
    flags = parseDkimTagList(tags.t, false) || [];
    if (!flags.length) errors.push('invalid-tag-list');
  }

  if (Object.prototype.hasOwnProperty.call(tags, 'n') && !isDkimQuotedPrintable(tags.n)) {
    errors.push('invalid-notes');
  }

  var unknownTags = Object.keys(tags).filter(function (name) {
    return DKIM_KEY_TAGS.indexOf(name) === -1;
  });

  return {
    valid: errors.length === 0,
    version: version,
    keyType: keyType,
    revoked: revoked,
    keyBits: keyBits,
    keyBytes: keyBytes,
    // Which of the two conformant RSA envelopes this key uses, as evidence.
    // It is NOT a quality signal — both are valid — but it explains why Web
    // Crypto confirmed one key and stayed silent about another.
    keyEncoding: keyEncoding,
    hashAlgorithms: hashAlgorithms,
    serviceTypes: serviceTypes,
    flags: flags,
    testing: flags.indexOf('y') !== -1,
    strictSubdomain: flags.indexOf('s') !== -1,
    notes: Object.prototype.hasOwnProperty.call(tags, 'n') ? tags.n : '',
    unknownTags: unknownTags,
    cryptoValidated: null,
    errors: Array.from(new Set(errors)),
    restrictions: restrictions,
    // Does this record APPLY to ordinary email for this domain?
    //
    // Deliberately not "is it well-formed". A key with a truncated `p=` was
    // meant for email and is broken, so it still counts as DKIM found and is
    // reported broken by `dkim-key-unparseable` — dropping it here would
    // silently convert a warning about a broken key into "no DKIM at all",
    // which is a worse answer and a regression of an existing finding. What
    // this excludes is the record that is perfectly good and simply not for
    // this purpose: an unrecognized `k=`, or `s=` scoped to another service.
    appliesToEmail: !revoked && restrictions.length === 0,
  };
}

/**
 * Selector discovery and key validation, over the passed capabilities.
 *
 * Everything above this line is pure and needs nothing. Everything below needs
 * the resolver, the platform's crypto, the generated catalog, or the
 * transitional SPF collaborator — which is why the split is a factory boundary
 * and not a file one: the catalog constants close over `dkimSelectorCatalog`,
 * so they cannot sit at module scope without importing generated data.
 */
export function createDkimCheck(capabilities) {
  // Destructured in the BODY, not in the parameter list — the same adjustment
  // `core/dnssec/matching.js` makes. `platform.test.mjs` recognizes
  // `const { … }` as a declaration but not a destructured parameter, so a
  // parameter named `crypto` reads to it as a bare ambient reach. A stated
  // limit of a lexical scan; adjusted to rather than adjusted.
  const {
    dohFetch, requireUsable, cleanAnswerData, crypto, dkimSelectorCatalog,
    // TEMPORARY. SPF-owned since Task 4.8 and injected by the composition
    // root; Phase 5 replaces it with audit-derived input.
    spfReferencedCatalogKeys,
  } = capabilities;
  /**
   * Two readers that look pure and are not: both take RAW answers and clean
   * them through the passed `cleanAnswerData`, so they belong to the factory
   * and not to module scope. Found by running them — a `ReferenceError` from
   * inside a `.map()`, not a syntax error.
   */
  function dkimKeyRecords(answers) {
    return answers.filter(function (answer) { return answer.type === 16; })
      .map(function (answer) { return cleanAnswerData(answer.data, 'TXT'); })
      .filter(function (value) {
        var tags = Object.create(null);
        String(value || '').split(';').forEach(function (part) {
          var separator = part.indexOf('=');
          if (separator < 0) return;
          tags[part.slice(0, separator).trim().toLowerCase()] = part.slice(separator + 1).trim();
        });
        return Object.prototype.hasOwnProperty.call(tags, 'p') && tags.p.length > 0 &&
          (!tags.v || tags.v.toLowerCase() === 'dkim1');
      });
  }

  /**
   * Split a selector's TXT answers into usable keys and revoked ones.
   *
   * `dkimKeyRecords()` above answers "is there a usable key here", and its
   * filter drops any record whose `p=` is empty. That is right for discovery
   * and wrong for reporting: RFC 6376 3.6.1 defines an empty `p=` as key
   * REVOCATION, so the records it discards are precisely the ones a domain
   * publishes to say "this selector is dead". Reporting a revoked selector as
   * absent tells the operator to go and create a key they deliberately killed.
   *
   * So the two questions are answered separately rather than by loosening the
   * existing filter, which would let a revoked key satisfy "DKIM is present".
   */
  function dkimRecordSet(answers) {
    var keys = [];
    var revoked = [];
    var unusable = [];
    var malformed = [];
    (answers || []).filter(function (answer) { return answer.type === 16; })
      .forEach(function (answer) {
        var value = cleanAnswerData(answer.data, 'TXT');
        var parsed = parseDkimKeyTagList(value);
        var tags = parsed.tags;
        // v= is optional for a DKIM key, but when it is present it identifies
        // the protocol. Keep malformed DKIM-family values (`DKIM2`, `dkim1`)
        // so the analyzer can explain them; ignore a record that explicitly
        // identifies some OTHER protocol. This matters for wildcard TXT:
        // gov.uk synthesizes its `v=DMARC1; p=reject` record at every selector,
        // and treating its DMARC p= tag as a public key awarded 15 DKIM points.
        if (Object.prototype.hasOwnProperty.call(tags, 'v') && !/^dkim/i.test(tags.v)) return;
        if (!Object.prototype.hasOwnProperty.call(tags, 'p')) {
          // Ignore unrelated TXT at a selector, but retain a recognizable DKIM
          // candidate whose required p= tag is missing. Dropping it here made
          // the analyzer's `missing-p` error unreachable and reported an empty
          // DNS name where the operator had actually published a broken key.
          if (Object.prototype.hasOwnProperty.call(tags, 'v')) malformed.push(value);
          return;
        }
        if (tags.p.length === 0) { revoked.push(value); return; }
        // Key-shaped is not the same as usable. A record with an unrecognized
        // `k=`, a service list that excludes email, or a hash list this
        // verifier cannot use is published and conformant — and answering "yes,
        // DKIM is configured" on the strength of it is a claim about signing
        // that the record does not support.
        if (analyzeDkimKey(value).appliesToEmail) keys.push(value);
        else unusable.push(value);
      });
    return { keys: keys, revoked: revoked, unusable: unusable, malformed: malformed };
  }

  var DKIM_CATALOG = dkimSelectorCatalog || { providers: {}, generic: [], temporal: [], prefixes: [], excluded: [] };
  var DKIM_PROVIDER_CATALOG_KEYS = {
    'Google Workspace': 'Google Workspace / Gmail',
    'Apple iCloud': 'Apple iCloud Mail',
    'Microsoft 365': 'Microsoft 365 / Exchange Online',
    'Zoho Mail': 'Zoho Mail & Zoho Suite',
    'Fastmail': 'Fastmail',
    'Proton Mail': 'Proton Mail',
    'Mailgun': 'Mailgun',
    'SendGrid': 'Twilio SendGrid',
    'Symantec/MessageLabs': 'Broadcom / Symantec / MessageLabs',
  };
  // Services a domain names directly in its own SPF record. An `include:` is
  // the domain stating that this vendor sends mail for it — the same claim MX
  // makes about the inbound provider, and just as good a reason to probe that
  // vendor's DKIM selectors. Without this, a Google-Workspace-on-MX domain
  // that runs support through Zendesk never gets `zendesk1`/`zendesk2` tried
  // outside a comprehensive scan, even though both are published.
  var RECOGNIZED_DKIM_SELECTORS = new Set(
    DKIM_SELECTORS.concat(
      Object.values(DKIM_CATALOG.providers).flat(),
      DKIM_CATALOG.generic || [],
      DKIM_CATALOG.temporal || []
    )
  );

  /**
   * Optional structural confirmation through Web Crypto.
   *
   * Confirmation only, and only for the encoding Web Crypto can express. It
   * never lowers a verdict reached without it:
   *
   *  - no `crypto.subtle` → `cryptoValidated` stays null, "we did not check"
   *  - a bare PKCS#1 key → also null. `importKey` takes 'spki' and not
   *    'pkcs1', so there is nothing here to confirm a conformant bare key
   *    with, and silence is the honest record. Treating that silence as a
   *    failure would report a valid published key as broken on the strength of
   *    an API's input formats.
   *  - an SPKI key that fails to import → `key-structure-invalid`, with the
   *    DER-derived size left exactly as it was. The size was read without the
   *    browser's help and does not become less true because the browser
   *    declined to confirm it.
   */
  async function validateDkimKeyStructure(key, txtValue) {
    var subtle = typeof crypto !== 'undefined' && crypto && crypto.subtle;
    if (!subtle || key.keyType !== 'rsa' || key.revoked || key.keyBits === null) return key;
    if (key.keyEncoding !== 'spki') return key;
    var bytes = base64ToBytes(parseDkimKeyTagList(txtValue).tags.p);
    if (!bytes) return key;
    try {
      await subtle.importKey('spki', bytes,
        { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, true, ['verify']);
      key.cryptoValidated = true;
    } catch (e) {
      key.cryptoValidated = false;
      if (key.errors.indexOf('key-structure-invalid') === -1) key.errors.push('key-structure-invalid');
      key.valid = false;
    }
    return key;
  }


  function catalogSelectors(emailProvider, comprehensive, spfRecord) {
    var providerKey = DKIM_PROVIDER_CATALOG_KEYS[emailProvider];
    var providerSelectors = providerKey && DKIM_CATALOG.providers[providerKey]
      ? DKIM_CATALOG.providers[providerKey] : [];
    if (comprehensive) {
      return Object.values(DKIM_CATALOG.providers).flat()
        .concat(DKIM_CATALOG.generic || [], DKIM_CATALOG.temporal || []);
    }
    // Comprehensive mode already covers every provider, so this only widens the
    // provider-aware scan. .concat() returns a new array each time, leaving the
    // catalog's own arrays untouched.
    spfReferencedCatalogKeys(spfRecord).forEach(function (key) {
      if (key !== providerKey && DKIM_CATALOG.providers[key]) {
        providerSelectors = providerSelectors.concat(DKIM_CATALOG.providers[key]);
      }
    });
    return providerSelectors;
  }

  // Which tested selectors exist *only* because SPF named their vendor. A
  // selector the MX provider (or the base list, or the user) would have
  // supplied anyway is not attributed here — it needed no explaining.
  function spfSelectorSources(selectors, emailProvider, comprehensive, spfRecord) {
    var sources = new Map();
    if (comprehensive) return sources;
    var providerKey = DKIM_PROVIDER_CATALOG_KEYS[emailProvider];
    var baseline = new Set(buildDkimSelectorList(selectors, emailProvider, false));
    spfReferencedCatalogKeys(spfRecord).forEach(function (key) {
      if (key === providerKey || !DKIM_CATALOG.providers[key]) return;
      DKIM_CATALOG.providers[key].forEach(function (selector) {
        var name = String(selector || '').trim().toLowerCase();
        // Set iteration follows SPF term order, so a selector two referenced
        // vendors share is credited to the one named first — deterministically.
        if (baseline.has(name) || sources.has(name)) return;
        sources.set(name, key);
      });
    });
    return sources;
  }

  function buildDkimSelectorList(selectors, emailProvider, comprehensive, spfRecord) {
    return Array.from(new Set(
      (selectors || []).concat(DKIM_SELECTORS, catalogSelectors(emailProvider, comprehensive, spfRecord))
        .map(function (selector) { return String(selector || '').trim().toLowerCase(); })
        .filter(validDkimSelector)
    ));
  }

  function isRecognizedDkimSelector(selector) {
    return RECOGNIZED_DKIM_SELECTORS.has(String(selector || '').trim().toLowerCase());
  }

  async function inspectDkimSelector(domain, selector, queryOpts, synthesized) {
    var queryName = `${selector}._domainkey.${domain}`;
    var name = queryName;
    var visited = new Set();
    var firstCname = '';

    for (var depth = 0; depth < 6; depth++) {
      if (visited.has(name)) break;
      visited.add(name);
      var result = requireUsable(await dohFetch(name, 'TXT', queryOpts), name, 'TXT');
      // A wildcard covering _domainkey answers every selector query alike, so a
      // value it synthesizes is not evidence of a key at this selector. Drop
      // those by content; what survives is published for this selector only.
      var notSynthesized = function (value) { return !(synthesized && synthesized.has(value)); };
      var set = dkimRecordSet(result.answers);
      var keys = set.keys.filter(notSynthesized);
      var unusable = set.unusable.filter(notSynthesized);
      var malformed = set.malformed.filter(notSynthesized);
      // A revoked key stops the walk as surely as a live one does. It is an
      // answer — the operator published it on purpose to retire the selector —
      // and continuing past it would report the selector as absent, which reads
      // as "you never set this up" rather than "you turned this off".
      var revoked = set.revoked.filter(notSynthesized);
      if (keys.length || revoked.length || unusable.length || malformed.length) {
        return { sel: selector, queryName: queryName, keys: keys, revoked: revoked, unusable: unusable, malformed: malformed, cname: firstCname };
      }
      var cnameAnswer = result.answers.find(function (answer) { return answer.type === 5; });
      if (!cnameAnswer) break;
      name = cleanAnswerData(cnameAnswer.data, 'CNAME').toLowerCase().replace(/\.$/, '');
      if (!firstCname) firstCname = name;
    }
    return { sel: selector, queryName: queryName, keys: [], revoked: [], unusable: [], malformed: [], cname: firstCname };
  }

  async function checkDKIM(domain, wildcard, selectors, emailProvider, comprehensive, spfRecord, queryOpts) {
    var wildcardDkim = !!(wildcard && wildcard.dkim);
    var synthesized = new Set((wildcard && wildcard.records) || []);
    var selectorList = buildDkimSelectorList(selectors, emailProvider, comprehensive, spfRecord);
    var spfSources = spfSelectorSources(selectors, emailProvider, comprehensive, spfRecord);
    var suppliedSelectors = new Set((selectors || [])
      .map(function (selector) { return String(selector || '').trim().toLowerCase(); })
      .filter(validDkimSelector));
    const found = [];
    const missingSelectors = [];
    const duplicated = [];
    const failedSelectors = [];
    const revokedSelectors = [];
    const unusableSelectors = [];
    const malformedSelectors = [];
    for (var offset = 0; offset < selectorList.length; offset += DKIM_SCAN_BATCH_SIZE) {
      var batch = selectorList.slice(offset, offset + DKIM_SCAN_BATCH_SIZE);
      var checks = await Promise.all(batch.map(async function (selector) {
        try {
          return await inspectDkimSelector(domain, selector, queryOpts, synthesized);
        } catch (error) {
          if (error && error.name === 'AbortError') throw error;
          return { sel: selector, keys: [], revoked: [], unusable: [], malformed: [], cname: '', error: true };
        }
      }));
      for (const { sel, queryName, keys, revoked, unusable, malformed, cname, error } of checks) {
        if (error) { failedSelectors.push(sel); continue; }
        // Reported whether or not a live key was also found, because a revoked
        // record left behind next to a working one is a different situation
        // from a selector that is only a revocation.
        (revoked || []).forEach(function (value) {
          revokedSelectors.push({ sel: sel, queryName: queryName, value: value, key: analyzeDkimKey(value) });
        });
        // Published here, and not a key this domain's email can be verified
        // with. Reported so the operator sees why the selector did not count,
        // rather than being told nothing was found at a name they configured.
        (unusable || []).forEach(function (value) {
          unusableSelectors.push({ sel: sel, queryName: queryName, value: value, key: analyzeDkimKey(value) });
        });
        (malformed || []).forEach(function (value) {
          malformedSelectors.push({ sel: sel, queryName: queryName, value: value, key: analyzeDkimKey(value) });
        });
        // RFC 6376 §3.6.2.2: key records MUST be unique per selector; with more
        // than one the result is undefined, so verification may fail depending on
        // which verifier looks.
        if (keys.length > 1) duplicated.push(sel);
        if (keys.length) {
          found.push({
            sel: sel,
            queryName: queryName,
            type: cname ? 'cname' : 'key',
            value: keys[0],
            cname: cname,
            uncommon: !isRecognizedDkimSelector(sel),
            viaSpf: spfSources.get(sel) || '',
            key: analyzeDkimKey(keys[0]),
          });
        } else if (suppliedSelectors.has(sel) && !(revoked || []).length && !(unusable || []).length && !(malformed || []).length) {
          // Only when NOTHING was published here. A selector carrying a revoked
          // key or one scoped to another service has a record at that name, and
          // reporting "No Domain Key Found" alongside a finding that describes
          // the record contradicts itself — the operator is told in one line
          // that the name is empty and in the next what it contains.
          missingSelectors.push({ sel: sel, queryName: queryName, cname: cname });
        }
      }
    }

    // One parallel pass rather than one await per selector. The DER walk has
    // already produced every size this reports; all that is outstanding is the
    // optional structural confirmation, and it never lowers a size.
    await Promise.all(found.map(function (entry) { return validateDkimKeyStructure(entry.key, entry.value); }));
    const keyProfile = summarizeDkimKeys(found);

    if (!found.length) {
      return { found: false, selectors: [], missingSelectors, testedSelectors: selectorList, failedSelectors, duplicated, revokedSelectors, unusableSelectors, malformedSelectors, keyProfile, confidence: 'sampled', scanMode: comprehensive ? 'comprehensive' : 'provider-aware', note: wildcardDkim ? 'noteWildcard' : failedSelectors.length ? 'noteNotFoundWithErrors' : 'noteNotFound' };
    }
    return { found: true, selectors: found, missingSelectors, testedSelectors: selectorList, failedSelectors, duplicated, revokedSelectors, unusableSelectors, malformedSelectors, keyProfile, confidence: 'observed', scanMode: comprehensive ? 'comprehensive' : 'provider-aware', note: '' };
  }

  /**
   * Roll the per-selector key analyses up to one domain-level profile.
   *
   * `mixed` is about strength, not algorithm: RSA-1024 next to RSA-2048 means
   * mail signed by the weaker selector is only as strong as that selector, so
   * the domain's real DKIM strength is its minimum and not its best. Ed25519
   * alongside RSA is not mixed in that sense — RFC 8463 double-signing is the
   * recommended migration path — so it is counted in `algorithms` and left out
   * of `mixed`.
   */
  function summarizeDkimKeys(selectors) {
    var sizes = [];
    var algorithms = [];
    (selectors || []).forEach(function (entry) {
      var key = entry && entry.key;
      if (!key) return;
      if (algorithms.indexOf(key.keyType) === -1) algorithms.push(key.keyType);
      if (typeof key.keyBits === 'number') sizes.push(key.keyBits);
    });
    return {
      minBits: sizes.length ? Math.min.apply(null, sizes) : null,
      maxBits: sizes.length ? Math.max.apply(null, sizes) : null,
      algorithms: algorithms,
      mixed: sizes.length > 1 && Math.min.apply(null, sizes) !== Math.max.apply(null, sizes),
    };
  }

  return {
    checkDKIM,
    dkimKeyRecords,
    dkimRecordSet,
    catalogSelectors,
    spfSelectorSources,
    buildDkimSelectorList,
    isRecognizedDkimSelector,
    inspectDkimSelector,
    summarizeDkimKeys,
    validateDkimKeyStructure,
  };
}
