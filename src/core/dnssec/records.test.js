#!/usr/bin/env node
/**
 * DNSSEC record parsing (RFC 4034). Task 4.5.
 *
 * The load-bearing rule is the one the module docblock opens with: **a DS
 * digest is hex and a DNSKEY public key is base64**, so the two parsers must
 * not share a normalizer. Folding a base64 key's case destroys it silently —
 * every digest then fails to match and a perfectly healthy zone is reported as
 * a broken chain, which is the most damaging verdict this tool can produce.
 * That is asserted directly rather than left to the comment.
 *
 * The other is that `valid` is a statement about the RECORD, not about the
 * key: `keyStructure` and the zone flag are separate answers, and collapsing
 * them is how a recognized name gets accepted without its value grammar.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import {
  parseDnskey, parseDs, dnskeyRdata, dnskeyKeyTag, dnsWireName, dnskeyStructure,
  dnssecAlgorithmEligibility, dnssecDigestEligibility, dnssecDigestName,
  DNSSEC_ALGORITHMS, DNSSEC_ZONE_SIGNING, DNSSEC_DIGESTS,
  DNSKEY_ERRORS, DS_ERRORS, DNSSEC_ALGORITHM_ELIGIBILITY,
  DNSSEC_DIGEST_ELIGIBILITY, DNSKEY_STRUCTURE_STATES,
} from './records.js';

const { eq, section, report } = createSuite();

/**
 * A real RFC 3110 exponent-and-modulus key: one octet of exponent length, the
 * 65537 exponent, then a 2048-bit modulus. Built rather than pasted, because a
 * hand-typed base64 string that is not a multiple of four decodes to null and
 * every assertion below then tests the failure path by accident.
 */
const rsaKey = bytes => Buffer.concat([Buffer.from([3, 1, 0, 1]), bytes]).toString('base64');
const RSA_KEY = rsaKey(Buffer.alloc(256, 0xab));
const SHA256_HEX = 'ab'.repeat(32);

/* ── 1. Published state constants ─────────────────────────────────────── */
section('1. State constants');

eq('seven DNSKEY error tokens', DNSKEY_ERRORS.length, 7);
eq('eight DS error tokens', DS_ERRORS.length, 8);
eq('three algorithm-eligibility values',
  [...DNSSEC_ALGORITHM_ELIGIBILITY], ['eligible', 'ineligible', 'unknown']);
eq('three digest-eligibility values',
  [...DNSSEC_DIGEST_ELIGIBILITY], ['eligible', 'ineligible', 'unknown']);
eq('three key-structure values',
  [...DNSKEY_STRUCTURE_STATES], ['valid', 'invalid', 'unknown']);
for (const [name, c] of Object.entries({
  DNSKEY_ERRORS, DS_ERRORS, DNSSEC_ALGORITHM_ELIGIBILITY,
  DNSSEC_DIGEST_ELIGIBILITY, DNSKEY_STRUCTURE_STATES,
})) eq(`${name} is frozen`, Object.isFrozen(c), true);

const dnskeyEmitters = {
  'unparseable-record': 'nonsense',
  'unbalanced-parentheses': `257 3 8 ( ${RSA_KEY}`,
  'bad-flags': `99999 3 8 ${RSA_KEY}`,
  'bad-protocol': `257 4 8 ${RSA_KEY}`,
  'bad-algorithm': `257 3 999 ${RSA_KEY}`,
  'empty-key': '257 3 8 ( )',
  'bad-key-encoding': '257 3 8 not!base64',
};
for (const [token, record] of Object.entries(dnskeyEmitters)) {
  eq(`DNSKEY ${token} is emitted`, parseDnskey(record).errors.includes(token), true);
  eq(`and ${token} is in DNSKEY_ERRORS`, DNSKEY_ERRORS.includes(token), true);
}
const dsEmitters = {
  'unparseable-record': 'nonsense',
  'unbalanced-parentheses': `1234 8 2 ( ${SHA256_HEX}`,
  'bad-key-tag': `99999 8 2 ${SHA256_HEX}`,
  'bad-algorithm': `1234 999 2 ${SHA256_HEX}`,
  'bad-digest-type': `1234 8 999 ${SHA256_HEX}`,
  'empty-digest': '1234 8 2 ( )',
  'bad-digest': '1234 8 2 zzzz',
  'bad-digest-length': '1234 8 2 abcd',
};
for (const [token, record] of Object.entries(dsEmitters)) {
  eq(`DS ${token} is emitted`, parseDs(record).errors.includes(token), true);
  eq(`and ${token} is in DS_ERRORS`, DS_ERRORS.includes(token), true);
}
eq('no DNSKEY record above emits a token the constant does not name',
  [...new Set(Object.values(dnskeyEmitters).flatMap(r => parseDnskey(r).errors))]
    .filter(t => !DNSKEY_ERRORS.includes(t)), []);
eq('and no DS record does either',
  [...new Set(Object.values(dsEmitters).flatMap(r => parseDs(r).errors))]
    .filter(t => !DS_ERRORS.includes(t)), []);

/* ── 2. The two normalizers must not be shared ────────────────────────── */
section('2. Hex folds, base64 does not');

const key = parseDnskey(`257 3 8 ${RSA_KEY}`);
eq('a DNSKEY parses', key.valid, true);
// The whole reason the parsers are written apart. Folding this to lowercase
// changes the key material, every digest then fails, and a healthy zone is
// reported as a broken chain.
eq('and its base64 public key keeps its case exactly', key.publicKey, RSA_KEY);
eq('which is not the same as its lowercase form', RSA_KEY === RSA_KEY.toLowerCase(), false);

const ds = parseDs(`1234 8 2 ${SHA256_HEX.toUpperCase()}`);
eq('a DS parses', ds.valid, true);
// Hex is case-insensitive, so folding it is free and makes comparison trivial.
eq('and its hex digest IS folded to lowercase', ds.digest, SHA256_HEX);

/* ── 3. `valid` is about the record, not the key ──────────────────────── */
section('3. Three separate questions');

// Algorithm 8 (RSASHA256) with a 2048-bit modulus: parses, structurally fine.
eq('a good RSA key is structurally valid', key.keyStructure, 'valid');
eq('its algorithm is eligible to sign', key.algorithmEligibility, 'eligible');
eq('and the zone flag is set', key.hasZoneFlag, true);

// Algorithm 13 (ECDSAP256SHA256) has a FIXED 64-byte key. A 2048-bit RSA
// modulus under it is a record that parses and a key that cannot exist.
const wrongSize = parseDnskey(`257 3 13 ${RSA_KEY}`);
eq('a record with an impossible key still PARSES', wrongSize.valid, true);
eq('but its structure is invalid', wrongSize.keyStructure, 'invalid');
eq('and the two answers are therefore different',
  wrongSize.valid === (wrongSize.keyStructure === 'valid'), false);

// An algorithm the IANA table does not carry is unknown, not ineligible.
eq('an unlisted algorithm is unknown, not ineligible',
  dnssecAlgorithmEligibility(200), 'unknown');
eq('algorithm 8 is eligible', dnssecAlgorithmEligibility(8), 'eligible');
eq('algorithm 1 is in the table and NOT a zone signer',
  dnssecAlgorithmEligibility(1), 'ineligible');
eq('and the table is what says so', DNSSEC_ZONE_SIGNING[1], false);
eq('an unknown algorithm gives an unknown key structure',
  dnskeyStructure(200, new Uint8Array(64)), 'unknown');

// A key without the zone bit may not verify RRsets, whatever else is true.
const noZone = parseDnskey(`256 3 8 ${RSA_KEY}`);
eq('flag 256 sets the zone bit', noZone.hasZoneFlag, true);
const notZone = parseDnskey(`0 3 8 ${RSA_KEY}`);
eq('flag 0 does not', notZone.hasZoneFlag, false);
eq('and the record is still valid', notZone.valid, true);

/* ── 4. Algorithm and digest naming ───────────────────────────────────── */
section('4. The IANA tables');

eq('algorithm 8 is RSASHA256', DNSSEC_ALGORITHMS[8], 'RSASHA256');
eq('algorithm 13 is ECDSAP256SHA256', DNSSEC_ALGORITHMS[13], 'ECDSAP256SHA256');
eq('digest 2 is SHA-256', DNSSEC_DIGESTS[2], 'SHA-256');
eq('digest 0 is named RESERVED rather than left unassigned', DNSSEC_DIGESTS[0], 'RESERVED');
eq('dnssecDigestName reads the table', dnssecDigestName(2), 'SHA-256');
eq('an unassigned digest type has no name', dnssecDigestName(99), null);
// Reserved is not the same as invalid: RFC 3658 reserves the value without
// saying a DS carrying it is invalid, and inventing that rule is not ours.
eq('digest 0 is not eligible for validation', dnssecDigestEligibility(0), 'ineligible');
eq('but a DS carrying it is not rejected', parseDs(`1234 8 0 ${SHA256_HEX}`).errors, []);
eq('digest 2 is eligible', dnssecDigestEligibility(2), 'eligible');
eq('an unassigned digest type is unknown', dnssecDigestEligibility(99), 'unknown');

/* ── 5. Deprecation is reported, never rejected ───────────────────────── */
section('5. Deprecated algorithms and digests');

eq('algorithm 5 (RSASHA1) is deprecated', parseDnskey(`257 3 5 ${RSA_KEY}`).deprecated, true);
eq('but the record is still valid', parseDnskey(`257 3 5 ${RSA_KEY}`).valid, true);
eq('algorithm 8 is not deprecated', key.deprecated, false);
eq('digest 1 (SHA-1) is deprecated',
  parseDs(`1234 8 1 ${'ab'.repeat(20)}`).deprecated, true);
eq('and that record is valid too', parseDs(`1234 8 1 ${'ab'.repeat(20)}`).valid, true);
eq('digest 2 is not deprecated', ds.deprecated, false);

/* ── 6. Digest length follows the digest type ─────────────────────────── */
section('6. DS digest lengths');

eq('SHA-1 is 20 bytes', parseDs(`1234 8 1 ${'ab'.repeat(20)}`).valid, true);
eq('a SHA-256 digest under type 1 is the wrong length',
  parseDs(`1234 8 1 ${SHA256_HEX}`).errors, ['bad-digest-length']);
eq('SHA-384 is 48 bytes', parseDs(`1234 8 4 ${'ab'.repeat(48)}`).valid, true);
eq('and a short one is not', parseDs(`1234 8 4 ${SHA256_HEX}`).errors, ['bad-digest-length']);
eq('an odd number of hex digits is not a digest',
  parseDs('1234 8 2 abc').errors.includes('bad-digest'), true);

/* ── 7. Wire name, rdata and key tag ──────────────────────────────────── */
section('7. Computed fields');

// RFC 4034 §5.1.4 takes the digest over the canonical owner name in WIRE
// format: length-prefixed labels, lowercased, root terminated.
eq('a wire name is length-prefixed and root-terminated',
  [...dnsWireName('a.test')], [1, 97, 4, 116, 101, 115, 116, 0]);
eq('and it is lowercased', [...dnsWireName('A.TEST')], [...dnsWireName('a.test')]);
eq('a trailing dot is not an extra label',
  [...dnsWireName('a.test.')], [...dnsWireName('a.test')]);
eq('the root is a single zero octet', [...dnsWireName('')], [0]);

eq('rdata is flags, protocol, algorithm then key', dnskeyRdata(key).slice(0, 4),
  new Uint8Array([1, 1, 3, 8]));
eq('an unparseable key has no rdata', dnskeyRdata(parseDnskey('nonsense')), null);
// RFC 4034 Appendix B: algorithm 1 uses the low bytes of the modulus, not the
// checksum every other algorithm uses.
eq('a key tag is a 16-bit number', dnskeyKeyTag(dnskeyRdata(key), 8) < 65536, true);
eq('and it is stable', dnskeyKeyTag(dnskeyRdata(key), 8), dnskeyKeyTag(dnskeyRdata(key), 8));
eq('the record reports the same tag it computes', key.keyTag, dnskeyKeyTag(dnskeyRdata(key), 8));

/* ── 8. Presentation form ─────────────────────────────────────────────── */
section('8. Parenthesised and split records');

eq('a parenthesised DNSKEY parses', parseDnskey(`257 3 8 ( ${RSA_KEY} )`).valid, true);
eq('and keeps its key intact', parseDnskey(`257 3 8 ( ${RSA_KEY} )`).publicKey, RSA_KEY);
eq('a lone opening parenthesis is unbalanced',
  parseDnskey(`257 3 8 ( ${RSA_KEY}`).errors, ['unbalanced-parentheses']);
eq('the same holds for DS',
  parseDs(`1234 8 2 ${SHA256_HEX} )`).errors, ['unbalanced-parentheses']);
// RFC 4034 permits algorithm mnemonics in zone-file format; this project's one
// resolver never emits them, and accepting a grammar nothing here can produce
// would be scope creep. Reported as unparseable, deliberately.
eq('an alphabetic algorithm field is unparseable, by design',
  parseDnskey(`257 3 RSASHA256 ${RSA_KEY}`).errors, ['unparseable-record']);
// `unparseable-record`, not `bad-algorithm`: the field never becomes a number,
// so the record does not reach per-field validation at all. Stated because the
// two readings are easy to confuse and only one is what the parser does.
eq('and the same is true of a mnemonic DS algorithm',
  parseDs(`1234 RSASHA256 2 ${SHA256_HEX}`).errors, ['unparseable-record']);
eq('an empty string is not a record', parseDnskey('').valid, false);
eq('nor is undefined', parseDs(undefined).valid, false);

report();
