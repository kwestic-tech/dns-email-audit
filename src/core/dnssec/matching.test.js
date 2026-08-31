#!/usr/bin/env node
/**
 * Local DS-to-DNSKEY matching (RFC 4034 §5.1.4). Task 4.5.
 *
 * One rule dominates: **every failure path lands on `unverifiable`, never on
 * `digest-mismatch`.** A mismatch verdict tells an operator their DNSSEC is
 * broken, and the only thing entitled to say that is arithmetic that actually
 * ran. So the negative controls here are mostly about the ways the arithmetic
 * can fail to run — an unparseable record, an unbuildable key, a digest type
 * Web Crypto does not implement, and a runtime with no subtle digest at all —
 * each of which must produce `unverifiable` with its own reason.
 *
 * Crypto is a passed capability, so the last of those is testable directly:
 * the same records go through a matcher built over a crypto that cannot hash.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { webcrypto } from 'node:crypto';
import { parseDnskey, parseDs, dnskeyRdata, dnsWireName } from './records.js';
import {
  createDsMatcher, anchorFactsUsable, dnskeyCanAnchor, matchConfirmsAnchor,
  DS_MATCH_STATES, DS_UNVERIFIABLE_REASONS, DNSSEC_DIGEST_WEBCRYPTO,
} from './matching.js';

const { eq, section, report } = createSuite();

const DOMAIN = 'example.test';
const RSA_KEY = Buffer.concat([Buffer.from([3, 1, 0, 1]), Buffer.alloc(256, 0xab)])
  .toString('base64');
const key = parseDnskey(`257 3 8 ${RSA_KEY}`);

/** The digest a conforming parent would publish for `key` at `DOMAIN`. */
async function realDigest(webCryptoName, k = key, owner = DOMAIN) {
  const input = new Uint8Array([...dnsWireName(owner), ...dnskeyRdata(k)]);
  const out = await webcrypto.subtle.digest(webCryptoName, input);
  return [...new Uint8Array(out)].map(b => b.toString(16).padStart(2, '0')).join('');
}

const matcher = createDsMatcher({ crypto: webcrypto });
const noCrypto = createDsMatcher({ crypto: {} });
const brokenCrypto = createDsMatcher({
  crypto: { subtle: { digest: async () => { throw new Error('unsupported'); } } },
});

/* ── 1. Published state constants ─────────────────────────────────────── */
section('1. State constants');

eq('five match states', [...DS_MATCH_STATES],
  ['unverifiable', 'unverifiable-digest-type', 'no-matching-key', 'confirmed', 'digest-mismatch']);
eq('five unverifiable reasons', [...DS_UNVERIFIABLE_REASONS],
  ['null', 'invalid-ds', 'invalid-owner', 'runtime-unavailable', 'unbuildable-key']);
eq('DS_MATCH_STATES is frozen', Object.isFrozen(DS_MATCH_STATES), true);
eq('DS_UNVERIFIABLE_REASONS is frozen', Object.isFrozen(DS_UNVERIFIABLE_REASONS), true);
// Only the three digest types Web Crypto actually implements. GOST and SM3 are
// absent on purpose, and so is the reserved 0.
eq('three computable digest types', Object.keys(DNSSEC_DIGEST_WEBCRYPTO), ['1', '2', '4']);
eq('and 2 is SHA-256', DNSSEC_DIGEST_WEBCRYPTO[2], 'SHA-256');

/* ── 2. Arithmetic that ran ───────────────────────────────────────────── */
section('2. confirmed and digest-mismatch');

const goodDs = parseDs(`${key.keyTag} 8 2 ${await realDigest('SHA-256')}`);
const confirmed = await matcher.matchDsToDnskeys(goodDs, [key], DOMAIN);
eq('a DS whose digest matches its key is confirmed', confirmed.match, 'confirmed');
eq('with no unverifiable reason', confirmed.unverifiableReason, null);
eq('and the matched key is reported', confirmed.matchedKeyAlgorithmEligibility, 'eligible');

// The only path to `digest-mismatch`: the tag matched, the hash ran, and the
// answer differed.
const wrongDigest = parseDs(`${key.keyTag} 8 2 ${'cd'.repeat(32)}`);
eq('a matching tag with a different digest is a mismatch',
  (await matcher.matchDsToDnskeys(wrongDigest, [key], DOMAIN)).match, 'digest-mismatch');

// A DS naming a key tag the child does not publish is not a mismatch — there
// was nothing to compare.
const orphan = parseDs(`9999 8 2 ${'cd'.repeat(32)}`);
eq('a DS with no key at its tag is no-matching-key',
  (await matcher.matchDsToDnskeys(orphan, [key], DOMAIN)).match, 'no-matching-key');
eq('and an empty key set gives the same answer',
  (await matcher.matchDsToDnskeys(goodDs, [], DOMAIN)).match, 'no-matching-key');

// The owner name is part of the digest input (RFC 4034 §5.1.4), so the same
// records under a different owner do not confirm.
eq('the same DS under a different owner does not confirm',
  (await matcher.matchDsToDnskeys(goodDs, [key], 'other.test')).match, 'digest-mismatch');

/* ── 3. Every failure lands on unverifiable ───────────────────────────── */
section('3. Arithmetic that could not run');

const bad = async (label, ds, keys, domain, match, reason) => {
  const r = await matcher.matchDsToDnskeys(ds, keys, domain);
  eq(label, [r.match, r.unverifiableReason], [match, reason]);
};

await bad('an unparseable DS is unverifiable, not a mismatch',
  parseDs('nonsense'), [key], DOMAIN, 'unverifiable', 'invalid-ds');
await bad('and so is a DS that failed its own validation',
  parseDs(`${key.keyTag} 8 2 abcd`), [key], DOMAIN, 'unverifiable', 'invalid-ds');
// The empty string is the ROOT, a legal owner encoding to a single zero
// octet — not an invalid one. `invalid-owner` is for a name the encoder
// refuses: a non-ASCII label, an over-long one, or a name past 255 octets.
await bad('a non-ASCII owner name is unverifiable',
  goodDs, [key], 'exämple.test', 'unverifiable', 'invalid-owner');
await bad('and so is an over-long label',
  goodDs, [key], `${'a'.repeat(64)}.test`, 'unverifiable', 'invalid-owner');
eq('while the root is a legal owner, not an invalid one',
  (await matcher.matchDsToDnskeys(goodDs, [key], '')).unverifiableReason !== 'invalid-owner',
  true);

// Digest types 3, 5, 6 and 0 are not in the Web Crypto table. Not computable
// is the whole claim — it is not a statement about the zone.
const gostDs = parseDs(`${key.keyTag} 8 3 ${'ab'.repeat(32)}`);
eq('a digest type Web Crypto does not implement is unverifiable-digest-type',
  (await matcher.matchDsToDnskeys(gostDs, [key], DOMAIN)).match, 'unverifiable-digest-type');

/**
 * `unbuildable-key` is DEAD CODE here, and this asserts the property that makes
 * it so rather than pretending to reach it — the same position
 * `legacy-shapes.test.mjs` already takes about the same branch.
 *
 * Candidates are selected with `key.valid === true`, and every key the parser
 * calls valid has decodable base64, so `dnskeyRdata()` always builds.
 * `digestsComputed` can only be zero when there were no candidates, which
 * returned `no-matching-key` earlier. Kept, not removed: it is a real member of
 * a real union, and a change that made a valid key unbuildable would have to
 * make this assertion fail before the branch went live.
 */
const KEY_SHAPES = [
  `257 3 8 ${RSA_KEY}`, '257 3 8 AwEAAQ==', '256 3 13 AwEAAQ==',
  '257 3 15 AwEAAQ==', '257 3 99 AwEAAQ==', '0 3 8 AwEAAQ==', '257 3 5 AwEAAQ==',
];
eq('every key the parser calls valid can be rebuilt, so unbuildable-key is unreachable',
  KEY_SHAPES.map(parseDnskey).filter(k => k.valid && dnskeyRdata(k) === null), []);
eq('and an invalid key is never a candidate in the first place',
  parseDnskey('257 3 8 not!base64').valid, false);
eq('so a DS naming a tag no valid key carries is no-matching-key, not unbuildable',
  (await matcher.matchDsToDnskeys(parseDs(`4242 8 2 ${'ab'.repeat(32)}`),
    [parseDnskey('257 3 8 not!base64')], DOMAIN)).match, 'no-matching-key');

/**
 * The runtime half. "Our environment could not hash this" and "your zone is
 * broken" are different sentences, and this is the assertion that keeps them
 * apart: the SAME records that confirm above must become `unverifiable` here,
 * never `digest-mismatch`.
 */
const withoutSubtle = await noCrypto.matchDsToDnskeys(goodDs, [key], DOMAIN);
eq('a runtime with no subtle digest at all is unverifiable',
  [withoutSubtle.match, withoutSubtle.unverifiableReason],
  ['unverifiable', 'runtime-unavailable']);
const refusing = await brokenCrypto.matchDsToDnskeys(goodDs, [key], DOMAIN);
eq('and a runtime that refuses the algorithm is too',
  [refusing.match, refusing.unverifiableReason], ['unverifiable', 'runtime-unavailable']);
// The control that gives the two above their meaning.
eq('while the same records confirm on a working runtime', confirmed.match, 'confirmed');

/* ── 4. Anchoring is a separate question from matching ────────────────── */
section('4. anchorFactsUsable and matchConfirmsAnchor');

eq('all three facts must hold', anchorFactsUsable('eligible', true, 'valid'), true);
eq('an ineligible algorithm disqualifies', anchorFactsUsable('ineligible', true, 'valid'), false);
eq('a missing zone flag disqualifies', anchorFactsUsable('eligible', false, 'valid'), false);
eq('invalid key structure disqualifies', anchorFactsUsable('eligible', true, 'invalid'), false);
// `unknown` is not `invalid`. Rejecting it would refuse zones signed to a
// specification newer than this build.
eq('an unknown key structure does NOT disqualify',
  anchorFactsUsable('eligible', true, 'unknown'), true);
eq('but an unknown algorithm does', anchorFactsUsable('unknown', true, 'valid'), false);

eq('dnskeyCanAnchor reads the same rule off a key', dnskeyCanAnchor(key), true);
eq('and says no for a key without the zone flag',
  dnskeyCanAnchor(parseDnskey(`0 3 8 ${RSA_KEY}`)), false);
eq('a null key anchors nothing', dnskeyCanAnchor(null), false);

// A confirmed match still has to anchor. Both halves are stated in one place
// on purpose: written twice they drift.
eq('a confirmed match against an anchoring key confirms the anchor',
  matchConfirmsAnchor(confirmed), true);
eq('a mismatch never confirms an anchor', matchConfirmsAnchor({ match: 'digest-mismatch' }), false);
eq('and neither does undefined', matchConfirmsAnchor(undefined), false);
// A deprecated-but-computable digest still anchors; an INELIGIBLE one does not.
eq('an ineligible digest type disqualifies a confirmed match',
  matchConfirmsAnchor({
    match: 'confirmed', digestEligibility: 'ineligible',
    matchedKeyAlgorithmEligibility: 'eligible', matchedKeyHasZoneFlag: true,
    matchedKeyStructure: 'valid',
  }), false);

/* ── 5. The set, and what it reports ──────────────────────────────────── */
section('5. matchDsSet');

const set = await matcher.matchDsSet([goodDs, orphan], [key], DOMAIN);
eq('one verdict per DS record, in order',
  set.ds.map(m => m.match), ['confirmed', 'no-matching-key']);
eq('the anchor is confirmed', set.anchorConfirmed, true);
eq('and the orphan is named by its key tag', set.orphanDs, [9999]);

const noneConfirm = await matcher.matchDsSet([orphan], [key], DOMAIN);
eq('no confirmation means no anchor', noneConfirm.anchorConfirmed, false);
eq('an empty DS set anchors nothing',
  (await matcher.matchDsSet([], [key], DOMAIN)).anchorConfirmed, false);
eq('and reports no orphans', (await matcher.matchDsSet([], [key], DOMAIN)).orphanDs, []);

// The whole-set version of rule 3: a runtime that cannot hash must not turn a
// healthy zone into a confirmed-nothing alarm.
const setNoCrypto = await noCrypto.matchDsSet([goodDs], [key], DOMAIN);
eq('without crypto the set is unverifiable', setNoCrypto.ds[0].match, 'unverifiable');
eq('and it confirms no anchor rather than denying one',
  setNoCrypto.anchorConfirmed, false);
eq('while naming no orphan either', setNoCrypto.orphanDs, []);

/* ── 6. Every produced value is in its published algebra ──────────────── */
section('6. The constants are not decoration');

const produced = [confirmed, await matcher.matchDsToDnskeys(wrongDigest, [key], DOMAIN),
  await matcher.matchDsToDnskeys(orphan, [key], DOMAIN),
  await matcher.matchDsToDnskeys(gostDs, [key], DOMAIN),
  withoutSubtle, await matcher.matchDsToDnskeys(parseDs('nonsense'), [key], DOMAIN)];
eq('every match state observed is in DS_MATCH_STATES',
  produced.map(r => r.match).filter(v => !DS_MATCH_STATES.includes(v)), []);
eq('and all five are reachable',
  [...new Set(produced.map(r => r.match))].sort(), [...DS_MATCH_STATES].sort());
// Four of the five reasons, not five: `unbuildable-key` is the dead branch
// above, and claiming coverage of it here would be the vacuous credit the
// measured matrix exists to remove.
eq('four of the five unverifiable reasons are reachable',
  [...new Set(produced.map(r => (r.unverifiableReason === null ? 'null' : r.unverifiableReason)))]
    .filter(v => v !== undefined).sort(),
  ['invalid-ds', 'null', 'runtime-unavailable']);
eq('every unverifiable reason observed is in the list',
  produced.map(r => r.unverifiableReason)
    .filter(v => v !== undefined)
    .map(v => (v === null ? 'null' : v))
    .filter(v => !DS_UNVERIFIABLE_REASONS.includes(v)), []);

// Two matchers over two runtimes share nothing.
eq('two matchers over two runtimes disagree exactly as their runtimes do',
  [(await matcher.matchDsToDnskeys(goodDs, [key], DOMAIN)).match,
    (await noCrypto.matchDsToDnskeys(goodDs, [key], DOMAIN)).match],
  ['confirmed', 'unverifiable']);

report();
