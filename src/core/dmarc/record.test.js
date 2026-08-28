#!/usr/bin/env node
/**
 * DMARC record parsing (RFC 9989). Task 4.6.
 *
 * Pure, and the assertions that matter are about the three tags DMARCbis
 * REMOVED and the ones it kept: `pct`, `rf` and `ri` are reported but neither
 * scored nor treated as errors, because a record written against RFC 7489
 * behaves differently depending on which specification the receiver
 * implements.
 *
 * The hand-written `mailto:` rule is asserted as PRESERVED, not as correct.
 * Ruled at Task 4.0 and reaffirmed at 4.6: reconciling it with
 * `core/shared/uri.js` is a behaviour change and outside 0.6.0.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { isMailtoUri } from '../shared/uri.js';
import {
  analyzeDmarc, emptyDmarcStatus, normalizePolicy, parseDmarcTag,
  parseDmarcUriList, parseTagList, validateDmarcVersion,
  POLICY_RANK, DMARC_TAGS_RFC9989, DMARC_TAGS_REMOVED,
} from './record.js';

const { eq, section, report } = createSuite();

/* ── 1. The RFC 9989 tag vocabulary ───────────────────────────────────── */
section('1. Tag vocabulary');

eq('eleven tags in RFC 9989', DMARC_TAGS_RFC9989.length, 11);
eq('and the three DMARCbis removed', [...DMARC_TAGS_REMOVED], ['pct', 'rf', 'ri']);
eq('the two lists do not overlap',
  DMARC_TAGS_RFC9989.filter(t => DMARC_TAGS_REMOVED.includes(t)), []);
eq('policies rank weakest to strongest',
  [POLICY_RANK.none, POLICY_RANK.quarantine, POLICY_RANK.reject], [0, 1, 2]);

// Reported, not scored and not an error. A receiver implementing RFC 9989
// ignores them; the operator should know before it bites them.
const withPct = analyzeDmarc('v=DMARC1; p=reject; pct=50');
eq('a removed tag is reported', withPct.removedTags, ['pct']);
eq('but the record is not malformed by it', withPct.malformed, false);
eq('and its status is ok', withPct.status, 'ok');
eq('and it is not an unknown tag', withPct.unknownTags, []);
const unknown = analyzeDmarc('v=DMARC1; p=reject; madeup=1');
eq('an unrecognized tag is unknown', unknown.unknownTags, ['madeup']);
eq('and does not malform the record', unknown.malformed, false);
eq('a duplicated tag is reported',
  analyzeDmarc('v=DMARC1; p=reject; p=none').duplicateTags, ['p']);

/* ── 2. The version field ─────────────────────────────────────────────── */
section('2. validateDmarcVersion');

eq('v=DMARC1 first is valid', validateDmarcVersion('v=DMARC1; p=none').valid, true);
eq('a record not starting with v= is not',
  validateDmarcVersion('p=none; v=DMARC1').valid, false);
eq('and says why', validateDmarcVersion('p=none; v=DMARC1').reason, 'not-first');
eq('a wrong version is refused', validateDmarcVersion('v=DMARC2; p=none').valid, false);
eq('an absent version is refused', validateDmarcVersion('p=none').valid, false);
eq('an empty record is absent', validateDmarcVersion('').reason, 'absent');

/* ── 3. Policies ──────────────────────────────────────────────────────── */
section('3. normalizePolicy');

eq('reject normalizes', normalizePolicy('reject'), 'reject');
eq('case does not matter', normalizePolicy('ReJeCt'), 'reject');
// NOT trimmed: the tag parser trims, so a policy value reaching here already
// has its whitespace removed and this function does not repeat the work.
eq('padding is not trimmed here — parseDmarcTag already did it',
  normalizePolicy('  none  '), null);
eq('and the tag parser is what trims it', parseDmarcTag('v=DMARC1; p=  none  ', 'p'), 'none');
eq('an unknown policy is not one', normalizePolicy('block'), null);
eq('an empty value is not one', normalizePolicy(''), null);
eq('undefined is not one', normalizePolicy(undefined), null);

eq('a tag is read case-insensitively', parseDmarcTag('V=DMARC1; P=reject', 'p'), 'reject');
eq('an absent tag is null', parseDmarcTag('v=DMARC1', 'sp'), null);

/* ── 4. parseTagList is DMARC's own, not parseOrderedFields ───────────── */
section('4. parseTagList');

eq('names are lowercased', parseTagList('P=reject').tags.p, 'reject');
eq('values are trimmed unconditionally', parseTagList('p = reject ').tags.p, 'reject');
// The four behavioural differences from core/shared/record-fields.js's
// parseOrderedFields, which is why the two were NOT merged at Task 4.0.
eq('a field with no = is dropped rather than failing the record',
  parseTagList('v=DMARC1; garbage').tags, { v: 'DMARC1' });
eq('and the record still parses', parseTagList('v=DMARC1; garbage').duplicates, []);
eq('duplicates are reported and the FIRST wins',
  parseTagList('p=reject; p=none'), { tags: { p: 'reject' }, duplicates: ['p'] });
eq('order is not preserved — it is a bag', Object.keys(parseTagList('p=none; v=DMARC1').tags),
  ['p', 'v']);

/* ── 5. Report URIs: the preserved hand-written rule ──────────────────── */
section('5. parseDmarcUriList');

const one = parseDmarcUriList('mailto:dmarc@example.test');
eq('a mailto destination parses', one.valid, true);
eq('and its domain is extracted', one.domains, ['example.test']);
eq('a size limit is permitted', parseDmarcUriList('mailto:a@example.test!10m').valid, true);
eq('and reported', parseDmarcUriList('mailto:a@example.test!10m').uris[0].sizeLimit, '10m');
eq('a bad size limit invalidates', parseDmarcUriList('mailto:a@example.test!xx').valid, false);
eq('a comma-separated list parses both',
  parseDmarcUriList('mailto:a@example.test,mailto:b@example.test').count, 2);
eq('an https destination is an unsupported scheme',
  parseDmarcUriList('https://example.test/r').uris[0].unsupportedScheme, true);
eq('and is invalid', parseDmarcUriList('https://example.test/r').valid, false);
eq('a bare address is not a URI', parseDmarcUriList('a@example.test').valid, false);
eq('an empty list is not valid', parseDmarcUriList('').valid, false);

/**
 * THE PRESERVED DIVERGENCE. This module's rule is `/^[^\s@]+\.[^\s@.]+$/` on
 * the domain; `core/shared/uri.js`'s `isMailtoUri()` applies RFC 6068. They
 * disagree, and the disagreement is deliberate for 0.6.0.
 *
 * Asserted as a FACT ABOUT TODAY, not as a correctness claim: ruled at Task
 * 4.0 and reaffirmed at 4.6, reconciliation is outside this release unless
 * separately authorized. The equivalence instrument detects such a change; it
 * does not authorize one.
 */
const divergent = 'mailto:a b@example.test';
eq('the shared RFC 6068 rule rejects a space in the local part',
  isMailtoUri(divergent), false);
eq('and DMARC\'s own rule accepts it — preserved, not endorsed',
  parseDmarcUriList(divergent).valid, true);
eq('the two therefore disagree, deliberately, in this release',
  isMailtoUri(divergent) === parseDmarcUriList(divergent).valid, false);

/* ── 6. The empty status ──────────────────────────────────────────────── */
section('6. emptyDmarcStatus');

const empty = emptyDmarcStatus('missing');
eq('an empty status carries the given state', empty.status, 'missing');
eq('with an empty policy rather than a null one', empty.policy, '');
eq('and no report destinations', empty.ruaUris.domains, []);
eq('and nothing enforcing', empty.enforcing, false);

/* ── 7. A whole record ────────────────────────────────────────────────── */
section('7. analyzeDmarc');

const full = analyzeDmarc('v=DMARC1; p=reject; sp=quarantine; rua=mailto:d@example.test; adkim=s');
eq('the policy is read', full.policy, 'reject');
eq('the subdomain policy is read', full.sp, 'quarantine');
eq('alignment is read', full.adkim, 's');
eq('the report destination is read', full.ruaUris.domains, ['example.test']);
eq('and the record is not malformed', full.malformed, false);
eq('its status is ok', full.status, 'ok');
// `present` and not `ok`: the record is there and cannot be applied. Those are
// different facts, and collapsing them loses the reason.
eq('a record with no p= is present but malformed',
  [analyzeDmarc('v=DMARC1').status, analyzeDmarc('v=DMARC1').malformed], ['present', true]);
eq('so is one whose version is not first', analyzeDmarc('p=reject; v=DMARC1').status, 'present');
eq('and an empty string is missing, not present', analyzeDmarc('').status, 'missing');

report();
