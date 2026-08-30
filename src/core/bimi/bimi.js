/**
 * BIMI record validation. Spec Design §4 and §12, Task 4.3.
 *
 * **Its own directory, and not part of `core/transport/`.** Brand indicators
 * are not mail transport security: BIMI says which logo a receiver may display
 * beside authenticated mail, MTA-STS and TLS-RPT say how mail is carried. The
 * earlier plan filed this under transport and the spec's tree omitted it
 * entirely; both were corrected in round 1, and the separation is the point of
 * the task rather than an accident of it.
 *
 * ── Pinned to a draft, deliberately ─────────────────────────────────────
 *
 * BIMI is still an Internet-Draft. This validates
 * draft-brand-indicators-for-message-identification §4.3 as of 2026-08, and a
 * later revision should be a deliberate change here AND in the fixtures — not
 * something that drifts in because a reader assumed the newest text.
 *
 * ── No resolver, and therefore no factory ───────────────────────────────
 *
 * This module is pure. The `default._bimi` TXT lookup is the audit
 * coordinator's — it is a lookup, and this owner does none — but everything
 * done WITH those records is here: `summarizeBimi()` owns the
 * candidate-versus-effective selection and the
 * `present` / `declined` / `advertised` / `multiple` shaping, moved from the
 * coordinator at Task 5.2a because Gate 5 requires it to hold no parsing rule.
 *
 * `core/caa/` and `core/mx/` have factories because they do lookups of their
 * own. This one does not, and inventing a factory to match its neighbours
 * would be symmetry standing in for structure.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s `validateBimiRecord`, `BIMI_EXT_VALUE` and `BIMI_LOGO_SUFFIX`,
 * unchanged apart from the two-space dedent and the `export` keyword. The
 * shared `EXT_NAME` production moved to `core/shared/record-fields.js` in the
 * same commit, because MTA-STS and TLS-RPT read it too.
 */

import { parseOrderedFields, EXT_NAME } from '../shared/record-fields.js';
import { isHttpUri } from '../shared/uri.js';
import { versionCandidates, leadingVersionMatches } from '../shared/record-selection.js';

/**
 * Every token `validateBimiRecord()` can put in `errors`.
 *
 * Published because spec §12.1 rule 3 compares an owner's exported state
 * constants against the reviewed registry, where this is `bimi.errors`. The
 * validator still returns literals; `bimi.test.js` proves the two agree.
 *
 * The two are not interchangeable: `duplicate-tags` names a record that repeats
 * a field, and it SUPPRESSES `invalid-syntax` even when the record is also
 * malformed — the duplication is the more specific complaint.
 */
export const BIMI_ERRORS = Object.freeze(['invalid-syntax', 'duplicate-tags']);

// BIMI's pinned grammar does not carry MTA-STS's `=` exclusion, so it keeps the
// looser value class rather than inheriting a restriction from a different
// specification.
var BIMI_EXT_VALUE = /^[\x21-\x3A\x3C-\x7E]+$/;
// Indicator formats the BIMI draft registers. SVG Tiny PS, plain or gzipped.
var BIMI_LOGO_SUFFIX = /\.svgz?(\?[^#]*)?(#.*)?$/i;
/**
 * Validate a BIMI TXT record against draft-brand-indicators-for-message-
 * identification §4.3 (revision as of 2026-08; BIMI is still an
 * Internet-Draft, so this is pinned deliberately and a later revision should
 * be a deliberate change here and in the fixtures).
 *
 * Three things the previous version could not express:
 *
 *  - `l=` PRESENT AND EMPTY is a valid, explicit declination to publish an
 *    indicator. `parsed.tags.l || ''` collapsed that into "missing", so a
 *    conformant record was reported invalid.
 *  - `v=BIMI1` is case-sensitive and must come first, so `v=bimi1` and
 *    `l=…; v=BIMI1` are both unusable and both validated before.
 *  - `https://` is a scheme and two slashes. A logo URL needs a real host,
 *    and an indicator needs an SVG suffix — a `.png` is not one.
 */
export function validateBimiRecord(record) {
  var fields = parseOrderedFields(record);
  if (!fields || !fields.length) {
    return { valid: false, logo: '', authority: '', declined: false, errors: ['invalid-syntax'] };
  }

  var seen = Object.create(null);
  var duplicates = [];
  var syntax = fields[0].name === 'v' && fields[0].value === 'BIMI1';
  var logo = '';
  var authority = '';
  var sawLogo = false;
  for (var i = 0; i < fields.length; i++) {
    var name = fields[i].name;
    if (seen[name]) duplicates.push(name);
    seen[name] = true;
    if (i === 0) continue;
    if (name === 'l') {
      sawLogo = true;
      logo = fields[i].value;
      // BIMI is the protocol that adds the FQDN and HTTPS constraints.
      if (logo && !(isHttpUri(logo, { httpsOnly: true, requireFqdn: true }) && BIMI_LOGO_SUFFIX.test(logo))) syntax = false;
    } else if (name === 'a') {
      authority = fields[i].value;
      if (authority && !isHttpUri(authority, { httpsOnly: true, requireFqdn: true })) syntax = false;
    } else if (name === 'v') syntax = false;
    else if (!EXT_NAME.test(name) || !BIMI_EXT_VALUE.test(fields[i].value)) syntax = false;
  }
  // `l=` is required; it may be empty, but it may not be absent.
  if (!sawLogo) syntax = false;
  var valid = syntax && !duplicates.length;
  return {
    valid: valid,
    logo: logo,
    authority: authority,
    // An explicit "we publish no indicator", which is a conformant record and
    // not a broken one. The caller decides what to show; this only reports it.
    declined: valid && sawLogo && !logo,
    errors: duplicates.length ? ['duplicate-tags'] : valid ? [] : ['invalid-syntax'],
  };
}

/**
 * The whole BIMI answer for one domain, from its `default._bimi` TXT records.
 *
 * Task 5.2a. Gate 5 requires the audit coordinator to hold no parsing rule,
 * and every decision below is one: which records announce BIMI, which of them
 * a sender would keep, which record to show, and what `present` means.
 *
 * ── The three facts this shape keeps apart ──────────────────────────────
 *
 * | Field | Says |
 * | --- | --- |
 * | `present` | An indicator is actually asserted. |
 * | `declined` | The draft's explicit "I publish none" — a valid record with an empty `l=`. Conformant, deliberate, and NOT a configured logo. |
 * | `advertised` | Something is published at the owner name, whether or not a sender would use it. |
 *
 * Counting a declination as present would report an indicator the operator
 * said they do not have; counting it as invalid would report a correct record
 * as broken.
 *
 * `present` is false when the record is DUPLICATED (draft §7.2, the same rule
 * RFC 8461 §3.1 and RFC 8460 §3 state for their own records): the operator
 * believes the control is active when it is not, which is worth saying out
 * loud rather than quietly resolving to the first record.
 *
 * `record` shows the sender-compatible record when there is one and the
 * malformed candidate otherwise — which is the evidence an operator needs.
 *
 * `null` in means the LOOKUP failed, which is not the same as a domain without
 * the record; `unknown` carries that distinction through to scoring and the UI
 * so an unverified control is never presented as an absent one.
 */
export function summarizeBimi(txt) {
  var matches = leadingVersionMatches(txt, 'BIMI1');
  var candidates = versionCandidates(txt, 'BIMI1');
  var record = matches[0] || candidates[0] || '';
  var validation = validateBimiRecord(record);
  return {
    present: matches.length === 1 && validation.valid && !validation.declined,
    declined: matches.length === 1 && validation.declined,
    advertised: candidates.length > 0,
    record: record,
    candidates: candidates,
    validation: validation,
    multiple: matches.length > 1,
    unknown: txt === null,
  };
}
