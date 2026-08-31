/**
 * MTA-STS record validation (RFC 8461 §3.1). Spec Design §4 and §12, Task 4.4.
 *
 * The TXT record only. Nothing here fetches the policy file at
 * `https://mta-sts.<domain>/.well-known/mta-sts.txt`, and
 * `advanced.mtaSts.policyVerified` stays false in this release for exactly
 * that reason — the record says a policy is advertised, not that it exists.
 *
 * Pure: no lookup, so no resolver and no factory.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s `validateMtaStsRecord` and `STS_ID`, unchanged apart from the
 * two-space dedent and the `export` keywords.
 */

import { parseOrderedFields, EXT_NAME } from '../shared/record-fields.js';
import { RECORD_EXT_VALUE } from './ext-value.js';
import { versionCandidates, leadingVersionMatches } from '../shared/record-selection.js';

/**
 * Every token `validateMtaStsRecord()` can put in `errors`.
 *
 * One member, and published anyway: spec §12.1 rule 3 compares an owner's
 * exported state constants against the reviewed registry, where this is
 * `transport.mtaSts.errors`. A one-member algebra is still an algebra, and the
 * test proves the validator emits that member and no other.
 */
export const MTA_STS_ERRORS = Object.freeze(['invalid-syntax']);

// RFC 8461 §3.1: sts-id = 1*32(ALPHA / DIGIT). No hyphens, no 33rd character.
const STS_ID = /^[a-z0-9]{1,32}$/i;

/**
 * Validate an MTA-STS TXT record against RFC 8461 §3.1.
 *
 * Ordered and anchored, not a tag-bag lookup. The ABNF puts the version
 * FIRST and writes it `%s"STSv1"`, which is case-SENSITIVE — so
 * `id=abc; v=STSv1` and `v=stsv1` are both unusable and both previously
 * validated. `id` is 1–32 alphanumerics: `has-hyphen` is not one, nor is a
 * 33-character string. A bare `garbage` field is not an extension; the
 * extension grammar requires a name and a value, so it cannot be dropped
 * silently.
 *
 * Getting this wrong suppressed `mta-sts-invalid` — a finding whose entire
 * purpose is to catch a control the operator believes is working.
 */
export function validateMtaStsRecord(record) {
  var fields = parseOrderedFields(record, { strictFieldSyntax: true });
  if (!fields || !fields.length) return { valid: false, id: '', errors: ['invalid-syntax'] };

  var seen = Object.create(null);
  var syntax = fields[0].name === 'v' && fields[0].value === 'STSv1';
  var id = '';
  for (var i = 0; i < fields.length; i++) {
    var name = fields[i].name;
    // RFC 8461 §3.1: "Parsers MUST accept TXT records ... If any non-repeated
    // field is duplicated, all entries except for the first SHALL be
    // ignored." A blanket duplicate rejection is the opposite of that: it
    // called a conformant record invalid, and then reported the LAST id as
    // effective — the one every sender discards.
    if (seen[name]) continue;
    seen[name] = true;
    if (i === 0) continue;
    if (name === 'id') { id = fields[i].value; if (!STS_ID.test(id)) syntax = false; }
    else if (name === 'v') continue;
    else if (!EXT_NAME.test(name) || !RECORD_EXT_VALUE.test(fields[i].value)) syntax = false;
  }
  if (!id) syntax = false;
  return { valid: syntax, id: id, errors: syntax ? [] : ['invalid-syntax'] };
}

/**
 * The whole MTA-STS answer for one domain, from its `_mta-sts` TXT records.
 *
 * Task 5.2a, moved out of `analyzeDomain()`: Gate 5 requires the coordinator to
 * hold no parsing rule, and selecting the records, choosing which one to show
 * and deciding what `present` means are all parsing rules.
 *
 * RFC 8461 §3.1: filter to the versioned records, and if the result is not
 * exactly one, the domain does not have the feature. So `present` is false when
 * the record is DUPLICATED — the operator believes the control is active when
 * it is not, which is worth saying out loud.
 *
 * An auditor does not discard the malformed candidate the way a sender does.
 * The record exists, at an owner name dedicated to this protocol, and "nothing
 * is published" and "what is published is not an active policy" are different
 * facts. `record` shows the sender-compatible record when there is one and the
 * malformed candidate otherwise, which is the evidence an operator needs.
 *
 * `policyVerified` is false here and always has been: this checks the DNS
 * record only. Fetching the policy file at
 * `https://mta-sts.<domain>/.well-known/mta-sts.txt` is an HTTPS request this
 * tool does not make, and the field stays so the distinction is visible rather
 * than implied.
 *
 * `null` in means the LOOKUP failed, which is not a domain without the record;
 * `unknown` carries that through to scoring and the UI.
 */
export function summarizeMtaSts(txt) {
  var matches = leadingVersionMatches(txt, 'STSv1');
  var candidates = versionCandidates(txt, 'STSv1');
  var record = matches[0] || candidates[0] || '';
  var validation = validateMtaStsRecord(record);
  return {
    present: matches.length === 1 && validation.valid,
    advertised: candidates.length > 0,
    policyVerified: false,
    record: record,
    candidates: candidates,
    validation: validation,
    multiple: matches.length > 1,
    unknown: txt === null,
  };
}
