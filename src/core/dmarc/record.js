/**
 * DMARC record parsing (RFC 9989). Spec Design §4 and §12, Task 4.6.
 *
 * Pure, domain-agnostic and resolver-free: a string in, a status out. Nothing
 * here knows which domain published the record, which is what lets the Tree
 * Walk and the audit layer both use it.
 *
 * ── DMARCbis, and the three tags that left ──────────────────────────────
 *
 * DMARCbis was published in May 2026 as RFC 9989 (RFC 9990 covering aggregate
 * reporting, RFC 9991 failure reporting), obsoleting RFC 7489 and RFC 9091.
 * `pct`, `rf` and `ri` are gone. A receiver implementing RFC 9989 ignores
 * them, so they are neither scored nor treated as errors — but their presence
 * IS reported, because a record written against RFC 7489 behaves differently
 * depending on which specification the receiver implements, and the operator
 * should know that before it bites them.
 *
 * ── The hand-written `mailto:` parser stays ─────────────────────────────
 *
 * `parseDmarcUriList()` validates a report destination with its own rule
 * (`/^[^\s@]+\.[^\s@.]+$/` on the domain) rather than through
 * `core/shared/uri.js`'s `isMailtoUri()`. The two disagree about which
 * destinations are valid.
 *
 * **Ruled at Task 4.0 and reaffirmed at 4.6: this behaviour is PRESERVED.**
 * Reconciling them is a behaviour change and is outside 0.6.0 unless
 * separately authorized. The equivalence instrument DETECTS such a change; it
 * does not authorize one, and a green run is not permission to have made it.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s DMARC tag vocabulary, parsers and `analyzeDmarc`, plus
 * `parseTagList` — which is DMARC's alone, and is deliberately NOT
 * `core/shared/record-fields.js`'s `parseOrderedFields`: it lowercases names,
 * trims unconditionally, drops fields carrying no `=`, and reports duplicates.
 * Unchanged apart from the two-space dedent and the `export` keywords.
 */

// Valid policy values per RFC 9989 §4.7, ordered weakest → strongest.
export const POLICY_RANK = { none: 0, quarantine: 1, reject: 2 };

/* ── RFC 9989 tag vocabulary ─────────────────────────────────────────────
   DMARCbis was published in May 2026 as RFC 9989 (with RFC 9990 covering
   aggregate reporting and RFC 9991 failure reporting), obsoleting RFC 7489
   and RFC 9091. The tag list below is the complete set it defines.

   `pct`, `rf` and `ri` are gone. A receiver implementing RFC 9989 ignores
   them, so we neither score them nor treat them as errors — but we do say
   they are there, because a record written against RFC 7489 will behave
   differently depending on which spec the receiver implements, and the
   operator should know that before it bites them.
   ───────────────────────────────────────────────────────────────────────── */
export const DMARC_TAGS_RFC9989 = ['v', 'p', 'sp', 'np', 'adkim', 'aspf', 'fo', 'rua', 'ruf', 'psd', 't'];
export const DMARC_TAGS_REMOVED = ['pct', 'rf', 'ri'];
var DMARC_FO_VALUES = ['0', '1', 'd', 's'];

/**
 * Parse a DMARC record into its tags (RFC 9989 §4.7).
 *
 * Two things this has to get right that a naive regex does not:
 *
 *  1. Tag names must be anchored. An unanchored /p=([^;]+)/ matches the `p=`
 *     inside `sp=` and `np=`, so `sp=reject; p=none` would parse as
 *     policy=reject. Tag order is arbitrary in real records.
 *  2. Tag names are case-insensitive — `P=REJECT` is valid and appears in
 *     the wild. Values are case-insensitive too, with one exception: the
 *     `v=` value is case SENSITIVE and must be exactly `DMARC1`.
 *
 * Subdomain policies inherit rather than default to permissive:
 * `sp` falls back to `p`, and `np` falls back to `sp` then `p`. A record with
 * `p=reject` and no `sp` DOES reject subdomain mail. `effectiveSp` and
 * `effectiveNp` carry the resolved values so scoring never has to re-derive
 * them.
 */
export function parseDmarcTag(record, name) {
  // (?:^|;)\s* anchors to a tag boundary so 'p' cannot match inside 'sp'/'np'.
  var m = record.match(new RegExp('(?:^|;)\\s*' + name + '\\s*=\\s*([^;]*)', 'i'));
  if (!m) return null;
  var value = m[1].trim();
  return value === '' ? null : value;
}

export function normalizePolicy(value) {
  if (!value) return null;
  var lower = String(value).toLowerCase();
  return POLICY_RANK[lower] !== undefined ? lower : null;
}

/**
 * RFC 9989 §4.7: `v` MUST be the first tag, and its value is case sensitive
 * with `DMARC1` the only accepted spelling. A record that fails either test
 * "MUST be ignored" in its entirety — so this is a hard failure, not a nit.
 * We still parse the rest of the record afterwards so the report can say
 * what the operator *meant* alongside the fact that nobody will honour it.
 */
export function validateDmarcVersion(record) {
  var m = String(record || '').match(/^\s*([A-Za-z][A-Za-z0-9_-]*)\s*=\s*([^;]*)/);
  if (!m) return { valid: false, reason: 'absent' };
  if (m[1].toLowerCase() !== 'v') return { valid: false, reason: 'not-first' };
  if (m[2].trim() !== 'DMARC1') return { valid: false, reason: 'bad-value' };
  return { valid: true, reason: null };
}

/**
 * Parse a `rua=`/`ruf=` value into its individual destinations.
 *
 * RFC 9989 §4.7 defines a comma-separated list of DMARC URIs, each with an
 * optional `!` size-limit suffix (digits plus an optional k/m/g/t unit).
 * A literal `!` inside a URI must be percent-encoded, so the LAST `!` is
 * unambiguously the delimiter.
 *
 * Only `mailto:` is a registered destination scheme for DMARC reporting.
 * Anything else parses but is undeliverable, which is reported separately
 * from outright malformed syntax because the fix is different.
 */
export function parseDmarcUriList(value) {
  var entries = String(value || '').split(',')
    .map(function (v) { return v.trim(); })
    .filter(Boolean);

  var uris = entries.map(function (raw) {
    var bang = raw.lastIndexOf('!');
    var uri = bang === -1 ? raw : raw.slice(0, bang);
    var limit = bang === -1 ? '' : raw.slice(bang + 1);
    var limitValid = limit === '' || /^\d+[kmgt]?$/i.test(limit);
    var scheme = (uri.indexOf(':') === -1 ? '' : uri.slice(0, uri.indexOf(':'))).toLowerCase();
    var mailbox = scheme === 'mailto' ? uri.slice(7) : '';
    var at = mailbox.lastIndexOf('@');
    var domain = at > 0 ? mailbox.slice(at + 1).toLowerCase().replace(/\.$/, '') : '';
    var wellFormed = scheme === 'mailto' && at > 0 && /^[^\s@]+\.[^\s@.]+$/.test(domain);
    return {
      raw: raw, uri: uri, scheme: scheme,
      mailbox: wellFormed ? mailbox : '',
      domain: wellFormed ? domain : '',
      sizeLimit: limit,
      unsupportedScheme: scheme !== '' && scheme !== 'mailto',
      valid: wellFormed && limitValid,
    };
  });

  return {
    uris: uris,
    count: uris.length,
    valid: uris.length > 0 && uris.every(function (u) { return u.valid; }),
    invalid: uris.filter(function (u) { return !u.valid; }).map(function (u) { return u.raw; }),
    domains: uris.filter(function (u) { return u.valid; }).map(function (u) { return u.domain; }),
  };
}

export function analyzeDmarc(dmarc, multiple) {
  // Legacy, and unreachable from analyzeDomain(): the Tree Walk never passes
  // `multiple`, because RFC 9989 §4.10 step 2 discards duplicate records at a
  // name and CONTINUES the walk — a record higher in the tree can still
  // apply, so a duplicate is no longer a policy verdict. Retained because
  // analyzeDmarc() is exported and directly constructed in tests, and because
  // removing a status token is a breaking change to a shape
  // report-comparison (0.8.0) exports. Do not describe this as current
  // discovery behaviour; buildIssues() raises the duplicate from the walk's
  // own observed[] evidence instead.
  if (multiple) return emptyDmarcStatus('permerror');
  if (!dmarc) return emptyDmarcStatus('missing');

  var parsedTags = parseTagList(dmarc);
  var tag = function (name) { return parseDmarcTag(dmarc, name); };
  var version = validateDmarcVersion(dmarc);

  var rawPolicy = tag('p');
  var policy = normalizePolicy(rawPolicy) || 'none';
  var rawSp = tag('sp');
  var rawNp = tag('np');
  var sp = normalizePolicy(rawSp);
  var np = normalizePolicy(rawNp);

  // "Absent, so it inherits" and "present but not a policy value" are
  // different problems with different fixes, and normalizePolicy() collapses
  // both to null. Keep the distinction so the finding can name the value the
  // operator actually wrote instead of reporting a tag they did not omit.
  var tagState = function (raw, normalized) {
    return raw === null ? 'absent' : normalized === null ? 'invalid' : 'valid';
  };
  var spState = tagState(rawSp, sp);
  var npState = tagState(rawNp, np);

  // Inheritance chain per RFC 9989 §4.7. Note that sp/np apply only to
  // subdomains of the Organizational Domain, never to the domain itself.
  var effectiveSp = sp || policy;
  var effectiveNp = np || sp || policy;

  // ── t= (RFC 9989 §4.7, new) ──
  // Test mode. `t=y` tells receivers the owner is still evaluating and the
  // policy should NOT be applied. Reports keep flowing. This is bis's
  // replacement for ramping with pct=, and it means `p=reject; t=y` gives
  // exactly as much spoofing protection as `p=none` — which is none.
  var rawT = tag('t');
  var tValid = rawT === null || /^[yn]$/i.test(String(rawT).trim());
  var testMode = String(rawT || 'n').trim().toLowerCase() === 'y';

  // ── psd= (RFC 9989 §4.7, new) ──
  // Marks a Public Suffix Domain so the Tree Walk knows where to stop.
  // Default is 'u' (unknown — use normal discovery), NOT 'n'.
  var rawPsd = tag('psd');
  var psdValid = rawPsd === null || /^[ynu]$/i.test(String(rawPsd).trim());
  var psd = String(rawPsd || 'u').trim().toLowerCase();

  // ── fo= (RFC 9989 §4.7) ──
  // Colon-separated subset of 0/1/d/s. Its content MUST be ignored when no
  // ruf= is present, which makes fo-without-ruf a silent no-op worth naming.
  var rawFo = tag('fo');
  var fo = rawFo === null ? '0' : String(rawFo).trim().toLowerCase();
  var foValid = rawFo === null || fo.split(':').every(function (v) {
    return DMARC_FO_VALUES.indexOf(v.trim()) !== -1;
  });

  // ── pct= (removed in RFC 9989) ──
  // Parsed for reporting only. It no longer contributes to the score: a
  // bis-conformant receiver ignores it outright. Guard against NaN anyway —
  // an unguarded parseInt used to poison every downstream total.
  var rawPct = tag('pct');
  var pct = 100;
  var pctValid = true;
  if (rawPct !== null) {
    var parsed = parseInt(rawPct, 10);
    if (isNaN(parsed)) { pctValid = false; }
    else { pct = Math.max(0, Math.min(100, parsed)); pctValid = parsed >= 0 && parsed <= 100; }
  }

  // RFC 9989 §4.7 defines exactly two alignment modes, `r` and `s`. Anything
  // else used to become `r` silently, which is the correct RECEIVER
  // behaviour and a poor auditor one: `adkim=strict` reads as strict to the
  // person who wrote it and relaxes alignment in practice. Keep the receiver
  // behaviour, report the divergence.
  var alignmentState = function (raw) {
    if (raw === null) return 'absent';
    var value = String(raw).trim().toLowerCase();
    return value === 's' ? 's' : value === 'r' ? 'r' : 'invalid';
  };
  var rawAdkim = tag('adkim');
  var rawAspf = tag('aspf');
  var adkimState = alignmentState(rawAdkim);
  var aspfState = alignmentState(rawAspf);
  var adkim = adkimState === 's' ? 's' : 'r';
  var aspf = aspfState === 's' ? 's' : 'r';

  var ruaUris = parseDmarcUriList(tag('rua'));
  var rufUris = parseDmarcUriList(tag('ruf'));
  var rua = ruaUris.count > 0;
  var ruf = rufUris.count > 0;

  // Classify every tag actually present against the RFC 9989 vocabulary.
  var presentTags = Object.keys(parsedTags.tags);
  var removedTags = presentTags.filter(function (k) { return DMARC_TAGS_REMOVED.indexOf(k) !== -1; });
  var unknownTags = presentTags.filter(function (k) {
    return DMARC_TAGS_RFC9989.indexOf(k) === -1 && DMARC_TAGS_REMOVED.indexOf(k) === -1;
  });

  // The published policy is what the operator wrote; the effective policy is
  // what receivers will actually do. Test mode is the only thing that can
  // make them differ, and keeping both means the UI can show the gap rather
  // than silently reporting one as the other.
  var effectivePolicy = testMode ? 'none' : policy;
  var enforcing = effectivePolicy === 'quarantine' || effectivePolicy === 'reject';

  // `present` covers a record receivers cannot act on: an unusable v=, an
  // unrecognized p=, or duplicate tags. A record exists, so it is neither
  // 'missing' nor trustworthy enforcement.
  var malformed = !version.valid
    || rawPolicy === null
    || normalizePolicy(rawPolicy) === null
    || parsedTags.duplicates.length > 0;
  var status = malformed ? 'present'
    : enforcing ? 'ok'
      : 'warn';

  return {
    status: status,
    cls: status === 'ok' ? 'ok' : 'warn',
    policy: policy, sp: sp, np: np,
    policyRaw: rawPolicy, spRaw: rawSp, npRaw: rawNp,
    spState: spState, npState: npState,
    adkimState: adkimState, aspfState: aspfState,
    adkimRaw: rawAdkim, aspfRaw: rawAspf,
    effectivePolicy: effectivePolicy,
    effectiveSp: effectiveSp, effectiveNp: effectiveNp,
    pct: pct, pctValid: pctValid, pctPresent: rawPct !== null,
    adkim: adkim, aspf: aspf,
    rua: rua, ruf: ruf, ruaUris: ruaUris, rufUris: rufUris,
    enforcing: enforcing,
    fo: fo, foValid: foValid, foPresent: rawFo !== null,
    testMode: testMode, tValid: tValid,
    psd: psd, psdValid: psdValid, psdPresent: rawPsd !== null,
    version: version,
    removedTags: removedTags, unknownTags: unknownTags,
    malformed: malformed, duplicateTags: parsedTags.duplicates,
  };
}

/** Shared shape for the "there is nothing to analyse" outcomes. */
export function emptyDmarcStatus(status) {
  return {
    // 'unknown' is not a failed control, it is an unexamined one: the walk
    // hit a transient DNS error and the record could not be read. It must
    // never wear the same red as a domain that genuinely published nothing.
    status: status, cls: status === 'unknown' ? 'warn' : 'crit',
    policy: '', effectivePolicy: '',
    rua: false, ruf: false,
    ruaUris: parseDmarcUriList(''), rufUris: parseDmarcUriList(''),
    sp: null, np: null, effectiveSp: null, effectiveNp: null,
    pct: 100, pctValid: true, pctPresent: false,
    adkim: 'r', aspf: 'r', enforcing: false,
    policyRaw: null, spRaw: null, npRaw: null,
    spState: 'absent', npState: 'absent',
    adkimState: 'absent', aspfState: 'absent',
    adkimRaw: null, aspfRaw: null,
    fo: '0', foValid: true, foPresent: false,
    testMode: false, tValid: true,
    psd: 'u', psdValid: true, psdPresent: false,
    version: { valid: false, reason: 'absent' },
    removedTags: [], unknownTags: [], duplicateTags: [],
  };
}

export function parseTagList(record) {
  var tags = {};
  var duplicates = [];
  String(record || '').split(';').forEach(function (part) {
    var at = part.indexOf('=');
    if (at === -1) return;
    var key = part.slice(0, at).trim().toLowerCase();
    var value = part.slice(at + 1).trim();
    if (Object.prototype.hasOwnProperty.call(tags, key)) duplicates.push(key);
    else tags[key] = value;
  });
  return { tags: tags, duplicates: duplicates };
}
