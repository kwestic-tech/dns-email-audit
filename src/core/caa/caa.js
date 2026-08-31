/**
 * CAA policy. Spec Design §4 and §12, Task 4.1.
 *
 * The first protocol owner extracted, and the one whose job is to prove the
 * pattern the other seven follow:
 *
 *  - **The resolver is passed, never imported.** §12 gives a protocol
 *    directory an edge to `core/shared/` and nothing else. `dohFetch` and
 *    `requireUsable` arrive as arguments to `createCaaCheck()`, so a test hands
 *    this module a fixture transport and the module cannot reach past its
 *    arguments for the real one.
 *  - **The pure grammar is separable from the lookup.** Everything except
 *    `createCaaCheck()` is a value function with no injection at all, and the
 *    unit tests reach it directly rather than through a fake network.
 *  - **The shared URI grammars are imported, not re-implemented.** `iodef` is
 *    validated with `core/shared/uri.js`, the same functions TLS-RPT and BIMI
 *    use.
 *
 * ── Why one module ──────────────────────────────────────────────────────
 *
 * `core/dns/` is four files because it is four LAYERS. CAA is one protocol
 * with one grammar and one lookup, and splitting a fourteen-line tree walk
 * into its own file would be file count standing in for structure. The owners
 * that genuinely hold several records — `core/transport/` above all — split by
 * record, as spec §3's tree already says.
 *
 * ── Raw-kind reading ────────────────────────────────────────────────────
 *
 * None. `checkCAA()` goes through `requireUsable()`, which means a resolver
 * failure THROWS and the caller's `optionalCheck()` fallback decides what the
 * unknown looks like. That fallback copies `DnsError.kind` and lets it escape
 * to `advanced.caa.error` — one of the eleven typed propagation paths — but
 * the copy is made at the call site, not here. This module reads no `.kind`
 * and appears on no reader allowlist.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s CAA block, unchanged apart from the two-space dedent, the
 * `export` keywords, `checkCAA` becoming the body of a factory that names its
 * two resolver capabilities, and `Object.freeze` on the two published state
 * constants. No parsing rule, no walk order and no result shape moved with it.
 */

import { isHttpUri, isMailtoUri } from '../shared/uri.js';


/* ── CAA (RFC 8659, RFC 9495) ─────────────────────────────────────────
   A CAA record set is a policy, and reducing it to a green dot loses the
   whole policy. `0 issue ";"` locks out every certificate authority and
   `0 issuewild ";"` locks out wildcards only; before this, both rendered
   identically to `0 issue "letsencrypt.org"`.
   ───────────────────────────────────────────────────────────────────── */

// RFC 8659 §4 defines issue, issuewild and iodef; RFC 9495 §3 defines
// issuemail. `contactemail` and `contactphone` are NOT from RFC 9495 — the
// IANA CAA registry attributes both to CA/Browser Forum documents, and an
// earlier comment here cited the wrong source for them.
export const CAA_KNOWN_TAGS = Object.freeze(['issue', 'issuewild', 'iodef', 'issuemail', 'contactemail', 'contactphone']);
/**
 * Every token `parseCaaRecord()` can put in a record's `errors`.
 *
 * Published because spec §12.1 rule 3 compares an owner's exported state
 * constants against the reviewed registry, where this is `caa.errors`. The
 * parser still pushes literals — moving code is not the place to rewrite six
 * push sites — so `caa.test.js` asserts that every literal it can emit is in
 * this list, which is what keeps the two from drifting apart.
 */
export const CAA_ERRORS = Object.freeze([
  'unparseable-record', 'bad-flags', 'bad-tag', 'unquoted-value',
  'bad-issue-value', 'bad-iodef-url',
]);

// Properties whose Property Value is an issuer-domain-name with optional
// parameters: RFC 8659 §4.2 and §4.3, and RFC 9495 §3.
var CAA_ISSUER_TAGS = ['issue', 'issuewild', 'issuemail'];
// RFC 8659 §4.2: label = (ALPHA / DIGIT) *( *("-") (ALPHA / DIGIT))
var CAA_LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i;
// RFC 8659 §4.2: value = *(%x21-3A / %x3C-7E) — VCHAR excluding ';' and SP.
var CAA_PARAMETER_VALUE = /^[\x21-\x3A\x3C-\x7E]*$/;
// RFC 8659 §4.4: the iodef value is a URL using the mailto, http or https
// scheme. The scheme list is the start of the check, not the whole of it.

/**
 * Validate an `issue` / `issuewild` / `issuemail` Property Value and return
 * its issuer-domain-name — `''` for a value that authorizes nobody, or null
 * when the value does not match the grammar at all.
 *
 * The distinction matters more than it looks. RFC 8659 §4.2 uses `%%%%%` as
 * its own example of a malformed value and requires a CA to treat it like an
 * absent issuer-domain-name, so a domain publishing only that has blocked
 * issuance. Reading the text before the first semicolon as a CA identity
 * turned that into "authorized: %%%%%" and reported the policy backwards —
 * the strongest form of the mistake this release exists to avoid, because it
 * says a domain is open when the RFC says it is shut.
 */
export function parseCaaIssueValue(value) {
  var text = String(value === undefined || value === null ? '' : value);
  var semicolon = text.indexOf(';');
  var domain = (semicolon === -1 ? text : text.slice(0, semicolon)).trim();
  if (domain) {
    var labels = domain.split('.');
    for (var i = 0; i < labels.length; i++) {
      if (!CAA_LABEL.test(labels[i])) return null;
    }
  }
  if (semicolon !== -1) {
    var rest = text.slice(semicolon + 1).trim();
    // A trailing ';' with nothing after it is legal: the parameters section
    // is optional even once its separator is present.
    if (rest) {
      var parameters = rest.split(';');
      for (var j = 0; j < parameters.length; j++) {
        var parameter = parameters[j].trim();
        var equals = parameter.indexOf('=');
        if (equals < 1) return null;
        if (!CAA_LABEL.test(parameter.slice(0, equals))) return null;
        if (!CAA_PARAMETER_VALUE.test(parameter.slice(equals + 1))) return null;
      }
    }
  }
  return domain.toLowerCase();
}

/**
 * RFC 8659 §4.4: an iodef destination is a mailto, http or https **URL**.
 *
 * A scheme prefix is not a URL. `mailto:not an address` starts with a
 * supported scheme and is not a destination anything can report to, so the
 * whole value goes through the same validators the other records use.
 *
 * Neither call passes options: `iodef` adds no `httpsOnly` and no
 * `requireFqdn`, which is exactly why those two are the caller's to opt into.
 * The legacy `isHttpUri(value, false)` this replaced was behaviourally
 * identical — `false || {}` is `{}` — but `false` is not the options object
 * `core/shared/uri.js` documents.
 */
export function isCaaIodefUrl(value) {
  return isMailtoUri(value) || isHttpUri(value);
}

/**
 * Parse one CAA record from its presentation form: `<flags> <tag> "<value>"`.
 *
 * Captured from the resolver rather than assumed — Cloudflare returns
 * `0 issue "letsencrypt.org"` and `0 iodef "mailto:dns-admin@example.org"`,
 * with the value quoted and the flags and tag bare. Unlike the DS/DNSKEY/TLSA
 * path this one IS quoted, which is why checkCAA() reads `a.data` directly
 * instead of going through cleanAnswerData().
 */
export function parseCaaRecord(presentationString) {
  var text = String(presentationString || '').trim();
  var errors = [];
  var match = /^(\S+)\s+(\S+)\s*([\s\S]*)$/.exec(text);
  if (!match) {
    return { flags: 0, critical: false, tag: '', value: '', known: false, valid: false, errors: ['unparseable-record'] };
  }

  var flags = 0;
  if (/^\d{1,3}$/.test(match[1]) && Number(match[1]) <= 255) flags = Number(match[1]);
  else errors.push('bad-flags');

  // RFC 8659 §4.1: the tag is 1–15 ALPHA/DIGIT octets, and it is matched
  // case-insensitively, so it is lowercased here once for every comparison.
  var tag = match[2].toLowerCase();
  if (!/^[a-z0-9]{1,15}$/.test(tag)) errors.push('bad-tag');

  var raw = match[3].trim();
  var value;
  if (/^".*"$/.test(raw)) value = raw.slice(1, -1).replace(/\\(.)/g, '$1');
  else {
    value = raw;
    // Not fatal: the value is still readable and every resolver observed
    // quotes it, so an unquoted one is worth naming without discarding.
    if (raw) errors.push('unquoted-value');
  }

  var known = CAA_KNOWN_TAGS.indexOf(tag) !== -1;

  // A known tag is a promise about the value's grammar, and until now only
  // the tag was checked. `contactemail` and `contactphone` are deliberately
  // NOT validated here. Neither affects the derived issuance posture, both
  // are defined by CA/Browser Forum documents rather than by an RFC this
  // file otherwise tracks, and a partial mailbox or telephone parser is far
  // easier to reject wrongly than to check usefully — a false
  // `caa-malformed` on a real record is worse than an unvalidated one.
  var issuer = null;
  if (known && CAA_ISSUER_TAGS.indexOf(tag) !== -1) {
    issuer = parseCaaIssueValue(value);
    if (issuer === null) errors.push('bad-issue-value');
  }
  if (known && tag === 'iodef' && !isCaaIodefUrl(value)) errors.push('bad-iodef-url');

  return {
    flags: flags,
    // RFC 8659 §4.1: bit 0, the most significant bit, is the Issuer Critical
    // flag. A CA that does not understand a critical property MUST refuse to
    // issue — so an unrecognized tag with this bit set is a live outage risk,
    // and the same tag without it is inert.
    critical: (flags & 0x80) !== 0,
    tag: tag,
    value: value,
    known: known,
    // The validated issuer-domain-name: '' authorizes nobody, null means the
    // value did not parse. Never a guess at what the operator might have
    // meant.
    issuer: issuer,
    valid: errors.length === 0,
    errors: errors,
  };
}

export function summarizeCaa(records) {
  var parsed = records.map(parseCaaRecord);
  var issueRecords = parsed.filter(function (r) { return r.tag === 'issue'; });
  var wildRecords = parsed.filter(function (r) { return r.tag === 'issuewild'; });
  // Only a record that PARSED contributes an issuer. A malformed value is an
  // absent issuer-domain-name per RFC 8659 §4.2, which is why it can block
  // issuance rather than authorize a CA whose name is nonsense.
  var namedIssuers = function (group) {
    return group.filter(function (r) { return r.valid && r.issuer; })
      .map(function (r) { return r.issuer; });
  };
  var issuers = namedIssuers(issueRecords);
  var wildcardIssuers = namedIssuers(wildRecords);

  return {
    parsed: parsed,
    issuers: issuers,
    // Empty is not "unrestricted". RFC 8659 §4.3: with no issuewild present,
    // wildcard issuance is governed by the issue set. Reading an absent
    // issuewild as "wildcards are open" inverts the policy.
    wildcardIssuers: wildcardIssuers,
    // RFC 8659 §4.2: an issue value of ';' (or empty) names no issuer, and a
    // set of those authorizes nobody at all.
    issuanceBlocked: issueRecords.length > 0 && issuers.length === 0,
    wildcardBlocked: wildRecords.length > 0 && wildcardIssuers.length === 0,
    iodef: parsed.filter(function (r) { return r.tag === 'iodef'; }).map(function (r) { return r.value; }),
    unknownCritical: parsed.filter(function (r) { return !r.known && r.critical; }).map(function (r) { return r.tag; }),
    // The raw presentation string, not the parsed tag: a record that failed
    // to parse may have no usable tag to name it by, and the operator needs
    // to see the text they published in order to find it in their zone.
    malformed: records.filter(function (raw, i) { return !parsed[i].valid; }),
  };
}

/**
 * The CAA lookup, over a passed resolver.
 *
 * Both capabilities are arguments rather than imports because §12 gives a
 * protocol directory no edge to `core/dns/`. `requireUsable` is the layer-2
 * gate: three kinds pass and the other seven throw, so a resolver failure
 * leaves this function as an exception and the CALLER's `optionalCheck()`
 * fallback decides what the unknown looks like.
 *
 * The raw `dohFetch` is deliberate and not an oversight. `dohQuery()` would
 * run `cleanAnswerData()` over the answers, and a CAA presentation string
 * arrives with its VALUE already quoted — `0 issue "letsencrypt.org"` — which
 * `parseCaaRecord()` requires and cleaning would strip.
 */
export function createCaaCheck({ dohFetch, requireUsable }) {
  return async function checkCAA(domain, queryOpts) {
    // Walk up the domain tree (CAA can be inherited from parent)
    const parts = domain.split('.');
    for (let i = 0; i < parts.length - 1; i++) {
      const check = parts.slice(i).join('.');
      const { answers } = requireUsable(await dohFetch(check, 'CAA', queryOpts), check, 'CAA');
      const caaAnswers = answers.filter(a => a.type === 257);
      if (caaAnswers.length > 0) {
        const records = caaAnswers.map(a => a.data);
        return Object.assign({ found: true, records: records, atDomain: check }, summarizeCaa(records));
      }
    }
    return Object.assign({ found: false, records: [], atDomain: null }, summarizeCaa([]));
  };
}
