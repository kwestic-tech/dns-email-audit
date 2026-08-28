/**
 * TLSA / DANE (RFC 6698, RFC 7671). Spec Design §4 and §12, Task 4.4.
 *
 * Syntax only. Nothing here connects to port 25 and nothing compares a TLSA
 * record against a certificate, so what is reported is what is published.
 *
 * ── Why this module takes a raw response and its neighbours do not ──────
 *
 * `mta-sts.js` and `tls-rpt.js` are pure validators. This one does a lookup,
 * and it needs the RAW response rather than a normalized array, for two
 * reasons that both have to survive any later tidying:
 *
 *  - **The AD bit.** `result.ad` is the only evidence that the record is
 *    carried by a validated chain, and layer 3 does not carry it.
 *  - **The type filter.** A TLSA query commonly returns a CNAME alongside the
 *    records, because pointing `_25._tcp.<host>` at a shared `_dane.<zone>`
 *    name is ordinary practice. `dohAll()` would hand that CNAME string to the
 *    record parser and report a malformed TLSA record on a correctly
 *    configured host, so the filter on type 52 is not optional.
 *
 * `cleanAnswerData` is therefore passed too, and applied by this module to the
 * answers it kept — the same cleaning layer 3 would have done, at the point
 * where the type is already known.
 *
 * ── authenticated: true, false and null are three answers ───────────────
 *
 * DANE is meaningful only when the TLSA record is carried by a validated
 * DNSSEC chain: without one, anyone on the path can strip or rewrite the
 * record, so an unsigned TLSA record provides no protection whatsoever while
 * looking exactly like protection.
 *
 * | `authenticated` | `unknown` | Meaning |
 * | --- | --- | --- |
 * | `true` | `false` | The validating resolver set AD for THIS name. |
 * | `false` | `false` | It did not. The record is published unprotected. |
 * | `null` | `true` | The lookup did not complete. Nothing is claimed. |
 *
 * `do=1` costs nothing — the query is being made anyway — and it is the
 * difference between "this record is not protected" and "we did not look".
 * Without it the `tlsa-published-unsigned` finding would announce "your TLSA
 * is unprotected" on a correctly signed zone purely because nothing had
 * looked.
 *
 * The AD bit is read for the QUERY NAME, not for the audited domain. A TLSA
 * record lives at `_25._tcp.<host>`, usually in a zone unrelated to the
 * audited domain, so the audited domain's chain evidence says nothing about
 * it.
 *
 * 0.4.0 kept a second flag, `qualified`, for the stronger claim that the chain
 * had been walked and verified. **0.5.0 retired the flag instead of completing
 * it** (`OQ-SEC9-07`): local DS-to-DNSKEY matching never validates RRSIGs, so
 * it can never exceed the per-host AD bit already recorded here, and a second
 * field that can only ever equal the first is a claim rather than a
 * distinction. `authenticated` is the ceiling, per host, and every string the
 * interface shows says "published", never "enabled".
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s TLSA block, unchanged apart from the two-space dedent, the
 * `export` keywords, and `checkTlsa` becoming the body of a factory that names
 * its four resolver capabilities.
 */

/**
 * Every token `parseTlsaRecord()` can put in `errors`. Registry algebra
 * `transport.tlsa.errors`.
 */
export const TLSA_ERRORS = Object.freeze([
  'unparseable-record', 'unbalanced-parentheses', 'bad-usage', 'bad-selector',
  'bad-matching-type', 'bad-association-data', 'bad-digest-length',
]);

var TLSA_MATCHING_LENGTHS = { 1: 32, 2: 64 };   // SHA-256, SHA-512; 0 is a full cert, any length

/**
 * Parse one TLSA record from its presentation form.
 *
 * Captured from the resolver before this was written, because the shape is
 * not the one the neighbouring DS parser would suggest: Cloudflare returns
 * TLSA as `3 1 1 ( 87D109DD… )` — parenthesised, with spaces inside the
 * parentheses, in uppercase hex — where DS comes back as four plain fields
 * in lowercase. Splitting on whitespace the way a DS parser does yields
 * ['3','1','1','('] and reads the association data as an empty string,
 * raising no error at all. Hence the explicit strip.
 */
export function parseTlsaRecord(presentationString) {
  var text = String(presentationString || '').trim();
  var match = /^(\d+)\s+(\d+)\s+(\d+)\s+([\s\S]+)$/.exec(text);
  if (!match) {
    return { usage: null, selector: null, matchingType: null, data: '', valid: false, errors: ['unparseable-record'] };
  }
  var usage = Number(match[1]);
  var selector = Number(match[2]);
  var matchingType = Number(match[3]);

  var errors = [];
  // The wrapper is either absent or one balanced outer pair. Stripping each
  // side independently accepted `( ABCD…` and `ABCD… )` alike, which defeats
  // the syntactic contract of a parser written specifically for this
  // presentation form.
  var body = match[4].trim();
  var opened = body.charAt(0) === '(';
  var closed = body.length > 1 && body.charAt(body.length - 1) === ')';
  if (opened !== closed) {
    return {
      usage: usage, selector: selector, matchingType: matchingType,
      data: '', valid: false, errors: ['unbalanced-parentheses'],
    };
  }
  if (opened) body = body.slice(1, -1);
  var data = body.replace(/\s+/g, '').toLowerCase();

  // RFC 6698 §2.1.1–2.1.3, and RFC 7671 §4 for the SMTP-usable subset.
  if (!(usage >= 0 && usage <= 3)) errors.push('bad-usage');
  if (!(selector >= 0 && selector <= 1)) errors.push('bad-selector');
  if (!(matchingType >= 0 && matchingType <= 2)) errors.push('bad-matching-type');
  if (!/^[0-9a-f]+$/.test(data) || data.length % 2 !== 0) errors.push('bad-association-data');
  else {
    var expected = TLSA_MATCHING_LENGTHS[matchingType];
    // Matching type 0 is the full certificate or SPKI, of no fixed length.
    if (expected !== undefined && data.length / 2 !== expected) errors.push('bad-digest-length');
  }

  return {
    usage: usage, selector: selector, matchingType: matchingType,
    data: data, valid: errors.length === 0, errors: errors,
  };
}

/**
 * The TLSA lookup, over a passed resolver.
 *
 * Four capabilities, all arguments: §12 gives a protocol directory no edge to
 * `core/dns/`. `dohFetch` and `requireUsable` rather than `dohQuery` because
 * the AD bit and the type-52 filter both need the raw response; `optionalCheck`
 * per host, so one unreachable exchange degrades to `unknown` instead of
 * discarding the others; `cleanAnswerData` because this module does layer 3's
 * cleaning itself, on the answers it kept.
 */
export function createTlsaCheck({ dohFetch, requireUsable, optionalCheck, cleanAnswerData }) {
  /** Look up `_25._tcp.<host>` for every MX host and validate what comes back. */
  async function checkTlsa(mxHosts, queryOpts) {
    var hosts = await Promise.all((mxHosts || []).map(async function (host) {
      var queryName = '_25._tcp.' + host;
      var UNKNOWN = {};
      // `do=1` costs nothing — the query is being made anyway — and it is the
      // difference between "this record is not protected" and "we did not
      // look". The filter on type 52 is not optional either: a TLSA query
      // commonly returns a CNAME alongside the records, because pointing
      // _25._tcp.<host> at a shared _dane.<zone> name is ordinary practice,
      // and handing that CNAME string to the record parser would report a
      // malformed TLSA record on a correctly configured host.
      var result = await optionalCheck(function () {
        return dohFetch(queryName, 'TLSA', Object.assign({}, queryOpts, { dnssec: true }))
          .then(function (r) { return requireUsable(r, queryName, 'TLSA'); });
      }, UNKNOWN);
      if (result === UNKNOWN) {
        return { host: host, queryName: queryName, records: [], present: false, authenticated: null, unknown: true };
      }
      var records = result.answers.filter(function (a) { return a.type === 52; })
        .map(function (a) { return parseTlsaRecord(cleanAnswerData(a.data, 'TLSA')); });
      return {
        host: host,
        queryName: queryName,
        records: records,
        present: records.length > 0,
        // The AD bit from the same validating resolver checkDNSSEC() already
        // trusts, read for THIS name rather than for the audited domain — an
        // MX host usually lives in someone else's zone, so the audited
        // domain's DNSSEC status says nothing about whether this record is
        // protected. null means the lookup did not complete.
        authenticated: result.ad === true,
        unknown: false,
      };
    }));

    var present = hosts.filter(function (h) { return h.present; });
    return {
      hosts: hosts,
      anyPresent: present.length > 0,
      // Every host that publishes TLSA does so under an authenticated chain.
      // Evidence, not a verdict: it is what the `tlsa-published-unsigned`
      // finding is gated on. This is the strongest true statement available
      // about a record in someone else's zone.
      allAuthenticated: present.length > 0 && present.every(function (h) { return h.authenticated === true; }),
      unauthenticatedHosts: present.filter(function (h) { return h.authenticated === false; })
        .map(function (h) { return h.host; }),
      unknown: hosts.some(function (h) { return h.unknown; }),
    };
  }

  return checkTlsa;
}
