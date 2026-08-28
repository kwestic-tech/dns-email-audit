/**
 * TLS-RPT record validation (RFC 8460 §3). Spec Design §4 and §12, Task 4.4.
 *
 * Same shape as MTA-STS — version first, `%s"TLSRPTv1"` case-sensitive — with
 * one structural difference that is easy to get wrong in the other direction:
 * `tlsrpt-record = tlsrpt-version 1*(field-delim tlsrpt-field)` where
 * `tlsrpt-field = tlsrpt-rua / tlsrpt-extension`, so **more than one `rua`
 * field is grammatical and conformant**. Rejecting a second one discarded a
 * valid record and threw away the first destination as evidence.
 *
 * Pure: no lookup, so no resolver and no factory.
 *
 * ── Moved, not redesigned ────────────────────────────────────────────────
 *
 * `js/dns.js`'s `validateTlsRptRecord`, unchanged apart from the two-space
 * dedent and the `export` keyword.
 */

import { parseOrderedFields, EXT_NAME } from '../shared/record-fields.js';
import { isHttpUri, isMailtoUri } from '../shared/uri.js';
import { RECORD_EXT_VALUE } from './ext-value.js';

/**
 * Every token `validateTlsRptRecord()` can put in `errors`. Registry algebra
 * `transport.tlsRpt.errors`.
 */
export const TLS_RPT_ERRORS = Object.freeze(['invalid-syntax']);


/**
 * Validate a TLS-RPT TXT record against RFC 8460 §3.
 *
 * Same shape as MTA-STS: version first, `%s"TLSRPTv1"` case-sensitive, and
 * every `rua` destination a real `https:` or `mailto:` URI. Prefix matching
 * accepted `mailto:not an address`, which is a string beginning with a
 * scheme and not a URI.
 */
export function validateTlsRptRecord(record) {
  var fields = parseOrderedFields(record, { strictFieldSyntax: true });
  if (!fields || !fields.length) return { valid: false, destinations: [], errors: ['invalid-syntax'] };

  var seen = Object.create(null);
  var syntax = fields[0].name === 'v' && fields[0].value === 'TLSRPTv1';
  var destinations = [];
  var sawRua = false;
  for (var i = 0; i < fields.length; i++) {
    var name = fields[i].name;
    if (i === 0) { seen[name] = true; continue; }
    // `tlsrpt-record = tlsrpt-version 1*(field-delim tlsrpt-field)` with
    // `tlsrpt-field = tlsrpt-rua / tlsrpt-extension`, so MORE THAN ONE `rua`
    // field is grammatical and conformant. Rejecting it discarded a valid
    // record and threw away the first destination as evidence.
    if (name === 'rua') {
      sawRua = true;
      var uris = fields[i].value.split(',').map(function (v) { return v.trim(); }).filter(Boolean);
      if (!uris.length) syntax = false;
      uris.forEach(function (uri) {
        // RFC 8460 imports RFC 3986 whole; it adds no FQDN rule.
        // It does add one encoding rule: comma, exclamation and semicolon
        // must not occur raw inside a destination URI.
        if (/[!,;]/.test(uri) || (!isMailtoUri(uri) && !isHttpUri(uri, { httpsOnly: true }))) syntax = false;
        destinations.push(uri);
      });
      continue;
    }
    // Everything else is non-repeatable: keep the first, ignore later copies.
    if (seen[name]) continue;
    seen[name] = true;
    if (name === 'v') continue;
    if (!EXT_NAME.test(name) || !RECORD_EXT_VALUE.test(fields[i].value)) syntax = false;
  }
  if (!sawRua) syntax = false;
  return { valid: syntax, destinations: destinations, errors: syntax ? [] : ['invalid-syntax'] };
}
