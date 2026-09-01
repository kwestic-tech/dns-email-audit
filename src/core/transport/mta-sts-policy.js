/**
 * User-supplied MTA-STS policy bodies (RFC 8461 §3.2).
 *
 * Pure protocol logic: no resolver, fetch, storage, DOM or platform import.
 * The caller enforces the 64 KB UTF-8 input limit before this parser runs.
 *
 * Policy extension values deliberately follow sts-policy-ext-value, which
 * permits visible punctuation such as `=` and `;`. The DNS TXT record uses a
 * different production; do not make this parser match that sibling's stricter
 * extension-value rule.
 *
 * `diagnostics` is a line index, NOT a mirror of `errors` + `warnings`. Every
 * token raised against a line appears in both; the four `missing-*` errors are
 * raised against the document as a whole and have no line, so they appear in
 * `errors` only. A consumer mapping tokens to evidence must handle both — the
 * spec's `kind: 'input'` evidence variant is what a line-less error gets.
 */

const MAX_AGE = 31557600;
const FIELD_NAME = /^[a-z0-9][a-z0-9_.-]{0,31}$/i;
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const REGISTERED_FIELDS = Object.freeze(['version', 'mode', 'mx', 'max_age']);

export const MTA_STS_POLICY_ERRORS = Object.freeze([
  'malformed-line', 'blank-line',
  'invalid-version', 'invalid-mode', 'invalid-mx', 'invalid-max-age',
  'missing-version', 'missing-mode', 'missing-max-age', 'missing-mx',
]);

/**
 * `wrong-case-field` is a WARNING and not an error, and the reason is the ABNF.
 *
 * `sts-policy-ext-name = (ALPHA / DIGIT) *31(...)`, so `Mode` is a legal
 * extension name and §3.2 says unknown fields SHALL be ignored. A conformant
 * policy may carry one, and calling that policy invalid would be wrong. When
 * the operator did mean the registered field, the resulting `missing-*` error
 * already carries the invalidity — this token only explains why.
 */
export const MTA_STS_POLICY_WARNINGS = Object.freeze([
  'duplicate-field', 'bom-present', 'wrong-case-field',
]);
export const MTA_STS_POLICY_LINE_ENDINGS = Object.freeze([
  'crlf', 'lf', 'mixed', 'none',
]);
/**
 * `null-mx` is deliberately ABSENT until `src/audit/artifacts.js` exists.
 *
 * A registered state no fixture can reach is a stop under the agent contract,
 * and a hand-built `{ nullMx: true }` in a unit test is the invented response
 * shape that rule names. Nothing in the tree produces a `nullMx` fact today —
 * null MX lives as `isNullMx()` and the `@null-mx` provider token — so the
 * member is added in the same reviewed step as the composer that produces it.
 * Until then a null-MX domain reaches this function as an empty host list and
 * degrades to `unknown`, which is correct: no delivery candidate is
 * established, so no mismatch may be claimed.
 */
export const MTA_STS_MX_COMPARE_STATES = Object.freeze([
  'compared', 'unknown',
]);

function lineEndingKind(text) {
  var hasCrlf = /\r\n/.test(text);
  var withoutCrlf = text.replace(/\r\n/g, '');
  var hasLf = /\n/.test(withoutCrlf);
  if (hasCrlf && hasLf) return 'mixed';
  if (hasCrlf) return 'crlf';
  if (hasLf) return 'lf';
  return 'none';
}

function validDomain(value) {
  var text = String(value || '');
  if (!text || text.length > 253 || text.endsWith('.')) return false;
  var labels = text.split('.');
  return labels.every(function (label) {
    return label.length >= 1 && label.length <= 63 &&
      /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i.test(label);
  });
}

function validMxPattern(value) {
  var text = String(value || '');
  if (text.startsWith('*.')) text = text.slice(2);
  if (text.includes('*')) return false;
  return validDomain(text);
}

function emptyResult(text) {
  return {
    valid: false,
    version: '',
    mode: null,
    mx: [],
    maxAge: null,
    duplicateKeys: [],
    unknownKeys: [],
    lineEndings: lineEndingKind(text),
    errors: [],
    warnings: [],
    diagnostics: [],
  };
}

function addDiagnostic(result, bucket, token, line) {
  result[bucket].push(token);
  result.diagnostics.push({ token: token, line: line });
}

/** Validate one policy body without fetching it or changing audit state. */
export function validateMtaStsPolicy(input) {
  var text = typeof input === 'string' ? input : '';
  var result = emptyResult(text);
  if (!text) {
    addDiagnostic(result, 'errors', 'malformed-line', 1);
    return result;
  }

  if (text.charCodeAt(0) === 0xfeff) {
    text = text.slice(1);
    addDiagnostic(result, 'warnings', 'bom-present', 1);
  }

  var lines = text.split(/\r\n|\n/);
  if (lines[lines.length - 1] === '') lines.pop();
  var seen = Object.create(null);
  var hasMalformedLine = false;

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    var lineNumber = i + 1;
    if (!line) {
      addDiagnostic(result, 'errors', 'blank-line', lineNumber);
      continue;
    }
    if (CONTROL.test(line) || line.includes('\r')) {
      addDiagnostic(result, 'errors', 'malformed-line', lineNumber);
      hasMalformedLine = true;
      continue;
    }
    var match = /^([^:]+):([\s\S]*)$/.exec(line);
    if (!match) {
      addDiagnostic(result, 'errors', 'malformed-line', lineNumber);
      hasMalformedLine = true;
      continue;
    }
    var name = match[1];
    var tail = match[2];
    if (!FIELD_NAME.test(name)) {
      addDiagnostic(result, 'errors', 'malformed-line', lineNumber);
      hasMalformedLine = true;
      continue;
    }
    var value = tail.replace(/^[ \t]*/, '').replace(/[ \t]*$/, '');
    if (!value || value.includes('\t')) {
      addDiagnostic(result, 'errors', 'malformed-line', lineNumber);
      hasMalformedLine = true;
      continue;
    }

    // A case variant of a registered name IS a legal extension name, so the
    // warning explains it and then flow CONTINUES into the ordinary extension
    // path: it is retained in `unknownKeys` for display and is subject to the
    // non-`mx` duplicate rule like any other extension. Short-circuiting here
    // dropped it from both.
    var foldedName = name.toLowerCase();
    if (name !== foldedName && REGISTERED_FIELDS.includes(foldedName)) {
      addDiagnostic(result, 'warnings', 'wrong-case-field', lineNumber);
    }

    if (name !== 'mx' && seen[name]) {
      if (!result.duplicateKeys.includes(name)) result.duplicateKeys.push(name);
      addDiagnostic(result, 'warnings', 'duplicate-field', lineNumber);
      continue;
    }
    seen[name] = true;

    if (name === 'version') {
      result.version = value;
      if (value !== 'STSv1') addDiagnostic(result, 'errors', 'invalid-version', lineNumber);
    } else if (name === 'mode') {
      if (value === 'enforce' || value === 'testing' || value === 'none') {
        result.mode = value;
      } else addDiagnostic(result, 'errors', 'invalid-mode', lineNumber);
    } else if (name === 'mx') {
      if (validMxPattern(value)) result.mx.push(value.toLowerCase());
      else addDiagnostic(result, 'errors', 'invalid-mx', lineNumber);
    } else if (name === 'max_age') {
      if (/^\d{1,10}$/.test(value) && Number(value) <= MAX_AGE) {
        result.maxAge = Number(value);
      } else addDiagnostic(result, 'errors', 'invalid-max-age', lineNumber);
    } else {
      result.unknownKeys.push(name);
    }
  }

  if (!hasMalformedLine) {
    if (!seen.version) result.errors.push('missing-version');
    if (!seen.mode) result.errors.push('missing-mode');
    if (!seen.max_age) result.errors.push('missing-max-age');
    if ((result.mode === 'enforce' || result.mode === 'testing') && !result.mx.length &&
        !result.errors.includes('invalid-mx')) result.errors.push('missing-mx');
  }
  result.valid = result.errors.length === 0;
  return result;
}

function normalizeHost(value) {
  return String(value || '').trim().toLowerCase().replace(/\.$/, '');
}

function patternMatches(pattern, host) {
  var expected = normalizeHost(pattern);
  var actual = normalizeHost(host);
  if (!expected.startsWith('*.')) return actual === expected;
  var suffix = expected.slice(2).split('.');
  var labels = actual.split('.');
  return labels.length === suffix.length + 1 &&
    labels.slice(1).join('.') === suffix.join('.');
}

function noComparison(state) {
  return { state: state, unmatchedHosts: [], unusedPatterns: [] };
}

/**
 * Compare policy patterns with already-audited DNS MX hostnames.
 *
 * `mxFact` is `{ hosts: string[], unknown?: boolean }` and is built by
 * `src/audit/artifacts.js` from the domain's PUBLISHED delivery candidates —
 * never from `advanced.mxHealth`. Three reasons, all of them load-bearing:
 *
 *   1. `mxHealth.hosts` holds audit OBJECTS, not hostnames. `audit-domain.js`
 *      already writes `mxHealth.hosts.map(h => h.host)` to get names out.
 *   2. `advanced.mxHealth` is `null` whenever deep checks are off (the
 *      interface disables them above 50 domains), the domain has no MX, or the
 *      domain publishes a null MX. An absent fact is NOT an empty fact.
 *   3. MTA-STS `mx` patterns are about which exchanges the policy permits,
 *      which the base MX lookup answers for every domain. Binding this to a
 *      cost-gated resolution-health check would silently switch the comparison
 *      off on the largest audits.
 *
 * The composer owes this function the domain's delivery candidates, which is
 * NOT the same as its MX records. RFC 5321 §5.1: "If an empty list of MXs is
 * returned, the address is treated as if it was associated with an implicit MX
 * RR, with a preference of 0, pointing to that host", and that rule "applies
 * only if there are no MX records present". A domain with no MX and a usable
 * address record therefore has one candidate — itself — and a policy naming it
 * is correct, not stale. The composer's four cases are in spec §3.
 *
 * Fails closed. Anything that is not an established, non-empty list of valid
 * hostnames yields `unknown`, because an empty or silently-filtered host list
 * compares as "every pattern is unused" and reports a healthy policy as stale.
 * A single unparseable entry fails the whole comparison rather than being
 * dropped: partial host knowledge cannot distinguish a stale pattern from an
 * unread one.
 */
export function compareMtaStsMx(patterns, mxFact) {
  if (!mxFact || typeof mxFact !== 'object') return noComparison('unknown');
  if (mxFact.unknown) return noComparison('unknown');
  if (!Array.isArray(mxFact.hosts) || !mxFact.hosts.length) {
    return noComparison('unknown');
  }

  var actual = [];
  for (var i = 0; i < mxFact.hosts.length; i++) {
    var entry = mxFact.hosts[i];
    if (typeof entry !== 'string') return noComparison('unknown');
    var host = normalizeHost(entry);
    // `filter(Boolean)` here would turn '' and '   ' into a confident empty
    // comparison, which is the stale-policy claim this guard exists to refuse.
    if (!validDomain(host)) return noComparison('unknown');
    actual.push(host);
  }

  var expected = (patterns || []).map(String);
  return {
    state: 'compared',
    unmatchedHosts: actual.filter(function (host) {
      return !expected.some(function (pattern) { return patternMatches(pattern, host); });
    }),
    unusedPatterns: expected.filter(function (pattern) {
      return !actual.some(function (host) { return patternMatches(pattern, host); });
    }),
  };
}
