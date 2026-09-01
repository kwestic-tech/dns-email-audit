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
 */

const MAX_AGE = 31557600;
const FIELD_NAME = /^[a-z0-9][a-z0-9_.-]{0,31}$/i;
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;
const REGISTERED_FIELDS = Object.freeze(['version', 'mode', 'mx', 'max_age']);

export const MTA_STS_POLICY_ERRORS = Object.freeze([
  'malformed-line', 'blank-line', 'wrong-case-field',
  'invalid-version', 'invalid-mode', 'invalid-mx', 'invalid-max-age',
  'missing-version', 'missing-mode', 'missing-max-age', 'missing-mx',
]);
export const MTA_STS_POLICY_WARNINGS = Object.freeze([
  'duplicate-field', 'bom-present',
]);
export const MTA_STS_POLICY_LINE_ENDINGS = Object.freeze([
  'crlf', 'lf', 'mixed', 'none',
]);
export const MTA_STS_MX_COMPARE_STATES = Object.freeze([
  'compared', 'unknown', 'null-mx',
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

    var foldedName = name.toLowerCase();
    if (name !== foldedName && REGISTERED_FIELDS.includes(foldedName)) {
      addDiagnostic(result, 'errors', 'wrong-case-field', lineNumber);
      continue;
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

/** Compare policy patterns with already-audited DNS MX hostnames. */
export function compareMtaStsMx(patterns, mxFact) {
  var fact = mxFact || {};
  if (fact.unknown) {
    return { state: 'unknown', unmatchedHosts: [], unusedPatterns: [] };
  }
  if (fact.nullMx) {
    return { state: 'null-mx', unmatchedHosts: [], unusedPatterns: [] };
  }
  var expected = (patterns || []).map(String);
  var actual = (fact.hosts || []).map(normalizeHost).filter(Boolean);
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
