/**
 * User-supplied MTA-STS policy bodies (RFC 8461 §3.2).
 *
 * Pure protocol logic: no resolver, fetch, storage, DOM or platform import.
 * The caller enforces the 64 KB UTF-8 input limit before this parser runs.
 */

const MAX_AGE = 31557600;
const FIELD_NAME = /^[a-z0-9][a-z0-9_.-]{0,31}$/i;
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/;

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
  };
}

/** Validate one policy body without fetching it or changing audit state. */
export function validateMtaStsPolicy(input) {
  var text = typeof input === 'string' ? input : '';
  var result = emptyResult(text);
  if (!text) {
    result.errors = ['malformed-line'];
    return result;
  }

  var lines = text.split(/\r\n|\n/);
  if (lines[lines.length - 1] === '') lines.pop();
  var seen = Object.create(null);
  var malformed = false;

  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (!line || CONTROL.test(line) || line.includes('\r')) {
      malformed = true;
      continue;
    }
    var match = /^([^:]+):([\s\S]*)$/.exec(line);
    if (!match) { malformed = true; continue; }
    var name = match[1];
    var tail = match[2];
    if (!FIELD_NAME.test(name)) { malformed = true; continue; }
    var value = tail.replace(/^[ \t]*/, '').replace(/[ \t]*$/, '');
    if (!value || value.includes('\t')) { malformed = true; continue; }

    if (name !== 'mx' && seen[name]) {
      if (!result.duplicateKeys.includes(name)) result.duplicateKeys.push(name);
      continue;
    }
    seen[name] = true;

    if (name === 'version') {
      result.version = value;
      if (value !== 'STSv1') result.errors.push('invalid-version');
    } else if (name === 'mode') {
      if (value === 'enforce' || value === 'testing' || value === 'none') {
        result.mode = value;
      } else result.errors.push('invalid-mode');
    } else if (name === 'mx') {
      if (validMxPattern(value)) result.mx.push(value.toLowerCase());
      else result.errors.push('invalid-mx');
    } else if (name === 'max_age') {
      if (/^\d{1,10}$/.test(value) && Number(value) <= MAX_AGE) {
        result.maxAge = Number(value);
      } else result.errors.push('invalid-max-age');
    } else {
      result.unknownKeys.push(name);
    }
  }

  if (malformed) result.errors = ['malformed-line'];
  if (!malformed) {
    if (!seen.version) result.errors.push('missing-version');
    if (!seen.mode) result.errors.push('missing-mode');
    if (!seen.max_age) result.errors.push('missing-max-age');
    if (result.mode !== 'none' && !result.mx.length &&
        !result.errors.includes('invalid-mx')) result.errors.push('missing-mx');
  }
  if (result.duplicateKeys.length) result.warnings.push('duplicate-field');
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
export function compareMtaStsMx(patterns, hosts) {
  var expected = (patterns || []).map(String);
  var actual = (hosts || []).map(normalizeHost).filter(Boolean);
  return {
    unmatchedHosts: actual.filter(function (host) {
      return !expected.some(function (pattern) { return patternMatches(pattern, host); });
    }),
    unusedPatterns: expected.filter(function (pattern) {
      return !actual.some(function (host) { return patternMatches(pattern, host); });
    }),
  };
}
