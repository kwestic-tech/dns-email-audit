/**
 * Shared helpers for the locale tooling in tools/.
 *
 * `flatten` and `placeholders` were lifted verbatim out of check-locales.mjs
 * so every script agrees with the validator on what counts as a key and what
 * counts as a placeholder.  Changing them here changes `npm test` too — that
 * is the point.
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

export const root = join(dirname(fileURLToPath(import.meta.url)), '..', '..');
export const localesDir = join(root, 'locales');

/** Tracking database for per-key translation state.  See docs in its header. */
export const STATUS_PATH = join(localesDir, 'translation-status.json');

export const SOURCE_LOCALE = 'en';

/**
 * Translation states, using the XLIFF 2.1 `state` vocabulary verbatim.
 *
 *   initial     source exists, no translation yet (locale holds English)
 *   translated  a translation exists but nobody has reviewed it
 *   reviewed    a human has checked it
 *   final       signed off and locked; tooling will not touch it
 *
 * XLIFF 2.1 keeps `state` to those four and puts everything else in
 * `subState`, which is namespaced by design.  We use:
 *
 *   kwestic:mt      machine/LLM translated, never human-reviewed
 *   kwestic:stale   the English changed after this translation was written
 *                   (the equivalent of gettext marking an entry `fuzzy`)
 */
export const STATES = ['initial', 'translated', 'reviewed', 'final'];
export const SUB_MT = 'kwestic:mt';
export const SUB_STALE = 'kwestic:stale';

/**
 * CLDR plural categories.  English only ever needs `one` and `other`, but
 * Polish selects `few`/`many`, Arabic additionally `zero`/`two`, and
 * js/i18n.js already resolves them correctly via Intl.PluralRules.  A locale
 * may therefore legitimately carry plural forms en.json does not have, and
 * the tooling must not treat those as stale keys and delete them.
 */
export const CLDR_CATEGORIES = ['zero', 'one', 'two', 'few', 'many', 'other'];

/** True when a node is a plural-form object, e.g. { one: …, other: … }. */
export const isPluralGroup = (node) =>
  node && typeof node === 'object' && !Array.isArray(node) &&
  Object.keys(node).length > 0 &&
  Object.keys(node).every(k => CLDR_CATEGORIES.includes(k));

/** Locale registry, read from index.json so there is one source of truth. */
export const LOCALES = JSON.parse(readFileSync(join(localesDir, 'index.json'), 'utf8'))
  .locales.filter(l => l.code !== SOURCE_LOCALE)
  .map(({ code, name, nativeName }) => ({ code, name, nativeName }));

export const LOCALE_CODES = LOCALES.map(l => l.code);

export const localeName = (code) => {
  const l = LOCALES.find(x => x.code === code);
  return l ? `${l.name} (${l.nativeName})` : code;
};

/** Flatten a nested bundle into dotted paths → string values. */
export function flatten(node, prefix = '', out = {}) {
  if (typeof node === 'string') { out[prefix] = node; return out; }
  if (Array.isArray(node)) {
    node.forEach((v, i) => flatten(v, prefix ? `${prefix}.${i}` : String(i), out));
    return out;
  }
  if (node && typeof node === 'object') {
    for (const [k, v] of Object.entries(node)) {
      if (k.startsWith('$')) continue; // $comment and friends
      flatten(v, prefix ? `${prefix}.${k}` : k, out);
    }
  }
  return out;
}

/** Sorted, comma-joined {0}/{1}/… set — two strings must agree on this. */
export const placeholders = (s) => (s.match(/\{\d+\}/g) || []).sort().join(',');

/**
 * The multiset of inline tags in a string, as a comparable key.
 *
 * Differences here are reported but NOT treated as defects: a translator may
 * legitimately wrap a different number of terms in <code> than the English
 * does, and 86 such cases already ship in this repo without any rendering
 * problem.  Use `balancedTags` for the invariant that actually matters.
 */
export const tags = (s) => (s.match(/<\/?[a-z][a-z0-9]*>/gi) || []).sort().join(',');

const VOID_TAGS = new Set(['br', 'hr', 'img', 'input', 'wbr']);

/**
 * The tags js/i18n.js `sanitizeFragment` builds nodes for.  Anything else in a
 * locale string is emitted as literal text at runtime — safe, but almost
 * certainly not what the translator meant, so it is caught here at author time
 * rather than shipping as visible angle brackets.
 *
 * Keep in step with RICH_TAGS in js/i18n.js.
 */
export const RICH_TAG_ALLOWLIST = new Set([
  'a', 'br', 'strong', 'code', 'em', 'b', 'i', 'small', 'ul', 'ol', 'li', 'p',
]);

/** Every tag name in `str` that is not on the rich-text allowlist. */
export function disallowedTags(str) {
  const found = [];
  for (const m of String(str).matchAll(/<\/?([a-z][a-z0-9]*)\b[^>]*?\/?>/gi)) {
    const name = m[1].toLowerCase();
    if (!RICH_TAG_ALLOWLIST.has(name) && !found.includes(name)) found.push(name);
  }
  return found;
}

/**
 * True when every inline tag is closed, in order.  This is the real
 * correctness test: unbalanced markup escapes into the surrounding DOM and
 * breaks the page, whereas a differing tag *count* only reads slightly
 * differently.  Attribute-bearing tags (<a href="…">) are matched properly.
 */
export function balancedTags(str) {
  const stack = [];
  for (const m of str.matchAll(/<(\/?)([a-z][a-z0-9]*)\b[^>]*?(\/?)>/gi)) {
    const name = m[2].toLowerCase();
    if (VOID_TAGS.has(name) || m[3] === '/') continue;
    if (m[1]) { if (stack.pop() !== name) return false; } else stack.push(name);
  }
  return stack.length === 0;
}

/**
 * Set `target[a][b][c] = value` for the dotted key "a.b.c", creating any
 * missing intermediate containers.  A numeric segment creates an array rather
 * than an object, so `csv.headers.3` round-trips as a real array index
 * instead of turning the array into `{"3": …}`.
 */
export function unflattenSet(target, dottedKey, value) {
  const parts = dottedKey.split('.');
  let node = target;
  for (let i = 0; i < parts.length - 1; i++) {
    const key = parts[i];
    const nextIsIndex = /^\d+$/.test(parts[i + 1]);
    if (node[key] === undefined || node[key] === null || typeof node[key] !== 'object') {
      node[key] = nextIsIndex ? [] : {};
    }
    node = node[key];
  }
  node[parts[parts.length - 1]] = value;
  return target;
}

/** First 8 hex chars of the SHA-256 of a string — the source fingerprint. */
export const hash = (s) => createHash('sha256').update(s, 'utf8').digest('hex').slice(0, 8);

export const localePath = (code) => join(localesDir, `${code}.json`);

export function loadLocale(code) {
  return JSON.parse(readFileSync(localePath(code), 'utf8'));
}

/**
 * Write a bundle back out.  2-space indent + trailing newline reproduces the
 * existing locales/*.json byte-for-byte (verified against all nine files), so
 * a no-op save leaves no diff.
 */
export function saveLocale(code, obj) {
  writeFileSync(localePath(code), JSON.stringify(obj, null, 2) + '\n', 'utf8');
}

export function loadStatus() {
  try {
    return JSON.parse(readFileSync(STATUS_PATH, 'utf8'));
  } catch {
    return { sourceLocale: SOURCE_LOCALE, locales: {} };
  }
}

/**
 * Serialize the status database with one line per key.
 *
 * JSON.stringify(…, 2) would spread every entry over five lines and turn a
 * one-word translation into a five-line diff across 4,000+ entries.  One line
 * per key keeps `git diff` on this file readable, which is the only reason
 * to commit it at all.
 */
export function saveStatus(status) {
  const lines = ['{', `  "sourceLocale": ${JSON.stringify(status.sourceLocale || SOURCE_LOCALE)},`, '  "locales": {'];
  const codes = LOCALE_CODES.filter(c => status.locales[c] && Object.keys(status.locales[c]).length);
  codes.forEach((code, ci) => {
    lines.push(`    ${JSON.stringify(code)}: {`);
    const keys = Object.keys(status.locales[code]).sort();
    keys.forEach((key, ki) => {
      const e = status.locales[code][key];
      const fields = [`"state": ${JSON.stringify(e.state)}`];
      if (e.subState) fields.push(`"subState": ${JSON.stringify(e.subState)}`);
      // Both fingerprints must survive the round trip: locale-sync compares
      // sourceHash against en.json and targetHash against the locale file to
      // tell "untouched placeholder" from "someone translated this". Dropping
      // targetHash here silently collapses those two cases into one.
      fields.push(`"sourceHash": ${JSON.stringify(e.sourceHash)}`);
      fields.push(`"targetHash": ${JSON.stringify(e.targetHash)}`);
      if (e.updatedAt) fields.push(`"updatedAt": ${JSON.stringify(e.updatedAt)}`);
      if (e.translator) fields.push(`"translator": ${JSON.stringify(e.translator)}`);
      lines.push(`      ${JSON.stringify(key)}: { ${fields.join(', ')} }${ki === keys.length - 1 ? '' : ','}`);
    });
    lines.push(`    }${ci === codes.length - 1 ? '' : ','}`);
  });
  lines.push('  }', '}');
  writeFileSync(STATUS_PATH, lines.join('\n') + '\n', 'utf8');
}

/**
 * Rebuild a locale bundle in en.json's structural order, taking the locale's
 * own value wherever it has one and the English string wherever it does not.
 * Returns { bundle, added: [dottedKey, …] }.
 *
 * Keys the locale has but en.json does not are dropped — check-locales.mjs
 * already warns about those as stale, and none exist today.
 */
export function mergeInEnOrder(en, locale) {
  const added = [];

  const walk = (enNode, locNode, prefix) => {
    if (typeof enNode === 'string') {
      if (typeof locNode === 'string') return locNode;
      added.push(prefix);
      return enNode;
    }
    if (Array.isArray(enNode)) {
      return enNode.map((v, i) =>
        walk(v, Array.isArray(locNode) ? locNode[i] : undefined, prefix ? `${prefix}.${i}` : String(i)));
    }
    if (enNode && typeof enNode === 'object') {
      const out = {};
      for (const [k, v] of Object.entries(enNode)) {
        const childPrefix = prefix ? `${prefix}.${k}` : k;
        if (k.startsWith('$')) { out[k] = v; continue; }
        const locChild = locNode && typeof locNode === 'object' ? locNode[k] : undefined;
        out[k] = walk(v, locChild, childPrefix);
      }
      // A plural group may legitimately carry more CLDR categories than
      // English does — Polish needs few/many, Arabic zero/two as well. Keep
      // them instead of mirroring en.json's shape and deleting the language's
      // own grammar.
      if (isPluralGroup(enNode) && locNode && typeof locNode === 'object') {
        for (const k of CLDR_CATEGORIES) {
          if (!(k in out) && typeof locNode[k] === 'string') out[k] = locNode[k];
        }
      }
      return out;
    }
    return enNode;
  };

  // meta.* is per-locale identity, never scaffolded from English.
  const bundle = walk(en, locale, '');
  if (locale.meta) bundle.meta = locale.meta;
  return { bundle, added: added.filter(k => !k.startsWith('meta.')) };
}

/** The translatable key set: every en.json string except meta.*. */
export function sourceKeys(enFlat) {
  return Object.keys(enFlat).filter(k => !k.startsWith('meta.'));
}

/**
 * True when `key` is an extra CLDR plural form of a key en.json does have —
 * e.g. `rows.count.few` where en.json only carries `rows.count.one/other`.
 * Such keys are expected in some languages, not stale.
 */
export function isExtraPluralForm(key, enFlat) {
  const i = key.lastIndexOf('.');
  if (i < 0) return false;
  const [parent, form] = [key.slice(0, i), key.slice(i + 1)];
  if (!CLDR_CATEGORIES.includes(form)) return false;
  return CLDR_CATEGORIES.some(c => `${parent}.${c}` in enFlat);
}
