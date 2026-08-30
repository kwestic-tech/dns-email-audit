#!/usr/bin/env node
/**
 * Validates every locale file against locales/en.json (the source of truth).
 *
 * Checks:
 *   • valid JSON
 *   • every locale listed in locales/index.json has a file, and vice versa
 *   • missing keys (fall back to English at runtime — reported as a warning)
 *   • unknown keys (typos or leftovers from a renamed key — warning)
 *   • {0}, {1}, … placeholder mismatches (these break the UI — error)
 *   • unbalanced inline markup, e.g. a <code> with no </code> (error)
 *   • inline tags outside the rich-text allowlist (error) — src/i18n/index.js
 *     renders anything else as literal text, so this closes the same gap
 *     at author time, with no parser and no dependency
 *   • per-key translation state, from locales/translation-status.json
 *     (initial / translated / reviewed / final, plus stale — warning)
 *   • src/data/locales-en.js is in sync with locales/en.json (error)
 *
 * Exit code is non-zero only for real errors, so translations can land while
 * still incomplete.  Run:  npm test
 *
 * `--strict` additionally fails on any key still in state `initial` — an
 * untranslated English placeholder.  That is the pre-PR gate (`npm run
 * locale:gate`), not the default, so a contributor sending a partial
 * translation is never blocked by it.
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import { flatten, placeholders, balancedTags, disallowedTags, isExtraPluralForm, loadStatus, SUB_STALE, root, localesDir } from './lib/locale-utils.mjs';

const strict = process.argv.includes('--strict');

let errors = 0;
let warnings = 0;

const fail = (msg) => { console.error(`  ✗ ${msg}`); errors++; };
const warn = (msg) => { console.warn(`  · ${msg}`); warnings++; };

function readJSON(path) {
  try {
    return JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    fail(`${path.replace(root + '/', '')} is not valid JSON — ${err.message}`);
    return null;
  }
}

// ── Load the reference bundle ────────────────────────────────────────────
const en = readJSON(join(localesDir, 'en.json'));
if (!en) process.exit(1);
const enFlat = flatten(en);
const enKeys = Object.keys(enFlat).filter(k => !k.startsWith('meta.'));

console.log(`Reference: locales/en.json — ${enKeys.length} keys\n`);

// The rich-text allowlist applies to the source bundle too — English is where
// a stray tag gets introduced first.
for (const k of enKeys) {
  const bad = disallowedTags(enFlat[k]);
  if (bad.length) fail(`locales/en.json → ${k} uses <${bad.join('>, <')}>, which is not on the rich-text allowlist`);
}

// ── Registry consistency ─────────────────────────────────────────────────
const index = readJSON(join(localesDir, 'index.json'));
const registered = index ? index.locales.map(l => l.code) : [];
// index.json is the registry and pending-translations.json is the translation
// manifest — neither is a locale bundle, so neither is compared against en.json.
const NOT_A_BUNDLE = ['index.json', 'translation-status.json'];
const onDisk = readdirSync(localesDir)
  .filter(f => f.endsWith('.json') && !NOT_A_BUNDLE.includes(f))
  .map(f => f.replace(/\.json$/, ''));

console.log('locales/index.json');
registered.filter(c => !onDisk.includes(c))
  .forEach(c => fail(`"${c}" is listed in index.json but locales/${c}.json is missing`));
onDisk.filter(c => !registered.includes(c))
  .forEach(c => fail(`locales/${c}.json exists but "${c}" is not listed in index.json — it will never be selectable`));
if (!errors) console.log('  ✓ registry and files agree');
console.log('');

// Per-key translation state, maintained by `npm run locale:sync`.  Without
// it a locale reads as 100% complete the moment English placeholders land,
// which is precisely the blind spot this file exists to close.
const status = loadStatus();

// ── Per-locale comparison ────────────────────────────────────────────────
for (const code of onDisk.filter(c => c !== 'en').sort()) {
  const bundle = readJSON(join(localesDir, `${code}.json`));
  if (!bundle) continue;
  const flat = flatten(bundle);
  const keys = Object.keys(flat).filter(k => !k.startsWith('meta.'));

  const missing = enKeys.filter(k => !(k in flat));
  // Extra CLDR plural forms (pl needs few/many, ar zero/two) are expected,
  // not stale — src/i18n/index.js resolves them through Intl.PluralRules.
  const unknown = keys.filter(k => !(k in enFlat) && !isExtraPluralForm(k, enFlat));
  const mismatched = keys.filter(k => k in enFlat && placeholders(flat[k]) !== placeholders(enFlat[k]));
  // Tag *counts* may legitimately differ between languages; unclosed tags may not.
  const unbalanced = keys.filter(k => !balancedTags(flat[k]));
  // Anything outside the allowlist renders as literal text rather than markup,
  // which is safe but wrong — catch it here rather than in the interface.
  const offAllowlist = keys.filter(k => disallowedTags(flat[k]).length);

  const entries = status.locales?.[code] || {};
  const tally = { initial: 0, translated: 0, reviewed: 0, final: 0, stale: 0 };
  for (const k of enKeys) {
    const e = entries[k];
    if (!e) { tally.initial++; continue; }
    tally[e.state] = (tally[e.state] || 0) + 1;
    if (e.subState === SUB_STALE) tally.stale++;
  }

  const done = enKeys.length - missing.length;
  const pct = Math.round((done / enKeys.length) * 100);
  console.log(`locales/${code}.json — ${done}/${enKeys.length} keys (${pct}%)`);

  mismatched.forEach(k =>
    fail(`${k}: placeholders differ (en has "${placeholders(enFlat[k]) || 'none'}", ${code} has "${placeholders(flat[k]) || 'none'}")`));
  unbalanced.forEach(k => fail(`${k}: inline markup is not balanced — an unclosed tag will break the page`));
  offAllowlist.forEach(k => fail(`${k}: uses <${disallowedTags(flat[k]).join('>, <')}>, which is not on the rich-text allowlist`));
  unknown.forEach(k => warn(`${k}: not present in en.json — typo or stale key?`));
  if (missing.length) warn(`${missing.length} key(s) missing — these fall back to English`);
  const breakdown = ['initial', 'translated', 'reviewed', 'final']
    .filter(st => tally[st]).map(st => `${tally[st]} ${st}`).join(', ');
  if (breakdown) console.log(`  state: ${breakdown}`);
  if (tally.initial) {
    const msg = `${tally.initial} key(s) still in state "initial" (untranslated English placeholder) — run \`npm run locale:todo\``;
    strict ? fail(msg) : warn(msg);
  }
  if (tally.stale) warn(`${tally.stale} translation(s) flagged stale — English changed underneath them`);
  if (!mismatched.length && !unbalanced.length && !offAllowlist.length && !unknown.length && !missing.length && !tally.initial && !tally.stale) console.log('  ✓ complete');
  console.log('');
}

// ── Inline fallback freshness ────────────────────────────────────────────
// Updated in the same commit as tools/build-fallback.mjs, deliberately: these
// two changing out of step is the failure npm test exists to catch, and it
// would surface as an i18n break degrading silently to English phases later.
const fallbackPath = join(root, 'src', 'data', 'locales-en.js');
console.log('src/data/locales-en.js');
if (!existsSync(fallbackPath)) {
  fail('missing — run `npm run build:fallback`');
} else {
  const text = readFileSync(fallbackPath, 'utf8');
  const start = text.indexOf('{');
  const end = text.lastIndexOf('}');
  let inline = null;
  try { inline = JSON.parse(text.slice(start, end + 1)); } catch { /* handled below */ }
  if (!inline) fail('could not be parsed — run `npm run build:fallback`');
  else if (JSON.stringify(inline) !== JSON.stringify(en)) fail('out of sync with locales/en.json — run `npm run build:fallback`');
  else console.log('  ✓ in sync with locales/en.json');
}

console.log(`\n${errors} error(s), ${warnings} warning(s)`);
process.exit(errors ? 1 : 0);
