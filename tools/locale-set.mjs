#!/usr/bin/env node
/**
 * Writes finished translations into locales/*.json and records them in the
 * state database.
 *
 * Input is a JSON patch — the inverse of `locale:todo --json` — either as a
 * file path or on stdin:
 *
 *   { "de": { "issue.dmarc-bad-fo.msg": "Das DMARC-Tag …" },
 *     "fr": { "issue.dmarc-bad-fo.msg": "La balise DMARC …" } }
 *
 *   npm run locale:set -- translations.json
 *   npm run locale:set -- translations.json --translator=claude-opus-5
 *   cat translations.json | npm run locale:set
 *
 * A unit is refused, and left in its current state, only for the two defects
 * that actually break the running page: {0}/{1} placeholders that do not
 * match the English, and inline markup that is not balanced.
 *
 * A differing *count* of <code>/<em> tags is reported but still written —
 * wrapping fewer or more terms than the English is a normal translation
 * choice, and 86 such cases already ship here with no rendering problem.
 */

import { readFileSync } from 'node:fs';
import {
  LOCALE_CODES, flatten, sourceKeys, loadLocale, saveLocale, unflattenSet,
  loadStatus, saveStatus, placeholders, tags, balancedTags, isExtraPluralForm,
  hash, localeName,
} from './lib/locale-utils.mjs';

const argv = process.argv.slice(2);
const translatorArg = argv.find(a => a.startsWith('--translator='));
const translator = translatorArg ? translatorArg.split('=')[1] : undefined;
const stateArg = argv.find(a => a.startsWith('--state='));
const newState = stateArg ? stateArg.split('=')[1] : 'translated';
const file = argv.find(a => !a.startsWith('--'));

if (!['translated', 'reviewed', 'final'].includes(newState)) {
  console.error(`--state must be translated, reviewed or final (got "${newState}")`);
  process.exit(1);
}

const raw = file ? readFileSync(file, 'utf8') : readFileSync(0, 'utf8');
let patch;
try {
  patch = JSON.parse(raw);
} catch (err) {
  console.error(`Input is not valid JSON — ${err.message}`);
  process.exit(1);
}

const today = new Date().toISOString().slice(0, 10);
const enFlat = flatten(loadLocale('en'));
const keys = new Set(sourceKeys(enFlat));
const status = loadStatus();
status.locales = status.locales || {};

const problems = [];
const notes = [];
let applied = 0;

for (const [code, units] of Object.entries(patch)) {
  if (!LOCALE_CODES.includes(code)) {
    problems.push(`unknown locale "${code}" — expected one of ${LOCALE_CODES.join(', ')}`);
    continue;
  }

  const bundle = loadLocale(code);
  const entries = status.locales[code] || {};
  let wrote = 0;

  for (const [key, translation] of Object.entries(units)) {
    // A language may need plural forms English lacks; validate those against
    // the `other` form, which every plural group has.
    const extraPlural = !keys.has(key) && isExtraPluralForm(key, enFlat);
    const english = extraPlural
      ? enFlat[`${key.slice(0, key.lastIndexOf('.'))}.other`] ?? enFlat[`${key.slice(0, key.lastIndexOf('.'))}.one`]
      : enFlat[key];
    if (!keys.has(key) && !extraPlural) { problems.push(`${code}/${key}: not a key in en.json`); continue; }
    if (typeof translation !== 'string' || !translation.trim()) {
      problems.push(`${code}/${key}: empty translation`); continue;
    }
    if (placeholders(translation) !== placeholders(english)) {
      problems.push(`${code}/${key}: placeholders differ — en has "${placeholders(english) || 'none'}", translation has "${placeholders(translation) || 'none'}"`);
      continue;
    }
    if (!balancedTags(translation)) {
      problems.push(`${code}/${key}: inline markup is not balanced — an unclosed tag would break the page`);
      continue;
    }
    if (tags(translation) !== tags(english)) {
      notes.push(`${code}/${key}: wraps a different set of terms in inline tags than the English (written anyway)`);
    }

    unflattenSet(bundle, key, translation);
    entries[key] = {
      state: newState,
      sourceHash: hash(english),
      targetHash: hash(translation),
      updatedAt: today,
      ...(translator ? { translator } : {}),
    };
    wrote++; applied++;
  }

  if (wrote) saveLocale(code, bundle);
  status.locales[code] = entries;

  const outstanding = sourceKeys(enFlat).filter(k => {
    const e = entries[k];
    return !e || e.state === 'initial' || e.subState === 'kwestic:stale';
  }).length;
  console.log(`${code} — ${localeName(code)}: ${wrote} written, ${outstanding} outstanding`);
}

saveStatus(status);

if (notes.length) {
  console.log('');
  notes.slice(0, 10).forEach(n => console.log(`  · ${n}`));
  if (notes.length > 10) console.log(`  · … and ${notes.length - 10} more`);
}
if (problems.length) {
  console.log('');
  problems.forEach(p => console.error(`  ✗ ${p}`));
}
console.log(`\n${applied} translation(s) applied as "${newState}"${problems.length ? `, ${problems.length} refused` : ''}.`);
process.exit(problems.length ? 1 : 0);
