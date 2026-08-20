#!/usr/bin/env node
/**
 * Emits the outstanding translation work.
 *
 * This is the file a translating agent reads.  It names the target language
 * explicitly — "German (Deutsch)", not a `de.json` filename the reader has to
 * decode — and ships each unit with the constraints that must survive
 * translation (placeholders, inline tags) attached to it, so nothing has to be
 * inferred from prose instructions further up a document.
 *
 *   npm run locale:todo                 human-readable summary, all locales
 *   npm run locale:todo -- de           summary for one locale
 *   npm run locale:todo -- de --json    machine-readable work order (stdout)
 *
 * `--json` is the agent-facing form; redirect it to a file or pipe it.
 * Work units are emitted for state `initial` (never translated) and for
 * anything flagged `kwestic:stale` (English moved underneath it).
 */

import {
  LOCALE_CODES, LOCALES, flatten, sourceKeys, loadLocale, loadStatus,
  placeholders, tags, SUB_STALE, localeName,
} from './lib/locale-utils.mjs';

const argv = process.argv.slice(2);
const asJson = argv.includes('--json');
const requested = argv.filter(a => !a.startsWith('--'));
const codes = requested.length ? requested : LOCALE_CODES;

const bad = codes.filter(c => !LOCALE_CODES.includes(c));
if (bad.length) {
  console.error(`Unknown locale(s): ${bad.join(', ')} — expected ${LOCALE_CODES.join(', ')}`);
  process.exit(1);
}

const enFlat = flatten(loadLocale('en'));
const keys = sourceKeys(enFlat);
const status = loadStatus();

function unitsFor(code) {
  const entries = status.locales[code] || {};
  const localeFlat = flatten(loadLocale(code));
  return keys
    .filter(k => {
      const e = entries[k];
      return !e || e.state === 'initial' || e.subState === SUB_STALE;
    })
    .map(k => {
      const e = entries[k] || {};
      const source = enFlat[k];
      const unit = {
        key: k,
        state: e.subState === SUB_STALE ? 'stale' : (e.state || 'initial'),
        source,
      };
      if (e.subState === SUB_STALE) unit.currentTranslation = localeFlat[k];
      const ph = placeholders(source);
      if (ph) unit.mustPreservePlaceholders = ph.split(',');
      const tg = tags(source);
      if (tg) unit.mustPreserveTags = [...new Set(tg.split(','))];
      if (source.includes('\n')) unit.multiline = true;
      return unit;
    });
}

if (asJson) {
  const out = codes.map(code => {
    const meta = LOCALES.find(l => l.code === code);
    const units = unitsFor(code);
    return {
      targetLocale: code,
      targetLanguage: meta.name,
      targetNativeName: meta.nativeName,
      sourceLanguage: 'English',
      sourceLocale: 'en',
      count: units.length,
      units,
    };
  });
  process.stdout.write(JSON.stringify(codes.length === 1 ? out[0] : out, null, 2) + '\n');
} else {
  let total = 0;
  for (const code of codes) {
    const units = unitsFor(code);
    total += units.length;
    const stale = units.filter(u => u.state === 'stale').length;
    const bits = [`${units.length - stale} never translated`];
    if (stale) bits.push(`${stale} stale`);
    console.log(`${code} — ${localeName(code)}: ${units.length} unit(s) outstanding (${bits.join(', ')})`);
  }
  console.log(`\n${total} translation unit(s) outstanding across ${codes.length} locale(s).`);
  if (total) console.log(`Machine-readable: npm run locale:todo -- <code> --json`);
}
