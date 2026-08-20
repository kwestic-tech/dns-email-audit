#!/usr/bin/env node
/**
 * Reconciles locales/*.json against en.json and rewrites the translation
 * state database at locales/translation-status.json.
 *
 * Two jobs:
 *
 *  1. Scaffold — any key in en.json missing from a locale is written in with
 *     the English string, so the JSON is always structurally complete.  This
 *     changes nothing at runtime (an English placeholder renders exactly like
 *     the English fallback a missing key produced) but it makes the gap
 *     countable instead of invisible.
 *
 *  2. Reconcile — derive each key's state from the files themselves rather
 *     than trusting whatever the database last said.  States follow the
 *     XLIFF 2.1 vocabulary; see tools/lib/locale-utils.mjs.
 *
 * The database stores a fingerprint of both sides — `sourceHash` (the English
 * the translation was made against) and `targetHash` (the translation as
 * written).  Comparing each against the file on disk answers, independently:
 * did the English move?  did the translation get edited?  gettext solves the
 * first with an auto-`fuzzy` flag; this is the same idea with the second
 * question added, which is what lets a re-translation clear its own flag.
 *
 * Idempotent: a second run with no file changes is a byte-identical no-op.
 *
 *   npm run locale:sync
 */

import { readFileSync } from 'node:fs';
import {
  LOCALE_CODES, flatten, sourceKeys, loadLocale, saveLocale, localePath,
  mergeInEnOrder, unflattenSet, loadStatus, saveStatus, hash,
  SUB_STALE, STATUS_PATH, root,
  isExtraPluralForm,
} from './lib/locale-utils.mjs';

const today = new Date().toISOString().slice(0, 10);

const en = loadLocale('en');
const enFlat = flatten(en);
const keys = sourceKeys(enFlat);

const status = loadStatus();
status.locales = status.locales || {};

const totals = { scaffolded: 0, refreshed: 0, stale: 0, unstale: 0, adopted: 0, pruned: 0, filesChanged: 0 };

console.log(`Source: locales/en.json — ${keys.length} keys\n`);

for (const code of LOCALE_CODES) {
  const before = readFileSync(localePath(code), 'utf8');
  const { bundle, added } = mergeInEnOrder(en, loadLocale(code));
  let current = flatten(bundle);

  const entries = status.locales[code] || {};
  const notes = [];

  // Drop database rows for keys en.json no longer has.
  for (const key of Object.keys(entries)) {
    if (!keys.includes(key) && !isExtraPluralForm(key, enFlat)) { delete entries[key]; totals.pruned++; }
  }

  for (const key of keys) {
    const english = enFlat[key];
    const enH = hash(english);
    const prev = entries[key];
    const value = current[key];

    // ── First sighting ────────────────────────────────────────────────
    if (!prev) {
      if (added.includes(key) || value === english) {
        entries[key] = { state: 'initial', sourceHash: enH, targetHash: enH, updatedAt: today };
        if (added.includes(key)) totals.scaffolded++;
      } else {
        // Baseline import: a translation that predates this database. We have
        // no record of which English it was made against, so we assume the
        // current one — the standard assumption when importing into a TMS.
        entries[key] = { state: 'translated', sourceHash: enH, targetHash: hash(value), updatedAt: today };
        totals.adopted++;
      }
      continue;
    }

    // ── Still an untranslated English placeholder ─────────────────────
    if (prev.state === 'initial') {
      if (hash(value) === prev.targetHash) {
        if (enH !== prev.sourceHash) {
          // Nobody has translated this and the English has since been edited,
          // so the locale is sitting on superseded English. Refresh it — same
          // fallback behaviour, current wording.
          unflattenSet(bundle, key, english);
          current = flatten(bundle);
          entries[key] = { state: 'initial', sourceHash: enH, targetHash: enH, updatedAt: today };
          notes.push(`~ ${key} — English edited, placeholder refreshed (still initial)`);
          totals.refreshed++;
        }
        continue;
      }
      // Somebody translated it directly in the JSON.
      entries[key] = {
        state: 'translated',
        ...(enH !== prev.sourceHash ? { subState: SUB_STALE } : {}),
        sourceHash: enH, targetHash: hash(value), updatedAt: today,
      };
      totals.adopted++;
      continue;
    }

    // ── translated / reviewed / final ─────────────────────────────────
    const tH = hash(value);
    const targetEdited = prev.targetHash !== tH;
    const sourceMoved = prev.sourceHash !== enH;

    if (targetEdited) {
      // The translation itself changed, so it was written against today's
      // English. Any prior review no longer applies — back to `translated`.
      entries[key] = {
        state: 'translated', sourceHash: enH, targetHash: tH, updatedAt: today,
        ...(prev.translator ? { translator: prev.translator } : {}),
      };
      if (prev.subState === SUB_STALE) totals.unstale++;
    } else if (sourceMoved) {
      // English moved underneath a finished translation. Flag it and keep the
      // old sourceHash, so it stays flagged until somebody re-translates.
      if (prev.subState !== SUB_STALE) {
        notes.push(`! ${key} — English changed since translation, needs re-review`);
        totals.stale++;
      }
      entries[key] = { ...prev, subState: SUB_STALE, targetHash: tH };
    } else {
      const next = { ...prev, targetHash: tH };
      if (next.subState === SUB_STALE) { delete next.subState; totals.unstale++; }
      entries[key] = next;
    }
  }

  status.locales[code] = entries;
  saveLocale(code, bundle);
  if (readFileSync(localePath(code), 'utf8') !== before) totals.filesChanged++;

  const by = (s) => Object.values(entries).filter(e => e.state === s).length;
  const staleN = Object.values(entries).filter(e => e.subState === SUB_STALE).length;
  const bits = [`${by('initial')} initial`, `${by('translated')} translated`];
  if (by('reviewed')) bits.push(`${by('reviewed')} reviewed`);
  if (by('final')) bits.push(`${by('final')} final`);
  if (staleN) bits.push(`${staleN} stale`);
  console.log(`locales/${code}.json — ${bits.join(', ')}`);
  notes.slice(0, 5).forEach(n => console.log(`  ${n}`));
  if (notes.length > 5) console.log(`  … and ${notes.length - 5} more`);
}

saveStatus(status);

console.log('');
if (totals.scaffolded) console.log(`${totals.scaffolded} key(s) scaffolded from English`);
if (totals.adopted) console.log(`${totals.adopted} existing translation(s) adopted into the database`);
if (totals.refreshed) console.log(`${totals.refreshed} placeholder(s) refreshed to current English`);
if (totals.stale) console.log(`${totals.stale} translation(s) newly flagged stale`);
if (totals.unstale) console.log(`${totals.unstale} translation(s) cleared their stale flag`);
if (totals.pruned) console.log(`${totals.pruned} database row(s) pruned (key gone from en.json)`);
console.log(`${totals.filesChanged} locale file(s) changed · database: ${STATUS_PATH.replace(root + '/', '')}`);
