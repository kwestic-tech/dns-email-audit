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
 *   • js/locales-en.js is in sync with locales/en.json (error)
 *
 * Exit code is non-zero only for real errors, so translations can land while
 * still incomplete.  Run:  npm test
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const localesDir = join(root, 'locales');

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

/** Flatten a nested bundle into dotted paths → string values. */
function flatten(node, prefix = '', out = {}) {
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

const placeholders = (s) => (s.match(/\{\d+\}/g) || []).sort().join(',');

// ── Load the reference bundle ────────────────────────────────────────────
const en = readJSON(join(localesDir, 'en.json'));
if (!en) process.exit(1);
const enFlat = flatten(en);
const enKeys = Object.keys(enFlat).filter(k => !k.startsWith('meta.'));

console.log(`Reference: locales/en.json — ${enKeys.length} keys\n`);

// ── Registry consistency ─────────────────────────────────────────────────
const index = readJSON(join(localesDir, 'index.json'));
const registered = index ? index.locales.map(l => l.code) : [];
const onDisk = readdirSync(localesDir)
  .filter(f => f.endsWith('.json') && f !== 'index.json')
  .map(f => f.replace(/\.json$/, ''));

console.log('locales/index.json');
registered.filter(c => !onDisk.includes(c))
  .forEach(c => fail(`"${c}" is listed in index.json but locales/${c}.json is missing`));
onDisk.filter(c => !registered.includes(c))
  .forEach(c => fail(`locales/${c}.json exists but "${c}" is not listed in index.json — it will never be selectable`));
if (!errors) console.log('  ✓ registry and files agree');
console.log('');

// ── Per-locale comparison ────────────────────────────────────────────────
for (const code of onDisk.filter(c => c !== 'en').sort()) {
  const bundle = readJSON(join(localesDir, `${code}.json`));
  if (!bundle) continue;
  const flat = flatten(bundle);
  const keys = Object.keys(flat).filter(k => !k.startsWith('meta.'));

  const missing = enKeys.filter(k => !(k in flat));
  const unknown = keys.filter(k => !(k in enFlat));
  const mismatched = keys.filter(k => k in enFlat && placeholders(flat[k]) !== placeholders(enFlat[k]));

  const done = enKeys.length - missing.length;
  const pct = Math.round((done / enKeys.length) * 100);
  console.log(`locales/${code}.json — ${done}/${enKeys.length} keys (${pct}%)`);

  mismatched.forEach(k =>
    fail(`${k}: placeholders differ (en has "${placeholders(enFlat[k]) || 'none'}", ${code} has "${placeholders(flat[k]) || 'none'}")`));
  unknown.forEach(k => warn(`${k}: not present in en.json — typo or stale key?`));
  if (missing.length) warn(`${missing.length} key(s) missing — these fall back to English`);
  if (!mismatched.length && !unknown.length && !missing.length) console.log('  ✓ complete');
  console.log('');
}

// ── Inline fallback freshness ────────────────────────────────────────────
const fallbackPath = join(root, 'js', 'locales-en.js');
console.log('js/locales-en.js');
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
