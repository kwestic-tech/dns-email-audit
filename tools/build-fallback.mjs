#!/usr/bin/env node
/**
 * Regenerates src/data/locales-en.js from locales/en.json.
 *
 * Why this file exists: browsers block fetch() of local JSON over file://, so
 * an app split across multiple files would break the moment someone
 * double-clicks index.html. Inlining the English bundle as a plain script
 * keeps that path working, and every other language still loads on demand.
 *
 * Run after editing locales/en.json:  npm run build:fallback
 */

import { readFileSync, writeFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const root = join(dirname(fileURLToPath(import.meta.url)), '..');
const source = join(root, 'locales', 'en.json');
const target = join(root, 'src', 'data', 'locales-en.js');

const raw = readFileSync(source, 'utf8');

let parsed;
try {
  parsed = JSON.parse(raw);
} catch (err) {
  console.error(`✗ locales/en.json is not valid JSON:\n  ${err.message}`);
  process.exit(1);
}

const banner = `/* AUTO-GENERATED — DO NOT EDIT.
 * Source: locales/en.json
 * Regenerate with: npm run build:fallback
 *
 * English is inlined here so the app works when index.html is opened directly
 * from disk (file://), where fetching locales/*.json is blocked by the browser.
 */
`;

// An ES module as of 0.6.0. The CONTENT is unchanged -- same keys, same values,
// same ordering -- so tools/check-locales.mjs still compares like with like.
// Only the wrapper moved, which is the whole of this release's claim about the
// localization contract: no key is added, changed or removed.
const body = `\nexport const LOCALE_EN = ${JSON.stringify(parsed, null, 2)};\n`;

writeFileSync(target, banner + body, 'utf8');
console.log(`✓ Wrote src/data/locales-en.js (${(banner + body).length.toLocaleString()} bytes)`);
