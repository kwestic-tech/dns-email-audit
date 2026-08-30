#!/usr/bin/env node
/**
 * The namespace source contract. Spec §10, Testing item 5.
 *
 * > No module under `src/` reads or writes `window.DnsAudit`,
 * > `globalThis.DnsAudit`, or any of the 24 names above, except the explicitly
 * > marked temporary adapters during Phase 2, and the generated boundary
 * > esbuild produces at stage 3.
 *
 * This is the condition round 2 attached to accepting IIFE output: a generated
 * global at the delivery boundary is acceptable **only if** the source graph is
 * forbidden from using it as an internal dependency. Without this contract, the
 * IIFE decision does not hold.
 *
 * ── Why this file replaced an ordering check ──────────────────────────────
 *
 * Phase 2 briefly carried a control aimed at the ES-hoisting bug this project
 * actually wrote: an entry point that installed the generated data *after*
 * importing its consumers. That control was real while the consumers READ
 * globals. Once `js/dns.js` and `src/i18n/index.js` took their data as
 * arguments, it stopped catching anything — measured, not assumed: a
 * deliberately hoisted entry now produces 30 cases, 5 surfaces, 0 differences,
 * because nothing evaluates against a global any more.
 *
 * So the protection moved to where it belongs. Ordering only matters when a
 * module reads a global at evaluation time, and this contract is what forbids
 * that — it catches the hazard COMING BACK rather than one instance of it.
 */

import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, sep } from 'node:path';

import { createSuite } from '../lib/assert.mjs';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, section, report } = createSuite();

/**
 * A HISTORICAL WATCHLIST, not the current published inventory.
 *
 * These are the 24 names the application created at `v0.5.0`, from spec §10.
 * Every one of them is gone: Task 2.7 contracted `DnsAudit` to two members,
 * Task 2.8 removed the fourteen function globals, and Task 6.2 retired the
 * last nine with both marked adapters.
 *
 * **All 24 are kept deliberately**, because the check this list feeds is about
 * REINTRODUCTION: a module that starts writing any of them fails here. A
 * watchlist that shrank as names were retired would stop watching exactly the
 * names most likely to come back.
 *
 * The CURRENT runtime surface is one generated global with two members —
 * `window.DnsAudit`, produced by esbuild from the entry point's exports.
 * `tests/build/parity.test.mjs` asserts it against the artifact and
 * `tests/build/file-url.test.mjs` against real Chrome. This file governs the
 * SOURCE graph, which creates none.
 */
const GLOBALS = [
  'DnsAudit', '__APP_TEST__',
  'i18n', 't', 'tp', 'tRaw', 'R',
  '__PUBLIC_SUFFIX_RULES__', '__DKIM_SELECTOR_CATALOG__', '__I18N_EN__',
  'startAudit', 'cancelAudit', 'clearAll', 'exportCSV', 'exportHTML',
  'filterTable', 'loadExample', 'loadFile', 'openLearnMore', 'setLang',
  'showHelp', 'sortTable', 'toggleDetail', 'toggleShowMe',
];

const ADAPTER_SENTINEL = 'LEGACY_ADAPTER';

function modules(dir, base) {
  if (!existsSync(dir)) return [];
  return readdirSync(dir, { withFileTypes: true }).flatMap(entry => {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) return modules(full, base);
    return entry.name.endsWith('.js') ? [relative(base, full)] : [];
  });
}

const srcDir = join(REPO, 'src');
const sources = modules(srcDir, srcDir).sort();

/* ── 1. The inventory is what it says it is ───────────────────────────── */
section('1. The closed global inventory');

eq('the inventory is 24 names', GLOBALS.length, 24);
eq('with no duplicates', GLOBALS.length, new Set(GLOBALS).size);

/* ── 2. Nothing under src/ touches the watched namespace ──────────────── */
section('2. No source module touches the watched namespace');

/**
 * Reads and writes both. A module that reads `window.DnsAudit` has taken an
 * internal dependency on the delivery boundary, which is exactly what the IIFE
 * decision was made conditional on forbidding.
 *
 * Comments are stripped first: these files document the rule they enforce, and
 * a comment naming `window.DnsAudit` is not a dependency on it.
 */
function globalTouches(source) {
  const code = source
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .split('\n').map(line => line.replace(/\/\/.*$/, '')).join('\n');
  const hits = [];
  for (const name of GLOBALS) {
    const pattern = new RegExp(`\\b(?:window|globalThis|self)\\s*\\.\\s*${name}\\b`);
    if (pattern.test(code)) hits.push(name);
  }
  return hits;
}

const adapters = [];
const offenders = [];
for (const relativePath of sources) {
  const source = readFileSync(join(srcDir, relativePath), 'utf8');
  const isAdapter = source.includes(ADAPTER_SENTINEL);
  if (isAdapter) adapters.push(relativePath);
  const touches = globalTouches(source);
  if (touches.length && !isAdapter) {
    offenders.push(`${relativePath} touches ${touches.join(', ')}`);
  }
}

eq('no module under src/ reads or writes a watched namespace property', offenders, []);

// **Task 6.2 emptied this list**, which is the Phase 6 end state: every global
// the application published had a consumer with no ESM owner, and each owner
// now exists. The list is asserted rather than counted so an adapter appearing
// that nobody added is caught.
eq('no marked adapter remains under src/', adapters.sort(), []);
// And with no adapter to excuse one, the rule above has no exemption left:
// nothing under `src/` touches a global at all.
eq('so nothing under src/ touches a global', offenders.length, 0);

/* ── 3. The check can fail ────────────────────────────────────────────── */
section('3. Negative control');

eq('a module reaching for window.DnsAudit is caught',
  globalTouches('const a = window.DnsAudit;'), ['DnsAudit']);
eq('so is globalThis', globalTouches('globalThis.__PUBLIC_SUFFIX_RULES__ = x;'), ['__PUBLIC_SUFFIX_RULES__']);
eq('and self', globalTouches('self.R = renderer;'), ['R']);
eq('spacing does not hide it', globalTouches('window . t ( "k" )'), ['t']);
eq('several at once are all reported',
  globalTouches('window.i18n; window.R;').sort(), ['R', 'i18n']);
// And the exclusions that keep it honest.
eq('a block comment naming one is not a dependency',
  globalTouches('/* window.DnsAudit is the delivery boundary */'), []);
eq('nor is a line comment', globalTouches('// window.R lives here\n'), []);
eq('a local of the same name is not a global read',
  globalTouches('const t = i18n.t; t("k");'), []);
eq('nor is a property access on something else',
  globalTouches('platform.document; engine.DnsAudit;'), []);

/**
 * The stated limit, asserted so it cannot be forgotten.
 *
 * This scan does not resolve aliases and never claimed to; it looks for the
 * literal receivers. `src/main.js` used to write its globals through one — the
 * IIFE's old `global` parameter, kept as `const global = window` — and that
 * was survivable only because the rule was "no module outside a MARKED ADAPTER
 * touches a watched namespace property" and it was the marked adapter.
 *
 * **There are no adapters now**, so the exemption is gone and the hole matters
 * more, not less. It is written down, and the RUNTIME surface is what actually
 * pins the inventory: `tests/build/parity.test.mjs` loads the artifact and
 * compares the names the code created, where an alias is invisible in the
 * other direction.
 */
eq('an aliased write is NOT caught — a stated limit',
  globalTouches('const global = window; global.startAudit = startAudit;'), []);
// The entry point no longer writes one, aliased or otherwise. Task 6.2.
eq('and the entry point no longer aliases window',
  /const global = window;/.test(readFileSync(join(srcDir, 'main.js'), 'utf8')), false);

/* ── 4. The legacy tree is gone ───────────────────────────────────────── */
section('4. js/ no longer exists');

/**
 * `js/` was not under the contract — it was what the contract existed to
 * retire, and Task 6.1 retired it. Counting what was left there made the
 * remaining work visible; the count reached zero when the directory did.
 *
 * The assertion is now that the directory is GONE, which is the end state that
 * counting was measuring toward. Counting files in a directory that does not
 * exist would report zero for the wrong reason.
 */
const jsDir = join(REPO, 'js');
eq('js/ no longer exists — Task 6.1 deleted it', existsSync(jsDir), false);
// The engine surface those 5,704 lines held is `tools/lib/legacy-engine.mjs`
// now: a test harness, not application code, and not in the bundle.
// `artifact.test.mjs` asserts no `js/` path is a bundle input.
eq('and the harness that replaced it is under tools/',
  existsSync(join(REPO, 'tools', 'lib', 'legacy-engine.mjs')), true);
report();
