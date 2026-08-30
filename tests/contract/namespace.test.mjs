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
 * The 24 globals the application created at v0.5.0, from spec §10's inventory.
 * Closed, and asserted against the built artifact by
 * `tests/build/parity.test.mjs` — this file governs the SOURCE graph.
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

/* ── 2. Only marked adapters may touch a global ───────────────────────── */
section('2. Only marked adapters touch the namespace');

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

eq('no module under src/ touches a global outside a marked adapter', offenders, []);

// The adapters, named. The list shrinks every phase and Phase 6 asserts it is
// empty; naming them means an adapter appearing that nobody added is caught.
eq('the marked adapters are the ones we expect', adapters.sort(),
  ['data/legacy-globals.js', 'main.js']);
console.log(`  adapters remaining: ${adapters.length}`);

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
 * `src/main.js` writes its fourteen function globals through an alias — the
 * IIFE's old `global` parameter, kept as `const global = window` so that the
 * 1,801-line body Task 2.6 moved could stay byte-identical. This scan does not
 * resolve aliases and never claimed to; it looks for the literal receivers.
 *
 * That costs nothing here, because the rule it enforces is "no module outside a
 * MARKED ADAPTER touches a global" and `src/main.js` is a marked adapter. It
 * would cost something if an unmarked module aliased its way past, so the hole
 * is written down and the RUNTIME surface is what actually pins the inventory:
 * `tests/build/parity.test.mjs` loads the artifact and compares the names the
 * code created, where an alias is invisible in the other direction.
 */
eq('an aliased write is NOT caught — a stated limit',
  globalTouches('const global = window; global.startAudit = startAudit;'), []);
eq('and the entry point does write them that way',
  /const global = window;/.test(readFileSync(join(srcDir, 'main.js'), 'utf8')), true);

/* ── 4. What still reaches for globals, and why ───────────────────────── */
section('4. The legacy consumers, counted');

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
