#!/usr/bin/env node
/**
 * Build `dist/app.min.js`. Spec Design §6, implementation Task 1.4.
 *
 *   node tools/build-bundle.mjs            build, then report size
 *   node tools/build-bundle.mjs --check    build and verify without writing a report
 *
 * The one delivery boundary. From the commit that points `index.html` at this
 * artifact, everything the browser runs comes through here.
 */

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { gzipSync } from 'node:zlib';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';
import esbuild from 'esbuild';

const REPO = join(dirname(fileURLToPath(import.meta.url)), '..');
const ENTRY = 'src/entry-legacy.js';
const OUTFILE = 'dist/app.min.js';

/**
 * The banner, written out explicitly.
 *
 * NOT `legalComments`. That setting preserves comments it finds, and there are
 * none to find: no file under `js/` carries an `@license`, `@preserve`, `/*!`
 * or `//!` comment, and the MIT text lives in the separate `LICENSE` file. So
 * `legalComments: 'inline'` would have preserved nothing at all while reading
 * like it preserved something (round 1, F7).
 */
function banner(version) {
  return [
    '/*!',
    ` * DNS & Email Security Auditor v${version}`,
    ' * Copyright (c) Kwestic LLC (Kwestic Media and Technology)',
    ' * MIT licensed. See LICENSE and THIRD_PARTY_NOTICES.md.',
    ' *',
    ' * Generated artifact. Do not edit; do not commit. Built from source at',
    ' * the commit being deployed. No third-party JavaScript reaches the browser.',
    ' */',
  ].join('\n');
}

/**
 * Configuration, per spec Design §6.
 *
 * Two settings are load-bearing and both are absences:
 *
 *  - **`globalName` is omitted.** esbuild assigns the entry point's exports to
 *    that name; `src/entry-legacy.js` has none, so an early
 *    `globalName: 'DnsAudit'` would emit a top-level `var DnsAudit` that
 *    OVERWRITES the real object from `js/dns.js:5601` and break the app on the
 *    commit that moves the delivery boundary. It arrives in §10's stage 3,
 *    against a facade that genuinely exports those members.
 *  - **`splitting` stays false and there is no dynamic import.** One artifact,
 *    per §25. `OQ-ARCH-05` holds the split for later, with measured
 *    repeat-visit data rather than an assumption.
 *
 * `format: 'iife'` keeps `file://` working and keeps the CSP shape. That is not
 * a preference: `js/locales-en.js` states in its own generated header that
 * English is inlined "so the app works when index.html is opened directly from
 * disk", and that file is 125,172 bytes — about 18% of the payload — bought and
 * paid for that purpose. A `type="module"` script would spend it.
 */
export function buildOptions(version) {
  return {
    absWorkingDir: REPO,
    entryPoints: [ENTRY],
    outfile: OUTFILE,
    bundle: true,
    format: 'iife',
    // globalName: deliberately absent until §10 stage 3. See above.
    minify: true,
    sourcemap: 'linked',
    target: 'es2020',
    splitting: false,
    metafile: true,
    banner: { js: banner(version) },
    legalComments: 'none',
    logLevel: 'silent',
  };
}

/**
 * The order `index.html` loads scripts in, read from the markup.
 *
 * Compared against what the bundle actually contains. The load order IS the
 * dependency graph until Phase 2 replaces it with real imports, and a silent
 * reordering would be a behaviour change wearing a build-config costume:
 * `js/dns.js` builds its public-suffix sets from `__PUBLIC_SUFFIX_RULES__`
 * while its IIFE runs, so moving the generated data later leaves them empty.
 */
export function scriptOrderFromMarkup(indexHtml) {
  return [...indexHtml.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi)]
    .map(match => match[1]);
}

/** The order the bundle actually pulled its inputs in. */
export function inputOrderFromMetafile(metafile) {
  const entry = Object.values(metafile.outputs).find(output => output.entryPoint);
  return entry.inputs
    ? Object.keys(entry.inputs).filter(path => path.startsWith('js/'))
    : [];
}

export async function build({ quiet = false } = {}) {
  const pkg = JSON.parse(readFileSync(join(REPO, 'package.json'), 'utf8'));
  mkdirSync(join(REPO, 'dist'), { recursive: true });

  const started = process.hrtime.bigint();
  const result = await esbuild.build(buildOptions(pkg.version));
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

  if (result.errors.length) {
    for (const error of result.errors) console.error(`build: ${error.text}`);
    throw new Error(`build: ${result.errors.length} error(s)`);
  }
  for (const warning of result.warnings) console.error(`build warning: ${warning.text}`);

  const bundle = readFileSync(join(REPO, OUTFILE));
  const map = readFileSync(join(REPO, `${OUTFILE}.map`));

  // The load order the markup declares must be the order the bundle used.
  const declared = scriptOrderFromMarkup(readFileSync(join(REPO, 'index.html'), 'utf8'));
  const bundled = inputOrderFromMetafile(result.metafile);
  const declaredLegacy = declared.filter(path => path.startsWith('js/'));
  if (declaredLegacy.length && String(declaredLegacy) !== String(bundled)) {
    throw new Error(
      'build: the bundle\'s input order does not match index.html\n' +
      `  index.html: ${declaredLegacy.join(' ')}\n` +
      `  bundle:     ${bundled.join(' ')}`);
  }

  return {
    metafile: result.metafile,
    elapsedMs,
    // The source map is excluded from the transfer figure per `OQ-ARCH-04`: it
    // is fetched only when a developer opens the tools, never by a visitor.
    raw: bundle.length,
    gzip: gzipSync(bundle).length,
    mapBytes: map.length,
    inputs: bundled,
    quiet,
  };
}

/**
 * Size reporting from the metafile. REPORTED, NEVER ENFORCED.
 *
 * A size budget that fails a build teaches people to raise the budget. What
 * this is for is making an accidental inclusion visible — a test file, a
 * dependency, a generated table that doubled — and per-input composition is
 * what answers "what got bigger" rather than just "something did".
 */
export function report(built) {
  const inputs = Object.entries(built.metafile.outputs)
    .find(([path]) => path.endsWith('app.min.js'))[1].inputs;
  const rows = Object.entries(inputs)
    .map(([path, meta]) => [path, meta.bytesInOutput])
    .sort((a, b) => b[1] - a[1]);

  const kb = n => (n / 1024).toFixed(1).padStart(8) + ' KB';
  console.log(`\n${OUTFILE}`);
  console.log(`  raw   ${kb(built.raw)}   (${built.raw.toLocaleString()} bytes)`);
  console.log(`  gzip  ${kb(built.gzip)}   (${built.gzip.toLocaleString()} bytes)`);
  console.log(`  map   ${kb(built.mapBytes)}   excluded from the transfer figure (OQ-ARCH-04)`);
  console.log(`  built in ${built.elapsedMs.toFixed(0)} ms\n`);
  console.log('  composition, by contribution to the output:');
  for (const [path, bytes] of rows) {
    const share = ((bytes / built.raw) * 100).toFixed(1).padStart(5);
    console.log(`    ${kb(bytes)}  ${share}%  ${path}`);
  }
}

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  const built = await build();
  writeFileSync(join(REPO, 'dist', 'metafile.json'), JSON.stringify(built.metafile, null, 2) + '\n');
  if (!process.argv.includes('--check')) report(built);
}
