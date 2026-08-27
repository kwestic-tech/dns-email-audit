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
const ENTRY = 'src/main.js';
const OUTFILE = 'dist/app.min.js';
// Build metadata, deliberately NOT under dist/.
//
// dist/ is copied wholesale into _site/, so anything written there ships. The
// metafile is a size manifest listing source paths; it is for tooling, not for
// visitors, and putting it in the published directory would have needed a
// per-file skip entry in the deploy allowlist — a judgment call in exactly the
// place this project keeps them out of. `dist/` now contains only the two files
// that ship. Caught by tests/build/artifact.test.mjs on its first run.
const METAFILE = '.build/metafile.json';

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
 *  - **`globalName: 'DnsAudit'`** is §10's stage 3, reached in Task 2.7. It
 *    emits a top-level `var DnsAudit = (() => { … })()` holding the ENTRY
 *    POINT'S EXPORTS — which is why it could not be enabled earlier: against an
 *    entry with no exports, or one whose exports were not the designed facade,
 *    it would have overwritten the real object with something else. That is the
 *    mistake spec 0.2 nearly shipped. The legacy `window.DnsAudit` assignment
 *    was removed from `src/main.js` in the same commit that turned this on, so
 *    the name has exactly one producer. `src/facade.expected.json` says what it
 *    must contain and `tests/build/parity.test.mjs` proves it, on both the
 *    source module and the artifact.
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
export function buildOptions(version, root = REPO) {
  return {
    absWorkingDir: root,
    entryPoints: [ENTRY],
    outfile: OUTFILE,
    bundle: true,
    format: 'iife',
    globalName: 'DnsAudit',
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

/**
 * Build into `root`, which defaults to the repository.
 *
 * Parameterised because the oracle validation now has to build every mutated
 * copy it makes: from the delivery-boundary commit onward the runner loads
 * `dist/app.min.js`, so a validator that mutated `js/` and did not rebuild
 * would be measuring an artifact the mutation never reached — a green run
 * proving nothing, which is the failure this project keeps finding.
 */
export async function build({ root = REPO } = {}) {
  const pkg = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));
  mkdirSync(join(root, 'dist'), { recursive: true });

  const started = process.hrtime.bigint();
  const result = await esbuild.build(buildOptions(pkg.version, root));
  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;

  if (result.errors.length) {
    for (const error of result.errors) console.error(`build: ${error.text}`);
    throw new Error(`build: ${result.errors.length} error(s)`);
  }
  for (const warning of result.warnings) console.error(`build warning: ${warning.text}`);

  const bundle = readFileSync(join(root, OUTFILE));
  const map = readFileSync(join(root, `${OUTFILE}.map`));

  // The load order the markup declares must be the order the bundle used.
  const declared = scriptOrderFromMarkup(readFileSync(join(root, 'index.html'), 'utf8'));
  const bundled = inputOrderFromMetafile(result.metafile);
  const declaredLegacy = declared.filter(path => path.startsWith('js/'));
  if (declaredLegacy.length && String(declaredLegacy) !== String(bundled)) {
    throw new Error(
      'build: the bundle\'s input order does not match index.html\n' +
      `  index.html: ${declaredLegacy.join(' ')}\n` +
      `  bundle:     ${bundled.join(' ')}`);
  }

  mkdirSync(join(root, '.build'), { recursive: true });
  writeFileSync(join(root, METAFILE), JSON.stringify(result.metafile, null, 2) + '\n');

  return {
    metafile: result.metafile,
    elapsedMs,
    // The source map is excluded from the transfer figure per `OQ-ARCH-04`: it
    // is fetched only when a developer opens the tools, never by a visitor.
    raw: bundle.length,
    gzip: gzipSync(bundle).length,
    mapBytes: map.length,
    inputs: bundled,
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

export const metafilePath = join(REPO, METAFILE);

if (process.argv[1] && import.meta.url === `file://${process.argv[1]}`) {
  const built = await build();
  if (!process.argv.includes('--check')) report(built);
}
