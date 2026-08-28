#!/usr/bin/env node
/**
 * What `_site/` contains, and what it must not. Task 1.10.
 *
 * Spec correction 4: a deployment allowlist already existed; what was missing
 * was a test. Nothing asserted its contents, so a careless edit to that array
 * could publish `tools/` or `docs/` unnoticed. Risk R7 got sharper when
 * non-shipping files moved under `src/`.
 *
 * Both directions are asserted. A presence-only check passes happily while
 * publishing the entire repository beside the site.
 */

import { readFileSync, existsSync, readdirSync, statSync } from 'node:fs';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, sep } from 'node:path';

import { createSuite } from '../lib/assert.mjs';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, section, report } = createSuite();
const SITE = join(REPO, '_site');

// Assembled here rather than assumed present, so this suite tests what the
// build produces rather than whatever happened to be lying around.
execFileSync('node', [join(REPO, 'tools', 'build-site.mjs')], { cwd: REPO, stdio: ['ignore', 'pipe', 'pipe'] });

const walk = (dir, base = dir) => readdirSync(dir).flatMap(name => {
  const full = join(dir, name);
  return statSync(full).isDirectory() ? walk(full, base) : [relative(base, full)];
});
const everyFile = walk(SITE);

/* ── 1. The exact top-level allowlist ─────────────────────────────────── */
section('1. Exact top-level allowlist');

const EXPECTED = ['CNAME', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'css', 'dist', 'index.html', 'locales'];
eq('_site holds exactly the allowlisted entries', readdirSync(SITE).sort(), EXPECTED);

/* ── 2. Absence ───────────────────────────────────────────────────────── */
section('2. What must not be published');

// Named directories and files, each one a thing that would be embarrassing or
// dangerous to serve.
for (const forbidden of ['src', 'tools', 'tests', 'docs', 'node_modules', 'js', 'assets',
  'package.json', 'package-lock.json', 'AGENTS.md', 'CLAUDE.md', '.git', '.github']) {
  eq(`_site has no ${forbidden}`, existsSync(join(SITE, forbidden)), false);
}

// And by pattern, anywhere in the tree — the check that survives someone adding
// a directory the list above does not name.
eq('no test file at any depth',
  everyFile.filter(f => /\.test\.(js|mjs)$/.test(f)), []);
eq('no source map for anything but the bundle',
  everyFile.filter(f => f.endsWith('.map') && !f.endsWith('app.min.js.map')), []);
eq('no markdown outside the two notices',
  everyFile.filter(f => f.endsWith('.md') && f !== 'THIRD_PARTY_NOTICES.md'), []);
// Build-time translation state, never a bundle the browser fetches.
eq('locales/translation-status.json is not published',
  everyFile.filter(f => f.endsWith('translation-status.json')), []);
eq('no JSON outside locales/',
  everyFile.filter(f => f.endsWith('.json') && !f.startsWith(`locales${sep}`)), []);

/* ── 3. Every reference resolves inside _site ─────────────────────────── */
section('3. Every reference resolves');

const html = readFileSync(join(SITE, 'index.html'), 'utf8');
const scripts = [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)].map(m => m[1]);
const links = [...html.matchAll(/<link\b[^>]*\bhref\s*=\s*["']([^"']+)["']/gi)].map(m => m[1]);

eq('exactly one script is referenced', scripts.length, 1);
eq('and it is the bundle', scripts[0], 'dist/app.min.js');
for (const reference of [...scripts, ...links].filter(r => !/^(https?:|data:|#|\/\/)/.test(r))) {
  eq(`${reference} resolves inside _site`, existsSync(join(SITE, reference)), true);
}

const bundle = readFileSync(join(SITE, 'dist', 'app.min.js'), 'utf8');
eq('the bundle is not empty', bundle.length > 100000, true);
const mapLink = /\/\/# sourceMappingURL=(\S+)/.exec(bundle);
eq('the source map link is present', Boolean(mapLink), true);
eq('and it resolves inside _site', existsSync(join(SITE, 'dist', mapLink[1])), true);

/* ── 4. No source or test path reached the artifact ───────────────────── */
section('4. Co-location safety, bound to the metafile');

/**
 * Round 2's R2-F7: a sentinel can be tree-shaken, renamed, duplicated, or
 * simply omitted from a new test file. The binding checks are the metafile's
 * input list, the source map's `sources`, the markup-sink scan over the
 * artifact (in `tools/csp.test.mjs`) and `_site/`'s contents.
 */
const metafile = JSON.parse(readFileSync(join(REPO, '.build', 'metafile.json'), 'utf8'));
const inputs = Object.keys(metafile.inputs);
eq('the metafile lists the inputs it bundled', inputs.length > 0, true);
eq('no test path is an input', inputs.filter(p => /\.test\.(js|mjs)$/.test(p)), []);
eq('no path under tests/ is an input', inputs.filter(p => p.startsWith('tests/')), []);
eq('no path under tools/ is an input', inputs.filter(p => p.startsWith('tools/')), []);
eq('no node_modules path is an input', inputs.filter(p => p.includes('node_modules')), []);
// Exactly the files that should be there, named rather than counted: the entry,
// the generated-data adapter, the three generated modules, the converted layers
// and the one file still under `js/`. This list shrinks on the `js/` side every
// Phase 2 commit, and a file appearing here that nobody added is what it exists
// to catch. Task 2.6 removed three at once — `js/app.js` became `src/main.js`,
// which absorbed `src/entry-legacy.js` and `src/legacy-bridge.js`.
eq('the inputs are exactly the modules the entry point reaches', inputs.sort(),
  ['js/dns.js',
    'src/core/dns/cache.js', 'src/core/dns/doh.js', 'src/core/dns/errors.js', 'src/core/dns/resolver.js',
    'src/data/dkim-selectors.js', 'src/data/legacy-globals.js',
    'src/data/locales-en.js', 'src/data/public-suffixes.js',
    'src/i18n/index.js', 'src/main.js',
    'src/platform/browser.js', 'src/runtime.js', 'src/ui/render.js']);
// Co-located unit tests are the reason this list is asserted rather than
// counted: `src/core/dns/doh.test.js` sits beside the module above and must
// never appear here. The suffix checks earlier in this section are the general
// rule; this list is the specific one.
eq('and the co-located test beside it is not among them',
  inputs.filter(p => p.endsWith('.test.js')), []);

const sourceMap = JSON.parse(readFileSync(join(SITE, 'dist', 'app.min.js.map'), 'utf8'));
eq('no test path appears in the source map',
  sourceMap.sources.filter(p => /\.test\.(js|mjs)$/.test(p)), []);
eq('no path under tests/ appears in the source map',
  sourceMap.sources.filter(p => p.includes('/tests/')), []);
// NOT a 1:1 correspondence, and assuming one was wrong: a module that
// contributes no code of its own is left out of the map's sources. The real
// invariant is that every mapped source is an input. All ten are code-bearing
// as of Task 2.6, which retired the two import-only adapters.
eq('every mapped source is one of the bundle inputs',
  sourceMap.sources.map(p => p.replace(/^(\.\.\/)+/, '')).filter(p => !inputs.includes(p)), []);
eq('every code-bearing input is mapped', sourceMap.sources.length, 14);

// Defence in depth, carrying no acceptance criterion of its own: a string that
// appears in every cross-cutting suite must appear nowhere in the artifact.
const SENTINEL = 'createSuite';
eq('no test-harness sentinel reached the artifact', bundle.includes(SENTINEL), false);

/* ── 5. No third-party JavaScript ─────────────────────────────────────── */
section('5. Supply chain at the boundary');

eq('the bundle carries no node_modules path', bundle.includes('node_modules'), false);
eq('nothing is fetched from another origin',
  [...scripts, ...links].filter(r => /^https?:/i.test(r)), []);
eq('the artifact is the only JavaScript published',
  everyFile.filter(f => f.endsWith('.js')), [join('dist', 'app.min.js')]);

/* ── 6. The check can fail ────────────────────────────────────────────── */
section('6. Negative control');

// The allowlist assertion is only worth something if it notices an addition.
eq('an extra top-level entry would be caught',
  JSON.stringify([...EXPECTED, 'tools'].sort()) === JSON.stringify(EXPECTED), false);
// And the pattern scans only if they notice a file.
eq('the test-file scan would catch one',
  [...everyFile, join('dist', 'thing.test.js')].filter(f => /\.test\.(js|mjs)$/.test(f)).length, 1);
eq('the source-map scan would catch one',
  [...sourceMap.sources, 'src/x.test.js'].filter(p => /\.test\.(js|mjs)$/.test(p)).length, 1);

report();
