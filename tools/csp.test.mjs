#!/usr/bin/env node
/**
 * The Content-Security-Policy in index.html, and the markup-sink scan.
 *
 * Dependency-free: the digest is recomputed with node:crypto, so an edit to
 * the structured-data block is self-correcting rather than silently drifting
 * away from the policy that authorizes it.
 */

import { readFileSync, readdirSync, statSync, existsSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative, sep } from 'node:path';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..');
const html = readFileSync(join(REPO, 'index.html'), 'utf8');

let pass = 0, fail = 0;
const eq = (label, actual, expected) => {
  const a = JSON.stringify(actual), e = JSON.stringify(expected);
  if (a === e) { pass++; return; }
  fail++;
  console.log(`  ✗ ${label}\n      expected ${e}\n      actual   ${a}`);
};
const section = s => console.log(`\n${s}\n${'─'.repeat(s.length)}`);

const policyMatch = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)">/);
const policy = policyMatch ? policyMatch[1] : '';
const directives = Object.fromEntries(
  policy.split(';').map(d => d.trim()).filter(Boolean)
    .map(d => { const [name, ...rest] = d.split(/\s+/); return [name, rest.join(' ')]; })
);

/* ── 1. The directives this release fixes ────────────────────────────── */
section('1. Policy directives');

eq('a policy is present', policy.length > 0, true);

// A fixed, published nonce authorizes any injected script bearing the same
// attribute, so the policy claimed a control it did not have. A hash is the
// same length and is true.
eq('no nonce- token in script-src', /nonce-/.test(directives['script-src'] || ''), false);
eq('no nonce attribute survives in the document', /nonce=/.test(html), false);
eq('script-src carries a sha256 hash', /'sha256-[A-Za-z0-9+/]+={0,2}'/.test(directives['script-src'] || ''), true);

// Nothing loads a remote image and nothing planned will. The only thing this
// forbids is fetching an image from a host named in a stranger's record, which
// would disclose the auditor's address to that host.
eq('img-src is exactly self and data:', directives['img-src'], "'self' data:");

// The single-destination privacy claim in PRIVACY.md rests on this line.
eq('connect-src is exactly self and Cloudflare',
  directives['connect-src'], "'self' https://cloudflare-dns.com");

eq('object-src is none', directives['object-src'], "'none'");
eq('base-uri is none', directives['base-uri'], "'none'");
eq('form-action is none', directives['form-action'], "'none'");
eq('default-src is self', directives['default-src'], "'self'");

/* ── 2. The hash matches the block it authorizes ─────────────────────── */
section('2. The JSON-LD hash matches');

const inline = [...html.matchAll(/<script(?![^>]*\ssrc=)[^>]*>([\s\S]*?)<\/script>/g)];
eq('there is exactly one inline script', inline.length, 1);

const digest = createHash('sha256').update(inline[0][1], 'utf8').digest('base64');
eq('the computed digest is authorized by the policy',
  (directives['script-src'] || '').includes(`'sha256-${digest}'`), true);

eq('the inline block is the structured data',
  /application\/ld\+json/.test(inline[0][0]), true);
eq('the structured data still parses', (() => {
  try { JSON.parse(inline[0][1]); return true; } catch (e) { return false; }
})(), true);

/* ── 3. Every script the page loads is listed ────────────────────────── */
section('3. Script loading');

// Amended when the delivery boundary moved (Task 1.6). This section used to
// assert the seven-file load order, because index.html WAS the dependency
// graph. It is not any more: the order lives in src/entry-legacy.js, and
// tools/build-bundle.mjs verifies the bundle's input order against the markup
// rather than either one trusting the other.
//
// Section 1's policy assertions are untouched and must stay that way.
const srcs = [...html.matchAll(/<script[^>]*\ssrc="([^"]+)"/g)].map(m => m[1]);
eq('exactly one script is loaded', srcs.length, 1);
eq('and it is the built artifact', srcs[0], 'dist/app.min.js');
eq('every script is same-origin', srcs.every(s => !/^https?:/i.test(s)), true);
// Not type="module". The CSP shape and file:// both depend on it: a module
// script is fetched with CORS, which file:// refuses outright.
eq('no script is a module', /<script[^>]*\stype="module"/.test(html), false);
// The artifact is generated, never committed.
eq('dist/ is git-ignored', readFileSync(join(REPO, '.gitignore'), 'utf8').split('\n').includes('dist/'), true);

/* ── 4. The markup-sink scan ─────────────────────────────────────────── */
section('4. Markup-sink scan (allowlist is empty)');

// Assignment only. Reading `outerHTML` is how the two document builders
// serialize, and is permitted; writing either property never is.
//
// Compound assignment counts. The spec's original pattern was
// `/\.(inner|outer)HTML\s*=[^=]/`, which misses `el.innerHTML += x` — the
// exact form this release removed from `log()`, where it made the progress log
// quadratic. A scan that cannot catch a regression to the thing it was written
// for is not a scan. `=(?!=)` keeps `===` and `==` (reads, not writes) out.
const SINK = /\.(inner|outer)HTML\s*(?:\*\*|<<|>>>?|&&|\|\||\?\?|[+\-*/%&|^])?=(?!=)/;
const OTHER_SINKS = /insertAdjacentHTML|document\.write/;

// The scan is load-bearing, so prove it catches what it claims to before
// trusting it over the source tree.
const SINK_CASES = [
  ['el.innerHTML = x', true],
  ['el.innerHTML += x', true],
  ['el.outerHTML+=x', true],
  ['node.innerHTML   =   y', true],
  ['el.innerHTML ||= x', true],
  ['el.innerHTML ??= x', true],
  ['if (el.innerHTML === x)', false],
  ['if (el.innerHTML == x)', false],
  ['var s = el.outerHTML;', false],
  ['return doc.documentElement.outerHTML', false],
];

function jsFiles(dir) {
  return readdirSync(dir).flatMap((name) => {
    const full = join(dir, name);
    if (statSync(full).isDirectory()) return jsFiles(full);
    return name.endsWith('.js') ? [full] : [];
  });
}

// The allowlist is EMPTY. That is what makes this check reliable: an empty
// allowlist has no judgment calls in it. If a file needs adding here, the
// design went wrong, not the check.
const ALLOWLIST = [];
eq('the allowlist is empty', ALLOWLIST.length, 0);

SINK_CASES.forEach(([code, shouldMatch]) => {
  eq(`the scan ${shouldMatch ? 'catches' : 'ignores'} \`${code}\``, SINK.test(code), shouldMatch);
});

// The scan covers every source tree that still holds hand-written browser code,
// plus the artifact that actually ships.
//
// Co-location (OQ-ARCH-09) will put *.test.js under src/, so the scan needs an
// exclusion — and this file's own comment warns that an allowlist with judgment
// calls in it stops being reliable. The exclusion is therefore a MECHANICAL
// FILENAME SUFFIX, never a list of specific files. A suffix rule has no
// judgment in it, and the named-file allowlist above stays empty.
const SOURCE_TREES = ['js', 'src'].filter(dir => existsSync(join(REPO, dir)));
const scanned = SOURCE_TREES
  .flatMap(dir => jsFiles(join(REPO, dir)))
  .filter(file => !file.endsWith('.test.js'))
  .sort();
// Named by responsibility rather than by path, because the paths move every
// Phase 2 commit and the property does not: whatever tree these files live in,
// the markup-sink scan has to be looking at them.
eq('the scan covers the audit coordinator', scanned.some(f => f.endsWith('main.js')), true);
eq('the scan covers the renderer', scanned.some(f => f.endsWith('render.js')), true);
eq('the scan covers the i18n layer', scanned.some(f => f.endsWith('index.js') && f.includes(`${sep}i18n${sep}`)), true);
eq('the scan covers the protocol engine', scanned.some(f => f.endsWith('dns.js')), true);
eq('the scan covers the src/ tree', scanned.some(f => f.includes(`${sep}src${sep}`)), true);
eq('and excludes co-located tests by suffix alone',
  scanned.some(f => f.endsWith('.test.js')), false);

/**
 * And the built artifact, which is what the browser actually runs.
 *
 * This is what pays for the suffix exclusion above: whatever the source tree
 * does, the property is proved on the code that ships. `npm test` runs
 * `pretest`, which builds the bundle, so it is always here — a scan that
 * silently skipped when the artifact was missing would be worth nothing.
 */
const ARTIFACT = join(REPO, 'dist', 'app.min.js');
eq('the built artifact exists to be scanned', existsSync(ARTIFACT), true);
const artifactSource = existsSync(ARTIFACT) ? readFileSync(ARTIFACT, 'utf8') : '';
eq('the artifact assigns no markup sink', SINK.test(artifactSource), false);
eq('and calls none of the other sinks', OTHER_SINKS.test(artifactSource), false);
// The scan is only meaningful if it is looking at the real thing.
eq('the artifact is the whole application, not a stub', artifactSource.length > 100000, true);

for (const file of scanned) {
  const rel = relative(REPO, file);
  const lines = readFileSync(file, 'utf8').split('\n');
  const hits = [];
  lines.forEach((line, i) => {
    // Strip line comments before scanning: the files document the rule they
    // enforce, and a comment naming `innerHTML` is not an assignment.
    const code = line.replace(/\/\/.*$/, '').replace(/^\s*\*.*$/, '');
    if (SINK.test(code) || OTHER_SINKS.test(code)) hits.push(`${rel}:${i + 1}: ${line.trim()}`);
  });
  eq(`${rel} assigns to no markup sink`, hits, []);
}

/* ── 5. The report's own policy ──────────────────────────────────────── */
section('5. The exported report declares its own policy');

const app = readFileSync(join(REPO, 'src', 'main.js'), 'utf8');
eq('the report builder emits a CSP meta tag',
  app.includes('Content-Security-Policy'), true);
eq("the report's policy is default-src 'none'",
  app.includes("default-src 'none'; style-src 'unsafe-inline'; img-src data:"), true);

/* ── Summary ─────────────────────────────────────────────────────────── */
console.log(`\n${'='.repeat(60)}`);
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
