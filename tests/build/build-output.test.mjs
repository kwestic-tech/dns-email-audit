#!/usr/bin/env node
/**
 * Build output is safe to share between gates that run at the same time.
 *
 *   node tests/build/build-output.test.mjs
 *
 * `npm test` rebuilds the bundle in `pretest` while `npm run inventory` may be
 * reading it, and both run `tests/build/artifact.test.mjs`. Two races followed:
 * a reader saw a partially written bundle or metafile (2 torn reads in 767),
 * and two artifact runs deleted each other's `_site` (43 of 80 runs failed
 * under four-way stress). A stress loop is evidence, not a gate — it passes by
 * luck as often as by design — so each guarantee is observed here directly:
 *
 *  1. The build publishes by rename. A hard link taken to each output before
 *     the build still holds the old bytes afterwards; a write in place would
 *     have changed them through the shared inode.
 *  2. The artifact suite assembles its site somewhere private. Its call to
 *     `build-site.mjs` is intercepted in two overlapping runs, which must name
 *     two different destinations, both outside the repository, and leave the
 *     repository's `_site` alone.
 *  3. `build-site.mjs` refuses a destination it could damage. The first version
 *     of the named-output interface removed whatever it was given, and `.`
 *     deleted the source tree. Every case runs in a disposable fixture: a
 *     broken check here deletes a temporary directory, never the checkout.
 *
 * Everything this suite writes is under its own temporary directory.
 */

import {
  readFileSync, writeFileSync, existsSync, readdirSync, statSync, mkdtempSync, mkdirSync, rmSync,
  cpSync, linkSync, symlinkSync, realpathSync,
} from 'node:fs';
import { spawn, spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { dirname, join, sep } from 'node:path';

import { createSuite } from '../lib/assert.mjs';
import { build } from '../../tools/build-bundle.mjs';

const REPO = process.argv[2] || join(dirname(fileURLToPath(import.meta.url)), '..', '..');
const { eq, section, report } = createSuite();

const scratch = mkdtempSync(join(tmpdir(), 'build-output-'));
process.on('exit', () => rmSync(scratch, { recursive: true, force: true }));
// Textual, against both spellings of the root: the path may already be gone,
// and the temporary directory is reached through a symlink on macOS.
const inside = (path, root) => [root, realpathSync(root)]
  .some(base => path === base || path.startsWith(base + sep));

/* ── 1. The bundle is published by rename ─────────────────────────────── */
section('1. The build replaces its outputs by rename, never in place');

const subject = join(scratch, 'subject');
for (const path of ['index.html', 'src', 'package.json']) {
  cpSync(join(REPO, path), join(subject, path), { recursive: true });
}
const OUTPUTS = ['dist/app.min.js', 'dist/app.min.js.map', '.build/metafile.json'];
const probes = join(scratch, 'probes');
mkdirSync(probes);
mkdirSync(join(subject, 'dist'));
mkdirSync(join(subject, '.build'));
for (const [i, output] of OUTPUTS.entries()) {
  writeFileSync(join(subject, output), `OLD ${output}`);
  linkSync(join(subject, output), join(probes, String(i)));
}

await build({ root: subject });

for (const [i, output] of OUTPUTS.entries()) {
  eq(`${output}: the bytes behind the old inode were not rewritten`,
    readFileSync(join(probes, String(i)), 'utf8').slice(0, 60), `OLD ${output}`);
  eq(`${output}: the path now names a different file`,
    statSync(join(subject, output)).ino !== statSync(join(probes, String(i))).ino, true);
}
const bundle = readFileSync(join(subject, 'dist/app.min.js'), 'utf8');
eq('the published bundle is the build, whole', /\/\/# sourceMappingURL=app\.min\.js\.map\s*$/.test(bundle), true);
eq('the published map is the build, whole',
  JSON.parse(readFileSync(join(subject, 'dist/app.min.js.map'), 'utf8')).sources.length > 0, true);
eq('the published metafile is the build, whole',
  Object.keys(JSON.parse(readFileSync(join(subject, '.build/metafile.json'), 'utf8')).outputs).length > 0, true);
// dist/ ships wholesale, so a temporary left in it would be published.
eq('dist/ holds only the two shipped files', readdirSync(join(subject, 'dist')).sort(),
  ['app.min.js', 'app.min.js.map']);
eq('no temporary is left in .build/', readdirSync(join(subject, '.build')), ['metafile.json']);

// Negative control: the probe does see a write in place.
linkSync(join(subject, 'dist/app.min.js'), join(probes, 'control'));
writeFileSync(join(subject, 'dist/app.min.js'), 'IN PLACE');
eq('a write in place would be caught', readFileSync(join(probes, 'control'), 'utf8'), 'IN PLACE');

/* ── 2. The artifact suite's site is private ──────────────────────────── */
section('2. Two overlapping artifact runs assemble in two private directories');

// A repository-shaped fixture holding what the artifact suite reads: the
// published inputs, the built bundle, the metafile and the site builder.
const fixture = join(scratch, 'fixture');
for (const path of ['index.html', 'CNAME', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'css', 'dist', 'locales',
  '.build/metafile.json', 'tools/build-site.mjs']) {
  cpSync(join(REPO, path), join(fixture, path), { recursive: true });
}
mkdirSync(join(fixture, '_site'));
writeFileSync(join(fixture, '_site', 'sentinel'), 'the repository site');

// Records the destination the suite hands to build-site, at the call itself.
const log = join(scratch, 'build-site-calls.log');
const hook = join(scratch, 'record-build-site.mjs');
writeFileSync(hook, [
  "import childProcess from 'node:child_process';",
  "import { syncBuiltinESMExports } from 'node:module';",
  "import { appendFileSync } from 'node:fs';",
  'const real = childProcess.execFileSync;',
  'childProcess.execFileSync = function (file, args, ...rest) {',
  '  appendFileSync(process.env.BUILD_SITE_LOG, JSON.stringify(args) + "\\n");',
  '  return real.call(this, file, args, ...rest);',
  '};',
  'syncBuiltinESMExports();',
].join('\n'));

const runArtifact = () => new Promise(done => {
  const child = spawn(process.execPath,
    ['--import', pathToFileURL(hook).href, join(REPO, 'tests/build/artifact.test.mjs'), fixture],
    { cwd: fixture, env: { ...process.env, BUILD_SITE_LOG: log }, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });
  child.on('exit', code => done({ code, output }));
});
const runs = await Promise.all([runArtifact(), runArtifact()]);

eq('both overlapping runs pass', runs.map(run => run.code), [0, 0]);
eq('both report no failures', runs.map(run => /\d+ passed, 0 failed/.test(run.output)), [true, true]);
const calls = existsSync(log)
  ? readFileSync(log, 'utf8').trim().split('\n').map(line => JSON.parse(line))
  : [];
eq('build-site was invoked once per run', calls.length, 2);
const destinations = calls.map(args => args[1] ?? null);
eq('each run names its own destination', destinations.every(Boolean), true);
eq('the two destinations differ', new Set(destinations).size, 2);
eq('neither destination is inside the repository',
  destinations.filter(Boolean).filter(path => inside(path, fixture)), []);
eq('the repository\'s _site was left alone',
  existsSync(join(fixture, '_site', 'sentinel')), true);
eq('each private destination is removed when its run ends',
  destinations.filter(Boolean).filter(path => existsSync(dirname(path))), []);

/* ── 3. build-site refuses a destination it could damage ──────────────── */
section('3. build-site refuses unsafe destinations');

// outer/ holds the repository, so the repository's parent is disposable too.
const outer = join(scratch, 'outer');
const repo = join(outer, 'repo');
for (const dir of ['tools', 'css', 'dist', 'locales']) mkdirSync(join(repo, dir), { recursive: true });
cpSync(join(REPO, 'tools/build-site.mjs'), join(repo, 'tools/build-site.mjs'));
for (const file of ['index.html', 'CNAME', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'css/app.css',
  'dist/app.min.js', 'locales/en.json', 'source-sentinel']) {
  writeFileSync(join(repo, file), 'fixture');
}
writeFileSync(join(outer, 'outer-sentinel'), 'fixture');
mkdirSync(join(outer, 'occupied'));
writeFileSync(join(outer, 'occupied', 'keep'), 'fixture');
symlinkSync(repo, join(outer, 'alias'));
symlinkSync(join(outer, 'nowhere'), join(outer, 'dangling'));

const buildSite = (...args) =>
  spawnSync(process.execPath, [join(repo, 'tools/build-site.mjs'), ...args], { cwd: repo, encoding: 'utf8' });
const survivors = () => [
  join(repo, 'source-sentinel'), join(repo, 'tools/build-site.mjs'), join(repo, 'css/app.css'),
  join(outer, 'outer-sentinel'), join(outer, 'occupied', 'keep'),
].filter(path => !existsSync(path));

const REFUSED = [
  ['the repository itself', '.'],
  ['an ancestor of the repository', '..'],
  ['an input directory', 'css'],
  ['a new path inside an input directory', 'css/nested'],
  ['a new path elsewhere inside the repository', 'site-copy'],
  ['a symlink alias into the repository', join(outer, 'alias', 'site-copy')],
  ['an existing directory outside the repository', join(outer, 'occupied')],
  ['a dangling symlink', join(outer, 'dangling')],
];
for (const [label, destination] of REFUSED) {
  const result = buildSite(destination);
  eq(`${label}: refused`, result.status, 1);
  eq(`${label}: and says so`, /refusing output/.test(result.stderr), true);
  eq(`${label}: nothing was removed`, survivors(), []);
}
eq('no refused destination was created',
  [join(repo, 'css/nested'), join(repo, 'site-copy'), join(outer, 'nowhere')].filter(existsSync), []);

// Positive controls: a fresh path outside the repository, and the default.
const fresh = buildSite(join(outer, 'site'));
eq('a new path outside the repository is built', fresh.status, 0);
eq('and holds the site', existsSync(join(outer, 'site', 'index.html')), true);
mkdirSync(join(repo, '_site'));
writeFileSync(join(repo, '_site', 'stale'), 'fixture');
const byDefault = buildSite();
eq('the default destination is still built', byDefault.status, 0);
eq('and still replaces the previous _site', existsSync(join(repo, '_site', 'stale')), false);
eq('with the site in it', existsSync(join(repo, '_site', 'index.html')), true);
eq('and nothing outside _site was removed', survivors(), []);

report();
