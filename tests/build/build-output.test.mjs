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
 *  1. The build publishes by rename. Every filesystem call that names a final
 *     output is recorded while the build runs, and the only ones allowed are
 *     reads and exactly one rename into place, from a temporary that was
 *     already whole. Hard links taken to the old outputs catch what that
 *     cannot see — esbuild writing from its own process — because a write in
 *     place changes the bytes behind the shared inode. Neither alone is
 *     enough: deleting the target and writing it afresh passes the hard links
 *     (round 2, finding 2), and a write from outside Node passes the recorder.
 *  2. The artifact suite assembles its site somewhere private. Its call to
 *     `build-site.mjs` is intercepted in two overlapping runs, which must name
 *     two different destinations and leave the repository's `_site` alone —
 *     and a third run with TMPDIR inside the repository must still pass.
 *  3. `build-site.mjs` refuses a destination it could damage, judged by
 *     filesystem identity rather than spelling. The first version of the
 *     named-output interface removed whatever it was given, and `.` deleted
 *     the source tree. Every case runs in a disposable fixture: a broken check
 *     here deletes a temporary directory, never the checkout.
 *
 * Everything this suite writes is under its own temporary directory. The
 * artifact runs it starts each allocate their own, beside it, and remove them.
 */

import fs, {
  readFileSync, writeFileSync, existsSync, readdirSync, statSync, mkdtempSync, mkdirSync, rmSync,
  cpSync, linkSync, symlinkSync, realpathSync,
} from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { spawn, spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { basename, dirname, join, resolve, sep } from 'node:path';

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

/**
 * Record every `node:fs` call — sync, callback or promise — whose first or
 * second argument names one of `targets`, until `uninstall()`.
 *
 * `syncBuiltinESMExports()` makes the replacement reach modules that imported
 * the functions by name, which is how `tools/build-bundle.mjs` imports them.
 * For a rename into a target, the size of its source at that moment is kept,
 * so the test can tell a whole temporary from one still being written.
 */
function recordFs(targets) {
  const calls = [];
  const restore = [];
  const size = fs.statSync;
  const real = fs.realpathSync;
  // One spelling per file: esbuild reports its outputs through the realpath
  // (/private/var on macOS) and this suite names them through the symlink.
  const key = path => {
    try { return join(real(dirname(path)), basename(path)); } catch { return path; }
  };
  const wanted = new Set([...targets].map(key));
  for (const api of [fs, fs.promises]) {
    for (const name of Object.keys(api)) {
      const original = api[name];
      if (typeof original !== 'function' || /^[A-Z]/.test(name)) continue;
      api[name] = function (...args) {
        args.slice(0, 2).forEach((arg, index) => {
          const path = arg instanceof URL ? fileURLToPath(arg) : arg;
          if (typeof path !== 'string' || path.length > 4096 || !wanted.has(key(resolve(path)))) return;
          const publish = /^rename/.test(name) && index === 1;
          calls.push({
            target: key(resolve(path)), name, index,
            // `readFileSync` reaches the exported `openSync`; read-only is a read.
            readOnly: /^open/.test(name) && [undefined, 'r', fs.constants.O_RDONLY].includes(args[1]),
            sourceBytes: publish ? size(args[0]).size : null,
          });
        });
        return original.apply(this, args);
      };
      restore.push(() => { api[name] = original; });
    }
  }
  syncBuiltinESMExports();
  return {
    calls,
    uninstall() { for (const undo of restore) undo(); syncBuiltinESMExports(); },
  };
}
const READ = /^(read|stat|lstat|exists|access|realpath)/;
const isPublish = call => /^rename/.test(call.name) && call.index === 1;
const same = (call, target) => call.target === join(realpathSync(dirname(target)), basename(target));
const violations = (calls, target) => calls
  .filter(call => same(call, target) && !READ.test(call.name) && !call.readOnly && !isPublish(call))
  .map(call => `${call.name}[${call.index}]`);

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

const recorder = recordFs(new Set(OUTPUTS.map(output => join(subject, output))));
try {
  await build({ root: subject });
} finally {
  recorder.uninstall();
}

for (const [i, output] of OUTPUTS.entries()) {
  const target = join(subject, output);
  const publishes = recorder.calls.filter(call => same(call, target) && isPublish(call));
  eq(`${output}: is only ever read, or renamed into place`, violations(recorder.calls, target), []);
  eq(`${output}: is published by exactly one rename`, publishes.length, 1);
  eq(`${output}: from a temporary that was already whole`,
    publishes[0]?.sourceBytes, statSync(target).size);
  eq(`${output}: the bytes behind the old inode were not rewritten`,
    readFileSync(join(probes, String(i)), 'utf8').slice(0, 60), `OLD ${output}`);
  eq(`${output}: the path now names a different file`,
    statSync(target).ino !== statSync(join(probes, String(i))).ino, true);
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

// Negative controls: each observer sees the failure the other one misses.
linkSync(join(subject, 'dist/app.min.js'), join(probes, 'control'));
writeFileSync(join(subject, 'dist/app.min.js'), 'IN PLACE');
eq('a write in place would be caught by the hard link', readFileSync(join(probes, 'control'), 'utf8'), 'IN PLACE');
const control = join(subject, 'dist/app.min.js');
const controlRecorder = recordFs(new Set([control]));
try {
  fs.unlinkSync(control);
  fs.writeFileSync(control, 'REWRITTEN');
} finally {
  controlRecorder.uninstall();
}
eq('a delete and rewrite would be caught by the recorder',
  violations(controlRecorder.calls, control), ['unlinkSync[0]', 'writeFileSync[0]']);

/* ── 2. The artifact suite's site is private ──────────────────────────── */
section('2. Artifact runs assemble in private directories');

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

const runArtifact = (log, env = {}) => new Promise(done => {
  const child = spawn(process.execPath,
    ['--import', pathToFileURL(hook).href, join(REPO, 'tests/build/artifact.test.mjs'), fixture],
    { cwd: fixture, env: { ...process.env, ...env, BUILD_SITE_LOG: log }, stdio: ['ignore', 'pipe', 'pipe'] });
  let output = '';
  child.stdout.on('data', chunk => { output += chunk; });
  child.stderr.on('data', chunk => { output += chunk; });
  child.on('exit', code => done({ code, output }));
});
const destinationsIn = log => (existsSync(log)
  ? readFileSync(log, 'utf8').trim().split('\n').map(line => JSON.parse(line)[1] ?? null)
  : []);

const log = join(scratch, 'build-site-calls.log');
const runs = await Promise.all([runArtifact(log), runArtifact(log)]);

eq('both overlapping runs pass', runs.map(run => run.code), [0, 0]);
eq('both report no failures', runs.map(run => /\d+ passed, 0 failed/.test(run.output)), [true, true]);
const destinations = destinationsIn(log);
eq('build-site was invoked once per run', destinations.length, 2);
eq('each run names its own destination', destinations.every(Boolean), true);
eq('the two destinations differ', new Set(destinations).size, 2);
eq('neither destination is inside the repository',
  destinations.filter(Boolean).filter(path => inside(path, fixture)), []);
eq('each private destination is removed when its run ends',
  destinations.filter(Boolean).filter(path => existsSync(dirname(path))), []);

// A temporary directory inside the checkout is a valid configuration, and
// both gates run this suite, so it must work there too (round 2, finding 3).
const insideTmp = join(fixture, 'tmp');
mkdirSync(insideTmp);
const insideLog = join(scratch, 'build-site-calls-inside.log');
const insideRun = await runArtifact(insideLog, { TMPDIR: insideTmp });
const [insideDestination] = destinationsIn(insideLog);
eq('with TMPDIR inside the repository, the artifact suite still passes', insideRun.code, 0);
eq('and reports no failures', /\d+ passed, 0 failed/.test(insideRun.output), true);
eq('its destination is under that TMPDIR', Boolean(insideDestination) && inside(insideDestination, insideTmp), true);
eq('and is removed when the run ends', existsSync(insideTmp) && readdirSync(insideTmp).length === 0, true);
eq('no run touched the repository\'s _site', readdirSync(join(fixture, '_site')), ['sentinel']);

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

const buildSite = (args, options = {}) => spawnSync(process.execPath,
  [...(options.execArgv || []), join(repo, 'tools/build-site.mjs'), ...args],
  { cwd: repo, encoding: 'utf8', env: { ...process.env, ...options.env } });
const survivors = () => [
  join(repo, 'source-sentinel'), join(repo, 'tools/build-site.mjs'), join(repo, 'css/app.css'),
  join(outer, 'outer-sentinel'), join(outer, 'occupied', 'keep'),
].filter(path => !existsSync(path));
const refusal = result => ({ status: result.status, refused: /refusing output/.test(result.stderr) });
const REFUSED_OUTCOME = { status: 1, refused: true };

const REFUSED = [
  ['the repository itself', '.'],
  ['an ancestor of the repository', '..'],
  ['an input directory', 'css'],
  ['a new path inside an input directory', 'css/nested'],
  ['a new path several levels inside an input', 'dist/deeper/nested'],
  ['a symlink alias into an input', join(outer, 'alias', 'css', 'nested')],
  ['an existing directory outside the repository', join(outer, 'occupied')],
  ['a dangling symlink', join(outer, 'dangling')],
];
for (const [label, destination] of REFUSED) {
  const result = buildSite([destination]);
  eq(`${label}: refused`, result.status, 1);
  eq(`${label}: and says so`, /refusing output/.test(result.stderr), true);
  eq(`${label}: nothing was removed`, survivors(), []);
}

// A case alias exists only on a case-insensitive filesystem — macOS by
// default, not the Linux CI runner. Where there is none, the assertion records
// that the alias does not resolve, which is why the bypass cannot happen there.
const caseAlias = join(outer, basename(repo).toUpperCase());
const aliased = existsSync(caseAlias) && statSync(caseAlias).ino === statSync(repo).ino;
eq('an alternate-case alias into an input is refused, where the filesystem has one',
  aliased ? refusal(buildSite([join(caseAlias, 'css', 'nested')])) : `no alias: ${existsSync(caseAlias)}`,
  aliased ? REFUSED_OUTCOME : 'no alias: false');

eq('no refused destination was created',
  [join(repo, 'css/nested'), join(repo, 'dist/deeper'), join(outer, 'nowhere')].filter(existsSync), []);

// The guard that keeps a named destination from being removed. Validation
// refuses anything that exists, so the guard matters only if the destination
// appears between validation and assembly; a preload makes that happen at the
// bundle check, which runs after validation (round 2).
const raced = join(outer, 'raced');
const raceHook = join(scratch, 'race-destination.mjs');
writeFileSync(raceHook, [
  "import fs from 'node:fs';",
  "import { syncBuiltinESMExports } from 'node:module';",
  "import { join } from 'node:path';",
  'const real = fs.existsSync;',
  'fs.existsSync = function (path) {',
  "  if (String(path).endsWith(join('dist', 'app.min.js')) && !real(process.env.RACE_DESTINATION)) {",
  '    fs.mkdirSync(process.env.RACE_DESTINATION);',
  "    fs.writeFileSync(join(process.env.RACE_DESTINATION, 'sentinel'), 'appeared after validation');",
  '  }',
  '  return real.apply(this, arguments);',
  '};',
  'syncBuiltinESMExports();',
].join('\n'));
const racedRun = buildSite([raced],
  { execArgv: ['--import', pathToFileURL(raceHook).href], env: { RACE_DESTINATION: raced } });
eq('a destination that appears after validation is built into', racedRun.status, 0);
eq('without removing what was already there', existsSync(join(raced, 'sentinel')), true);
eq('and it holds the site', existsSync(join(raced, 'index.html')), true);

// Positive controls: fresh paths inside and outside the repository, and the
// default.
const fresh = buildSite([join(outer, 'site')]);
eq('a new path outside the repository is built', fresh.status, 0);
eq('and holds the site', existsSync(join(outer, 'site', 'index.html')), true);
const beside = buildSite(['site-copy']);
eq('a new path inside the repository but outside its inputs is built', beside.status, 0);
eq('and holds the site', existsSync(join(repo, 'site-copy', 'index.html')), true);
mkdirSync(join(repo, '_site'));
writeFileSync(join(repo, '_site', 'stale'), 'fixture');
const byDefault = buildSite([]);
eq('the default destination is still built', byDefault.status, 0);
eq('and still replaces the previous _site', existsSync(join(repo, '_site', 'stale')), false);
eq('with the site in it', existsSync(join(repo, '_site', 'index.html')), true);
eq('and nothing outside _site was removed', survivors(), []);

report();
