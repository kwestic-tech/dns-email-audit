#!/usr/bin/env node

import { cp, mkdir, rm } from 'node:fs/promises';
import { existsSync, lstatSync, realpathSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, resolve } from 'node:path';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');

// The deployment allowlist. `js` became `dist` when the delivery boundary
// moved: what ships is the built artifact and its source map, not the source
// it was built from. Everything absent from this list is absent from the
// published site, and tests/build/artifact.test.mjs asserts both directions.
const files = ['index.html', 'CNAME', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'css', 'dist', 'locales'];

/**
 * A named destination, refused unless it is safe to create.
 *
 * `_site` unless a directory is named. tests/build/artifact.test.mjs names a
 * private one: it runs in both `npm test` and `npm run inventory`, and two
 * runs removing and refilling the same `_site` at once failed each other with
 * EEXIST or ENOENT partway through the copy.
 *
 * A named destination is never removed, only created, so it must not exist
 * yet. The first version of this removed whatever it was given, and `.` from
 * the repository root deleted the source tree before failing to copy
 * `index.html` out of it. Not existing already rules out the repository, its
 * ancestors and `/`.
 *
 * It must also not be inside an input: copying `css` into `css/nested` copies
 * a directory into itself, and `cp` writes the top-level files before it
 * notices. Elsewhere in the repository is allowed — a temporary directory can
 * live there, and a new directory nobody removes has nothing to damage.
 *
 * "Inside" is judged by filesystem identity, device and inode, walking up from
 * the nearest existing ancestor. A spelling cannot be trusted to name a
 * directory once: symlinks alias it, and on a case-insensitive filesystem
 * `caserepo/css` reaches `CaseRepo/css` while `realpath` keeps the spelling it
 * was given.
 */
function namedOutput(path) {
  const target = resolve(path);
  const refuse = why => {
    console.error(`build-site: refusing output ${path}: ${why}`);
    process.exit(1);
  };
  const exists = p => lstatSync(p, { throwIfNoEntry: false }) !== undefined;
  if (exists(target)) refuse('it already exists; name a directory that does not, and it will be created');

  let existing = dirname(target);
  while (!exists(existing)) existing = dirname(existing);

  const identity = p => { const stat = statSync(p); return `${stat.dev}:${stat.ino}`; };
  const inputs = new Map(files.filter(file => existsSync(join(repo, file)))
    .map(file => [identity(join(repo, file)), file]));
  let dir;
  try {
    dir = realpathSync(existing);
  } catch {
    refuse(`${existing} cannot be resolved`);
  }
  for (;;) {
    const input = inputs.get(identity(dir));
    if (input) refuse(`it is inside ${input}, which the site is copied from`);
    if (dir === dirname(dir)) break;
    dir = dirname(dir);
  }
  return target;
}

const output = process.argv[2] ? namedOutput(process.argv[2]) : join(repo, '_site');

// locales/pending-translations.json is build-time tracking state, not a
// bundle the browser ever fetches — it must not be published with the site.
const skip = new Set([join(repo, 'locales', 'translation-status.json')]);

// A missing artifact must stop the assemble rather than publish an index.html
// whose only script 404s. `npm run build` builds the bundle first for exactly
// this reason.
const bundle = join(repo, 'dist', 'app.min.js');
if (!existsSync(bundle)) {
  console.error('build-site: dist/app.min.js is missing. Run `npm run build:bundle` first.');
  process.exit(1);
}

if (!process.argv[2]) await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
for (const file of files) {
  await cp(join(repo, file), join(output, file), { recursive: true, filter: (src) => !skip.has(src) });
}
console.log(`Built static site in ${output}`);
