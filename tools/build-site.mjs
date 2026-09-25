#!/usr/bin/env node

import { cp, mkdir, rm } from 'node:fs/promises';
import { existsSync, lstatSync, realpathSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { basename, dirname, join, resolve, sep } from 'node:path';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');

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
 * `index.html` out of it. It must also resolve outside the repository, judged
 * through symlinks: copying into an input directory copies it into itself.
 * Not existing already rules out the repository, its ancestors and `/`.
 */
function namedOutput(path) {
  const target = resolve(path);
  const refuse = why => {
    console.error(`build-site: refusing output ${path}: ${why}`);
    process.exit(1);
  };
  const exists = p => lstatSync(p, { throwIfNoEntry: false }) !== undefined;
  if (exists(target)) refuse('it already exists; name a directory that does not, and it will be created');

  let existing = target;
  const rest = [];
  while (!exists(existing)) {
    rest.unshift(basename(existing));
    existing = dirname(existing);
  }
  const real = join(realpathSync(existing), ...rest);
  const realRepo = realpathSync(repo);
  if (real === realRepo || real.startsWith(realRepo + sep)) refuse('it is inside the repository');
  return target;
}

const output = process.argv[2] ? namedOutput(process.argv[2]) : join(repo, '_site');
// The deployment allowlist. `js` became `dist` when the delivery boundary
// moved: what ships is the built artifact and its source map, not the source
// it was built from. Everything absent from this list is absent from the
// published site, and tests/build/artifact.test.mjs asserts both directions.
const files = ['index.html', 'CNAME', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'css', 'dist', 'locales'];

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
