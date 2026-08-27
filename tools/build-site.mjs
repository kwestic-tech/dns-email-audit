#!/usr/bin/env node

import { cp, mkdir, rm } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');
const output = join(repo, '_site');
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

await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
for (const file of files) {
  await cp(join(repo, file), join(output, file), { recursive: true, filter: (src) => !skip.has(src) });
}
console.log(`Built static site in ${output}`);
