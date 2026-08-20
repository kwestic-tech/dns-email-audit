#!/usr/bin/env node

import { cp, mkdir, rm } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');
const output = join(repo, '_site');
const files = ['index.html', 'CNAME', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'css', 'js', 'locales'];

// locales/pending-translations.json is build-time tracking state, not a
// bundle the browser ever fetches — it must not be published with the site.
const skip = new Set([join(repo, 'locales', 'translation-status.json')]);

await rm(output, { recursive: true, force: true });
await mkdir(output, { recursive: true });
for (const file of files) {
  await cp(join(repo, file), join(output, file), { recursive: true, filter: (src) => !skip.has(src) });
}
console.log(`Built static site in ${output}`);
