#!/usr/bin/env node
/**
 * Run this once, immediately before pushing and opening the PR.
 *
 *   1. re-syncs locale state, so anything added to en.json since the last
 *      pass is caught rather than remembered
 *   2. writes a Localization status block to tmp/PR_DESCRIPTION.md from the
 *      state database, not from anyone's recollection
 *
 * Exits non-zero if anything is still `initial` or `stale`, so a PR does not
 * quietly ship English placeholders — `npm run locale:todo` lists exactly
 * what is outstanding.
 *
 *   npm run pr:prep
 */

import { mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { LOCALE_CODES, loadStatus, localeName, SUB_STALE, root } from './lib/locale-utils.mjs';

const OUT_PATH = join(root, 'tmp', 'PR_DESCRIPTION.md');
const rel = (p) => p.replace(root + '/', '');

console.log('→ npm run locale:sync\n');
const sync = spawnSync(process.execPath, [join(root, 'tools', 'locale-sync.mjs')], { cwd: root, encoding: 'utf8' });
process.stdout.write(sync.stdout || '');
if (sync.status !== 0) {
  process.stderr.write(sync.stderr || '');
  console.error('\nSync failed — fix the above before opening the PR.');
  process.exit(1);
}

const status = loadStatus();
const rows = LOCALE_CODES.map(code => {
  const entries = Object.values(status.locales?.[code] || {});
  return {
    code,
    initial: entries.filter(e => e.state === 'initial').length,
    stale: entries.filter(e => e.subState === SUB_STALE).length,
    translated: entries.filter(e => e.state === 'translated').length,
    reviewed: entries.filter(e => e.state === 'reviewed' || e.state === 'final').length,
  };
});

const initial = rows.reduce((n, r) => n + r.initial, 0);
const stale = rows.reduce((n, r) => n + r.stale, 0);
const outstanding = initial + stale;

const block = outstanding > 0
  ? `## Localization status

⚠️ **${outstanding} translation unit(s) outstanding** — these render the English fallback:

| locale | initial | stale |
|---|---|---|
${rows.filter(r => r.initial || r.stale).map(r => `| ${r.code} — ${localeName(r.code)} | ${r.initial} | ${r.stale} |`).join('\n')}

Run \`npm run locale:todo\` to list them, translate, then \`npm run locale:set\`.
They fall back to English at runtime with no functional impact, so this is not
a merge blocker — but \`npm run locale:gate\` will flag it.
`
  : `## Localization status

✅ **All ${rows.length} locales fully translated** — no key is in state \`initial\`, and no translation is stale against the current English.

| locale | translated | reviewed/final |
|---|---|---|
${rows.map(r => `| ${r.code} — ${localeName(r.code)} | ${r.translated} | ${r.reviewed} |`).join('\n')}
`;

mkdirSync(dirname(OUT_PATH), { recursive: true });
writeFileSync(OUT_PATH, block, 'utf8');

console.log(`\n${'─'.repeat(58)}`);
process.stdout.write(block);
console.log('─'.repeat(58));
console.log(`\nWritten to ${rel(OUT_PATH)} (git-ignored — paste it into the PR description).`);
process.exit(outstanding ? 1 : 0);
