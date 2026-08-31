#!/usr/bin/env node
/**
 * The live backtest's request counter is a privacy instrument, not decoration.
 * Keep the counted fetch on the engine boundary after composition changes.
 */

import { readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join } from 'node:path';

import { createSuite } from '../tests/lib/assert.mjs';

const { eq, section, report } = createSuite();
const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const source = readFileSync(join(ROOT, 'tools/backtest.mjs'), 'utf8');

function engineUsesCountedFetch(text) {
  const code = text.replace(/\/\*[\s\S]*?\*\//g, '').replace(/\/\/.*$/gm, '');
  return /platform\s*:\s*\{\s*fetch\s*:\s*countingFetch\b/.test(code);
}

section('The live fan-out counter reaches the engine');

eq('the engine receives countingFetch', engineUsesCountedFetch(source), true);

// Negative control: this is the exact 0.6.0 regression. The counter existed,
// but composition passed the ambient fetch around it, so every run reported 0.
eq('passing the ambient fetch instead is caught',
  engineUsesCountedFetch(source.replace(
    'platform: { fetch: countingFetch', 'platform: { fetch: fetch'
  )), false);

report();
