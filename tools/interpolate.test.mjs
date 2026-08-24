#!/usr/bin/env node
/**
 * Placeholder interpolation. Pure — no DOM, no network.
 *
 * The defect this file exists to pin down: the previous `interpolate()` looped
 * i from 0 upward and replaced `{i}` by split/join, so an argument substituted
 * at {0} became part of the string {1} then scanned. Every current message
 * takes an internal value first, so nothing reachable exploited it — but
 * dmarcbis-tree-walk (0.3.0) and dns-protocol-depth (0.4.0) both add messages
 * whose first argument is a DNS-derived name.
 */

import { loadApp } from './lib/browser-harness.mjs';

const win = loadApp({ files: ['js/locales-en.js', 'js/i18n.js'] });
const { t, tp } = win;

let pass = 0, fail = 0;
const eq = (label, actual, expected) => {
  if (actual === expected) { pass++; return; }
  fail++;
  console.log(`  ✗ ${label}\n      expected ${JSON.stringify(expected)}\n      actual   ${JSON.stringify(actual)}`);
};
const section = s => console.log(`\n${s}\n${'─'.repeat(s.length)}`);

// The real bundle has no two-argument message whose first argument is
// attacker-shaped, so the template is injected directly to test the function
// rather than a particular message.
const bundle = win.__I18N_EN__;
bundle.__test__ = {
  two: 'a {0} b {1} c',
  one: 'only {0}',
  stray: 'has {0} and {5}',
  repeated: '{0} then {0} again',
  outOfOrder: '{1} before {0}',
};

/* ── 1. A substituted value is never rescanned ───────────────────────── */
section('1. A substituted value is never rescanned');

eq('injected {1} survives as literal text',
  t('__test__.two', 'a {1} b', 'X'), 'a a {1} b b X c');

eq('injected {0} does not re-substitute itself',
  t('__test__.one', '{0}'), 'only {0}');

eq('a DNS-shaped value carrying a placeholder stays inert',
  t('__test__.two', 'v=spf1 include:{1}.evil.example -all', 'SECOND'),
  'a v=spf1 include:{1}.evil.example -all b SECOND c');

eq('two arguments each containing the other index',
  t('__test__.two', '{1}', '{0}'), 'a {1} b {0} c');

/* ── 2. Missing indices stay visible ─────────────────────────────────── */
section('2. Missing indices stay visible');

eq('a stray {5} with one argument stays literal',
  t('__test__.stray', 'A'), 'has A and {5}');

eq('a stray {5} with three arguments stays literal',
  t('__test__.stray', 'A', 'B', 'C'), 'has A and {5}');

eq('no argument at all leaves every placeholder',
  t('__test__.two'), 'a {0} b {1} c');

/* ── 3. Ordinary behaviour is unchanged ──────────────────────────────── */
section('3. Ordinary behaviour is unchanged');

eq('both placeholders fill', t('__test__.two', 'X', 'Y'), 'a X b Y c');
eq('a repeated index fills every occurrence',
  t('__test__.repeated', 'X'), 'X then X again');
eq('placeholders may appear out of order',
  t('__test__.outOfOrder', 'first', 'second'), 'second before first');
eq('a numeric argument is stringified', t('__test__.one', 42), 'only 42');
eq('an unknown key returns the key', t('__test__.missing'), '__test__.missing');

/* ── 4. Every shipped message still renders ──────────────────────────── */
section('4. Every shipped message still renders');

// Build the expectation in ONE pass too. Chained .replace() calls would
// reintroduce the exact defect under test: replacing {0} with a value
// containing "{1}" leaves a second "{1}" for the next replace to find.
const fill = (template, ...args) =>
  template.replace(/\{(\d+)\}/g, (m, d) => (Number(d) < args.length ? String(args[Number(d)]) : m));

// A real three-argument message from the bundle, exercised the way js/app.js
// calls it. `score.unproven` takes (points, max, pillar list).
eq('score.unproven fills all three',
  t('score.unproven', '12', 30, 'DKIM'),
  fill(bundle.score.unproven, '12', 30, 'DKIM'));

// A DNS-derived first argument, which is what 0.3.0 and 0.4.0 introduce.
eq('a hostile hostname in argument 0 cannot reach argument 1',
  t('score.unproven', '{1}', 30, 'DKIM'),
  fill(bundle.score.unproven, '{1}', 30, 'DKIM'));

/* ── 5. Plurals use the same single pass ─────────────────────────────── */
section('5. Plurals use the same single pass');

bundle.__test__.plural = { one: '{0} thing with {1}', other: '{0} things with {1}' };
eq('plural one', tp('__test__.plural', 1, 'X'), '1 thing with X');
eq('plural other', tp('__test__.plural', 5, 'X'), '5 things with X');
eq('a count that looks like a placeholder cannot inject',
  tp('__test__.plural', 5, '{0}'), '5 things with {0}');

/* ── Summary ─────────────────────────────────────────────────────────── */
console.log(`\n${'='.repeat(60)}`);
console.log(`${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
