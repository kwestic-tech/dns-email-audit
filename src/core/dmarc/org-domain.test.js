#!/usr/bin/env node
/**
 * The organizational domain, from the Public Suffix List. Task 4.6.
 *
 * Every assertion here runs against a FIXTURE list of four rules, never the
 * shipped 10,239. That is the point of the factory: a module that reached for
 * the real table could not be handed a fixture one, and the fixture-identity
 * probes in `legacy-shapes.test.mjs` work by watching the answer change.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { createOrgDomain } from './org-domain.js';

const { eq, section, report } = createSuite();

const orgDomain = createOrgDomain({
  publicSuffixRules: ['com', 'co.uk', '*.ck', '!www.ck', 'test'],
});

/* ── 1. The three rule kinds ──────────────────────────────────────────── */
section('1. Exact, wildcard and exception rules');

eq('an exact rule takes one label below it', orgDomain('a.b.example.com'), 'example.com');
eq('a multi-label exact rule too', orgDomain('x.y.example.co.uk'), 'example.co.uk');
// A wildcard rule makes every child of `ck` a suffix, so the org domain is one
// label further down than the exact reading would give.
eq('a wildcard rule consumes an extra label', orgDomain('a.b.ck'), 'a.b.ck');
// An exception rule cancels the wildcard for exactly that name.
eq('an exception rule cancels the wildcard', orgDomain('www.ck'), 'www.ck');
eq('and below the exception it behaves normally', orgDomain('a.www.ck'), 'www.ck');

/* ── 2. The prevailing rule, and the shapes below it ──────────────────── */
section('2. No match, and short names');

// The PSL's implicit `*` rule: an unlisted suffix is one label.
eq('an unlisted TLD falls back to one label', orgDomain('a.b.example.invalid'), 'example.invalid');
eq('a two-label name is already organizational', orgDomain('example.com'), 'example.com');
eq('a bare suffix has nothing below it', orgDomain('com'), 'com');
eq('a single label is itself', orgDomain('localhost'), 'localhost');
eq('an empty name is empty', orgDomain(''), '');
eq('undefined is empty', orgDomain(undefined), '');

/* ── 3. Normalization ─────────────────────────────────────────────────── */
section('3. Case and trailing dots');

eq('the answer is lowercased', orgDomain('A.B.EXAMPLE.COM'), 'example.com');
eq('a trailing dot is not a label', orgDomain('a.example.com.'), 'example.com');
eq('empty labels are dropped', orgDomain('a..example.com'), 'example.com');

/* ── 4. The list is per factory, which is the fixture invariant ───────── */
section('4. Two lists share nothing');

const strict = createOrgDomain({ publicSuffixRules: ['com'] });
const wider = createOrgDomain({ publicSuffixRules: ['com', 'example.com'] });
eq('the same name reads differently under two lists',
  [strict('a.b.example.com'), wider('a.b.example.com')],
  ['example.com', 'b.example.com']);
// The half that makes the fixture probes meaningful: nothing is shared, so a
// fixture list cannot be silently replaced by production data.
eq('and neither factory can see the other\'s rules',
  strict('a.b.example.com'), 'example.com');
eq('an empty list falls back to the prevailing rule everywhere',
  createOrgDomain({ publicSuffixRules: [] })('a.b.example.com'), 'example.com');
eq('and so does a missing one',
  createOrgDomain({})('a.b.example.com'), 'example.com');

report();
