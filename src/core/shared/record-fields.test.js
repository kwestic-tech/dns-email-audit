#!/usr/bin/env node
/**
 * Ordered record-field parsing. Spec §12, Task 4.0.
 *
 * Two properties carry the whole reason this is not a tag map: ORDER is
 * preserved, and a field without `=` fails the whole record rather than being
 * dropped. Both are what caught `id=abc; v=STSv1` and a bare `garbage` field,
 * and both are asserted with the negative case beside them.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { parseOrderedFields, EXT_NAME } from './record-fields.js';

const { eq, section, report } = createSuite();

/* ── 1. Order is the point ────────────────────────────────────────────── */
section('1. Fields come back in record order');

eq('a two-field record parses in order',
  parseOrderedFields('v=STSv1; id=20200101'),
  [{ name: 'v', value: 'STSv1' }, { name: 'id', value: '20200101' }]);
// The negative case: the same fields the other way round must NOT look the
// same. An unordered map cannot express the difference, which is how a record
// with its version field second validated.
eq('the reversed record is a different parse',
  parseOrderedFields('id=20200101; v=STSv1'),
  [{ name: 'id', value: '20200101' }, { name: 'v', value: 'STSv1' }]);

/* ── 2. A field that is not name=value fails the record ───────────────── */
section('2. Null, not a dropped field');

eq('a bare token is not an extension', parseOrderedFields('v=STSv1; garbage'), null);
eq('a leading bare token fails too', parseOrderedFields('garbage; v=STSv1'), null);
eq('an empty name is still a field', parseOrderedFields('=x'), [{ name: '', value: 'x' }]);
eq('an empty value is still a field', parseOrderedFields('id='), [{ name: 'id', value: '' }]);
eq('an empty record is one empty field, which no validator accepts',
  parseOrderedFields(''), null);
eq('only the first = splits a field',
  parseOrderedFields('ext=a=b'), [{ name: 'ext', value: 'a=b' }]);

/* ── 3. The delimiter, and the strict-syntax option ───────────────────── */
section('3. field-delim and strictFieldSyntax');

// `field-delim = *WSP ";" *WSP`, so surrounding whitespace belongs to the
// delimiter and is removed in both modes.
eq('whitespace around the delimiter is the delimiter',
  parseOrderedFields('v=STSv1 ;  id=1', { strictFieldSyntax: true }),
  [{ name: 'v', value: 'STSv1' }, { name: 'id', value: '1' }]);
eq('a single trailing delimiter is permitted by both ABNFs',
  parseOrderedFields('v=STSv1;'), [{ name: 'v', value: 'STSv1' }]);
eq('two trailing delimiters are not', parseOrderedFields('v=STSv1;;'), null);

// MTA-STS and TLS-RPT write their fields as single literals, so `v = STSv1`
// is not one of them. BIMI's grammar is looser, hence an option.
eq('strict mode keeps the space inside the value',
  parseOrderedFields('v = STSv1', { strictFieldSyntax: true }),
  [{ name: 'v ', value: ' STSv1' }]);
eq('and loose mode trims it away',
  parseOrderedFields('v = STSv1'), [{ name: 'v', value: 'STSv1' }]);

/* ── 4. The extension-name production ─────────────────────────────────── */
section('4. EXT_NAME');

// `sts-ext-name = (ALPHA / DIGIT) *31(ALPHA / DIGIT / "_" / "-" / ".")`, read
// by MTA-STS, TLS-RPT and BIMI. Shared because it is ONE production; the
// extension VALUE class differs per protocol and stays with each owner.
eq('a simple name', EXT_NAME.test('ext'), true);
eq('digits, underscore, hyphen and dot are all legal', EXT_NAME.test('a9_b-c.d'), true);
eq('a single character is enough', EXT_NAME.test('a'), true);
eq('32 characters is the limit', EXT_NAME.test('a'.repeat(32)), true);
eq('33 is not', EXT_NAME.test('a'.repeat(33)), false);
eq('it must START with ALPHA or DIGIT', EXT_NAME.test('_ext'), false);
eq('a hyphen may not lead either', EXT_NAME.test('-ext'), false);
eq('an empty name is not one', EXT_NAME.test(''), false);
eq('and neither is one with a space', EXT_NAME.test('a b'), false);

// No `g` flag, so `.test()` retains nothing between calls — which is what lets
// a directory forbidden to hold state export a regex at all.
eq('the pattern carries no g flag', EXT_NAME.global, false);
eq('so repeated tests agree', [EXT_NAME.test('ext'), EXT_NAME.test('ext')], [true, true]);

/* ── 5. Total over non-strings ────────────────────────────────────────── */
section('5. It returns rather than throws');

eq('undefined is an empty record', parseOrderedFields(undefined), null);
eq('null is an empty record', parseOrderedFields(null), null);
eq('a number is read as its text', parseOrderedFields(0), null);

report();
