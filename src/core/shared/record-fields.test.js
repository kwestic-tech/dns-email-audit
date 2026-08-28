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
import { parseOrderedFields } from './record-fields.js';

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

/* ── 4. Total over non-strings ────────────────────────────────────────── */
section('4. It returns rather than throws');

eq('undefined is an empty record', parseOrderedFields(undefined), null);
eq('null is an empty record', parseOrderedFields(null), null);
eq('a number is read as its text', parseOrderedFields(0), null);

report();
