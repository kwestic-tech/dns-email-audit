#!/usr/bin/env node
/**
 * Base64 decoding. Spec §12, Task 4.0.
 *
 * Two owners decode base64 for the same reason — a public key arrives as text
 * — and both read a null return as "this does not decode" rather than
 * catching. So the assertions here are about what must be REFUSED: canonical
 * encoding, because several distinct strings otherwise decode to one DER
 * value, and the exact whitespace RFC 6376 §3.2 allows, because a bare LF in a
 * key record is a malformed record and must not vanish during decoding.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { base64ToBytes } from './base64.js';

const { eq, section, report } = createSuite();
const bytes = value => { const r = base64ToBytes(value); return r === null ? null : [...r]; };

/* ── 1. It decodes ────────────────────────────────────────────────────── */
section('1. Decoding');

eq('the empty string is zero bytes', bytes(''), []);
eq('one padded group', bytes('AA=='), [0]);
eq('two padded groups', bytes('AAE='), [0, 1]);
eq('an unpadded group', bytes('AAEC'), [0, 1, 2]);
eq('the full alphabet round-trips its high bytes', bytes('//8='), [255, 255]);
eq('a realistic prefix decodes', bytes('MIIBIjAN'), [0x30, 0x82, 0x01, 0x22, 0x30, 0x0d]);
eq('the result is a Uint8Array',
  base64ToBytes('AAEC') instanceof Uint8Array, true);

/* ── 2. What is not base64 ────────────────────────────────────────────── */
section('2. Null rather than a throw');

eq('a length that is not a multiple of four', bytes('AAA'), null);
eq('a character outside the alphabet', bytes('AA*A'), null);
eq('URL-safe base64 is a different alphabet', bytes('a-_A'), null);
eq('padding in the middle', bytes('AA==AAAA'), null);
eq('three padding characters', bytes('A==='), null);
eq('undefined is the empty string', bytes(undefined), []);
eq('null is the empty string', bytes(null), []);

/* ── 3. Canonical encoding: the unused pad bits must be zero ──────────── */
section('3. RFC 4648 canonical form');

// Without this, 'AB==' and 'AA==' both decode to [0] and two different key
// records compare equal.
eq('AA== is canonical', bytes('AA=='), [0]);
eq('AB== sets pad bits and is refused', bytes('AB=='), null);
eq('AAE= is canonical', bytes('AAE='), [0, 1]);
eq('AAF= sets pad bits and is refused', bytes('AAF='), null);

/* ── 4. Exactly the whitespace RFC 6376 §3.2 folds ────────────────────── */
section('4. Folding whitespace, and only that');

eq('a space between groups is folding', bytes('AAEC AwQ='), bytes('AAECAwQ='));
eq('a space inside a group is too', bytes('AAE CAwQ='), bytes('AAECAwQ='));
eq('a tab is dropped too', bytes('AAE\tCAwQ='), bytes('AAECAwQ='));
eq('CRLF followed by whitespace is a fold', bytes('AAEC\r\n AwQ='), bytes('AAECAwQ='));

// A bare LF is NOT folding whitespace. Silently removing it would report a
// malformed key record as a good key.
eq('a bare LF makes the record malformed', bytes('AAEC\nAwQ='), null);
eq('a bare CR does too', bytes('AAEC\rAwQ='), null);
eq('a CRLF not followed by whitespace does too', bytes('AAEC\r\nAwQ='), null);
eq('a vertical tab does too', bytes('AAEC\x0bAwQ='), null);
eq('a form feed does too', bytes('AAEC\x0cAwQ='), null);
eq('a NUL does too', bytes('AAEC\x00AwQ='), null);

report();
