#!/usr/bin/env node
/**
 * BIMI record validation. Spec Design §4, Task 4.3.
 *
 * Three things the pre-0.5.0 validator could not express, and all three are
 * asserted here with the reading they replaced named beside them:
 *
 *  - `l=` present and EMPTY is a conformant declination, not a missing tag;
 *  - `v=BIMI1` is case-sensitive and must come FIRST;
 *  - a logo URL needs a real host and an SVG suffix — `https://` is a scheme
 *    and two slashes, and a `.png` is not an indicator.
 *
 * No resolver appears anywhere in this file, because the module takes none.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { validateBimiRecord, BIMI_ERRORS } from './bimi.js';

const { eq, section, report } = createSuite();
const LOGO = 'https://example.test/logo.svg';

/* ── 1. The published error vocabulary ────────────────────────────────── */
section('1. State constants');

eq('two error tokens', [...BIMI_ERRORS], ['invalid-syntax', 'duplicate-tags']);
eq('and the list is frozen', Object.isFrozen(BIMI_ERRORS), true);
eq('a malformed record emits invalid-syntax',
  validateBimiRecord('v=BIMI1; l=nonsense').errors, ['invalid-syntax']);
eq('a repeated field emits duplicate-tags',
  validateBimiRecord(`v=BIMI1; l=${LOGO}; l=${LOGO}`).errors, ['duplicate-tags']);
// duplicate-tags is the more specific complaint and suppresses the other.
eq('a record that is both duplicated and malformed reports the duplication',
  validateBimiRecord('v=BIMI1; l=bad; l=bad').errors, ['duplicate-tags']);
eq('a valid record emits nothing', validateBimiRecord(`v=BIMI1; l=${LOGO}`).errors, []);

/* ── 2. l= present and empty is a declination ─────────────────────────── */
section('2. The empty indicator');

const declined = validateBimiRecord('v=BIMI1; l=');
eq('an empty l= is a VALID record', declined.valid, true);
eq('and it is a declination', declined.declined, true);
eq('with no logo', declined.logo, '');
eq('and no errors', declined.errors, []);

// The reading it replaced: `parsed.tags.l || ''` collapsed present-and-empty
// into absent, and reported a conformant record invalid.
const absent = validateBimiRecord('v=BIMI1');
eq('an ABSENT l= is not a declination', absent.declined, false);
eq('it is invalid — l= is required, and may be empty but not missing',
  absent.valid, false);
eq('so the two are distinguishable', declined.valid === absent.valid, false);

const publishing = validateBimiRecord(`v=BIMI1; l=${LOGO}`);
eq('a record with a logo is valid', publishing.valid, true);
eq('and is not a declination', publishing.declined, false);
eq('and reports the logo', publishing.logo, LOGO);

/* ── 3. The version field is exact, and first ─────────────────────────── */
section('3. v=BIMI1');

eq('lowercase v=bimi1 is not the version', validateBimiRecord('v=bimi1; l=').valid, false);
eq('nor is v=BIMI2', validateBimiRecord('v=BIMI2; l=').valid, false);
eq('the version must come first',
  validateBimiRecord(`l=${LOGO}; v=BIMI1`).valid, false);
eq('a repeated v= is invalid even in first position',
  validateBimiRecord('v=BIMI1; v=BIMI1; l=').errors, ['duplicate-tags']);
eq('a record with no fields at all is invalid', validateBimiRecord('').valid, false);
eq('and says so as invalid-syntax', validateBimiRecord('').errors, ['invalid-syntax']);
eq('undefined is not a record', validateBimiRecord(undefined).valid, false);
eq('a bare token is not a field list', validateBimiRecord('garbage').valid, false);

/* ── 4. The logo URL, where BIMI adds both constraints ────────────────── */
section('4. l= is an https FQDN URL with an SVG suffix');

eq('an https .svg logo is accepted', validateBimiRecord(`v=BIMI1; l=${LOGO}`).valid, true);
eq('a gzipped .svgz is too',
  validateBimiRecord('v=BIMI1; l=https://example.test/logo.svgz').valid, true);
eq('a query string after the suffix is allowed',
  validateBimiRecord('v=BIMI1; l=https://example.test/logo.svg?v=2').valid, true);
eq('and a fragment is too',
  validateBimiRecord('v=BIMI1; l=https://example.test/logo.svg#a').valid, true);

// BIMI is the protocol that ADDS httpsOnly and requireFqdn. core/shared/uri.js
// defaults both off, and these are the assertions that prove BIMI turns them on.
eq('http is refused — BIMI requires https',
  validateBimiRecord('v=BIMI1; l=http://example.test/logo.svg').valid, false);
eq('a single-label host is refused — BIMI requires an FQDN',
  validateBimiRecord('v=BIMI1; l=https://localhost/logo.svg').valid, false);
eq('a .png is not an indicator',
  validateBimiRecord('v=BIMI1; l=https://example.test/logo.png').valid, false);
eq('a scheme and two slashes is not a URL',
  validateBimiRecord('v=BIMI1; l=https://').valid, false);
eq('nor is a bare path', validateBimiRecord('v=BIMI1; l=/logo.svg').valid, false);
eq('a space in the URL is refused',
  validateBimiRecord('v=BIMI1; l=https://example.test/my logo.svg').valid, false);

/* ── 5. a= is a URL with no suffix rule ───────────────────────────────── */
section('5. The Verified Mark Certificate');

eq('an https authority is accepted',
  validateBimiRecord(`v=BIMI1; l=${LOGO}; a=https://example.test/vmc.pem`).valid, true);
eq('and it is reported',
  validateBimiRecord(`v=BIMI1; l=${LOGO}; a=https://example.test/vmc.pem`).authority,
  'https://example.test/vmc.pem');
eq('a= carries no SVG rule — the suffix belongs to l=',
  validateBimiRecord(`v=BIMI1; l=${LOGO}; a=https://example.test/vmc.txt`).valid, true);
eq('but it still requires https',
  validateBimiRecord(`v=BIMI1; l=${LOGO}; a=http://example.test/vmc.pem`).valid, false);
eq('an empty a= is permitted', validateBimiRecord(`v=BIMI1; l=${LOGO}; a=`).valid, true);
eq('and reports no authority', validateBimiRecord(`v=BIMI1; l=${LOGO}; a=`).authority, '');

/* ── 6. Extensions, and the value class BIMI does NOT inherit ─────────── */
section('6. Extension fields');

eq('a well-formed extension is accepted',
  validateBimiRecord(`v=BIMI1; l=${LOGO}; ext=value`).valid, true);
eq('an extension name that is not (ALPHA/DIGIT)*31 is not one',
  validateBimiRecord(`v=BIMI1; l=${LOGO}; _ext=value`).valid, false);
eq('nor is a 33-character name',
  validateBimiRecord(`v=BIMI1; l=${LOGO}; ${'a'.repeat(33)}=value`).valid, false);
eq('a 32-character name is the limit and is accepted',
  validateBimiRecord(`v=BIMI1; l=${LOGO}; ${'a'.repeat(32)}=value`).valid, true);
eq('an extension with an empty value is not one',
  validateBimiRecord(`v=BIMI1; l=${LOGO}; ext=`).valid, false);
eq('a space in an extension value is refused',
  validateBimiRecord(`v=BIMI1; l=${LOGO}; ext=a b`).valid, false);

/**
 * BIMI's pinned grammar does NOT carry MTA-STS's exclusion of `=` from the
 * extension value class. That is the whole reason `RECORD_EXT_VALUE` stayed
 * with `core/transport/` while `EXT_NAME` moved to `core/shared/`, so it is
 * asserted rather than left as a comment.
 */
eq('an = inside an extension value is legal here, unlike MTA-STS',
  validateBimiRecord(`v=BIMI1; l=${LOGO}; ext=a=b`).valid, true);

/* ── 7. Every emitted token is in the published algebra ───────────────── */
section('7. The constant is not decoration');

const records = ['', 'garbage', 'v=BIMI1', 'v=bimi1; l=', `v=BIMI1; l=${LOGO}`,
  'v=BIMI1; l=', `v=BIMI1; l=${LOGO}; l=${LOGO}`, 'v=BIMI1; l=nonsense',
  `v=BIMI1; l=${LOGO}; _ext=v`];
const emitted = [...new Set(records.flatMap(r => validateBimiRecord(r).errors))];
eq('no record emits a token the constant does not name',
  emitted.filter(t => !BIMI_ERRORS.includes(t)), []);
eq('and both tokens are reachable', emitted.sort(), ['duplicate-tags', 'invalid-syntax']);

report();
