#!/usr/bin/env node
/**
 * Provider detection. Task 4.9.
 *
 * Names, from records. The assertions worth holding are the ones where the
 * fallback ORDER decides the answer — `@none` versus `@implicit-mx` versus
 * `@null-mx` are three different statements about a domain's mail, and they
 * are reached by testing in a particular sequence.
 *
 * `isNullMx` is injected, so this file also proves the edge: the detectors
 * work against a supplied determination and reach for nothing.
 */

import { createSuite } from '../../tests/lib/assert.mjs';
import { isNullMx } from '../core/mx/mx.js';
import { createDetectors } from './detectors.js';

const { eq, section, report } = createSuite();
const { detectDNSProvider, detectEmailProvider, detectHosting } =
  createDetectors({ isNullMx });

/* ── 1. DNS provider ──────────────────────────────────────────────────── */
section('1. detectDNSProvider');

eq('a known operator is named',
  detectDNSProvider(['ns1.cloudflare.com', 'ns2.cloudflare.com'], 'example.test'), 'Cloudflare');
eq('an empty NS set is unknown', detectDNSProvider([], 'example.test'), '@unknown');
// A three-label vendor name is capitalized out of the penultimate label.
eq('an unrecognized operator is named from its own domain',
  detectDNSProvider(['ns1.cloudns.net'], 'example.test'), 'Cloudns');
// The ccSLD rule: `.co.uk` is not the vendor name.
eq('a ccSLD steps past the second-level label',
  detectDNSProvider(['ns1.vendor.co.uk'], 'example.test'), 'Vendor');
eq('a two-label NS has no vendor label to take',
  detectDNSProvider(['ns1.test'], 'example.test'), '@custom');
eq('a trailing dot is not a label', detectDNSProvider(['ns1.cloudns.net.'], 'example.test'), 'Cloudns');

/* ── 2. Email provider, and the three ways to have no mail ───────────── */
section('2. detectEmailProvider');

eq('a known provider is named',
  detectEmailProvider(['1 aspmx.l.google.com'], 'example.test', []), 'Google Workspace');

/**
 * Three different statements, reached in order. Collapsing any two of them
 * would tell an operator something they did not publish.
 */
eq('RFC 7505 `0 .` is an explicit refusal of mail',
  detectEmailProvider(['0 .'], 'example.test', ['192.0.2.1']), '@null-mx');
eq('no MX but an address is implicit MX — RFC 5321 §5.1',
  detectEmailProvider([], 'example.test', ['192.0.2.1']), '@implicit-mx');
eq('no MX and no address is no mail at all',
  detectEmailProvider([], 'example.test', []), '@none');
eq('and the three are distinct', new Set([
  detectEmailProvider(['0 .'], 'example.test', ['192.0.2.1']),
  detectEmailProvider([], 'example.test', ['192.0.2.1']),
  detectEmailProvider([], 'example.test', []),
]).size, 3);

// The null-MX test comes FIRST: a `0 .` domain with addresses must not be read
// as implicit MX.
eq('a null MX outranks the address records it also publishes',
  detectEmailProvider(['0 .'], 'example.test', ['192.0.2.1', '2001:db8::1']), '@null-mx');
// RFC 7505 §3: a null MX is exclusive, so `0 .` beside a real exchange is not
// one — and the injected predicate is what says so.
eq('a null MX beside a real exchange is not a null MX',
  detectEmailProvider(['0 .', '10 mail.example.test'], 'example.test', []) === '@null-mx', false);

/* ── 3. The injected determination is really injected ─────────────────── */
section('3. isNullMx is a capability, not an import');

// The negative control for the edge: a detector built over a predicate that
// never fires cannot produce `@null-mx`, which it could not fail to produce if
// it were reaching for the real one.
const neverNull = createDetectors({ isNullMx: () => false });
// `0 .` then falls through to the vendor patterns, matches none, and lands on
// `@custom-unknown` — an MX set that exists and is not recognized. The point
// is that it is NOT `@null-mx`.
eq('a predicate that never fires yields no null-MX verdict',
  neverNull.detectEmailProvider(['0 .'], 'example.test', ['192.0.2.1']), '@custom-unknown');
eq('while the real predicate does', 
  detectEmailProvider(['0 .'], 'example.test', ['192.0.2.1']), '@null-mx');
const alwaysNull = createDetectors({ isNullMx: () => true });
eq('and one that always fires yields it for any MX set',
  alwaysNull.detectEmailProvider(['10 mail.example.test'], 'example.test', []), '@null-mx');
eq('while the real predicate disagrees with both',
  detectEmailProvider(['10 mail.example.test'], 'example.test', []) === '@null-mx', false);

/* ── 4. Hosting ───────────────────────────────────────────────────────── */
section('4. detectHosting');

eq('a known host is named', detectHosting(['185.199.108.153'], [], 'example.test'), 'GitHub Pages');
eq('no addresses and no CNAME is no web presence',
  detectHosting([], [], 'example.test'), '@no-web');
eq('an unrecognized address is custom', detectHosting(['192.0.2.1'], [], 'example.test'), '@custom');
// A CNAME pointing inside the audited domain is not a third-party host.
eq('a same-domain CNAME is not automatically a loop',
  detectHosting([], ['host.example.test'], 'example.test'), '@custom');

report();
