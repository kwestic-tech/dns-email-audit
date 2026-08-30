#!/usr/bin/env node
/**
 * Provider detection. Task 4.9.
 *
 * Names, from records. The assertions worth holding are the ones where the
 * fallback ORDER decides the answer — `@none` versus `@implicit-mx` versus
 * `@null-mx` are three different statements about a domain's mail, and they
 * are reached by testing in a particular sequence.
 *
 * The null-MX determination is a FACT this module is given, not one it makes,
 * so this file also proves the edge: `detectEmailProvider()` answers from the
 * boolean it was handed and reaches for nothing. `core/mx/`'s real predicate
 * is imported HERE, in the test, to compute what audit computes — which is
 * exactly the edge `providers/` itself does not have.
 */

import { createSuite } from '../../tests/lib/assert.mjs';
import { isNullMx } from '../core/mx/mx.js';
import {
  detectDNSProvider, detectEmailProvider, detectHosting, selectVerifications,
} from './detectors.js';

const { eq, section, report } = createSuite();

/** What audit does: derive the fact once, with the owner's predicate. */
const forMx = (mx, domain, addresses) => detectEmailProvider(mx, domain, addresses, isNullMx(mx));

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
  forMx(['1 aspmx.l.google.com'], 'example.test', []), 'Google Workspace');

/**
 * Three different statements, reached in order. Collapsing any two of them
 * would tell an operator something they did not publish.
 */
eq('RFC 7505 `0 .` is an explicit refusal of mail',
  forMx(['0 .'], 'example.test', ['192.0.2.1']), '@null-mx');
eq('no MX but an address is implicit MX — RFC 5321 §5.1',
  forMx([], 'example.test', ['192.0.2.1']), '@implicit-mx');
eq('no MX and no address is no mail at all',
  forMx([], 'example.test', []), '@none');
eq('and the three are distinct', new Set([
  forMx(['0 .'], 'example.test', ['192.0.2.1']),
  forMx([], 'example.test', ['192.0.2.1']),
  forMx([], 'example.test', []),
]).size, 3);

// The null-MX test comes FIRST: a `0 .` domain with addresses must not be read
// as implicit MX.
eq('a null MX outranks the address records it also publishes',
  forMx(['0 .'], 'example.test', ['192.0.2.1', '2001:db8::1']), '@null-mx');
// RFC 7505 §3: a null MX is exclusive, so `0 .` beside a real exchange is not
// one — and `core/mx/`'s predicate is what says so, from outside this module.
eq('a null MX beside a real exchange is not a null MX',
  forMx(['0 .', '10 mail.example.test'], 'example.test', []) === '@null-mx', false);

/* ── 3. The determination is a fact, not a decision made here ─────────── */
section('3. The null-MX answer comes from the fact it is given');

// The negative control for the edge, and it is stronger than the injected
// predicate's was: the verdict follows the ARGUMENT rather than the records,
// which it could not do if this module were deciding for itself.
//
// `0 .` with the fact false falls through to the vendor patterns, matches
// none, and lands on `@custom-unknown` — an MX set that exists and is not
// recognized. The point is that it is NOT `@null-mx`.
eq('a false fact yields no null-MX verdict, whatever the records say',
  detectEmailProvider(['0 .'], 'example.test', ['192.0.2.1'], false), '@custom-unknown');
eq('while the fact audit really derives does',
  forMx(['0 .'], 'example.test', ['192.0.2.1']), '@null-mx');
eq('and a true fact yields it for any MX set',
  detectEmailProvider(['10 mail.example.test'], 'example.test', [], true), '@null-mx');
eq('while the derived fact disagrees with both',
  forMx(['10 mail.example.test'], 'example.test', []) === '@null-mx', false);
// A missing fourth argument is `undefined`, which is falsy — so an old
// three-argument call never invents a null MX. That is what makes the legacy
// wrapper in `js/dns.js` the only thing standing between the two shapes.
eq('and an omitted fact is simply not a null MX',
  detectEmailProvider(['0 .'], 'example.test', []) === '@null-mx', false);

/* ── 4. Hosting ───────────────────────────────────────────────────────── */
section('4. detectHosting');

eq('a known host is named', detectHosting(['185.199.108.153'], [], 'example.test'), 'GitHub Pages');
eq('no addresses and no CNAME is no web presence',
  detectHosting([], [], 'example.test'), '@no-web');
eq('an unrecognized address is custom', detectHosting(['192.0.2.1'], [], 'example.test'), '@custom');
// A CNAME pointing inside the audited domain is not a third-party host.
eq('a same-domain CNAME is not automatically a loop',
  detectHosting([], ['host.example.test'], 'example.test'), '@custom');


/* ── 5. Verification records ──────────────────────────────────────────── */
section('5. selectVerifications');

// Names, from records — which is why this is here rather than in src/audit/.
// A verification record is a vendor saying the domain proved control to them;
// it is not a finding and nothing scores it.
eq('a Google verification record is selected',
  selectVerifications(['google-site-verification=abc']), ['google-site-verification=abc']);
eq('an Apple one is too', selectVerifications(['apple-domain=xyz']), ['apple-domain=xyz']);
eq('both are kept, in the order published',
  selectVerifications(['apple-domain=a', 'v=spf1 -all', 'google-site-verification=b']),
  ['apple-domain=a', 'google-site-verification=b']);
// Selection is case-insensitive, like every other record selector here.
eq('and case does not hide one', selectVerifications(['GOOGLE-SITE-VERIFICATION=abc']).length, 1);
eq('an unrelated TXT record is not a verification', selectVerifications(['v=spf1 -all']), []);
eq('a null TXT set is empty rather than a throw', selectVerifications(null), []);

report();
