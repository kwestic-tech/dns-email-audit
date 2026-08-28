#!/usr/bin/env node
/**
 * The shared URI grammars. Spec §12, Task 4.0.
 *
 * Three protocol owners read these two functions, and the reason they can
 * share them is that the grammar is the same and only the CONSTRAINTS differ.
 * So the negative controls here are mostly about the constraints: proving that
 * `httpsOnly` and `requireFqdn` are off by default, because turning either on
 * everywhere is the defect the options exist to prevent — it rejected
 * conforming TLS-RPT and CAA records.
 *
 * The eleven helpers `isHttpUri()` and `isMailtoUri()` are built from are not
 * exported and are covered through them.
 */

import { createSuite } from '../../../tests/lib/assert.mjs';
import { isHttpUri, isMailtoUri } from './uri.js';

const { eq, section, report } = createSuite();

/* ── 1. The http/https production ─────────────────────────────────────── */
section('1. isHttpUri');

eq('a plain https URL is one', isHttpUri('https://example.test/report'), true);
eq('so is http', isHttpUri('http://example.test/'), true);
eq('scheme matching is case-insensitive', isHttpUri('HTTPS://example.test/'), true);
eq('a bare host is not a URI', isHttpUri('example.test'), false);
eq('nor is another scheme', isHttpUri('ftp://example.test/'), false);
eq('nor is a mailto', isHttpUri('mailto:a@example.test'), false);
eq('an empty value is not one', isHttpUri(''), false);
eq('neither is undefined', isHttpUri(undefined), false);

// RFC 3986 §2.1: '%' introduces two hex digits or the URI is malformed.
eq('a valid percent escape passes', isHttpUri('https://example.test/a%2Fb'), true);
eq('a truncated one does not', isHttpUri('https://example.test/a%2'), false);
eq('nor does a non-hex one', isHttpUri('https://example.test/a%zz'), false);

// The productions, not merely the absence of whitespace. `<`, `>`, `"` and
// `{` are not URI characters and were accepted before this was validated.
eq('a space is refused', isHttpUri('https://example.test/a b'), false);
eq('an angle bracket in the path is refused', isHttpUri('https://example.test/<a>'), false);
eq('a brace in the query is refused', isHttpUri('https://example.test/?a={b}'), false);
eq('a legal query and fragment pass', isHttpUri('https://example.test/p?a=b&c=d#frag'), true);
// No path at all: the authority production is greedy up to `/`, `?` or `#`,
// so this is the host `example.testpath` and a legal URI. It is NOT the
// slashless-path case its old label claimed — see the note on that guard in
// uri.js, which no input can reach.
eq('a host with no path is a URI', isHttpUri('https://example.testpath'), true);

/**
 * The IP-literal case, which is why the host rule is RFC 3986 §3.2.2 and not
 * "must be an FQDN". Requiring a dotted name here refused
 * `https://[2001:db8::1]/r`, a perfectly good TLS-RPT destination.
 */
eq('an IPv6 literal host is a legal URI', isHttpUri('https://[2001:db8::1]/r'), true);
eq('an IPv4 host is too', isHttpUri('https://192.0.2.1/r'), true);
eq('an unbracketed IPv6 host is not', isHttpUri('https://2001:db8::1/r'), false);
eq('a garbage IPv6 literal is not', isHttpUri('https://[2001:db8::zz]/r'), false);
eq('a port is allowed', isHttpUri('https://example.test:8443/r'), true);
eq('userinfo is allowed', isHttpUri('https://user@example.test/r'), true);

/* ── 2. The two constraints belong to the caller ──────────────────────── */
section('2. httpsOnly and requireFqdn are opt-in');

// The negative control for the whole shared-module decision: if either
// constraint were baked in, CAA and TLS-RPT would lose conforming records.
eq('http passes by default', isHttpUri('http://example.test/'), true);
eq('and is refused under httpsOnly', isHttpUri('http://example.test/', { httpsOnly: true }), false);
eq('https passes under httpsOnly', isHttpUri('https://example.test/', { httpsOnly: true }), true);

eq('a single-label host passes by default', isHttpUri('https://localhost/r'), true);
eq('and is refused under requireFqdn', isHttpUri('https://localhost/r', { requireFqdn: true }), false);
eq('a dotted host passes under requireFqdn',
  isHttpUri('https://example.test/r', { requireFqdn: true }), true);
eq('a trailing dot is still an FQDN',
  isHttpUri('https://example.test./r', { requireFqdn: true }), true);
eq('an IPv6 literal is not an FQDN',
  isHttpUri('https://[2001:db8::1]/r', { requireFqdn: true }), false);

// The DNS size limits are part of the FQDN rule, not decoration: a character
// check alone calls a 64-octet label an FQDN that no resolver can answer.
const long = 'a'.repeat(64);
eq('a 63-octet label is an FQDN',
  isHttpUri(`https://${'a'.repeat(63)}.test/`, { requireFqdn: true }), true);
eq('a 64-octet label is not',
  isHttpUri(`https://${long}.test/`, { requireFqdn: true }), false);
eq('and it still passes without the constraint', isHttpUri(`https://${long}.test/`), true);

/* ── 3. The mailto production ─────────────────────────────────────────── */
section('3. isMailtoUri');

eq('a plain mailto is one', isMailtoUri('mailto:reports@example.test'), true);
eq('a comma-separated list is one', isMailtoUri('mailto:a@example.test,b@example.test'), true);
eq('an http URL is not', isMailtoUri('https://example.test/'), false);
eq('a bare address is not', isMailtoUri('reports@example.test'), false);
eq('an empty value is not', isMailtoUri(''), false);
eq('a mailto with no address is not', isMailtoUri('mailto:'), false);
eq('an address with no domain is not', isMailtoUri('mailto:reports@'), false);
// The same option arrangement as isHttpUri: the constraint is the caller's.
// Neither current caller passes it, and it is contract either way.
eq('a single-label domain passes by default', isMailtoUri('mailto:reports@localhost'), true);
eq('and is refused under requireFqdn',
  isMailtoUri('mailto:reports@localhost', { requireFqdn: true }), false);
eq('a dotted domain passes under requireFqdn',
  isMailtoUri('mailto:reports@example.test', { requireFqdn: true }), true);
eq('a space is refused', isMailtoUri('mailto:a b@example.test'), false);
eq('headers are permitted', isMailtoUri('mailto:a@example.test?subject=dmarc'), true);
eq('a header with no value is not', isMailtoUri('mailto:a@example.test?subject'), false);
eq('a percent-encoded address decodes', isMailtoUri('mailto:a%40example.test'), true);
eq('a broken percent escape is refused', isMailtoUri('mailto:a%4'), false);
eq('an unterminated quoted local part is refused', isMailtoUri('mailto:"a@example.test'), false);

report();
