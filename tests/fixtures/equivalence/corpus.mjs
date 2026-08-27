/**
 * The equivalence corpus. Task 0.4.a.
 *
 * Deterministic by construction: every answer comes from
 * `tools/lib/doh-fixture.mjs`, never from the network. `tools/backtest.mjs`
 * queries Cloudflare and is a local grade-DISTRIBUTION check only — it is
 * never a gate and it is never the oracle here.
 *
 * A case may audit SEVERAL domains through ONE page. That is how the DoH
 * cache's page lifetime becomes observable: `tools/scoring.test.mjs:1888-1891`
 * asserts a first DMARC walk issues 3 queries and a sibling issues 1, and
 * `PRIVACY.md:30-33` publishes the resulting fan-out. A corpus that built a
 * fresh page per domain would report a clean trace while the cache was being
 * narrowed underneath it.
 *
 * Coverage is recorded in `tests/state-matrix.json`, not here. One source of
 * truth: the matrix names the case, and `tests/contract/state-matrix.test.mjs`
 * rejects a matrix row naming a case this file does not export.
 */

import {
  dohFixture, txt, ns, mx, a, aaaa, cname, caa, tlsa, ds, dnskey, rrsig,
} from '../../../tools/lib/doh-fixture.mjs';

/* ── Shared record shapes ─────────────────────────────────────────────── */

// A DS/DNSKEY pair that does NOT match: the digest is arbitrary, so the local
// matcher reports no-matching-key or digest-mismatch rather than confirming.
const ORPHAN_DS = ds('12345 8 2 ' + 'ab'.repeat(32));
const SOME_DNSKEY = dnskey('257 3 8 AwEAAcJ8Fd6n4u9pQqZ8kX2mB1vN3wY5tR7cL0aS6dF9gH2jK4mP8nQ1rT3v');

/**
 * Every case answers `example.com A`, because `startAudit()` pre-flights with
 * `checkConnectivity()` before it audits anything and refuses the run when the
 * resolver is unreachable. That query is part of the application's real
 * fan-out and it stays in the trace.
 */
const corpusFixture = map => dohFixture(Object.assign({ 'example.com A': a('93.184.216.34') }, map));

const cases = [];

/* ── 1. A well-configured, signed, enforcing domain ───────────────────── */

cases.push({
  id: 'enforcing-signed',
  description: 'DMARC p=reject, SPF -all, DKIM present, CAA, MTA-STS, TLS-RPT, BIMI, DNSSEC secure',
  domains: [{ domain: 'alpha.test' }],
  spfNames: ['_spf.alpha.test'],
  fetch: () => corpusFixture({
    'alpha.test NS': { ad: true, answers: ns('ns1.alpha.test', 'ns2.alpha.test') },
    'alpha.test MX': mx('10 mail.alpha.test'),
    'alpha.test TXT': txt('v=spf1 include:_spf.alpha.test -all', 'google-site-verification=abc'),
    'alpha.test A': a('192.0.2.10'),
    'alpha.test AAAA': aaaa('2001:db8::10'),
    'alpha.test CAA': caa('0 issue "letsencrypt.org"', '0 iodef "mailto:security@alpha.test"'),
    'alpha.test DS': { ad: true, answers: [] },
    'alpha.test DNSKEY': { ad: true, answers: [] },
    '_spf.alpha.test TXT': txt('v=spf1 ip4:192.0.2.0/24 -all'),
    '_dmarc.alpha.test TXT': txt('v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:dmarc@alpha.test'),
    'default._bimi.alpha.test TXT': txt('v=BIMI1; l=https://alpha.test/logo.svg'),
    '_mta-sts.alpha.test TXT': txt('v=STSv1; id=20260101000000Z'),
    '_smtp._tls.alpha.test TXT': txt('v=TLSRPTv1; rua=mailto:tlsrpt@alpha.test'),
    'selector1._domainkey.alpha.test TXT': txt('v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy8Hn4Xk1cVw2rQ7pT9mN3bY6dK8fJ2gL5hR0sW4vZ1xC6nM9qA3tE7uI0oP2yB5jD8kF1lG4hN7mS0wX3zV6cR9bT2eU5iO8pA1yQ4rL7nK0dH3gJ6fM9sB2vC5xZ8jW1tY4uI7oE0pR3qS6bN9mF2lD5hG8kA1cX4vT7zJ0yB3wQ6rM9nL2sP5dK8fH1gT4uE7iO0aY3xC6jV9bW2mR5tZ8pN1qL4hS7kD0gF3lJ6nB9wI2yA5cM8vX1oT4rE7uQ0pK3zH6dG9jS2bY5fN8mL1tW4xV7iC0aR3qP6nZ9kJ2gD5hB8lF1yO4uT7wM0sX3vE6cQwIDAQAB'),
    'mail.alpha.test A': a('192.0.2.20'),
    'mail.alpha.test AAAA': aaaa('2001:db8::20'),
    '_25._tcp.mail.alpha.test TLSA': { ad: true, answers: tlsa('3 1 1 ( ' + 'CD'.repeat(32) + ' )') },
    'www.alpha.test A': a('192.0.2.10'),
  }),
});

/* ── 2. Nothing published ─────────────────────────────────────────────── */

cases.push({
  id: 'bare-registered',
  description: 'a registered domain with MX and nothing else — every control absent',
  domains: [{ domain: 'bravo.test' }],
  fetch: () => corpusFixture({
    'bravo.test NS': ns('ns1.bravo.test'),
    'bravo.test MX': mx('10 mail.bravo.test'),
    'mail.bravo.test A': a('198.51.100.5'),
  }),
});

/* ── 3. Unregistered ──────────────────────────────────────────────────── */

cases.push({
  id: 'unregistered',
  description: 'NXDOMAIN on the NS probe — the three-property early-return shape',
  domains: [{ domain: 'charlie.test' }],
  fetch: () => corpusFixture({}),
});

/* ── 4. Cache reuse across a sibling subdomain ────────────────────────── */

/**
 * The case the DoH cache exists for, and the one a narrowing refactor breaks.
 *
 * Two domains, one page. The second audit's DMARC tree walk climbs through
 * `_dmarc.delta.test` — already answered for the first — so the trace records
 * the reuse as a query that did NOT happen. `tools/scoring.test.mjs:1891`
 * asserts the same property; this is its equivalence-surface counterpart.
 */
cases.push({
  id: 'cache-reuse-siblings',
  description: 'two sibling names audited through one page; the second reuses the first walk',
  domains: [
    { domain: 'delta.test' },
    { domain: 'sub.delta.test' },
  ],
  fetch: () => corpusFixture({
    'delta.test NS': ns('ns1.delta.test'),
    'delta.test MX': mx('10 mail.delta.test'),
    'delta.test TXT': txt('v=spf1 -all'),
    '_dmarc.delta.test TXT': txt('v=DMARC1; p=quarantine; rua=mailto:d@delta.test'),
    'sub.delta.test NS': ns('ns1.delta.test'),
    'sub.delta.test MX': mx('10 mail.delta.test'),
    'sub.delta.test TXT': txt('v=spf1 -all'),
    'mail.delta.test A': a('203.0.113.5'),
  }),
});

/* ── 5. A parked domain ───────────────────────────────────────────────── */

cases.push({
  id: 'parked-null-mx',
  description: 'RFC 7505 null MX — the PARKED_WEIGHTS rubric',
  domains: [{ domain: 'echo.test' }],
  fetch: () => corpusFixture({
    'echo.test NS': ns('ns1.echo.test'),
    'echo.test MX': mx('0 .'),
    'echo.test TXT': txt('v=spf1 -all'),
    '_dmarc.echo.test TXT': txt('v=DMARC1; p=reject'),
    'echo.test CAA': caa('0 issue ";"'),
  }),
});

/* ── 6. A bogus DNSSEC chain ──────────────────────────────────────────── */

/**
 * SERVFAIL that resolves with checking disabled: the resolver saying validation
 * failed. This is the only path that sets `checkingDisabled` on the audit's
 * query options, so it is the only case where the trace carries `cd=1`.
 */
cases.push({
  id: 'dnssec-bogus',
  description: 'SERVFAIL that succeeds with cd=1 — the resolver-bogus claim and the cd=1 re-query',
  domains: [{ domain: 'foxtrot.test' }],
  fetch: () => corpusFixture({
    'foxtrot.test NS': 'servfail',
    'foxtrot.test NS cd': ns('ns1.foxtrot.test'),
    'foxtrot.test MX cd': mx('10 mail.foxtrot.test'),
    'foxtrot.test TXT cd': txt('v=spf1 -all'),
    '_dmarc.foxtrot.test TXT cd': txt('v=DMARC1; p=none'),
    'mail.foxtrot.test A cd': a('203.0.113.9'),
  }),
});

/* ── 7. An orphan DS ──────────────────────────────────────────────────── */

cases.push({
  id: 'dnssec-orphan-ds',
  description: 'a DS whose key tag matches no published DNSKEY — the computed ds-no-matching-key claim',
  domains: [{ domain: 'golf.test' }],
  fetch: () => corpusFixture({
    'golf.test NS': ns('ns1.golf.test'),
    'golf.test MX': mx('10 mail.golf.test'),
    'golf.test TXT': txt('v=spf1 -all'),
    'golf.test DS': ORPHAN_DS,
    'golf.test DNSKEY': SOME_DNSKEY,
    '_dmarc.golf.test TXT': txt('v=DMARC1; p=none'),
    'mail.golf.test A': a('203.0.113.11'),
  }),
});

/* ── 8. Hygiene sentinels ─────────────────────────────────────────────── */

/**
 * A record carrying a bidirectional override and a zero-width space. The
 * renderer's `‹RLO›` and `‹ZWSP›` sentinels are exact text, which is why
 * `canonicalization.md` §5 forbids normalizing whitespace text nodes away.
 */
cases.push({
  id: 'hygiene-sentinels',
  description: 'a bidi override and a zero-width space in published records',
  domains: [{ domain: 'hotel.test' }],
  fetch: () => corpusFixture({
    'hotel.test NS': ns('ns1.hotel.test'),
    'hotel.test MX': mx('10 mail​.hotel.test'),
    'hotel.test TXT': txt('v=spf1 include:‮safe.example -all'),
    '_dmarc.hotel.test TXT': txt('v=DMARC1; p=none; rua=mailto:re‮ports@hotel.test'),
    'mail​.hotel.test A': a('203.0.113.13'),
  }),
});

export { cases };
export default cases;
