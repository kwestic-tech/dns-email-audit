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
import { RSA_2048_SPKI, RSA_2048_PKCS1, RSA_1024_SPKI, RSA_512_SPKI, ED25519_RAW } from './keys.mjs';

/* ── Shared record shapes ─────────────────────────────────────────────── */

// A DS/DNSKEY pair that does NOT match: the digest is arbitrary, so the local
// matcher reports no-matching-key or digest-mismatch rather than confirming.
const ORPHAN_DS = ds('12345 8 2 ' + 'ab'.repeat(32));
/** A conformant 2048-bit RSA SPKI public key, shared by the DKIM fixtures. */


const SOME_DNSKEY = dnskey('257 3 8 AwEAAcJ8Fd6n4u9pQqZ8kX2mB1vN3wY5tR7cL0aS6dF9gH2jK4mP8nQ1rT3v');

/**
 * Every case answers `example.com A`, because `startAudit()` pre-flights with
 * `checkConnectivity()` before it audits anything and refuses the run when the
 * resolver is unreachable. That query is part of the application's real
 * fan-out and it stays in the trace.
 */
const corpusFixture = (map, transport = {}) => {
  const inner = dohFixture(Object.assign({ 'example.com A': a('93.184.216.34') }, map));
  if (!Object.keys(transport).length) return inner;
  // Two transport kinds the fixture map cannot express, because neither is a
  // DNS response: `network-error` is a fetch that throws, and `timeout` is a
  // fetch that never settles until the request's own timer aborts it. Both are
  // in the closed ten-kind set and both are reachable in production, so the
  // corpus has to be able to produce them rather than leaving them to a suite.
  const impl = (url, init) => {
    const params = new URL(String(url), 'https://cloudflare-dns.com').searchParams;
    const name = String(params.get('name') || '').toLowerCase().replace(/\.$/, '');
    const behaviour = transport[name];
    if (behaviour === 'network-error') return Promise.reject(new Error('socket closed'));
    if (behaviour === 'timeout') {
      return new Promise((resolve, reject) => {
        init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      });
    }
    return inner(url, init);
  };
  impl.calls = inner.calls;
  return impl;
};

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
    'selector1._domainkey.alpha.test TXT': txt('v=DKIM1; k=rsa; p=' + RSA_2048_SPKI),
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

/* ── 9. SPF status and warning variants ───────────────────────────────── */

/**
 * Eight domains, one page. Each reaches a different `analyzeSpf()` verdict, and
 * the three provider-mismatch warnings need the provider detection to agree, so
 * each carries the MX its warning is about.
 */
cases.push({
  id: 'spf-variants',
  description: 'every analyzeSpf status and every warning token',
  domains: [
    { domain: 'multi.spf.test' }, { domain: 'google.spf.test' },
    { domain: 'icloud.spf.test' }, { domain: 'ms.spf.test' },
    { domain: 'permit.spf.test' }, { domain: 'neutral.spf.test' },
    { domain: 'softfail.spf.test' }, { domain: 'present.spf.test' },
  ],
  fetch: () => corpusFixture({
    // permerror: RFC 7208 §4.5 — more than one v=spf1 record.
    'multi.spf.test NS': ns('ns1.other.test'),
    'multi.spf.test MX': mx('10 mail.other.test'),
    'multi.spf.test TXT': txt('v=spf1 -all', 'v=spf1 include:x.test -all'),
    // Provider mismatches. The SPF record omits the provider's own include.
    'google.spf.test NS': ns('ns1.other.test'),
    'google.spf.test MX': mx('1 aspmx.l.google.com'),
    'google.spf.test TXT': txt('v=spf1 ip4:198.51.100.0/24 -all'),
    'icloud.spf.test NS': ns('ns1.other.test'),
    'icloud.spf.test MX': mx('10 mx01.mail.icloud.com'),
    'icloud.spf.test TXT': txt('v=spf1 ip4:198.51.100.0/24 -all'),
    'ms.spf.test NS': ns('ns1.other.test'),
    'ms.spf.test MX': mx('0 ms-test.mail.protection.outlook.com'),
    'ms.spf.test TXT': txt('v=spf1 ip4:198.51.100.0/24 -all'),
    // The three all-qualifier verdicts, plus a record with no all at all.
    'permit.spf.test NS': ns('ns1.other.test'),
    'permit.spf.test MX': mx('10 mail.other.test'),
    'permit.spf.test TXT': txt('v=spf1 +all'),
    'neutral.spf.test NS': ns('ns1.other.test'),
    'neutral.spf.test MX': mx('10 mail.other.test'),
    'neutral.spf.test TXT': txt('v=spf1 ?all'),
    'softfail.spf.test NS': ns('ns1.other.test'),
    'softfail.spf.test MX': mx('10 mail.other.test'),
    'softfail.spf.test TXT': txt('v=spf1 ip4:198.51.100.0/24 ~all'),
    'present.spf.test NS': ns('ns1.other.test'),
    'present.spf.test MX': mx('10 mail.other.test'),
    'present.spf.test TXT': txt('v=spf1 ip4:198.51.100.0/24'),
    'mail.other.test A': a('198.51.100.10'),
  }),
});

/* ── 10. SPF subnet sizes, redundancy and lookup accounting ───────────── */

cases.push({
  id: 'spf-subnets-and-lookups',
  description: 'LOW/MEDIUM/HIGH subnets in both families, redundancy, and the lookup counters',
  domains: [
    { domain: 'sizes.spf.test' }, { domain: 'redundant.spf.test' },
    { domain: 'overlimit.spf.test' }, { domain: 'nearlimit.spf.test' },
    { domain: 'cycle.spf.test' }, { domain: 'macro.spf.test' },
    { domain: 'void.spf.test' },
  ],
  spfNames: ['a.chain.test', 'b.chain.test', 'c.chain.test'],
  fetch: () => corpusFixture({
    // One record per severity tier, in both address families.
    'sizes.spf.test NS': ns('ns1.other.test'),
    'sizes.spf.test MX': mx('10 mail.other.test'),
    'sizes.spf.test TXT': txt('v=spf1 ip4:192.0.2.1/32 ip4:192.0.2.0/26 ip4:198.51.100.0/24 ' +
      'ip6:2001:db8::/64 ip6:2001:db8::/48 ip6:2001:db8::/32 -all'),
    // `a` resolves inside a block the same record already authorizes.
    'redundant.spf.test NS': ns('ns1.other.test'),
    'redundant.spf.test MX': mx('10 mail.other.test'),
    'redundant.spf.test TXT': txt('v=spf1 ip4:203.0.113.0/24 a -all'),
    'redundant.spf.test A': a('203.0.113.7'),
    // Eleven lookups: over the RFC 7208 §4.6.4 limit of ten.
    'overlimit.spf.test NS': ns('ns1.other.test'),
    'overlimit.spf.test MX': mx('10 mail.other.test'),
    'overlimit.spf.test TXT': txt('v=spf1 include:i1.test include:i2.test include:i3.test ' +
      'include:i4.test include:i5.test include:i6.test include:i7.test include:i8.test ' +
      'include:i9.test include:i10.test include:i11.test -all'),
    // Nine: inside the limit and inside the warning band.
    'nearlimit.spf.test NS': ns('ns1.other.test'),
    'nearlimit.spf.test MX': mx('10 mail.other.test'),
    'nearlimit.spf.test TXT': txt('v=spf1 include:i1.test include:i2.test include:i3.test ' +
      'include:i4.test include:i5.test include:i6.test include:i7.test include:i8.test ' +
      'include:i9.test -all'),
    'i1.test TXT': txt('v=spf1 ip4:192.0.2.0/24 -all'),
    'i2.test TXT': txt('v=spf1 ip4:192.0.2.0/24 -all'),
    'i3.test TXT': txt('v=spf1 ip4:192.0.2.0/24 -all'),
    'i4.test TXT': txt('v=spf1 ip4:192.0.2.0/24 -all'),
    'i5.test TXT': txt('v=spf1 ip4:192.0.2.0/24 -all'),
    'i6.test TXT': txt('v=spf1 ip4:192.0.2.0/24 -all'),
    'i7.test TXT': txt('v=spf1 ip4:192.0.2.0/24 -all'),
    'i8.test TXT': txt('v=spf1 ip4:192.0.2.0/24 -all'),
    'i9.test TXT': txt('v=spf1 ip4:192.0.2.0/24 -all'),
    'i10.test TXT': txt('v=spf1 ip4:192.0.2.0/24 -all'),
    'i11.test TXT': txt('v=spf1 ip4:192.0.2.0/24 -all'),
    // A circular include: a -> b -> c -> a. The walk records the cycle and does
    // not recurse forever.
    'cycle.spf.test NS': ns('ns1.other.test'),
    'cycle.spf.test MX': mx('10 mail.other.test'),
    'cycle.spf.test TXT': txt('v=spf1 include:a.chain.test -all'),
    'a.chain.test TXT': txt('v=spf1 include:b.chain.test -all'),
    'b.chain.test TXT': txt('v=spf1 include:c.chain.test -all'),
    'c.chain.test TXT': txt('v=spf1 include:a.chain.test -all'),
    // A macro makes the lookup count indeterminate: the target is not known
    // until a message is being evaluated.
    'macro.spf.test NS': ns('ns1.other.test'),
    'macro.spf.test MX': mx('10 mail.other.test'),
    'macro.spf.test TXT': txt('v=spf1 include:%{d}.macro.test -all'),
    // Three includes that resolve to no SPF record at all: void lookups.
    'void.spf.test NS': ns('ns1.other.test'),
    'void.spf.test MX': mx('10 mail.other.test'),
    'void.spf.test TXT': txt('v=spf1 include:v1.test include:v2.test include:v3.test -all'),
    'mail.other.test A': a('198.51.100.10'),
  }),
});

/* ── 11. Hosting and email-provider sentinels ─────────────────────────── */

cases.push({
  id: 'provider-sentinels',
  description: 'the hosting and email-provider sentinel vocabularies',
  domains: [
    { domain: 'proxied.host.test' }, { domain: 'noweb.host.test' },
    { domain: 'loop.host.test' }, { domain: 'forward.host.test' },
    { domain: 'implicit.host.test' }, { domain: 'unknown.host.test' },
    { domain: 'custom.host.test' }, { domain: 'nomail.host.test' },
    { domain: 'dnserror.host.test' },
  ],
  fetch: () => corpusFixture({
    // A Cloudflare-proxied address range.
    'proxied.host.test NS': ns('ns1.other.test'),
    'proxied.host.test MX': mx('10 mail.other.test'),
    'www.proxied.host.test A': a('104.21.5.5'),
    // No address and no CNAME at www.
    'noweb.host.test NS': ns('ns1.other.test'),
    'noweb.host.test MX': mx('10 mail.other.test'),
    // A CNAME cycle at www.
    'loop.host.test NS': ns('ns1.other.test'),
    'loop.host.test MX': mx('10 mail.other.test'),
    'www.loop.host.test CNAME': cname('alias.loop.host.test'),
    'alias.loop.host.test CNAME': cname('www.loop.host.test'),
    // Porkbun's mail forwarding.
    'forward.host.test NS': ns('ns1.other.test'),
    'forward.host.test MX': mx('10 fwd1.porkbun.com'),
    // No MX at all, but addresses exist: RFC 5321 §5.1 implicit MX.
    'implicit.host.test NS': ns('ns1.other.test'),
    'implicit.host.test A': a('198.51.100.30'),
    // The name exists but publishes no NS records at all.
    'unknown.host.test NS': 'nodata',
    'unknown.host.test MX': mx('10 mail.other.test'),
    // A two-label nameserver name, which detectDNSProvider cannot shorten to a
    // provider label.
    'custom.host.test NS': ns('ns1.hoster'),
    'custom.host.test MX': mx('10 mail.other.test'),
    // No MX, no addresses: mail is impossible.
    'nomail.host.test NS': ns('ns1.other.test'),
    // The website probe fails rather than answering, so hosting is unknown
    // rather than absent — and `checks-unverified` names Website.
    'dnserror.host.test NS': ns('ns1.other.test'),
    'dnserror.host.test MX': mx('10 mail.other.test'),
    'www.dnserror.host.test CNAME': 'servfail',
    'mail.other.test A': a('198.51.100.10'),
  }),
});

/* ── 12. The website probe switched off ───────────────────────────────── */

/**
 * Its own case because the option is a control on the page, not a per-domain
 * argument: `startAudit()` reads one checkbox for the whole run.
 */
cases.push({
  id: 'website-probe-off',
  description: 'opts.www off — hosting stays at its default and detection never runs',
  options: { www: false },
  fetch: () => corpusFixture({
    'nowww.host.test NS': ns('ns1.other.test'),
    'nowww.host.test MX': mx('10 mail.nowww.host.test'),
    'nowww.host.test TXT': txt('v=spf1 -all'),
    'mail.nowww.host.test A': a('198.51.100.10'),
  }),
  domains: [{ domain: 'nowww.host.test' }],
});

/* ── 13. The A+ and A grade tiers ─────────────────────────────────────── */

/**
 * Both tiers require a signed zone — `gradeFor()` skips any tier whose
 * `requiresDnssec` is set when `dnssecSigned` is false — so these are the same
 * configuration as `enforcing-signed` with successively more controls removed.
 */
cases.push({
  id: 'grade-tiers',
  description: 'the A+ and A grade tiers, which only a signed zone can reach',
  domains: [{ domain: 'aplus.grade.test' }, { domain: 'a.grade.test' }],
  fetch: () => corpusFixture({
    // 30 dmarc + 15 spf + 15 dkim + 15 dnssec + 10 caa = 85 - test mode? No:
    // no BIMI, MTA-STS or TLS-RPT, so 79 lands in the A+ band.
    'aplus.grade.test NS': { ad: true, answers: ns('ns1.other.test') },
    'aplus.grade.test MX': mx('10 mail.other.test'),
    'aplus.grade.test TXT': txt('v=spf1 -all'),
    'aplus.grade.test CAA': caa('0 issue "letsencrypt.org"'),
    '_dmarc.aplus.grade.test TXT': txt('v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:d@aplus.grade.test'),
    'selector1._domainkey.aplus.grade.test TXT': txt('v=DKIM1; k=rsa; p=' + RSA_2048_SPKI),
    // The same, minus CAA: 69, in the A band.
    'a.grade.test NS': { ad: true, answers: ns('ns1.other.test') },
    'a.grade.test MX': mx('10 mail.other.test'),
    'a.grade.test TXT': txt('v=spf1 -all'),
    '_dmarc.a.grade.test TXT': txt('v=DMARC1; p=reject; sp=reject; adkim=s; aspf=s; rua=mailto:d@a.grade.test'),
    'selector1._domainkey.a.grade.test TXT': txt('v=DKIM1; k=rsa; p=' + RSA_2048_SPKI),
    'mail.other.test A': a('198.51.100.10'),
  }),
});

/* ── 14. Web Crypto refusing a key the DER walk accepted ──────────────── */

/**
 * The DKIM fixture both profiles share.
 *
 * A conformant 2048-bit RSA SPKI key. Nothing about it is malformed — the
 * point of the pair below is that the *same* published record produces two
 * different operator-visible verdicts depending on what the browser's Web
 * Crypto does with it.
 */
const CRYPTO_PROFILE_RECORDS = domain => ({
  [`${domain} NS`]: ns('ns1.other.test'),
  [`${domain} MX`]: mx('10 mail.other.test'),
  [`${domain} TXT`]: txt('v=spf1 -all'),
  [`_dmarc.${domain} TXT`]: txt('v=DMARC1; p=reject; rua=mailto:d@' + domain),
  [`selector1._domainkey.${domain} TXT`]: txt('v=DKIM1; k=rsa; p=' + RSA_2048_SPKI),
  'mail.other.test A': a('198.51.100.10'),
});

/**
 * `cryptoValidated: false` and `key-structure-invalid`, through all five
 * surfaces.
 *
 * **Native Node Web Crypto cannot produce this state**, and this case does not
 * claim it does. `validateDkimKeyStructure()` (js/dns.js:1067) sets `false`
 * only when `crypto.subtle.importKey` rejects a key the project's own DER walk
 * has already accepted, and Node v26.7.0 imported every probe inside that
 * window — 16-bit through 2048-bit moduli, `e=3` and `e=65537`. The keys Node
 * might have refused are rejected by `derReadRsaPublicKey()` first and never
 * reach the import. A stricter browser does reject keys in this window, which
 * is why the production branch exists at all.
 *
 * Coverage of these two states therefore DEPENDS ON the explicit
 * `crypto-import-rejects` platform profile, which is recorded in the manifest
 * for every case. Nothing is fabricated: the production code constructs the
 * state itself when the injected `importKey` rejects, exactly as it would in a
 * browser. No result object is assembled by hand anywhere in this corpus.
 *
 * Recorded per the §6 decision of 2026-08-27 — see
 * `tests/state-algebras.json`, algebra `dkim.key.cryptoValidated`.
 */
cases.push({
  id: 'dkim-crypto-import-rejects',
  description: 'a conformant RSA key whose Web Crypto import is refused — cryptoValidated false, key-structure-invalid',
  platform: 'crypto-import-rejects',
  domains: [{ domain: 'refused.crypto.test' }],
  fetch: () => corpusFixture(CRYPTO_PROFILE_RECORDS('refused.crypto.test')),
});

/**
 * The negative control, and it carries an acceptance criterion of its own.
 *
 * Same records, same wrapper, `importKey` delegated instead of refused. It is
 * what makes the case above evidence rather than an observation: without it,
 * the difference could be anything about running under a substituted platform.
 * With it, the two cases differ in exactly one thing.
 */
cases.push({
  id: 'dkim-crypto-import-accepts',
  description: 'the same key under the same wrapper with the import delegated — the control that isolates the refusal',
  platform: 'crypto-import-accepts',
  domains: [{ domain: 'accepted.crypto.test' }],
  fetch: () => corpusFixture(CRYPTO_PROFILE_RECORDS('accepted.crypto.test')),
});
