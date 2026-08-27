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
import {
  RSA_2048_SPKI, RSA_2048_PKCS1, RSA_1024_SPKI, RSA_512_SPKI, ED25519_RAW,
  DNSSEC_ZONE_KEY, DNSSEC_KEY_TAG, DS_MATCHING_SECURE, DS_MISMATCHED,
} from './keys.mjs';

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
const corpusFixture = (map, override = {}) => {
  const inner = dohFixture(Object.assign({ 'example.com A': a('93.184.216.34') }, map));
  if (!Object.keys(override).length) return inner;
  /**
   * Answers keyed on the FULL query identity, not just name and type.
   *
   * Two things the fixture map cannot express, and both are load-bearing here:
   *
   *  - `timeout` and `network-error`. Neither is a DNS response — one is a
   *    request that never settles until its own timer aborts it, the other a
   *    fetch that throws — so neither can be written as a map entry.
   *  - A failure that applies ONLY to the `do=1` query. `checkDNSSEC()` asks
   *    for the same NS record the audit already fetched, differing only in the
   *    DNSSEC-OK bit, and `dohFetch` keys its cache on that bit
   *    (js/dns.js:207). So the two are genuinely different queries, and
   *    `dnssec.error` is unreachable unless a fixture can tell them apart.
   *
   * Keys are `"<name> <TYPE>"`, optionally suffixed ` do` and/or ` cd`.
   */
  const impl = (url, init) => {
    const params = new URL(String(url), 'https://cloudflare-dns.com').searchParams;
    const name = String(params.get('name') || '').toLowerCase().replace(/\.$/, '');
    const type = TYPE_BY_NUMBER[params.get('type')] || params.get('type');
    const key = name + ' ' + type +
      (params.get('do') === '1' ? ' do' : '') +
      (params.get('cd') === '1' ? ' cd' : '');
    const behaviour = override[key] ?? override[name];
    if (behaviour === 'network-error') return Promise.reject(new Error('socket closed'));
    if (behaviour === 'timeout') {
      return new Promise((resolve, reject) => {
        init.signal.addEventListener('abort', () => reject(new Error('aborted')), { once: true });
      });
    }
    if (behaviour !== undefined) {
      if (behaviour === 'http-error') return Promise.resolve({ ok: false, status: 502 });
      const status = { nxdomain: 3, servfail: 2, refused: 5, nodata: 0, 'dns-error': 4 }[behaviour];
      if (status === undefined) throw new Error(`corpus: unknown override behaviour '${behaviour}'`);
      return Promise.resolve({ ok: true, status: 200, json: async () => ({ Status: status, Answer: [] }) });
    }
    return inner(url, init);
  };
  impl.calls = inner.calls;
  return impl;
};

const TYPE_BY_NUMBER = {
  1: 'A', 2: 'NS', 5: 'CNAME', 12: 'PTR', 15: 'MX', 16: 'TXT', 28: 'AAAA',
  43: 'DS', 48: 'DNSKEY', 52: 'TLSA', 257: 'CAA',
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

/* ── 15. DKIM key shapes ──────────────────────────────────────────────── */

const DKIM_SELECTORS = [
  'sed25519', 'sedbad', 'secdsa', 'spkcs1', 'sbadver', 'svnotfirst',
  'sbadtaglist', 'sdup', 'sbadk', 'snotes', 'shash', 'ssvc', 'sunparse',
  'srevoked', 'smalformed', 'scname', 's1024', 's512', 'stesting',
];

/**
 * One domain, nineteen selectors, one page.
 *
 * `dkimRecordSet()` (js/dns.js:481) partitions a selector's answers into four
 * buckets — usable keys, revoked, unusable and malformed — and the distinction
 * is the whole point: a revoked key is a deliberate act, an unusable one is a
 * conformant record scoped to another service, and reporting either as "no
 * DKIM" tells the operator to create a key they already dealt with. Each bucket
 * needs its own selector here.
 */
cases.push({
  id: 'dkim-key-shapes',
  description: 'every DKIM key type, encoding, error token and restriction, across all four record buckets',
  options: { selectors: DKIM_SELECTORS },
  domains: [{ domain: 'keys.dkim.test' }],
  fetch: () => corpusFixture({
    'keys.dkim.test NS': ns('ns1.other.test'),
    'keys.dkim.test MX': mx('10 mail.other.test'),
    'keys.dkim.test TXT': txt('v=spf1 -all'),
    '_dmarc.keys.dkim.test TXT': txt('v=DMARC1; p=reject; rua=mailto:d@keys.dkim.test'),
    // RFC 8463 §3: the p= value is the RAW 32-byte Ed25519 key, not an SPKI
    // structure, so there is no modulus and keyBits stays null.
    'sed25519._domainkey.keys.dkim.test TXT': txt('v=DKIM1; k=ed25519; p=' + ED25519_RAW),
    'sedbad._domainkey.keys.dkim.test TXT': txt('v=DKIM1; k=ed25519; p=AAAAAAAAAAAAAAAAAAAAAA=='),
    // An unrecognized key type is IGNORED, not malformed (RFC 6376 §3.6.1).
    'secdsa._domainkey.keys.dkim.test TXT': txt('v=DKIM1; k=ecdsa; p=' + RSA_2048_SPKI),
    // The bare PKCS#1 envelope, which is conformant and which Web Crypto
    // cannot express — so cryptoValidated stays null rather than false.
    'spkcs1._domainkey.keys.dkim.test TXT': txt('v=DKIM1; k=rsa; p=' + RSA_2048_PKCS1),
    'sbadver._domainkey.keys.dkim.test TXT': txt('v=DKIM2; k=rsa; p=' + RSA_2048_SPKI),
    'svnotfirst._domainkey.keys.dkim.test TXT': txt('k=rsa; v=DKIM1; p=' + RSA_2048_SPKI),
    'sbadtaglist._domainkey.keys.dkim.test TXT': txt('v=DKIM1;; k=rsa; p=' + RSA_2048_SPKI),
    'sdup._domainkey.keys.dkim.test TXT': txt('v=DKIM1; k=rsa; k=rsa; p=' + RSA_2048_SPKI),
    // A tag name that is not a hyphenated-word: invalid-key-type, and the type
    // itself falls to unknown with the unsupported-key-type restriction.
    'sbadk._domainkey.keys.dkim.test TXT': txt('v=DKIM1; k=1rsa; p=' + RSA_2048_SPKI),
    'snotes._domainkey.keys.dkim.test TXT': txt('v=DKIM1; k=rsa; n==ZZ; p=' + RSA_2048_SPKI),
    // Well-formed, and it offers this verifier no hash it can use.
    'shash._domainkey.keys.dkim.test TXT': txt('v=DKIM1; k=rsa; h=sha512; p=' + RSA_2048_SPKI),
    // RFC 8460 s=tlsrpt: a legitimate restriction, and not a key for email.
    'ssvc._domainkey.keys.dkim.test TXT': txt('v=DKIM1; k=rsa; s=tlsrpt; p=' + RSA_2048_SPKI),
    'sunparse._domainkey.keys.dkim.test TXT': txt('v=DKIM1; k=rsa; p=!!!!'),
    // RFC 6376 §3.6.1: an empty p= is REVOCATION, a complete record.
    'srevoked._domainkey.keys.dkim.test TXT': txt('v=DKIM1; k=rsa; p='),
    'smalformed._domainkey.keys.dkim.test TXT': txt('v=DKIM1; k=rsa'),
    // A selector published as a CNAME to the key's real home, which is how
    // most hosted signing is configured.
    'scname._domainkey.keys.dkim.test': cname('key.host.test'),
    'key.host.test TXT': txt('v=DKIM1; k=rsa; p=' + RSA_2048_SPKI),
    's1024._domainkey.keys.dkim.test TXT': txt('v=DKIM1; k=rsa; p=' + RSA_1024_SPKI),
    's512._domainkey.keys.dkim.test TXT': txt('v=DKIM1; k=rsa; p=' + RSA_512_SPKI),
    'stesting._domainkey.keys.dkim.test TXT': txt('v=DKIM1; k=rsa; t=y; p=' + RSA_2048_SPKI),
    'mail.other.test A': a('198.51.100.10'),
  }),
});

/* ── 16. DKIM discovery outcomes ──────────────────────────────────────── */

/**
 * The three `note` values and the comprehensive scan mode.
 *
 * `noteWildcard` needs a wildcard that actually reaches `_domainkey`, which is
 * measured at two labels rather than inferred: RFC 4592 §2.2.1 stops synthesis
 * below an existing node, and not every nameserver honours it.
 */
cases.push({
  id: 'dkim-discovery-notes',
  description: 'noteWildcard, noteNotFoundWithErrors and the comprehensive scan mode',
  // `optWildcard` is UNCHECKED in index.html, so the two wildcard probes do not
  // run unless a case asks for them — and `noteWildcard` is unreachable without
  // them. The default came from the subject's own markup, which is exactly why
  // the page skeleton is derived from it rather than hand-listed.
  options: { dkimComprehensive: true, wildcard: true, selectors: ['broken'] },
  domains: [{ domain: 'wild.dkim.test' }, { domain: 'errors.dkim.test' }],
  fetch: () => corpusFixture({
    // A wildcard TXT that synthesizes at every selector name, so nothing found
    // under it is evidence of a key at that selector.
    'wild.dkim.test NS': ns('ns1.other.test'),
    'wild.dkim.test MX': mx('10 mail.other.test'),
    'wild.dkim.test TXT': txt('v=spf1 -all'),
    '*.wild.dkim.test TXT': txt('wildcard-synthesized-value'),
    '*._domainkey.wild.dkim.test TXT': txt('wildcard-synthesized-value'),
    '_dmarc.wild.dkim.test TXT': txt('v=DMARC1; p=none'),
    // A selector whose lookup fails rather than answering: found is false AND
    // a selector could not be checked, which is a different note from a plain
    // "nothing published".
    'errors.dkim.test NS': ns('ns1.other.test'),
    'errors.dkim.test MX': mx('10 mail.other.test'),
    'errors.dkim.test TXT': txt('v=spf1 -all'),
    '_dmarc.errors.dkim.test TXT': txt('v=DMARC1; p=none'),
    'broken._domainkey.errors.dkim.test TXT': 'servfail',
    'mail.other.test A': a('198.51.100.10'),
  }),
});

/* ── 17. DMARC record content and the tree walk ───────────────────────── */

cases.push({
  id: 'dmarc-record-variants',
  description: 'unusable records, invalid tag values, every fo value and the alignment states',
  domains: [
    { domain: 'unusable.dmarc.test' }, { domain: 'badtags.dmarc.test' },
    { domain: 'fo1.dmarc.test' }, { domain: 'fod.dmarc.test' }, { domain: 'fos.dmarc.test' },
    { domain: 'relaxed.dmarc.test' }, { domain: 'pct.dmarc.test' },
  ],
  fetch: () => corpusFixture({
    // A record receivers cannot act on: p= is not a policy value. Neither
    // 'missing' nor trustworthy enforcement, so `present`.
    'unusable.dmarc.test NS': ns('ns1.other.test'),
    'unusable.dmarc.test MX': mx('10 mail.other.test'),
    '_dmarc.unusable.dmarc.test TXT': txt('v=DMARC1; p=bogus'),
    // sp= present but not a policy value, and both alignment tags written the
    // way a person would rather than the way the RFC defines.
    'badtags.dmarc.test NS': ns('ns1.other.test'),
    'badtags.dmarc.test MX': mx('10 mail.other.test'),
    '_dmarc.badtags.dmarc.test TXT': txt('v=DMARC1; p=reject; sp=bogus; np=nope; adkim=strict; aspf=relaxed; psd=maybe; t=maybe; fo=9'),
    // The fo= vocabulary, one value per domain. Its content MUST be ignored
    // without ruf=, which is what makes fo-without-ruf worth naming.
    'fo1.dmarc.test NS': ns('ns1.other.test'),
    'fo1.dmarc.test MX': mx('10 mail.other.test'),
    '_dmarc.fo1.dmarc.test TXT': txt('v=DMARC1; p=reject; fo=1; ruf=mailto:f@fo1.dmarc.test'),
    'fod.dmarc.test NS': ns('ns1.other.test'),
    'fod.dmarc.test MX': mx('10 mail.other.test'),
    '_dmarc.fod.dmarc.test TXT': txt('v=DMARC1; p=reject; fo=d; ruf=mailto:f@fod.dmarc.test'),
    'fos.dmarc.test NS': ns('ns1.other.test'),
    'fos.dmarc.test MX': mx('10 mail.other.test'),
    '_dmarc.fos.dmarc.test TXT': txt('v=DMARC1; p=reject; fo=s; ruf=mailto:f@fos.dmarc.test'),
    // Alignment written explicitly as relaxed, which is the default and still
    // a present tag — `absent` and `r` are different facts about the record.
    'relaxed.dmarc.test NS': ns('ns1.other.test'),
    'relaxed.dmarc.test MX': mx('10 mail.other.test'),
    '_dmarc.relaxed.dmarc.test TXT': txt('v=DMARC1; p=quarantine; adkim=r; aspf=r; rua=mailto:d@relaxed.dmarc.test'),
    // pct= was removed by RFC 9989. Parsed for reporting, scored at nothing,
    // and the suggestion is always "remove it".
    'pct.dmarc.test NS': ns('ns1.other.test'),
    'pct.dmarc.test MX': mx('10 mail.other.test'),
    '_dmarc.pct.dmarc.test TXT': txt('v=DMARC1; p=reject; pct=50; rf=afrf; ri=86400; zz=extension'),
    'mail.other.test A': a('198.51.100.10'),
  }),
});

/* ── 18. The RFC 9989 tree walk ───────────────────────────────────────── */

/**
 * The walk's four termination states and the five observations it records.
 *
 * The walk does NOT stop at the first record it finds — steps 2 and 6 stop
 * early only on `psd=n` or `psd=y` — and duplicate records at one name are
 * discarded while the walk CONTINUES, because a record higher in the tree can
 * still apply. Both are easy to get wrong and both are visible here as the
 * ordered `dmarcWalk` subsequence in the trace surface.
 */
cases.push({
  id: 'dmarc-tree-walk',
  description: 'psd-y, psd-n and error termination, plus every observation reason',
  domains: [
    { domain: 'a.b.psdy.test' }, { domain: 'a.psdn.test' },
    { domain: 'broken.walk.test' }, { domain: 'observed.walk.test' },
    { domain: 'apex.walk.test' }, { domain: 'diagnose.walk.test' },
    { domain: 'absentv.walk.test' },
  ],
  fetch: () => corpusFixture({
    // psd=y at a public-suffix-like parent: the Organizational Domain is one
    // label BELOW it, and may carry no record of its own.
    'a.b.psdy.test NS': ns('ns1.other.test'),
    'a.b.psdy.test MX': mx('10 mail.other.test'),
    '_dmarc.psdy.test TXT': txt('v=DMARC1; p=reject; psd=y; rua=mailto:d@psdy.test'),
    // psd=n stops the walk and names the Organizational Domain outright.
    'a.psdn.test NS': ns('ns1.other.test'),
    'a.psdn.test MX': mx('10 mail.other.test'),
    '_dmarc.psdn.test TXT': txt('v=DMARC1; p=quarantine; psd=n; rua=mailto:d@psdn.test'),
    // A transient failure partway up. The upper tree was not examined, so the
    // HIGHEST record is unknowable and the verdict is `unknown` rather than
    // `missing` — optionalCheck's rule applied to the core path.
    'broken.walk.test NS': ns('ns1.other.test'),
    'broken.walk.test MX': mx('10 mail.other.test'),
    '_dmarc.broken.walk.test TXT': 'servfail',
    // Four records that are meant to be DMARC and are not readable as one,
    // plus a duplicate pair at a single name.
    'observed.walk.test NS': ns('ns1.other.test'),
    'observed.walk.test MX': mx('10 mail.other.test'),
    '_dmarc.observed.walk.test TXT': txt('v=dmarc1; p=none'),
    // TWO VALID policy records at one name. RFC 9989 §4.10 step 2 discards them
    // both and the walk CONTINUES, so the duplicate is evidence rather than a
    // termination reason. A pair that merely LOOKS like DMARC would be filtered
    // out before the duplicate rule ever ran, which is what the first draft of
    // this fixture got wrong.
    '_dmarc.walk.test TXT': txt('v=DMARC1; p=none', 'v=DMARC1; p=reject'),
    // The four diagnosable near-misses, at a name of their own.
    'diagnose.walk.test NS': ns('ns1.other.test'),
    'diagnose.walk.test MX': mx('10 mail.other.test'),
    '_dmarc.diagnose.walk.test TXT': txt('p=none; v=DMARC1'),
    'absentv.walk.test NS': ns('ns1.other.test'),
    'absentv.walk.test MX': mx('10 mail.other.test'),
    '_dmarc.absentv.walk.test TXT': txt('p=reject'),
    // A valid policy record published at the APEX instead of under _dmarc,
    // which no receiver reads. Costs no query — analyzeDomain already holds
    // the apex TXT set.
    'apex.walk.test NS': ns('ns1.other.test'),
    'apex.walk.test MX': mx('10 mail.other.test'),
    'apex.walk.test TXT': txt('v=spf1 -all', 'v=DMARC1; p=reject'),
    'mail.other.test A': a('198.51.100.10'),
  }),
});

/* ── 19. External report authorization (RFC 9990 §4) ──────────────────── */

/**
 * Sending reports to a domain you do not control requires that domain to
 * publish `<policy-domain>._report._dmarc.<destination>`. Until it does,
 * conformant receivers discard the reports and the operator gets silence.
 *
 * A DNS failure is `unverifiable`, never `unauthorized`: a timeout is not
 * evidence of a missing record, and calling it one sends someone chasing a
 * vendor over our own flaky lookup.
 */
cases.push({
  id: 'dmarc-report-authorization',
  description: 'authorized, unauthorized, override-mismatch and every unverifiable reason',
  domains: [{ domain: 'reports.test' }],
  fetch: () => corpusFixture({
    'reports.test NS': ns('ns1.other.test'),
    'reports.test MX': mx('10 mail.other.test'),
    'reports.test TXT': txt('v=spf1 -all'),
    '_dmarc.reports.test TXT': txt('v=DMARC1; p=reject; ' +
      'rua=mailto:a@ok.vendor.test,mailto:b@bad.vendor.test,mailto:c@quiet.vendor.test,' +
      'mailto:d@third.vendor.test,mailto:e@loose.vendor.test,mailto:f@refuse.vendor.test,' +
      'mailto:g@servererror.vendor.test'),
    // Authorized, by the exact constructed name.
    'reports.test._report._dmarc.ok.vendor.test TXT': txt('v=DMARC1'),
    // A TXT that exists and does not parse authorizes nothing — which usually
    // means a truncated or hand-mangled record, not an absent one.
    'reports.test._report._dmarc.bad.vendor.test TXT': txt('v=DMARC1; this-is-not-a-tag-value-pair'),
    // Nothing published at all.
    'reports.test._report._dmarc.quiet.vendor.test TXT': 'nodata',
    // Step 9's override pointing at a THIRD host: conformant receivers send to
    // neither URI, so the arrangement is unusable rather than authorized.
    'reports.test._report._dmarc.third.vendor.test TXT': txt('v=DMARC1; rua=mailto:x@elsewhere.test'),
    // A merely malformed override is ignored (RFC 9990 §3.5) and the
    // authorization stands.
    'reports.test._report._dmarc.loose.vendor.test TXT': txt('v=DMARC1; rua=not-a-uri'),
    'reports.test._report._dmarc.refuse.vendor.test TXT': 'refused',
    'reports.test._report._dmarc.servererror.vendor.test TXT': 'http-error',
    'mail.other.test A': a('198.51.100.10'),
  }),
});

/* ── 20. Report authorization that could not be determined ────────────── */

/**
 * The rest of the `unverifiable` vocabulary, including the two kinds no DNS
 * answer can express and the RFC 9990 §4 step 4 length limit.
 *
 * `name-too-long` needs the CONSTRUCTED name to exceed 253 octets, so the
 * audited domain itself has to be long — cannot-determine and not-authorized
 * are different facts and the step says to stop rather than guess.
 */
const LONG_POLICY_DOMAIN = ('l'.repeat(60) + '.').repeat(3) + 'policy.test';

cases.push({
  id: 'dmarc-report-unverifiable',
  description: 'servfail, dns-error, timeout, network-error and the 253-octet name limit',
  domains: [{ domain: 'failures.test' }, { domain: LONG_POLICY_DOMAIN }],
  fetch: () => corpusFixture({
    'failures.test NS': ns('ns1.other.test'),
    'failures.test MX': mx('10 mail.other.test'),
    'failures.test TXT': txt('v=spf1 -all'),
    '_dmarc.failures.test TXT': txt('v=DMARC1; p=reject; ' +
      'rua=mailto:a@sf.vendor.test,mailto:b@notimp.vendor.test,' +
      'mailto:c@slow.vendor.test,mailto:d@down.vendor.test'),
    'failures.test._report._dmarc.sf.vendor.test TXT': 'servfail',
    // Any status responseKind() does not name. 4 is NOTIMP.
    'failures.test._report._dmarc.notimp.vendor.test TXT': { status: 4, answers: [] },
    [`${LONG_POLICY_DOMAIN} NS`]: ns('ns1.other.test'),
    [`${LONG_POLICY_DOMAIN} MX`]: mx('10 mail.other.test'),
    [`${LONG_POLICY_DOMAIN} TXT`]: txt('v=spf1 -all'),
    [`_dmarc.${LONG_POLICY_DOMAIN} TXT`]: txt('v=DMARC1; p=reject; rua=mailto:x@' + 'd'.repeat(60) + '.vendor.test'),
    'mail.other.test A': a('198.51.100.10'),
  }, {
    // Neither of these is a DNS response, so neither can be written as a
    // fixture entry: `timeout` is a request that never settles until its own
    // timer aborts it, and `network-error` is a fetch that throws.
    'failures.test._report._dmarc.slow.vendor.test': 'timeout',
    'failures.test._report._dmarc.down.vendor.test': 'network-error',
  }),
});

/* ── 21. DNSSEC chain states ──────────────────────────────────────────── */

/**
 * The states §4's rules derive from the resolver's verdict and from what the
 * child and parent publish.
 *
 * Local DS-to-DNSKEY matching feeds findings and never the classifier: nothing
 * computed here can demote a zone the resolver validated. `servfail.nl` is the
 * reason — its DS confirms its KSK by SHA-256 and the zone is bogus.
 */
cases.push({
  id: 'dnssec-chain-states',
  description: 'confirmed, mismatch, unanchored, unverifiable-digest-type and an unreachable resolver',
  domains: [
    { domain: 'secure.dnssec.test' }, { domain: 'mismatch.dnssec.test' },
    { domain: 'unanchored.dnssec.test' }, { domain: 'gost.dnssec.test' },
    { domain: 'unreachable.dnssec.test' },
  ],
  fetch: () => corpusFixture({
    // A DS whose digest genuinely hashes to this key over this owner name.
    'secure.dnssec.test NS': ns('ns1.other.test'),
    'secure.dnssec.test MX': mx('10 mail.other.test'),
    'secure.dnssec.test TXT': txt('v=spf1 -all'),
    'secure.dnssec.test DS': ds(DS_MATCHING_SECURE),
    'secure.dnssec.test DNSKEY': dnskey(DNSSEC_ZONE_KEY),
    // The same key, and the digest computed for a DIFFERENT owner name — so it
    // cannot hash correctly here. Both
    // lookups completed and a determinate verdict exists, so this is positive
    // local proof of a broken link rather than an absence of evidence.
    'mismatch.dnssec.test NS': ns('ns1.other.test'),
    'mismatch.dnssec.test MX': mx('10 mail.other.test'),
    'mismatch.dnssec.test DS': ds(DS_MATCHING_SECURE),
    'mismatch.dnssec.test DNSKEY': dnskey(DNSSEC_ZONE_KEY),
    // Keys published, no DS at the parent: signed and not anchored.
    'unanchored.dnssec.test NS': ns('ns1.other.test'),
    'unanchored.dnssec.test MX': mx('10 mail.other.test'),
    'unanchored.dnssec.test DS': 'nodata',
    'unanchored.dnssec.test DNSKEY': dnskey(DNSSEC_ZONE_KEY),
    // Digest type 3 is GOST R 34.11-94: registered, deprecated by RFC 9906,
    // and not something Web Crypto implements. Not computable is the whole
    // claim — it is never reported as a mismatch.
    'gost.dnssec.test NS': ns('ns1.other.test'),
    'gost.dnssec.test MX': mx('10 mail.other.test'),
    'gost.dnssec.test DS': ds(DNSSEC_KEY_TAG + ' 8 3 ' + 'ab'.repeat(32)),
    'gost.dnssec.test DNSKEY': dnskey(DNSSEC_ZONE_KEY),
    // The NS probe never returns a definite answer, so the resolver's verdict
    // is unknown and the state is indeterminate rather than insecure.
    'unreachable.dnssec.test NS': 'refused',
    'unreachable.dnssec.test MX': mx('10 mail.other.test'),
    'mail.other.test A': a('198.51.100.10'),
  }),
});

/* ── 22. DNSSEC record parsing ────────────────────────────────────────── */

/**
 * Every DS and DNSKEY error token, and the digest-name vocabulary including
 * the ranges IANA reserves.
 *
 * A registered digest type parsed WITHOUT its registered grammar is a gap, not
 * forward compatibility, so every registered type has its length checked —
 * including the two this build cannot compute. Only a genuinely unassigned or
 * private-use value is carried unjudged.
 */
cases.push({
  id: 'dnssec-record-parsing',
  description: 'every DS and DNSKEY error token, plus the reserved and private-use digest ranges',
  domains: [{ domain: 'ds.parse.test' }, { domain: 'key.parse.test' }],
  fetch: () => corpusFixture({
    'ds.parse.test NS': ns('ns1.other.test'),
    'ds.parse.test MX': mx('10 mail.other.test'),
    'ds.parse.test DNSKEY': dnskey(DNSSEC_ZONE_KEY),
    'ds.parse.test DS': ds(
      'not-a-ds-record',                                  // unparseable-record
      '1 8 2 ( ' + 'ab'.repeat(32),                       // unbalanced-parentheses
      '99999 8 2 ' + 'ab'.repeat(32),                     // bad-key-tag
      '1 300 2 ' + 'ab'.repeat(32),                       // bad-algorithm
      '1 8 300 ' + 'ab'.repeat(32),                       // bad-digest-type
      '1 8 2 zzzz',                                       // bad-digest
      '1 8 2 abcd',                                       // bad-digest-length
      '1 8 0 ' + 'ab'.repeat(20),                         // digestName RESERVED (type 0)
      '1 8 1 ' + 'ab'.repeat(20),                         // SHA-1
      '1 8 4 ' + 'ab'.repeat(48),                         // SHA-384
      '1 8 5 ' + 'ab'.repeat(32),                         // GOST R 34.11-2012
      '1 8 6 ' + 'ab'.repeat(32),                         // SM3
      '1 8 7 ' + 'ab'.repeat(32),                         // unassigned — no name
      '1 8 200 ' + 'ab'.repeat(32),                       // RESERVED range
      '1 8 253 ' + 'ab'.repeat(32),                       // PRIVATE-USE range
    ),
    'key.parse.test NS': ns('ns1.other.test'),
    'key.parse.test MX': mx('10 mail.other.test'),
    'key.parse.test DS': ds(DS_MATCHING_SECURE),
    'key.parse.test DNSKEY': dnskey(
      'not-a-dnskey-record',                              // unparseable-record
      '257 3 8 ( AwEAAQ==',                               // unbalanced-parentheses
      '70000 3 8 AwEAAQ==',                               // bad-flags
      '257 4 8 AwEAAQ==',                                 // bad-protocol
      '257 3 300 AwEAAQ==',                               // bad-algorithm
      '257 3 8 !!!!',                                     // bad-key-encoding
      '257 3 3 AwEAAQ==',                                 // DSA: deprecated, ineligible
      '257 3 15 AwEAAQ==',                                // Ed25519 with the wrong length
      '257 3 99 AwEAAQ==',                                // unregistered: eligibility unknown
    ),
    'mail.other.test A': a('198.51.100.10'),
  }),
});

/* ── 23. DNSSEC evidence that did not arrive ──────────────────────────── */

/**
 * `dnssec.error` carries the kind of the NS lookup that failed, and reaching it
 * needs a failure that applies ONLY to the `do=1` query — the audit's own NS
 * probe must succeed or there is no result to observe. `dohFetch` keys its
 * cache on the DNSSEC-OK bit (js/dns.js:207), so the two are different queries
 * and the override map can answer them differently.
 *
 * `cancelled` is deliberately absent from this case. An abort during the DNSSEC
 * queries aborts every other in-flight lookup too, their `optionalCheck()`
 * wrappers re-throw `AbortError`, and the whole audit throws rather than
 * producing a result — so it is asserted by direct call instead.
 */
const dnssecFailureCase = (label, behaviour) => ({
  domain: `${label}.evidence.test`,
  records: {
    [`${label}.evidence.test NS`]: ns('ns1.other.test'),
    [`${label}.evidence.test MX`]: mx('10 mail.other.test'),
    [`${label}.evidence.test TXT`]: txt('v=spf1 -all'),
  },
  override: { [`${label}.evidence.test NS do`]: behaviour },
});

const DNSSEC_FAILURES = [
  dnssecFailureCase('nx', 'nxdomain'),
  dnssecFailureCase('sf', 'servfail'),
  dnssecFailureCase('ref', 'refused'),
  dnssecFailureCase('other', 'dns-error'),
  dnssecFailureCase('http', 'http-error'),
  dnssecFailureCase('slow', 'timeout'),
  dnssecFailureCase('down', 'network-error'),
];

cases.push({
  id: 'dnssec-evidence-missing',
  description: 'every transport kind the DNSSEC NS probe can report, plus partial evidence',
  domains: [
    ...DNSSEC_FAILURES.map(f => ({ domain: f.domain })),
    { domain: 'partial.evidence.test' },
  ],
  fetch: () => corpusFixture({
    ...Object.assign({}, ...DNSSEC_FAILURES.map(f => f.records)),
    // One of the two child/parent lookups completed and the other did not, so
    // the residual verdict rests on less evidence than a clean one. Stated
    // rather than inferred from an empty array.
    'partial.evidence.test NS': ns('ns1.other.test'),
    'partial.evidence.test MX': mx('10 mail.other.test'),
    'partial.evidence.test TXT': txt('v=spf1 -all'),
    'partial.evidence.test DNSKEY': dnskey(DNSSEC_ZONE_KEY),
    'mail.other.test A': a('198.51.100.10'),
  }, {
    ...Object.assign({}, ...DNSSEC_FAILURES.map(f => f.override)),
    // The cd=1 re-query has to fail too. A SERVFAIL that RESOLVES with checking
    // disabled is the resolver saying validation failed, which is `bogus` and
    // not missing evidence — that distinction is rule 1 of §4 and the
    // `dnssec-bogus` case already covers it.
    'sf.evidence.test NS do cd': 'servfail',
    'partial.evidence.test DS do': 'servfail',
  }),
});

/* ── 24. DS records that say nothing about the zone ───────────────────── */

/**
 * Every failure path in `matchDsToDnskeys()` lands on `unverifiable`, never on
 * `digest-mismatch`. A mismatch verdict tells an operator their DNSSEC is
 * broken, and the only thing entitled to say that is arithmetic that ran.
 *
 * `invalid-owner` needs a name the wire-format encoder refuses — a label over
 * 63 octets — which is a statement about our own input rather than about the
 * zone, and says so.
 */
/**
 * `invalid-owner` is NOT here, and that was measured rather than assumed. A name
 * with a label over 63 octets is rejected by the application's own domain
 * parsing before `startAudit()` ever queues it, so the engine never sees one and
 * the corpus cannot reach the state. It is asserted by a direct
 * `matchDsToDnskeys()` call in legacy-shapes.test.mjs §5d instead.
 */
cases.push({
  id: 'dnssec-unverifiable-reasons',
  description: 'invalid-ds, an ineligible algorithm, and empty rdata bodies',
  domains: [{ domain: 'invalidds.dnssec.test' }],
  fetch: () => corpusFixture({
    'invalidds.dnssec.test NS': ns('ns1.other.test'),
    'invalidds.dnssec.test MX': mx('10 mail.other.test'),
    'invalidds.dnssec.test DNSKEY': dnskey(
      DNSSEC_ZONE_KEY,
      // RSAMD5. RFC 9905 §3.1 makes it MUST NOT for signing, so the registry's
      // zone-signing column says ineligible — a fact about the algorithm, not
      // about whether this build can parse it.
      '257 3 1 AwEAAQ==',
      // An empty parenthesised body: parsed, and carrying no key.
      '257 3 8 ()',
    ),
    // A DS that did not parse is a statement about our own input, so it is
    // unverifiable with a reason and never a mismatch.
    'invalidds.dnssec.test DS': ds('1 8 2 zzzz', '1 8 2 ()'),
    'mail.other.test A': a('198.51.100.10'),
  }),
});

/* ── 25. The runtime refusing a digest it advertised ──────────────────── */

/**
 * `runtime-unavailable`: `dnssecDigestHex()` returned null because
 * `crypto.subtle.digest` refused an algorithm it advertises. Recorded, not
 * returned — an earlier candidate may already have proved the match, and a
 * completed proof cannot be undone by failing to inspect another key.
 *
 * Reached through the same mechanism as the DKIM key case and on the same
 * terms as the §6 decision of 2026-08-27: an explicit, deterministic platform
 * profile, recorded per case in the manifest. Native Node computes SHA-256
 * perfectly well, so this is not native-Node coverage.
 */
cases.push({
  id: 'dnssec-digest-unavailable',
  description: 'a runtime that refuses the digest algorithm it advertises',
  platform: 'crypto-digest-unavailable',
  domains: [{ domain: 'nodigest.dnssec.test' }],
  fetch: () => corpusFixture({
    'nodigest.dnssec.test NS': ns('ns1.other.test'),
    'nodigest.dnssec.test MX': mx('10 mail.other.test'),
    'nodigest.dnssec.test TXT': txt('v=spf1 -all'),
    'nodigest.dnssec.test DS': ds(DS_MATCHING_SECURE),
    'nodigest.dnssec.test DNSKEY': dnskey(DNSSEC_ZONE_KEY),
    'mail.other.test A': a('198.51.100.10'),
  }),
});

/* ── 26. CAA policy ───────────────────────────────────────────────────── */

/**
 * A CAA record set is a policy, and reducing it to a green dot loses the
 * policy. `0 issue ";"` locks out every certificate authority; an absent
 * `issuewild` does NOT mean wildcards are open, it means the issue set governs
 * them (RFC 8659 §4.3).
 *
 * A malformed value is an ABSENT issuer-domain-name per §4.2, which is why it
 * can block issuance rather than authorize a CA whose name is nonsense — the
 * strongest form of the mistake this release must not make, because it says a
 * domain is open when the RFC says it is shut.
 */
cases.push({
  id: 'caa-policy',
  description: 'every CAA error token, the full known-tag vocabulary, and an unknown critical property',
  domains: [{ domain: 'policy.caa.test' }],
  fetch: () => corpusFixture({
    'policy.caa.test NS': ns('ns1.other.test'),
    'policy.caa.test MX': mx('10 mail.other.test'),
    'policy.caa.test TXT': txt('v=spf1 -all'),
    'policy.caa.test CAA': caa(
      'issue',                                  // unparseable-record: one token
      '999 issue "ca.test"',                    // bad-flags: outside 0-255
      '0 thistagiswaytoolong "ca.test"',        // bad-tag: over 15 octets
      '0 issue ca.test',                        // unquoted-value: readable, named
      '0 issue "%%%%%"',                        // bad-issue-value — §4.2's own example
      '0 iodef "mailto:not an address"',        // bad-iodef-url: a scheme is not a URL
      '0 issuewild ";"',                        // wildcards locked out
      '0 issuemail "ca.test"',                  // RFC 9495 §3
      '0 contactemail "admin@policy.caa.test"',
      '0 contactphone "+15550100"',
      '128 unknowncrit "x"',                    // Issuer Critical: a live outage risk
    ),
    'mail.other.test A': a('198.51.100.10'),
  }),
});

/* ── 27. MX health and TLSA ───────────────────────────────────────────── */

/**
 * Two MX hosts, one with IPv6 and one without, so `ipv6Coverage` is `some`
 * rather than `all` or `none` — and a third whose address lookups fail, which
 * must read as `unknown` rather than as an outage. One failed lookup and one
 * empty answer is not evidence of absence.
 */
cases.push({
  id: 'mx-health-and-tlsa',
  description: 'partial IPv6 coverage, a host that could not be checked, and every TLSA error token',
  domains: [{ domain: 'hosts.mx.test' }],
  fetch: () => corpusFixture({
    'hosts.mx.test NS': ns('ns1.other.test'),
    'hosts.mx.test TXT': txt('v=spf1 -all'),
    'hosts.mx.test MX': mx('10 dual.mx.test', '20 v4only.mx.test', '30 unknown.mx.test'),
    'dual.mx.test A': a('198.51.100.20'),
    'dual.mx.test AAAA': aaaa('2001:db8::20'),
    'v4only.mx.test A': a('198.51.100.21'),
    // Both address lookups fail, so `resolves` is unknown and the host is left
    // out of the concentration analysis rather than counted either way.
    'unknown.mx.test A': 'servfail',
    'unknown.mx.test AAAA': 'servfail',
    // A TLSA answer commonly returns a CNAME alongside the records, because
    // pointing _25._tcp.<host> at a shared _dane name is ordinary practice.
    // Handing that CNAME to the record parser would report a malformed TLSA on
    // a correctly configured host, which is what the type filter prevents.
    '_25._tcp.dual.mx.test TLSA': [
      ...cname('_dane.mx.test'),
      ...tlsa(
        'garbage',                                  // unparseable-record
        '3 1 1 ( ' + 'ab'.repeat(32),               // unbalanced-parentheses
        '9 1 1 ' + 'ab'.repeat(32),                 // bad-usage
        '3 9 1 ' + 'ab'.repeat(32),                 // bad-selector
        '3 1 9 ' + 'ab'.repeat(32),                 // bad-matching-type
        '3 1 1 zzzz',                               // bad-association-data
        '3 1 1 abcd',                               // bad-digest-length
        '3 1 1 ( ' + 'AB'.repeat(32) + ' )',        // valid, in the resolver's own form
      ),
    ],
  }),
});

/* ── 28. Controls that could not be verified ──────────────────────────── */

/**
 * An audit that quietly omits a control looks identical to one where the
 * control is fine. These four lookups fail rather than answering, so each
 * pillar scores zero as an UNPROVEN control rather than an absent one, and
 * `checks-unverified` names them.
 */
cases.push({
  id: 'unverified-controls',
  description: 'CAA, MTA-STS, BIMI and TLS-RPT lookups that failed rather than answered',
  domains: [{ domain: 'unverified.test' }],
  fetch: () => corpusFixture({
    'unverified.test NS': ns('ns1.other.test'),
    'unverified.test MX': mx('10 mail.other.test'),
    'unverified.test TXT': txt('v=spf1 -all'),
    '_dmarc.unverified.test TXT': txt('v=DMARC1; p=reject; rua=mailto:d@unverified.test'),
    'unverified.test CAA': 'servfail',
    '_mta-sts.unverified.test TXT': 'servfail',
    '_smtp._tls.unverified.test TXT': 'servfail',
    'default._bimi.unverified.test TXT': 'servfail',
    'mail.other.test A': a('198.51.100.10'),
  }),
});

/* ── 29. BIMI duplicate tags ──────────────────────────────────────────── */

cases.push({
  id: 'bimi-duplicate-tags',
  description: 'a BIMI record with a repeated tag — duplicate-tags rather than invalid-syntax',
  domains: [{ domain: 'dup.bimi.test' }],
  fetch: () => corpusFixture({
    'dup.bimi.test NS': ns('ns1.other.test'),
    'dup.bimi.test MX': mx('10 mail.other.test'),
    'dup.bimi.test TXT': txt('v=spf1 -all'),
    '_dmarc.dup.bimi.test TXT': txt('v=DMARC1; p=reject; rua=mailto:d@dup.bimi.test'),
    'default._bimi.dup.bimi.test TXT': txt('v=BIMI1; l=https://dup.bimi.test/a.svg; l=https://dup.bimi.test/b.svg'),
    'mail.other.test A': a('198.51.100.10'),
  }),
});
