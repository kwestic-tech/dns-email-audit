# DNS & Email Security Auditor

A free, dependency-free browser application for auditing DNS, email
authentication, mail-transport security, and related domain controls. Audit up
to 200 domains at once and get evidence-backed findings, a confidence-aware
grade, plain-language explanations, and copy-ready remediation examples.

**[Open the live auditor →](https://dnsaudit.kwestic.com)**

The application has no backend, signup, or analytics. Audits run in the browser
using [Cloudflare DNS over HTTPS](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/).
Kwestic does not receive or store audit results. DNS query names are necessarily
sent to Cloudflare and are subject to Cloudflare's privacy policy.

## Highlights

- Bulk audits for up to 200 domains, with progress, cancellation, and results
  kept in submitted order.
- SPF, DKIM, DMARC, DNSSEC, CAA, MTA-STS, TLS-RPT, BIMI, MX, NS, wildcard TXT,
  and website-hosting checks.
- Provider detection for DNS, inbound email, and common hosting platforms.
- A weighted 0–100 rubric with A++ through F grades and per-pillar breakdowns.
- Score and grade ranges when public DNS cannot support a conclusive result.
- Search, filters, sortable results, expandable evidence, CSV export, and a
  self-contained script-free HTML report.
- Complete UI localization in English, German, Spanish, French, Italian,
  Japanese, Korean, Simplified Chinese, and Traditional Chinese.
- No runtime dependencies, database, cookies, accounts, or server-side audit
  processing.

## What it checks

| Area | What the auditor verifies |
| --- | --- |
| **Domain registration** | Uses NS results to distinguish registered and unregistered domains. |
| **DNS provider** | Identifies common managed providers and self-hosted nameservers. |
| **Website hosting** | Traverses the `www` CNAME chain with loop protection, resolves final A/AAAA records, and identifies common hosts and proxies. |
| **MX and mail state** | Detects inbound providers, explicit RFC 7505 null MX (`0 .`), absent MX, and fragile RFC 5321 implicit-MX fallback. |
| **SPF** | Validates record uniqueness, provider includes, `all` qualifiers, and case-insensitive syntax. |
| **SPF evaluation** | Recursively follows lookup-causing terms and `include`/`redirect` policies; reports cycles, excessive depth, macros, void lookups, and RFC 7208's 10-lookup limit. |
| **DKIM** | Tests common, provider-associated, user-supplied, or comprehensive catalog selectors; follows CNAME delegation and requires an active public key. |
| **DMARC** | Validates against RFC 9989 (DMARCbis): record uniqueness, strict `v=` placement and casing, the full tag set (`p`, `sp`, `np`, `adkim`, `aspf`, `fo`, `rua`, `ruf`, `psd`, `t`), report-URI syntax, and tags the new RFC removed (`pct`, `rf`, `ri`) or does not define; discovers inherited organizational-domain policies with the Public Suffix List. |
| **DMARC test mode** | Detects `t=y`, which tells receivers not to apply the policy — so `p=reject; t=y` is reported and scored as `none` rather than as enforcement. |
| **DMARC report authorization** | For report destinations outside your organizational domain, checks whether that domain published the `_report._dmarc` record (RFC 9990 §4.3), including the wildcard form. Without it receivers discard those reports silently. |
| **DNSSEC** | Distinguishes secure, insecure, bogus, and indeterminate validation results using the resolver's authenticated-data response. |
| **CAA** | Walks up the domain tree to find the effective certificate-authority restrictions. |
| **MTA-STS** | Validates discovery-record uniqueness and syntax, including the required `id=` tag. |
| **TLS-RPT** | Validates uniqueness, syntax, and the required supported `rua=` destination. |
| **BIMI** | Validates uniqueness, BIMI syntax, and an HTTPS logo URL. |
| **Wildcard TXT** | Optionally detects wildcard TXT behavior that can interfere with DKIM and DMARC names. |

Transport errors are not converted into empty DNS answers. Timeouts, HTTP
failures, SERVFAIL, REFUSED, cancellation, NXDOMAIN, and successful no-data
responses remain distinct, so a resolver problem is not reported as a missing
security control.

## Using the auditor

Enter one domain per line or upload a `.txt` or `.csv` file up to 1 MB. Duplicate
inputs are removed, internationalized domain names are normalized, and invalid
hostnames are rejected before querying DNS.

The audit options include:

- **DKIM selector checks** — enabled by default and provider-aware.
- **Comprehensive DKIM scan** — tests the full vetted selector catalog and is
  limited to five domains per run to bound DNS traffic.
- **Additional DKIM selectors** — test selectors recovered from a
  `DKIM-Signature` header or DMARC report.
- **Website hosting detection** — follows the `www` chain instead of assuming
  the apex and `www` share infrastructure.
- **Wildcard TXT detection** — opt-in because it adds another query per domain.

Found DKIM selectors display the exact query name, CNAME target when applicable,
and resolved public-key data. A supplied selector outside the catalog is labeled
**Uncommon**. A supplied selector without an active key is shown as **No Domain
Key Found**.

## Confidence and unknown results

Some controls cannot be conclusively disproved through DNS alone. DKIM selectors,
for example, cannot be enumerated; failing to find a guessed selector does not
prove a sender is unsigned. DNSSEC validation can also be indeterminate when the
resolver request fails.

The auditor preserves that uncertainty:

- observed active controls receive their normal score;
- confirmed missing or invalid controls score accordingly;
- inconclusive DKIM or DNSSEC checks produce minimum and maximum scores and, when
  necessary, a grade range such as `C–B`;
- disabling DKIM reports **Not checked** instead of silently penalizing it.

## How grading works

Active-mail domains use a weighted score out of 100:

| Pillar | Points |
| --- | ---: |
| DMARC | 30 |
| SPF | 15 |
| DKIM | 15 |
| DNSSEC | 15 |
| CAA | 10 |
| MTA-STS | 8 |
| BIMI | 4 |
| TLS-RPT | 3 |

DMARC's 30 points are split across policy (12), effective subdomain coverage
(6), aggregate reporting (6), strict alignment (3), forensic reporting (2), and
deliverable report destinations (1). The detail view exposes every pillar and
DMARC sub-score.

DMARC is scored against **RFC 9989** (DMARCbis, May 2026), which obsoletes
RFC 7489 and RFC 9091. Two consequences are worth stating plainly:

- **`pct=` earns no points.** RFC 9989 removed the tag, so a conformant receiver
  ignores it. It is still parsed and reported — receivers that have not migrated
  do honour it, which means a `pct=` below 100 now produces *inconsistent*
  enforcement across the internet — but it no longer moves the score.
- **`t=y` scores at the `none` tier.** Test mode tells receivers not to apply the
  policy, so `p=reject; t=y` provides exactly as much spoofing protection as
  `p=none`. The published policy is still shown; the score reflects what
  receivers will actually do.

| Grade | Minimum score | Additional requirement |
| --- | ---: | --- |
| A++ | 85 | DNSSEC |
| A+ | 75 | DNSSEC |
| A | 65 | DNSSEC |
| B | 50 | — |
| C | 30 | — |
| D | 10 | — |
| F | 0 | — |

DNSSEC gates every A tier because poisoned DNS can undermine the other records.
A detected wildcard TXT bug is an immediate F because it invalidates DKIM and
DMARC lookups below the domain.

### Parked domains

An explicit null-MX domain has no mail flow, so DKIM, BIMI, MTA-STS, and TLS-RPT
do not apply. It uses a separate rubric:

| Pillar | Points |
| --- | ---: |
| SPF | 30 |
| DMARC | 30 |
| DNSSEC | 25 |
| CAA | 15 |

A parked domain with null MX, `SPF -all`, `DMARC p=reject`, DNSSEC, and CAA can
therefore receive a high grade without publishing irrelevant sender controls.

### Standards-sensitive scoring behavior

- `sp` inherits `p`, and `np` inherits `sp` then `p`. Missing inheritance tags
  are not penalized; only an effectively weaker subdomain policy loses points.
- More than one SPF or DMARC policy is a permerror. Multiple versioned MTA-STS,
  TLS-RPT, or BIMI records make the feature unusable. Multiple DKIM keys for one
  selector are undefined and reported instead of choosing one silently.
- CAA and MX legitimately allow multiple records and are not treated as
  duplicates.
- SPF that exceeds 10 lookup-causing terms, has too many void lookups, or has
  multiple policies scores zero. `+all` and `?all` also score zero.
- MTA-STS discovery can be validated in-browser, but most policy hosts block
  cross-origin reads. An unfetched HTTPS policy is explicitly **unverified** and
  receives only partial credit.

## DKIM selector discovery

Normal scans combine:

1. a small built-in common-selector set;
2. selectors associated with the detected mail provider; and
3. selectors supplied by the user.

Comprehensive mode tests 1,677 vetted exact provider, generic, sequential, and
temporal selectors. The source catalog also retains two non-queryable HubSpot
prefix patterns and six excluded fixed Amazon SES guesses as metadata. Easy DKIM
uses generated tokens, and BYODKIM selectors are selected by the domain owner,
so neither has an authoritative fixed selector to guess.

The scanner:

- validates a non-empty DKIM `p=` key instead of accepting arbitrary TXT data;
- follows delegated CNAME chains with depth and loop protection;
- batches queries and reports query failures separately from no-data results;
- preserves the selector, full query name, CNAME target, and resolved key in the
  UI and exports.

For the strongest verification, supply the `s=` value from a real
`DKIM-Signature` header or a DMARC aggregate report.

Regenerate the browser catalog from a compatible Markdown table with:

```bash
npm run update:dkim-selectors -- /path/to/recognized_dkim_selectors.md
```

Running the command without a source path normalizes the existing generated
catalog and reapplies exclusions:

```bash
npm run update:dkim-selectors
```

## Languages

The application ships with complete locale bundles for:

| Code | Language |
| --- | --- |
| `en` | English |
| `de` | German / Deutsch |
| `es` | Spanish / Español |
| `fr` | French / Français |
| `it` | Italian / Italiano |
| `ja` | Japanese / 日本語 |
| `ko` | Korean / 한국어 |
| `zh-CN` | Simplified Chinese / 简体中文 |
| `zh-TW` | Traditional Chinese / 繁體中文 |

`locales/en.json` is the source of truth. Locale validation checks JSON syntax,
registry consistency, canonical keys, runtime placeholders, and the generated
English fallback. Missing translated keys fall back to English.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the translation workflow and rules for
placeholders, inline HTML, plurals, and DNS examples.

## Run locally

Requirements: [Node.js](https://nodejs.org/) 18 or newer. There are no package
dependencies to install.

```bash
git clone https://github.com/kwestic-tech/dns-email-audit.git
cd dns-email-audit
npm start
```

Open <http://localhost:8080>.

Any static HTTP server can serve the repository. Opening `index.html` directly
over `file://` also works in English; browsers block fetching the other locale
JSON files from disk, so translated interfaces require HTTP.

## Tests and developer commands

| Command | Purpose |
| --- | --- |
| `npm start` | Start the dependency-free development server on port 8080. |
| `npm run check` | Validate locale files and the generated English fallback. |
| `npm test` | Run locale validation plus 174 parser, protocol, and scoring assertions. |
| `npm run test:scoring` | Run the parser and scoring assertions only. |
| `npm run build:fallback` | Regenerate `js/locales-en.js` after editing `locales/en.json`. |
| `npm run build` | Build the allowlisted static deployment into `_site/`. |
| `npm run update:psl` | Refresh the vendored Mozilla Public Suffix List snapshot. |
| `npm run update:dkim-selectors` | Normalize or import the DKIM selector catalog. |

### Live scoring backtest

```bash
node tools/backtest.mjs --sample
node tools/backtest.mjs domains.txt
node tools/backtest.mjs domains.txt --json > results.json
node tools/backtest.mjs domains.txt --comprehensive-dkim  # maximum 5 domains
```

The backtest loads the production scoring code and reports grade distribution,
score percentiles, per-pillar adoption, and best/worst results. JSON output also
includes DKIM scan mode, selector evidence, misses, failed queries, and the
maximum possible score. It requires outbound network access and is not run in CI.

## Build and deployment

The browser application itself does not require bundling. For deployment,
`npm run build` copies only the public runtime files into `_site/`:

```bash
npm test
npm run build
```

The included GitHub Pages workflow runs the complete test suite, builds `_site`,
and deploys the artifact on pushes to `main`. The CI workflow runs `npm test` on
every pull request and push to `main`. GitHub Actions are pinned to commit SHAs.

The contents of `_site/` can also be deployed to any static host, including
Netlify, Cloudflare Pages, S3, or a conventional web server.

## Project layout

```text
dns-email-audit/
├── index.html                  # accessible, localized application markup
├── css/style.css               # responsive application and report styles
├── js/
│   ├── app.js                  # UI orchestration, rendering, filtering, exports
│   ├── dns.js                  # DNS transport, analysis, findings, and scoring
│   ├── i18n.js                 # locale loading, fallback, and safe rich text
│   ├── locales-en.js           # generated English file:// fallback
│   ├── public-suffixes.js      # generated Public Suffix List snapshot
│   └── dkim-selectors.js       # generated DKIM selector catalog
├── locales/
│   ├── index.json              # shipped-language registry
│   ├── en.json                 # source-of-truth UI text
│   └── de/es/fr/it/ja/ko/zh-*  # translated locale bundles
├── tools/
│   ├── serve.mjs               # dependency-free local server
│   ├── check-locales.mjs       # locale and fallback validation
│   ├── scoring.test.mjs        # parser, protocol, and scoring tests
│   ├── backtest.mjs            # live grade-distribution analysis
│   ├── build-site.mjs          # allowlisted `_site` build
│   ├── build-fallback.mjs      # en.json → locales-en.js
│   ├── update-psl.mjs          # Public Suffix List updater
│   └── update-dkim-selectors.mjs
├── .github/workflows/          # CI and GitHub Pages deployment
├── CHANGELOG.md
├── CONTRIBUTING.md
├── THIRD_PARTY_NOTICES.md
└── LICENSE
```

All user-facing application text lives in the locale bundles. `js/dns.js`
returns stable identifiers and structured data rather than English UI strings,
keeping audit logic independent from translation work.

## Privacy and browser security

- DNS requests go directly from the browser to `cloudflare-dns.com`.
- Audit results are not sent to Kwestic or written to persistent storage.
- The selected language is stored in `localStorage`.
- A restrictive Content Security Policy allows same-origin runtime assets,
  limits external connections to Cloudflare DNS-over-HTTPS, and restricts
  scripts, frames, objects, forms, and referrer data.
- DNS-derived output is escaped, and translated rich HTML is sanitized through
  an allowlist before rendering.
- Uploaded domain files are processed locally and limited to 1 MB.
- Generated HTML reports are self-contained and contain no executable scripts.

## Known limitations

- DNS cannot enumerate DKIM selectors; comprehensive mode improves coverage but
  cannot prove that no other selector exists.
- Browser CORS restrictions prevent reliable HTTPS policy retrieval for most
  MTA-STS hosts, so policy enforcement remains unverified.
- DNS, email-provider, and hosting detection use public records and heuristics;
  unusual or private infrastructure may be labeled custom or unknown.
- DNSSEC status reflects validation performed by the configured Cloudflare DoH
  resolver rather than an independent local validating resolver.

## Contributing

Bug reports, protocol corrections, provider-detection additions, DKIM catalog
updates, translations, and tests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © Kwestic LLC (Kwestic Media and Technology)
