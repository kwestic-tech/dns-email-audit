# DNS & Email Security Auditor

[![CI](https://github.com/kwestic-tech/dns-email-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/kwestic-tech/dns-email-audit/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/kwestic-tech/dns-email-audit/blob/main/LICENSE)

A free browser application with no runtime dependencies for auditing DNS,
email authentication, mail-transport security, and related domain controls.
Audit up to 200 domains at once and get evidence-backed findings, a
confidence-aware grade, plain-language explanations, and copy-ready
remediation examples.

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
- Controls that public DNS cannot confirm are scored as unconfigured, and every
  one of them is named with the step that recovers the points.
- Search, filters, sortable results, expandable evidence, CSV export, and a
  self-contained script-free HTML report.
- A versioned JSON report, and comparison of two of them entirely in the
  browser: new, resolved and changed findings, record deltas, and score movement
  per domain. Nothing is stored — the comparison lives in the tab and is gone on
  exit or reload.
- Stable structured findings with five severity levels, confidence, source-bound
  DNS evidence, and a dependency-ordered remediation view. CSV exports finding
  ids, severities and the first remediation step alongside the legacy columns.
- Private local validation for a supplied MTA-STS policy or BIMI SVG logo,
  with strict pre-parse limits, explicit user-supplied provenance, and no
  upload, persistence, score change, automatic fetch, or logo rendering.
- Complete UI localization in fourteen languages: English, German, Spanish,
  French, Indonesian, Italian, Japanese, Korean, Dutch, Polish, Brazilian
  Portuguese, Turkish, Simplified Chinese, and Traditional Chinese.
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
| **SPF authorized range size** | Classifies every `ip4:`/`ip6:` block by how much address space it authorizes, on separate tables per family — IPv4 by host count, IPv6 by allocation tier, so a `/64` is read as the standard single-subnet allocation it is (RFC 4291 §2.5.4) rather than as 2^64 hosts. Advisory: it reports size, not ownership. |
| **SPF redundancy** | Flags `a`/`mx` mechanisms whose resolved addresses an `ip4:`/`ip6:` block in the same record already authorizes, so the lookup they spend can be reclaimed against the 10-lookup limit. Requires *both* address families to be covered before recommending removal. Advisory. |
| **DKIM** | Tests common, provider-associated, user-supplied, or comprehensive catalog selectors; follows CNAME delegation and requires an active public key. |
| **DMARC** | Validates against RFC 9989 (DMARCbis): record uniqueness, strict `v=` placement and casing, the full tag set (`p`, `sp`, `np`, `adkim`, `aspf`, `fo`, `rua`, `ruf`, `psd`, `t`), report-URI syntax, and tags the new RFC removed (`pct`, `rf`, `ri`) or does not define; discovers inherited organizational-domain policies with the RFC 9989 DNS Tree Walk. |
| **DMARC test mode** | Detects `t=y`, which tells receivers not to apply the policy — so `p=reject; t=y` is reported and scored as `none` rather than as enforcement. |
| **DMARC report authorization** | For report destinations outside your organizational domain, checks whether that domain published the `_report._dmarc` record (RFC 9990 §4.3), including the wildcard form. Without it receivers discard those reports silently. |
| **DNSSEC** | Six states — secure, insecure, signed-but-unanchored, DS/DNSKEY mismatch, bogus and indeterminate — from the resolver's authenticated-data flag, with the child's `DNSKEY` set matched against the parent's `DS` records locally by Web Crypto. Every claim is attributed to the resolver or to local computation. When validation itself causes SERVFAIL, the audit preserves that bogus verdict and uses checking-disabled responses only to render the diagnostic row. |
| **CAA** | Walks up the domain tree to find the effective certificate-authority restrictions. |
| **MTA-STS** | Validates discovery-record uniqueness and syntax, including the required `id=` tag. A separate local panel validates a supplied policy body, its mode and cache lifetime, and its `mx` patterns against the audited delivery candidates. |
| **TLS-RPT** | Validates uniqueness, syntax, and the required supported `rua=` destination. |
| **BIMI** | Validates uniqueness, BIMI syntax, and an HTTPS logo URL. The local panel screens a supplied SVG for active or external content and reports named SVG Tiny PS profile diagnostics without rendering it. |
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

After an audit completes, **Export JSON** saves the run as a versioned report:
the same facts the table shows, normalized, with the options that were in force,
the resolver used, and the analysis version that scored it. **Import report**
then compares a saved report against what is on screen, or — with no audit
running — against a second saved report.

The comparison is honest about what it cannot say. A protocol one report did not
observe is marked, with its reason, rather than counted as fixed; two reports
scored by different analysis versions show their findings without a score delta;
and two reports from different releases show what moved without calling it
resolved, because a release can add or correct a finding on its own. A file that
is not a report from this tool, or is malformed, is refused with the field that
failed rather than partially loaded.

After an audit completes, open **Validate a local MTA-STS policy or BIMI logo**
below the results. Select one completed domain, paste the policy or SVG source
or choose its local file, then run the analysis. These findings describe only
the material you supplied; they appear separately from public-DNS findings and
are discarded when the page reloads.

## Confidence and unknown results

Some controls cannot be conclusively disproved through DNS alone. DKIM selectors,
for example, cannot be enumerated; failing to find a guessed selector does not
prove a sender is unsigned. DNSSEC validation can also be indeterminate when the
resolver request fails.

The auditor preserves that uncertainty:

- observed active controls receive their normal score;
- confirmed missing or invalid controls score accordingly;
- a control this tool could not confirm scores zero, exactly like one that is
  genuinely absent — the grade is always a single letter, never a range;
- a grade resting on such a control is drawn with a dashed border and an
  asterisk (`B*`), in its own tier colour, so a recoverable check is visible
  while scanning the table rather than only inside an expanded row;
- because that costs real points, every unconfirmed control is named in the
  results together with the step that recovers them. Inconclusive DKIM points
  at the **Additional DKIM selectors** field; indeterminate DNSSEC asks for a
  re-run; disabling DKIM checking reports **Not checked** and says what it cost;
- a check whose DNS lookup fails outright is treated the same way. A SERVFAIL or
  timeout on CAA, MTA-STS, TLS-RPT, BIMI, the SPF lookup count or website hosting
  leaves the rest of the audit intact, and the affected checks are named so a
  re-run can settle them.

Only the core `NS`, `MX`, `TXT` and `_dmarc` lookups are fail-closed. Without
them there is nothing to audit, so the domain is reported as an error rather
than scored on partial data. Everything else degrades. A transient resolver
failure on an optional check must never discard a complete, valid audit — nor
be recorded as a missing record, which would lower a grade for our failed query
rather than the domain's configuration.

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
| `id` | Indonesian / Bahasa Indonesia |
| `it` | Italian / Italiano |
| `ja` | Japanese / 日本語 |
| `ko` | Korean / 한국어 |
| `nl` | Dutch / Nederlands |
| `pl` | Polish / Polski |
| `pt-BR` | Brazilian Portuguese / Português (BR) |
| `tr` | Turkish / Türkçe |
| `zh-CN` | Simplified Chinese / 简体中文 |
| `zh-TW` | Traditional Chinese / 繁體中文 |

`locales/en.json` is the source of truth. Locale validation checks JSON syntax,
registry consistency, canonical keys, runtime placeholders, and the generated
English fallback. Missing translated keys fall back to English.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the translation workflow and rules for
placeholders, inline HTML, plurals, and DNS examples.

## Run locally

Requirements: [Node.js](https://nodejs.org/) 20 or newer. A clean checkout
needs the exact-pinned build dependency installed and the browser artifact
built before it can be served:

```bash
git clone https://github.com/kwestic-tech/dns-email-audit.git
cd dns-email-audit
npm ci
npm run build
npm start
```

Open <http://localhost:8080>.

Any static HTTP server can serve the repository after `npm run build` has
created `dist/app.min.js`. Opening `index.html` directly over `file://` also
works in English after that build; browsers block fetching the other locale
JSON files from disk, so translated interfaces require HTTP.

## Tests and developer commands

| Command | Purpose |
| --- | --- |
| `npm ci` | Install exact versions of esbuild and its platform binary; no install scripts run. |
| `npm start` | Serve the already-built application on port 8080 with the dependency-free development server. |
| `npm run check` | Validate locale files and the generated English fallback. |
| `npm test` | Build the bundle, then run locale validation plus **5,491** parser, protocol, scoring, rendering, export, contract and artifact assertions. |
| `npm run test:scoring` | Run the parser and scoring assertions only. |
| `npm run test:render` | Run the rendering, interpolation, export and CSP assertions only. |
| `npm run build:fallback` | Regenerate `src/data/locales-en.js` after editing `locales/en.json`. |
| `npm run build` | Bundle `src/` into `dist/app.min.js`, then build the allowlisted static deployment into `_site/`. |
| `npm run inventory` | Run every suite and check each one's assertion count against `tests/inventory.json`. |
| `npm run test:file-url` | Open the built page from `file://` in real Chrome. |
| `npm run test:local-input-security` | Drive hostile and conformant local artifacts through the production panel in real Chrome while observing network, storage, and DOM insertion. |
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

The browser loads `dist/app.min.js`, so a source checkout must be bundled
before it can run. `npm run build` creates that artifact and then copies only
the public runtime files into `_site/` for deployment:

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
├── src/                        # the application — ES modules
│   ├── main.js                 # entry point: platform, one runtime, the facade
│   ├── runtime.js              # composition root
│   ├── core/dns/               # DoH transport, cache, resolver, cancellation
│   ├── core/spf|dkim|dmarc|…/  # one directory per protocol, plus shared/
│   ├── audit/                  # which checks run, scoring, findings, observability
│   ├── providers/              # DNS, email and hosting detection
│   ├── ui/                     # render.js, report.js, report-data.js, events.js
│   ├── i18n/index.js           # locale loading, fallback, and safe rich text
│   └── data/                   # generated: locales-en, public suffixes, DKIM
├── dist/app.min.js             # the built artifact — what the browser loads
├── locales/
│   ├── index.json              # shipped-language registry
│   ├── en.json                 # source-of-truth UI text
│   └── de/es/fr/it/ja/ko/zh-*  # translated locale bundles
├── tests/
│   ├── contract/               # allowed imports, transport kinds, namespace
│   ├── build/                  # artifact, parity, equivalence, file:// in Chrome
│   └── fixtures/equivalence/   # the corpus and its committed release baselines
├── tools/
│   ├── serve.mjs               # dependency-free local server
│   ├── build-bundle.mjs        # esbuild → dist/app.min.js
│   ├── build-site.mjs          # allowlisted `_site` build
│   ├── check-locales.mjs       # locale and fallback validation
│   ├── scoring.test.mjs        # parser, protocol, and scoring tests
│   ├── backtest.mjs            # live grade-distribution analysis
│   ├── build-fallback.mjs      # en.json → src/data/locales-en.js
│   ├── update-psl.mjs          # Public Suffix List updater
│   └── update-dkim-selectors.mjs
├── .github/workflows/          # CI and GitHub Pages deployment
├── CHANGELOG.md
├── CONTRIBUTING.md
├── THIRD_PARTY_NOTICES.md
└── LICENSE
```

**The source is `src/`; the artifact is `dist/app.min.js`.** `index.html` loads
the artifact and nothing else — one script tag, a classic script rather than a
module so the page still opens from `file://`. Edit `src/`, run
`npm run build`, and the browser sees the change. `AGENTS.md` carries the
directory ownership table and the allowed-import matrix, which a contract test
enforces.

All user-facing application text lives in the locale bundles. The protocol and
audit layers return stable identifiers and structured data rather than English
UI strings, keeping audit logic independent from translation work.

## Privacy and browser security

- DNS requests go directly from the browser to `cloudflare-dns.com`.
- Audit results are not sent to Kwestic or written to persistent storage.
- The selected language is stored in `localStorage`.
- No cookies are set. Unlike a cookie, `localStorage` is never transmitted
  over the network — it stays on the device and is never sent to this app's
  host, to Cloudflare, or anywhere else.
- The `dns-email-audit-lang` key has no expiration; it persists until the
  user or browser clears site data. See [PRIVACY.md](PRIVACY.md) for the
  full policy and [SECURITY.md](SECURITY.md) for vulnerability reporting.
- One audit is many DNS queries, not one: a typical domain fans out to
  roughly 41 with the default options, and following the SPF `include:` chain
  means Cloudflare also sees the audited domain's email vendor hostnames. See
  [PRIVACY.md](PRIVACY.md#what-cloudflare-can-see) for detail.
- A restrictive Content Security Policy allows same-origin runtime assets,
  limits external connections to Cloudflare DNS-over-HTTPS, and restricts
  scripts, frames, objects, forms, and referrer data.
- DNS-derived output is inserted as text nodes and never parsed as markup. No
  file under `src/` assigns to `innerHTML` or `outerHTML`; the allowlist for
  that rule is empty and enforced by both a runtime setter trap in the test
  DOM and a static scan in `npm test`. Translated rich text is tokenized
  against a twelve-tag allowlist, and anything outside it is rendered as
  literal text rather than markup.
- Records that render deceptively are shown, not hidden. Characters Unicode
  marks `Default_Ignorable` — bidirectional overrides, zero-width and invisible
  characters — plus C0/C1 controls are replaced in the display by a visible
  marker naming the code point (`‹RLO›`, `‹ZWSP›`, `‹U+0007›`), so the character
  cannot reorder the text and the reader can still see that it was published.
  Three families are deliberately exempt because they are legitimate content:
  variation selectors, and shorthand and musical notation format controls.
  Script-format characters such as the Arabic number signs are not
  default-ignorable at all, so Arabic, Syriac and Egyptian text renders
  normally. Both exports name what was found in a separate `Record Hygiene`
  column, and neither substitutes a marker into the data.
- **The CSV export is spreadsheet-safe, with one documented limit.** A domain
  controls its own record text, and a cell beginning `=`, `+`, `-`, `@`, or a
  tab/newline is executed as a formula when a CSV is opened in Excel or Google
  Sheets — RFC 4180 quoting does not prevent this, because the quotes are
  stripped before the cell is evaluated. Any such cell is prefixed with an
  apostrophe, which makes the spreadsheet treat the cell as text rather than a
  formula, and the row is marked `formula-leading` in the `Record Hygiene`
  column. On CSV import the apostrophe is visible in the cell — it is hidden
  only when one is typed into a cell directly — so the neutralisation is
  disclosed twice: in the data and in the hygiene column.

  This is the only place the CSV departs from the published bytes; every other
  character, including invisible ones, is exported exactly as received. The
  prefix is a *display-time* mitigation: OWASP notes that Excel may drop it if
  the file is re-saved as CSV from within Excel and then reopened, and that no
  single escaping strategy is safe across every spreadsheet application. If you
  need the bytes exactly as published, read the HTML report or the results
  table rather than the CSV.
- Uploaded domain files are processed locally and limited to 1 MB.
- Supplied MTA-STS and BIMI artifacts stay in memory, are limited to 64 KiB and
  32 KiB respectively before parsing, never affect the DNS score, and are
  discarded on reload.
- Generated HTML reports are self-contained and contain no executable scripts.

## Known limitations

- DNS cannot enumerate DKIM selectors; comprehensive mode improves coverage but
  cannot prove that no other selector exists.
- Browser CORS restrictions prevent reliable automatic HTTPS policy retrieval
  for most MTA-STS hosts. The DNS-only result therefore remains unverified;
  operators can validate a policy they already possess in the local panel.
- DNS, email-provider, and hosting detection use public records and heuristics;
  unusual or private infrastructure may be labeled custom or unknown.
- Report comparison is between exactly two reports, bounded to 200 domains and
  8 MB per file, and holds no history: there is no trend over time, because
  keeping one would mean storing audits, which this tool does not do.
- DNSSEC status reflects validation performed by the configured Cloudflare DoH
  resolver rather than an independent local validating resolver. The `DS`-to-
  `DNSKEY` digest matching this tool performs locally is diagnostic evidence
  beside that verdict, never a substitute for it: signatures are not verified,
  so a zone whose DS matches perfectly can still be failing validation.

## Contributing

Bug reports, protocol corrections, provider-detection additions, DKIM catalog
updates, translations, and tests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © Kwestic LLC (Kwestic Media and Technology)
