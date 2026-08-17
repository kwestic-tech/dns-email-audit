# Changelog

All notable changes to this project are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **A note for translators while the project is at 0.x:** the key structure in
> `locales/en.json` is not frozen yet. Keys may be renamed or restructured
> between minor releases as the first translations reveal what needs splitting
> or merging. `npm run check` will flag any of your keys that no longer exist
> upstream after you pull. From 1.0.0 onward, a key rename will be treated as a
> breaking change and will only happen in a major release.

## [Unreleased]

### Changed

- **Scoring is now a single weighted 0–100 rubric** instead of an additive
  points-to-grade shortcut. Pillars: DMARC 30, SPF 15, DKIM 15, DNSSEC 15,
  CAA 10, MTA-STS 8, BIMI 4, TLS-RPT 3. DNSSEC still gates the A tier — an
  unsigned zone caps the grade at B regardless of everything else.
- TLS-RPT now contributes to the score. Previously it was displayed in the
  advanced strip but had no effect on the grade.
- The `A` grade is reachable again. Thresholds are 85 (A++), 75 (A+), 65 (A),
  50 (B), 30 (C), 10 (D), all A tiers requiring DNSSEC.
- Parked domains (no MX) are scored on their own rubric — SPF 30, DMARC 30,
  DNSSEC 25, CAA 15 — since DKIM, BIMI, MTA-STS and TLS-RPT cannot apply to a
  domain with no mail flow. A fully hardened parked domain can now reach the
  A tier rather than being capped at B.
- CSV export gained Grade, Score, and the full DMARC tag set (`sp`, `np`,
  `pct`, `adkim`, `aspf`, `ruf`). The grade was previously absent entirely.

### Added

- Full DMARC tag parsing per RFC 7489 and RFC 9091: `sp`, `np`, `pct`,
  `adkim`, `aspf`, `ruf`, with the documented inheritance chain
  (`np` → `sp` → `p`) resolved into `effectiveSp` / `effectiveNp`.
- Per-pillar score breakdown in each domain's detail row, including the DMARC
  sub-score components, so a grade can be explained rather than just asserted.
- New checks: `dmarc-quarantine` (harden to reject), `dmarc-weak-sp`,
  `dmarc-weak-np`, `dmarc-partial-pct`, `dmarc-bad-pct`,
  `dmarc-invalid-policy` — each with a full explainer and example records.
- Duplicate-record detection for all six record types that fail closed with
  more than one record: SPF (RFC 7208 §4.5), DMARC (RFC 7489 §6.6.3), MTA-STS
  (RFC 8461 §3.1), TLS-RPT (RFC 8460 §3), BIMI (draft §7.2) and DKIM keys per
  selector (RFC 6376 §3.6.2.2). Each scores zero for its pillar and raises a
  dedicated issue with merge instructions — previously the first record was
  silently used and the domain scored as if correctly configured. CAA and MX are
  excluded: multiple records there are legitimate.
- `npm run test:scoring` — 125 assertions over the parser, sub-scores, grade
  ladder, rubric integrity, duplicate-record handling and issue detection.
- `tools/backtest.mjs` — runs the real scoring code against live domains and
  prints the grade distribution, score percentiles and per-pillar adoption, for
  validating threshold changes.

### Fixed

- DMARC records were selected with a case-sensitive prefix match, so a valid
  `V=DMARC1` record was reported as **missing** and the domain scored as having
  no DMARC at all. Same bug affected SPF, DKIM, BIMI, MTA-STS and TLS-RPT
  record selection.
- A `pct=` value that wasn't a number produced `NaN`, which propagated through
  the total and silently graded the domain **F**. Out-of-range values are now
  clamped and flagged.
- An unrecognised `p=` value (typo, unsupported keyword) was treated as
  `p=none` and earned partial credit. Receivers cannot act on it, so it now
  scores zero and raises a critical issue.
- Subdomain policy was previously unscored: `p=reject` with no `sp` tag is
  fully protective via inheritance, but any rubric keyed on tag *presence*
  penalises it. Scoring now uses the effective policy, so explicit and
  inherited protection score equally and only genuine weakening (`sp=none`)
  costs points.
- An SPF record exceeding the 10-lookup limit evaluates to `permerror` and
  never passes, but scored full marks for a strict `-all`. It now scores zero.
- `+all` and `?all` no longer earn partial SPF credit, while a missing provider
  include — a real record one line short — still does.
- DKIM key extraction took `txt[0]` after testing whether *any* record at the
  selector was a key, so an unrelated TXT record sharing the selector name could
  be reported as the DKIM key. It now filters to `v=DKIM1` records first.
- "Not configured" recommendations for MTA-STS, TLS-RPT and BIMI are suppressed
  when the record exists but is duplicated — telling someone to publish a record
  they already have twice is actively misleading.

## [0.1.0] — 2026-08-17

First public release.

### Added

- Audits SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT, CAA and DNSSEC for up to 200
  domains per run, entirely client-side via Cloudflare DNS-over-HTTPS.
- Detects DNS provider, email provider and website hosting from NS, MX, A and
  CNAME records, including self-hosted setups and ccSLD domains.
- SPF lookup-depth analysis that follows `include:` and `redirect=` one level
  deep and warns before the hard 10-lookup limit.
- Wildcard TXT detection — catches a `* TXT` record silently breaking DKIM and
  DMARC on every subdomain.
- Letter grading (A++ through F) with DNSSEC as a hard gate on any A grade, and
  a separate scoring path for parked domains with no email.
- Plain-language explanation and copy-paste DNS records for every issue found,
  behind a "Show me" toggle.
- Long-form guides for BIMI, MTA-STS, TLS-RPT, CAA and DNSSEC, opened in a new
  tab as self-contained pages.
- CSV export and a self-contained, script-free HTML report.
- Filter, search and sort across results; per-domain detail rows.
- Internationalization: English and Spanish, with a dependency-free JSON
  translation layer. Missing keys fall back to English, so partial translations
  are usable.
- `npm run check` validates every locale against `en.json` — placeholder
  mismatches and stale keys fail CI, missing keys only warn.
- GitHub Actions workflows for Pages deployment and locale validation.

### Notes

- Spanish ships at roughly 40% coverage; the remainder falls back to English.
- No backend, no build step, no runtime dependencies. Opening `index.html`
  directly from disk works in English — browsers block `fetch()` of local JSON
  over `file://`, so other languages need the app served over HTTP.

[Unreleased]: https://github.com/kwestic-tech/dns-email-audit/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/kwestic-tech/dns-email-audit/releases/tag/v0.1.0
