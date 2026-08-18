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

- **DMARC is now evaluated against RFC 9989 (DMARCbis, May 2026)** instead of
  RFC 7489 + RFC 9091, which it obsoletes. The parser accepts the complete
  RFC 9989 tag set — `v`, `p`, `sp`, `np`, `adkim`, `aspf`, `fo`, `rua`, `ruf`,
  `psd`, `t` — and classifies anything else as removed (`pct`, `rf`, `ri`) or
  unknown.
- **`pct=` no longer contributes to the score.** RFC 9989 removed the tag, so a
  conformant receiver ignores it; scoring it meant grading against an obsolete
  spec. It is still parsed and surfaced: any record carrying `pct=` now gets a
  **recommendation** to remove it, naming RFC 9989 and its May 2026
  ratification, with a "Learn more" guide covering the migration. Advice to
  drop an obsolete tag is guidance rather than a defect, so it sits in
  Recommendations rather than Issues — but a `pct=` below 100 has a live
  consequence (receivers that have not migrated still honour it, so
  enforcement differs from one receiver to the next) and keeps its own
  warning-level finding.
- **The DMARC sub-score redistributes those 4 points.** New split: policy 12
  (was 10), effective subdomain coverage 6, aggregate reports 6 (was 5), strict
  alignment 3, forensic reports 2, and a new 1-point component for report
  destinations that can actually be delivered to. The total is unchanged at 30.
  Backtested over the 40-domain live sample: 29 domains scored identically, 11
  moved by 1–3 points, and **no domain changed letter grade**.
- The score breakdown now shows a "Report destinations" component in place of
  "Enforcement rate (pct=)".
- CSV export gains a `DMARC Test Mode (t=)` column (inserted after
  `DMARC Policy`). The header row is now backfilled per-index from English, so
  a locale whose header array predates a new column can no longer misalign the
  export.

### Added

- **`t=` (test mode) support.** `t=y` tells receivers not to apply the policy,
  so `p=reject; t=y` is scored at the `none` tier and badged as
  "reject (test mode, not applied)" rather than as enforcement. This was
  previously invisible: the record would have graded as full enforcement.
- **`psd=` parsing and validation**, including a warning when a domain that is
  not a public suffix declares `psd=y`.
- **Strict `v=` validation.** RFC 9989 requires `v=` to be the first tag with
  the case-sensitive value `DMARC1`; a record failing either test must be
  ignored entirely. `v=dmarc1` and a misplaced `v=` are now reported as
  critical findings rather than parsed as valid.
- **Report-URI parsing for `rua=`/`ruf=`**, covering the comma-separated list
  form, the `!` size-limit suffix, and unsupported schemes. A published but
  undeliverable destination is now a finding instead of a silent monitoring gap.
- **External report-destination detection and verification.** Reports sent
  outside the organizational domain require the destination to publish an
  authorization record (RFC 9990 §4.3). The audit now queries
  `<policy-domain>._report._dmarc.<destination>` and falls back to the
  wildcard form `*._report._dmarc.<destination>` that most reporting vendors
  publish, then reports a verdict per destination:
  - **authorized** — no finding at all. A correctly-configured domain hears
    nothing, which is the point: the previous blanket "verify this" notice
    fired on every external destination and was a false positive on every
    properly set-up domain (cloudflare.com and paypal.com both included).
  - **unauthorized** — a warning naming only the destinations that are
    actually being discarded.
  - **unverifiable** — an informational note when the DNS lookup itself
    failed. A timeout is missing evidence, not evidence of a missing record.

  Authorization is evaluated per URI, matching the RFC, so a record mixing an
  in-house mailbox with a vendor address is scored and reported correctly: the
  record stays valid, and only the unauthorized destination is flagged. When
  the advanced checks are off, the previous advisory notice remains as a
  fallback.
- **`fo=` validation**, plus a notice when `fo=` is present with no `ruf=`,
  where receivers must ignore it.
- Duplicate DMARC tags now report as their own finding rather than as
  "invalid p=".
- **A `dmarc-rfc9989` "Learn more" guide** explaining what DMARCbis changed:
  the RFC 9989/9990/9991 split, why `pct=` was removed, how `t=` replaces it
  for staged rollout, the complete eleven-tag vocabulary, and external report
  authorization.
- 119 new assertions covering the above (`npm run test:scoring`), including
  checks that every recommendation has translated text and that no
  recommendation links to a guide that does not exist.

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
