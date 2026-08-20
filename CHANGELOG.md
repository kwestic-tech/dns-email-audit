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

Nothing yet.

## [0.2.0] — 2026-08-20

### Added

- **SPF authorized-range size audit.** Every `ip4:`/`ip6:` block in a record is
  classified by how much address space it authorizes. IPv4 is judged on host
  count — a `/24` is 256 addresses that can all send as you. IPv6 is judged on
  allocation tier and deliberately does *not* reuse the IPv4 table: RFC 4291
  §2.5.4 makes `/64` the standard single-subnet allocation, frequently one mail
  server, and the `2^n` reasoning that makes an IPv4 `/24` worth a look would
  rate that same `/64` as eighteen quintillion hosts and flag it hardest of all.
  `nih.gov` publishes four of them and they are unremarkable. Single-host blocks
  are classified but never surfaced as findings — `stanford.edu` publishes 15
  `ip4:` mechanisms, 13 of them `/32`, and a line each saying "this is one host"
  buries everything worth reading.
- **SPF redundancy audit.** An `a` or `mx` mechanism spends one of the 10
  permitted DNS lookups. When every address it resolves to already sits inside
  an `ip4:`/`ip6:` block written into the same record, that lookup buys no
  authorization and can be reclaimed. `python.org` is a live example: its `mx`
  resolves to exactly the two addresses its own `ip4:`/`ip6:` mechanisms list,
  and removing it takes the record from 8 lookups to 7 — out of the near-limit
  warning band — with no change to which servers can send.

  Removal is only ever recommended when **both** address families are fully
  covered. A hostname with an `AAAA` record, in a record carrying no `ip6:`
  mechanism, is never flagged: the IPv4 side looks fully covered, and acting on
  that would silently drop IPv6 authorization. Partial coverage is reported as
  an informational note instead, so the finding is not lost and the mechanism
  is not deleted while it is still doing real work.

  Both checks are advisory and feed no part of the weighted rubric — verified
  by a before/after back-test showing no grade or score movement across the
  40-domain sample. They cost no DNS lookups at all on records with no
  `ip4:`/`ip6:` block, which is most of them.
- **`PRIVACY.md` and `SECURITY.md`,** linked from the options row, the "How it
  works" callout and the page footer in all nine shipped locales, with the link
  labels translated like every other string in the app. `PRIVACY.md` documents
  the whole footprint: one `localStorage` key (`dns-email-audit-lang`, written
  only when the language selector is used), no cookies, no analytics, no
  backend. It also states what the app does *not* hide — one audit is roughly
  30 DNS queries, not one, and because the SPF `include:` chain is resolved,
  the query pattern reveals which email and SaaS vendors the audited domain
  uses, not merely that someone looked it up. Documentation only; nothing about
  what the app stores or transmits changed.

### Fixed

- **A failed optional DNS lookup no longer discards the whole audit.** Every
  check behind `www`, `wildcard` and the advanced set threw on SERVFAIL, and
  because nothing caught the throw the entire result was dropped — SPF, DKIM,
  DMARC, MX and all — for a domain whose core records had resolved perfectly.
  A transient resolver failure on website-hosting detection was enough to
  delete a complete email-security audit. Across a 200-domain run that is close
  to certain to hit someone. Optional checks now degrade to a stated unknown
  and the audit completes.
- **A failed optional lookup is named instead of passed over.** CAA, MTA-STS,
  BIMI, TLS-RPT and the SPF lookup count each record whether their lookup
  actually answered, and any that did not are listed in the results by name so
  a re-run can settle them. They are scored as unconfigured — see the grading
  change below.
- **A failed wildcard probe is no longer read as "no wildcard".** Each depth
  stays explicitly false until its own probe answers.
- **The wildcard TXT check no longer fails domains it cannot be harming.** The
  probe asked one label deep, at `_wildcardtest99xyz.<domain>`, but inferred
  harm to DKIM discovery, which happens two labels deep at
  `<selector>._domainkey.<domain>`. It measured at a depth that does not
  predict the harm. `apple.com` and `ibm.com` both scored F (0/100) on the
  strength of an apex wildcard that never reaches DKIM — Apple's is a
  deliberate anti-spoofing measure, `*.apple.com IN TXT "v=spf1
  redirect=_spf.apple.com"`, so that mail from an invented subdomain meets a
  real SPF policy instead of finding none. Two of the three F verdicts in a
  15-domain survey were wrong. The probe now runs at both depths and the
  verdict follows the one that was actually measured.
- **No "you have not configured this" advice for checks that never ran.**
  The CAA, MTA-STS, TLS-RPT, BIMI and DNSSEC recommendations are suppressed
  when the corresponding lookup did not complete.
- **DKIM issue notes interpolate their counts.** `dkim-unverified` and
  `dkim-missing` rendered the literal `{0}` and `{1}` placeholders because the
  selector counts were never passed to the renderer. This note becomes far more
  common once failed lookups stop aborting the audit.

### Added

- A `checks-unverified` finding naming exactly which checks could not be
  completed, so a gap in the audit is stated rather than silently omitted.
- A `@dns-error` hosting state ("Lookup failed") distinct from a domain that
  genuinely has no web presence.
- `optionalCheck()`, the single wrapper all optional checks route through. It
  converts a DNS failure into a declared fallback and deliberately re-throws
  `AbortError`, so cancelling an audit is never mistaken for an unknown result.
- 32 new assertions, including a simulated resolver in which only the core
  records answer and every optional lookup returns SERVFAIL.

### Unchanged

- Core lookups stay fail-closed. With no usable NS response there is nothing to
  audit, and reporting a failure remains better than inventing a result.

### Changed

- **Grades are always a single letter — the floor–ceiling range is gone.** An
  unverifiable control used to be left unscored, which produced a two-letter
  grade like `C–B`, or `B–A+` in the worst case observed. Across a 40-domain
  live sample, 9 domains (22.5%) displayed one. A range reads as an error
  rather than a result and told nobody what to do next. Unproven controls now
  score zero, exactly like the parked-domain rubric has always scored them, and
  `grade`, `pts` and `cls` are the only score fields the UI reads
  (`gradeMin`, `gradeMax`, `maxPossible` and `uncertain` are removed).
- **A grade resting on an unverified check is marked in the results table.**
  The circle is drawn with a dashed border in its own tier colour and the
  letter carries an asterisk — `B*` rather than `B` — so a recoverable check is
  visible while scanning a 200-domain table, without expanding a row. The
  marker is display-only: `pts`, `grade` and `cls` are untouched, and the score
  object carries a new `unproven` array naming the pillars behind it. It covers
  DKIM (sampled or not checked), indeterminate DNSSEC, and any failed CAA,
  MTA-STS, BIMI or TLS-RPT lookup. It deliberately does not read as a warning:
  the tier colour is kept, because the grade is the real grade.
- **Every unproven control now states what it cost and how to recover it.**
  Because uncertainty is no longer free, `dkim-unverified` and
  `dnssec-indeterminate` are warnings rather than notes: the first names the
  **Additional DKIM selectors** field, the second asks for a re-run first and
  then gives the evidence a GitHub issue needs. `checks-unverified` likewise
  warns and says a re-run recovers the points. A new `dkim-not-checked` note
  covers the domain audited with DKIM checking switched off, which would
  otherwise have dropped 15 points in silence.
- **A wildcard TXT record no longer scores an instant F.** Even where the
  wildcard genuinely does cover `_domainkey` — `netflix.com` is the one case in
  the survey where it does — F=0 was the wrong answer. A poisoned `_domainkey`
  makes DKIM *absence* unverifiable; it leaves SPF, DMARC, DNSSEC and CAA
  perfectly measurable, and selectors that are published still resolve and
  still verify. DKIM now routes into the existing confidence machinery
  (`sampled` confidence, `noteWildcard`, `dkim-unverified`) and the remaining
  pillars stand on their own, which is how every other uncertainty in this
  project is already handled.
- **The two wildcard depths are reported separately.** A wildcard only the apex
  probe sees is an informational finding with no score effect
  (`wildcard-txt-apex`); one that reaches `_domainkey` is a warning
  (`wildcard-txt-dkim`). The old blanket `wildcard-txt` critical issue is gone.
- **A value synthesized by a `_domainkey` wildcard is no longer accepted as a
  DKIM key.** A wildcard whose value happens to parse as a key would otherwise
  report DKIM present at every selector tried, which is worse than reporting
  none. Such values are discarded by content.
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

[Unreleased]: https://github.com/kwestic-tech/dns-email-audit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/kwestic-tech/dns-email-audit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/kwestic-tech/dns-email-audit/releases/tag/v0.1.0
