# DNS &amp; Email Security Auditor

A free, browser-based auditor for DNS and email authentication. Paste up to 200 domains and get SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT, CAA and DNSSEC results with a letter grade, plain-language explanations of every problem, and copy-paste DNS records to fix them.

Every query runs client-side against [Cloudflare's DNS-over-HTTPS API](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/). There is no backend, signup, or analytics, and the app does not send data to Kwestic or store audit results. DNS query names are sent directly to Cloudflare and are subject to Cloudflare's privacy policy.

**[▶ Live demo](https://kwestic-tech.github.io/dns-email-audit/)**

---

## What it checks

| Check | What it tells you |
| --- | --- |
| **NS** | Which DNS provider hosts the zone |
| **MX** | Which email provider receives mail |
| **SPF** | Whether authorized senders are declared, and how strictly (`-all` / `~all` / `?all` / `+all`) |
| **SPF lookup depth** | Recursively evaluates lookup-causing terms, includes, redirects, cycles and void lookups against RFC 7208 limits |
| **DKIM** | Probes common and user-supplied selectors; an unsuccessful sample is reported as unknown, not proof that DKIM is absent |
| **DMARC** | Whether a policy exists, and whether it's `none`, `quarantine` or `reject` |
| **BIMI** | Whether a logo record is published |
| **MTA-STS** | Whether the discovery TXT record is structurally valid; the HTTPS policy remains unverified in the browser-only build |
| **TLS-RPT** | Whether TLS failure reports are configured |
| **CAA** | Which certificate authorities may issue certs (walks up the domain tree) |
| **DNSSEC** | Whether responses validate (AD flag) |
| **Wildcard TXT** | Detects a `* TXT` record, which silently breaks DKIM and DMARC on every subdomain |
| **Duplicate records** | Flags more than one SPF, DMARC, DKIM, BIMI, MTA-STS or TLS-RPT record — every one of these fails closed per its RFC |

Results export to CSV (for spreadsheets) or to a self-contained HTML report (for sharing).

---

## Running it

It's a static site with no build step and no dependencies.

```bash
git clone https://github.com/kwestic-tech/dns-email-audit.git
cd dns-email-audit
npm start           # → http://localhost:8080
```

Any static server works — `python3 -m http.server 8080`, `npx serve`, whatever you have.

You can also open `index.html` straight from disk. It works, in English only: browsers block `fetch()` of local JSON over `file://`, so the other languages can't load. English is inlined into `js/locales-en.js` precisely so this path keeps working.

### Deploying

The repo is deployable as-is to any static host. For **GitHub Pages**, either:

- **Settings → Pages → Source: Deploy from a branch**, `main` / root — done, no workflow needed; or
- **Settings → Pages → Source: GitHub Actions**, which uses the included [`.github/workflows/pages.yml`](.github/workflows/pages.yml).

The same folder drops onto Netlify, Cloudflare Pages, or S3 unchanged.

---

## How grading works

Every domain gets a weighted score out of 100 and a letter grade. The full
breakdown is shown in each domain's detail row, so a grade can always be
explained rather than just asserted.

| Pillar | Points | Why that weight |
| --- | --- | --- |
| **DMARC** | 30 | The richest signal available, and the only thing that makes SPF and DKIM enforceable |
| **SPF** | 15 | Bypassable on its own without DMARC enforcement |
| **DKIM** | 15 | Same — necessary but not sufficient |
| **DNSSEC** | 15 | Also gates the A tier (see below) |
| **CAA** | 10 | Independent attack surface: mis-issued TLS certificates |
| **MTA-STS** | 8 | Independent attack surface: mail in transit |
| **BIMI** | 4 | Trust signal; requires DMARC enforcement + DKIM to work at all |
| **TLS-RPT** | 3 | Visibility into TLS delivery failures |

DMARC's 30 points split further: policy (`p=`) 10, effective subdomain coverage
6, enforcement rate (`pct=`) 4, aggregate reports (`rua=`) 5, strict alignment
(`adkim=s`/`aspf=s`) 3, forensic reports (`ruf=`) 2.

**Grades:** A++ ≥ 85, A+ ≥ 75, A ≥ 65, B ≥ 50, C ≥ 30, D ≥ 10, otherwise F.

When a control cannot be conclusively tested from public DNS — most notably
DKIM when none of the sampled selectors exists, or DNSSEC when validation is
indeterminate — the UI shows a score and grade range. Unknown is never silently
converted into a failed control.

**DNSSEC gates the A tier.** Without a signed zone the grade caps at B no matter
how good everything else is — an attacker who can poison your DNS responses can
undermine every other record measured here. A wildcard TXT record is an instant
F for the same reason: it breaks DKIM and DMARC lookups on every subdomain,
which invalidates the rest of the audit.

**Parked domains** (an explicit RFC 7505 null MX, `0 .`) are scored on a separate rubric — SPF 30, DMARC 30,
DNSSEC 25, CAA 15 — because DKIM, BIMI, MTA-STS and TLS-RPT cannot apply to a
domain with no mail flow. A parked domain with a null MX, `SPF -all`,
`DMARC p=reject` and a signed zone is correctly hardened and scores accordingly.

### Two things the rubric deliberately gets right

**Inherited subdomain policy counts.** Per RFC 7489, subdomains inherit `p=`
when `sp=` is absent, so `p=reject` alone protects subdomains fully. Scoring
tag *presence* would penalise a correct configuration, so the score uses the
**effective** policy (`sp ?? p`, and `np ?? sp ?? p`) and takes the weaker of
the two branches. Only genuine weakening — `sp=none` on a `p=reject` domain —
costs points.

**A duplicated record scores zero, because the mechanism fails closed.** Six
record types allow exactly one record and specify failure when there are more:
SPF (RFC 7208 §4.5) and DMARC (RFC 7489 §6.6.3) hard-fail; MTA-STS
(RFC 8461 §3.1), TLS-RPT (RFC 8460 §3) and BIMI (draft §7.2) require senders to
assume the feature is absent; DKIM keys must be unique per selector
(RFC 6376 §3.6.2.2) or the result is undefined. In each case the operator
believes the control is active when it is not, so the audit reports it as a
finding rather than silently scoring the first record. CAA and MX are excluded
deliberately — multiple records there are normal and expected.

**A broken SPF record scores zero, however strict it looks.** More than 10 DNS
lookups evaluates to `permerror`, which receivers treat as a failure, so
`-all` on an over-limit record earns nothing. Likewise `+all` and `?all`
authorise the entire internet and are worth nothing — while a missing provider
include, a real record one line short, keeps partial credit.

### Validating a scoring change

```bash
npm run test:scoring          # standards and scoring assertions, no network needed
node tools/backtest.mjs --sample   # grade distribution over live domains
node tools/backtest.mjs domains.txt --json > after.json
node tools/backtest.mjs domains.txt --comprehensive-dkim # full catalog, max 5 domains
```

`backtest.mjs` loads the production scoring code and reports the grade
histogram, score percentiles and per-pillar adoption. Run it before and after
changing weights or thresholds — a rubric that lands most of the internet on F
is measuring the wrong thing. It needs outbound DNS, so run it locally rather
than in CI.

### DKIM selector discovery

DKIM selectors cannot be enumerated through DNS, so the normal audit combines
the built-in common selectors, user-supplied selectors, and selectors associated
with the detected mail provider. The optional comprehensive scan checks the full
vendored catalog's 1,683 exact provider, generic, sequential, and temporal
selectors. Two additional HubSpot entries are selector prefixes rather than
queryable names and remain represented as catalog metadata. Because a full scan
can generate substantial DNS traffic, comprehensive scans are explicitly
enabled and limited to five domains per run.

The scanner validates an active DKIM key instead of treating any TXT response as
a key, follows delegated CNAME chains, and reports the exact number of selectors
tested. A scan that finds no key remains inconclusive: a sender can always use a
selector absent from the catalog. For definitive verification, supply the `s=`
selector from a real `DKIM-Signature` header or a DMARC aggregate report.
Recognized findings show the selector, full `<selector>._domainkey.<domain>`
query name, CNAME target when applicable, and complete TXT key data. A supplied
selector outside the catalog is labeled **Uncommon**; a supplied selector that
does not resolve to an active key is listed as **No Domain Key Found**.

Refresh the generated browser catalog from a compatible Markdown table with:

```bash
npm run update:dkim-selectors -- /path/to/recognized_dkim_selectors.md
```

---

## Project layout

```
dns-email-audit/
├── index.html              # markup only — every string carries a data-i18n key
├── css/style.css
├── js/
│   ├── locales-en.js       # AUTO-GENERATED English bundle (offline fallback)
│   ├── public-suffixes.js  # AUTO-GENERATED PSL snapshot for DMARC discovery
│   ├── dkim-selectors.js   # AUTO-GENERATED recognized selector catalog
│   ├── i18n.js             # translation loader: t(), tp(), tRaw(), setLang()
│   ├── dns.js              # DoH queries, analysis, scoring — no English in here
│   └── app.js              # rendering, orchestration, exports
├── locales/
│   ├── index.json          # registry of shipped languages
│   ├── en.json             # ← source of truth for all UI text
│   └── es.json
├── tools/
│   ├── build-fallback.mjs  # en.json → js/locales-en.js
│   ├── check-locales.mjs   # validates every locale against en.json
│   ├── scoring.test.mjs    # unit tests for the parser and scoring model
│   ├── update-psl.mjs      # refreshes the vendored Public Suffix List
│   ├── update-dkim-selectors.mjs # Markdown catalog → browser selector data
│   ├── serve.mjs           # dependency-free local development server
│   └── backtest.mjs        # grade distribution over live domains
└── .github/workflows/
    ├── pages.yml           # deploy to GitHub Pages
    └── ci.yml              # runs the locale check on every PR
```

### The one rule worth knowing

`js/dns.js` contains **no user-facing English**. Anything a person reads is a stable identifier — `'@none'`, `'spf-missing'`, `'noteWildcard'` — and `js/app.js` turns it into words via the i18n layer.

That separation is what makes the app translatable without forking the logic: a translator never touches JavaScript, and a bug fix in the analysis never invalidates a translation. Tokens standing in for translatable text are prefixed with `@`; provider names that are proper nouns (`Cloudflare`, `Google Workspace`) pass through untranslated on purpose.

---

## Translations

The UI ships in **English** and **Spanish**. Help wanted for French, Italian, German, Simplified and Traditional Chinese, Japanese and Korean — see **[CONTRIBUTING.md](CONTRIBUTING.md)** for the (short) process.

Adding a language means writing one JSON file and adding one line to a registry. No build tooling, no code changes.

```bash
npm run check          # how complete is each locale?
npm run build:fallback # after editing locales/en.json
```

Missing keys fall back to English at runtime, so a partial translation is genuinely useful — ship it and refine later.

---

## Privacy

DNS queries go from your browser directly to `cloudflare-dns.com`. No results or telemetry are sent to Kwestic, and nothing is written to storage except your language preference in `localStorage`. The domain names being queried are necessarily disclosed to Cloudflare's resolver and are subject to Cloudflare's privacy policy.

Because it's client-side, the app can't work inside a sandboxed iframe that blocks external requests — you'll see a banner explaining this if that happens.

---

## Contributing

Bug reports, provider-detection additions, new DKIM selectors and translations are all welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © Kwestic LLC (Kwestic Media and Technology)
