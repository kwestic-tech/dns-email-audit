# DNS &amp; Email Security Auditor

A free, browser-based auditor for DNS and email authentication. Paste up to 200 domains and get SPF, DKIM, DMARC, BIMI, MTA-STS, TLS-RPT, CAA and DNSSEC results with a letter grade, plain-language explanations of every problem, and copy-paste DNS records to fix them.

Every query runs client-side against [Cloudflare's DNS-over-HTTPS API](https://developers.cloudflare.com/1.1.1.1/encryption/dns-over-https/). There is no backend, no signup, no analytics, and nothing is stored or transmitted anywhere else.

**[▶ Live demo](https://kwestic-tech.github.io/dns-email-audit/)**

---

## What it checks

| Check | What it tells you |
| --- | --- |
| **NS** | Which DNS provider hosts the zone |
| **MX** | Which email provider receives mail |
| **SPF** | Whether authorized senders are declared, and how strictly (`-all` / `~all` / `?all` / `+all`) |
| **SPF lookup depth** | How close the record is to the hard 10-lookup limit, following includes one level deep |
| **DKIM** | Probes 10 common selectors for a signing key |
| **DMARC** | Whether a policy exists, and whether it's `none`, `quarantine` or `reject` |
| **BIMI** | Whether a logo record is published |
| **MTA-STS** | Whether inbound TLS is enforced |
| **TLS-RPT** | Whether TLS failure reports are configured |
| **CAA** | Which certificate authorities may issue certs (walks up the domain tree) |
| **DNSSEC** | Whether responses validate (AD flag) |
| **Wildcard TXT** | Detects a `* TXT` record, which silently breaks DKIM and DMARC on every subdomain |

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

## Project layout

```
dns-email-audit/
├── index.html              # markup only — every string carries a data-i18n key
├── css/style.css
├── js/
│   ├── locales-en.js       # AUTO-GENERATED English bundle (offline fallback)
│   ├── i18n.js             # translation loader: t(), tp(), tRaw(), setLang()
│   ├── dns.js              # DoH queries, analysis, scoring — no English in here
│   └── app.js              # rendering, orchestration, exports
├── locales/
│   ├── index.json          # registry of shipped languages
│   ├── en.json             # ← source of truth for all UI text
│   └── es.json
├── tools/
│   ├── build-fallback.mjs  # en.json → js/locales-en.js
│   └── check-locales.mjs   # validates every locale against en.json
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

DNS queries go from your browser directly to `cloudflare-dns.com`. That's the only network request the app makes. No results, domains, or telemetry are sent anywhere, and nothing is written to storage except your language preference in `localStorage`.

Because it's client-side, the app can't work inside a sandboxed iframe that blocks external requests — you'll see a banner explaining this if that happens.

---

## Contributing

Bug reports, provider-detection additions, new DKIM selectors and translations are all welcome. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

[MIT](LICENSE) © Kwestic LLC (Kwestic Media and Technology)
