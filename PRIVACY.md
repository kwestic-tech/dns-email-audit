# Privacy Policy

Part of [dns-email-audit](https://github.com/kwestic-tech/dns-email-audit) —
a free, browser-based DNS and email security auditor.

This is a static, client-side web app. There is no backend, no account
system, and no server operated by this project — everything below is fully
verifiable by reading the source.

## What leaves your browser

Two kinds of request leave your browser, and neither goes to Kwestic:

1. **DNS-over-HTTPS queries**, sent directly to Cloudflare's
   `cloudflare-dns.com` resolver. These are the only third-party requests the
   app makes.
2. **Same-origin requests for the app's own files** — the HTML, CSS,
   JavaScript, and the `locales/*.json` translation file for your selected
   language — fetched from whichever static host is serving the app. These
   carry no audit data; they are the ordinary requests any web page makes to
   load itself.

Nothing else leaves your browser: no analytics, no telemetry, no
error-reporting service, and no audit results, domain lists, or usage data
are ever sent to Kwestic or any Kwestic-operated server — because none
exists.

### What Cloudflare can see

Auditing one domain is **not** a single DNS query. A full audit fans out into
roughly 32 queries for a typical domain, and more when the comprehensive DKIM
scan is enabled. For example, auditing `cloudflare.com` with default options
issues 46 queries.

These are measured numbers, not estimates: `node tools/backtest.mjs` reports
the fan-out of every run it makes, and the figures above were taken from a
40-domain sample at release 0.3.0. Re-measure rather than trusting this
paragraph if you need the number to be exact for your own list — a domain with
a long SPF `include:` chain or many DKIM selectors costs considerably more than
one without.

Those queries cover more than the name you typed. They include:

- The domain itself (`NS`, `MX`, `A`, `AAAA`, `TXT`, `CAA`, `DNSSEC`).
- Subdomains derived from the standards being checked — `_dmarc.<domain>`,
  `<selector>._domainkey.<domain>` for each DKIM selector tried,
  `default._bimi.<domain>`, `_mta-sts.<domain>`, `_smtp._tls.<domain>`.
- **Every name between the audited domain and the top-level domain.** Since
  0.3.0, DMARC discovery follows the RFC 9989 DNS Tree Walk instead of a
  bundled Public Suffix List, so auditing `a.b.example.com` queries
  `_dmarc.a.b.example.com`, `_dmarc.b.example.com`, `_dmarc.example.com` and
  `_dmarc.com`. The walk is capped at eight queries however long the name is,
  and stops early at a `psd=` boundary.
- **Hostnames belonging to third parties**, discovered by following the
  domain's own SPF `include:` chain and DMARC reporting addresses — for
  example `_spf.google.com`, `spf.mandrillapp.com`, `mail.zendesk.com`, or
  `_spf.salesforce.com`. Since 0.3.0 this also includes a Tree Walk over each
  DMARC **report destination**, because RFC 9990 §4 defines the external-
  reporting check in terms of organizational domains and those now come from
  DNS rather than from the bundled list.

That last category matters: because the SPF chain is resolved, the pattern of
queries can reveal **which email and SaaS vendors the audited domain uses**,
not merely that you looked the domain up.

The app also issues one `A` query for `example.com` before each run, as a
pre-flight check that the resolver is reachable. This is a fixed probe and
does not depend on what you entered.

All of these query names are visible to Cloudflare and are governed by
Cloudflare's own privacy policy, not this project's. If that is not an
acceptable trade-off for the domains you intend to audit, run the app against
a resolver you control, or don't audit those domains here.

## What is stored on your device

This app writes exactly one value, to `localStorage`:

| Key | Value | Purpose | Written when | Expires |
| --- | --- | --- | --- | --- |
| `dns-email-audit-lang` | a language code, e.g. `en` | Remembers your UI language between visits | Only when you pick a language from the selector — a first visit that never touches the selector writes nothing at all | Never automatically — until cleared |

That's the entire footprint. Domains you've audited and scan results are
never written to storage; they exist only in memory for the browser tab's
session and are gone on reload or close. Nothing is written to
`sessionStorage`, IndexedDB, or the cache API.

## Cookies

This app sets no cookies. `localStorage` is a different mechanism: unlike a
cookie, its contents are never sent over the network to anyone — not to this
app's static host, not to Cloudflare, not to any third party. It stays on
your device until you or your browser clears it. Because no cookies are set
and no personal data is transmitted, this app shows no cookie-consent banner.

## Clearing stored data

Clear `dns-email-audit-lang` any time through your browser's "clear cookies
and site data" setting for this site, or from developer tools:

```js
localStorage.removeItem('dns-email-audit-lang');
```

Clearing it just resets the UI to your browser's detected language on next
visit.

## Source

Every claim above is checkable in code, at
[github.com/kwestic-tech/dns-email-audit](https://github.com/kwestic-tech/dns-email-audit):

- `js/dns.js` contains the only third-party network calls — every request to
  Cloudflare's DoH endpoint goes through the `DOH` constant defined there.
- `js/i18n.js` contains the only `localStorage` call in the app
  (`localStorage.setItem` / `getItem` on `dns-email-audit-lang`), and the
  same-origin fetch of `locales/*.json`.
- `js/app.js` fetches `css/style.css` from the same origin when building an
  exported report, so the export is self-contained.
- The `Content-Security-Policy` in `index.html` enforces this at the browser
  level: `connect-src` permits only `'self'` and `https://cloudflare-dns.com`,
  so the app cannot send data anywhere else even if it tried.

## Changes to this policy

Any change to what this app stores or transmits will be reflected here in the
same pull request as the code change that causes it.
