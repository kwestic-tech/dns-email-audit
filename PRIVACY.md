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
roughly 41 queries for a typical domain with the **default options**, and more
when the comprehensive DKIM scan is enabled. For example, auditing
`cloudflare.com` with the defaults issues 61 queries.

These are measured numbers, not estimates: `node tools/backtest.mjs` reports
the fan-out of every run it makes — it drives the audit directly and loads no
page, so the two fixed probes below are not in these figures — and the figures
above were taken from a
40-domain sample at release 0.5.0. 0.5.0 added exactly **two** queries per
domain — a `DNSKEY` and a `DS` lookup for the audited name — and that figure is
per-domain and deterministic: `cloudflare.com` measured 43 at 0.4.0 and 45 at
0.5.0 with the deep checks off, both times.

The 40-domain totals moved by less than 80 between the two releases, which is
not a contradiction: DKIM selector discovery varies with what each domain
publishes at the moment it is asked, so the sample average carries more
run-to-run noise than two queries per domain. **Trust the per-domain figure
over a difference between two sample totals.** Three earlier corrections are
worth keeping visible. The text before 0.3.0 said 30 and 32; re-measuring at `v0.2.3` showed
the `cloudflare.com` figure had been 42 for some time, so part of that rise was
a stale number being corrected rather than new traffic, with the Tree Walk
accounting for the rest. The 0.3.0 text then said 46, and the same domain with
0.4.0's deep checks *off* measures 43 — running 0.3.0 and 0.4.0 back to back
gives 43 for both, so that movement is the domain's own DNS changing under us,
not the app asking for less. The 0.5.0 rise from 43 to 45 is the opposite kind
of change: two named queries the app now always makes.

That is the general lesson: this number is a property of the domains as much as
of the app. Re-measure rather than trusting this paragraph if you need it to be
exact for your own list — a domain with a long SPF `include:` chain or many
DKIM selectors costs considerably more than one without.

**Where that number comes from, and how to lower it.** 0.4.0 added MX-host
resolution and TLSA lookups — the "deep protocol checks" — which are the only
checks whose cost scales with the audited domain's own configuration: three
queries per MX host to resolve it and probe for a `CNAME`, plus one `TLSA` query
per host.

**They are on by default.** The checkbox in the options row ships ticked, so an
ordinary run of one domain makes them, and the 41-per-domain and 61-for-
`cloudflare.com` figures above are the numbers with them on. Above 50 domains
they switch themselves off and the interface says so; you can tick the box again
to run them anyway, and that choice lasts for the browser tab's session.

Since 0.9.2 the deep checks also reverse-look-up the addresses of an MX host
named inside the audited domain. Measured on the 32-case deterministic corpus
through the shipping implementation and the page cache, that adds **8 queries
across 80 audited domains — 0.1 per domain**, because most domains name their
MX hosts after their provider and are not examined at all. A domain that does
use a name in its own zone pays one query per address of its first two such
hosts, and up to four more if a reverse name is found and has to be confirmed.

That corpus measures the cost, not the shape of the internet: its reverse names
are self-hosted, so forward confirmation is reached in unit tests rather than
there. The ceiling above — twelve for any one domain — is what bounds it.

Turning them off leaves **about 34 queries per domain** on the 40-domain sample
and **45** for `cloudflare.com`. That is 0.3.0's and 0.4.0's shared figure of 43
plus 0.5.0's two DNSSEC lookups, which are not part of the deep checks and
cannot be switched off: they are how the chain state is established at all.

Those queries cover more than the name you typed. They include:

- The domain itself (`NS`, `MX`, `A`, `AAAA`, `TXT`, `CAA`, and for DNSSEC a
  `DNSKEY` and a `DS` alongside the existing `NS` probe).
- **With the deep protocol checks enabled — which is the default** — each MX
  host by name: an `A`, an `AAAA` and a `CNAME` query per host, plus
  `_25._tcp.<mx-host>` for its `TLSA` record. These names belong to whoever runs the domain's mail, which is
  frequently a third-party provider rather than the domain itself.
- **With the deep protocol checks enabled, for an MX host named inside the
  audited domain** — the reverse zone of each of its addresses
  (`<reversed>.in-addr.arpa` or `.ip6.arpa`), and, where that reverse name is
  forward-confirmed, the name itself. That last name belongs to whoever runs
  the mail service and is not published by the audited domain: it is reached by
  following the domain's own MX record one hop further. A domain whose MX hosts
  are named by its provider — the common case for hosted mail — makes none of
  these queries. At most the two lowest-preference such hosts are examined, at
  most four addresses each, and at most two provider names are resolved per
  domain, which bounds this at twelve additional queries for any one domain.
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

### Two fixed probes that are not about your domains

Separately from the audit itself, the app issues an `A` query for `example.com`
**twice**, to check that the resolver is reachable:

| When | How often |
| --- | --- |
| When the page finishes loading, before you have typed anything | once per page load |
| Immediately before an audit run starts | once per run, however many domains that run covers |

Both are fixed probes for the same fixed name. Neither depends on what you
entered, and neither is repeated per domain — a run covering nine domains sends
the second probe once, not nine times. They are excluded from the per-domain
figures above, which count only the queries an audit makes about the domain you
asked about.

The page-load probe is why `example.com` is queried even in a session where you
never run an audit. It has always been sent; it was measured for the first time
in 0.6.0, when the equivalence runner began driving the page through its real
`DOMContentLoaded` boot instead of skipping straight to the audit.

> **Verified against the query trace, not asserted.** The equivalence suite
> records every DNS query each of its 32 cases makes, and at the 0.6.0 release
> every case shows `example.com A` exactly **twice** — including the case that
> audits an unregistered domain and stops after three queries, and the case
> that audits two domains in one page, which still shows two. That is the
> page-load probe plus the per-run probe, and it is what makes "once per run,
> however many domains that run covers" a measurement rather than a claim.

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

- `src/core/dns/doh.js` contains the only third-party network calls — every
  request to Cloudflare's DoH endpoint goes through the `DOH_ENDPOINT` constant
  defined there, and it is the only module in the application that calls
  `fetch` against a host this project does not serve.
- `src/i18n/index.js` contains the only `localStorage` call in the app
  (`localStorage.setItem` / `getItem` on `dns-email-audit-lang`), and the
  same-origin fetch of `locales/*.json` — including the `locales/index.json`
  read at page load.
- `src/ui/report.js` fetches `css/style.css` from the same origin when building
  an exported report, so the export is self-contained. The fetch has lived
  there since 0.6.0; this file named `src/main.js` until 0.8.1.
- The `Content-Security-Policy` in `index.html` enforces this at the browser
  level: `connect-src` permits only `'self'` and `https://cloudflare-dns.com`,
  so the app cannot send data anywhere else even if it tried.

## Changes to this policy

Any change to what this app stores or transmits will be reflected here in the
same pull request as the code change that causes it.
