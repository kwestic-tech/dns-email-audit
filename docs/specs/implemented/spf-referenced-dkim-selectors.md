# Spec: DKIM selectors for SPF-referenced providers

| Field | Value |
| --- | --- |
| Spec version | 1.0 (Implemented) |
| Target release | 0.2.2 |
| Status | Implemented and released |
| Released in | `v0.2.2`, 2026-08-20 |
| Pull request | [#15](https://github.com/kwestic-tech/dns-email-audit/pull/15) |
| Implementation commit | `1e6a736` |
| Merge commit | `e158020` |
| Depends on | The DKIM selector catalog and `parseSpfTerms()`, both already present |
| Blocks | [dns-protocol-depth](../dns-protocol-depth.md), which analyses the keys this release finds |
| Slug for open questions | `VIASPF` |
| Last updated | 2026-08-20 |

> **Retrospective spec.** Written after the work shipped. The implementation
> tracks the original specification closely; the divergences are recorded under
> **As implemented** and are mostly a matter of where code was placed and one
> optional item that was built rather than skipped.

## Problem

Provider-aware DKIM mode — the default, non-comprehensive scan — tested
selectors for the single email provider detected from MX records. MX names
exactly one provider, so a helpdesk or ESP that signs part of a domain's mail
stayed invisible.

`slack.com` is the live case. Its SPF record is
`v=spf1 include:_spf.qualtrics.com include:mail.zendesk.com
include:_spfextra.slack.com -all`. MX detection says Google Workspace, so
provider-aware mode never tried `zendesk1`/`zendesk2` — even though the domain's
own SPF record explicitly states that Zendesk sends mail for it, and those
selectors are real, distinct, published CNAME records.

The only way to surface them was the comprehensive scan: 1,677 selectors, capped
at five domains per run. That is a great deal of DNS for a signal already
sitting in a record the audit had already fetched.

## Scope

In provider-aware mode, additionally test the selectors of any catalog provider
whose known SPF-include hostname — or `redirect=` target — appears in the
domain's **own** top-level SPF record.

## Non-goals

- **No change to comprehensive mode.** It already covers everything.
- **No walking into included records.** Only the literal `include:` and
  `redirect=` hostnames present in the domain's own record are matched.
  `_spf.qualtrics.com`'s own TXT is not fetched and not inspected.
- **No new DNS lookups** beyond the additional selector probes themselves. The
  SPF record is reused from the fetch that already happened.
- **No scoring change**, no change to wildcard-DKIM handling, and no change to
  the `confidence` or `scanMode` fields. This changes *which selectors get
  tested*, not how results are graded.
- **No Amazon SES entry.** SES Easy DKIM uses randomized per-identity selector
  tokens rather than a fixed name; the catalog already documents that exclusion
  for exactly this reason, and static probing gives no signal.
- **No `_spf.google.com` or `spf.protection.outlook.com` mappings.** Plausible
  future additions, out of scope here. See `OQ-VIASPF-02`.

## Design

An `include:` is the domain stating that a vendor sends mail for it — the same
claim MX makes about the inbound provider, and a claim the domain owner had to
publish deliberately. Treating it as a selector hint is therefore not guessing;
it is reading what the domain already said.

A mapping table pairs each vendor's documented SPF-include hostname with its
catalog key. `spfReferencedCatalogKeys()` walks the parsed SPF terms, matching
`include:` mechanisms and `redirect=` modifiers — a `redirect=` target plays the
same delegative role — skipping any value containing a `%{...}` macro, which
cannot resolve to a literal hostname and gets the same treatment
`countSpfLookups()` already gives it.

`catalogSelectors()` unions the referenced providers' selectors into the
MX-detected provider's list, skipping a referenced provider that is already the
MX-detected one. Selector-string-level deduplication is already handled
downstream by `buildDkimSelectorList()`.

`spfRecord` threads through `buildDkimSelectorList()` and `checkDKIM()` to the
existing call site, which already has the record in scope.

## As implemented

**1. The mapping table lives in `js/dns.js`, not `js/dkim-selectors.js`.** The
spec placed it in the selector catalog file and exposed it as
`global.__DKIM_SPF_INCLUDE_PROVIDERS__`. It shipped as a module-local
`DKIM_SPF_INCLUDE_PROVIDERS` at [`js/dns.js:43`](../../../js/dns.js), beside the
code that consumes it. `js/dkim-selectors.js` is a generated catalog maintained
by `tools/update-dkim-selectors.mjs`; a hand-maintained mapping table does not
belong in a generated file, and the global was unnecessary indirection. All ten
entries shipped exactly as specified, with a comment recording that each
hostname was confirmed to serve a live `v=spf1` record when the table was
written — the verification the spec required before merge.

**2. The optional attribution was built, not skipped.** The spec marked it
*nice-to-have, skip if it adds meaningful scope*. It was built, because without
it a selector belonging to neither the MX provider nor anything the user typed
appears with no explanation. Each finding carries `viaSpf`
([`js/dns.js:530`](../../../js/dns.js)) and renders as *via SPF: Zendesk* in the
detail view ([`js/app.js:428`](../../../js/app.js)) and the CSV export
([`js/app.js:761`](../../../js/app.js)). Selectors that would have been tested
anyway are not tagged.

**3. `spfReferencedCatalogKeys` is exported** ([`js/dns.js:1991`](../../../js/dns.js))
so the test suite can assert against it directly.

## Localization impact

One new key, `dkim.viaSpf` — `"via SPF: {0}"` — where `{0}` is the vendor's
catalog name and is not translated. Thirteen locales plus English in the same
change.

## Testing

Seven cases in `tools/scoring.test.mjs`, section 27:

| Case | Expectation |
| --- | --- |
| MX → Microsoft 365, SPF → `include:mail.zendesk.com`, `zendesk1` published | Provider-aware scan finds it |
| SPF → `include:sendgrid.net` | Twilio SendGrid selectors added under the right catalog key |
| SPF → `redirect=mail.zendesk.com` | Evaluated the same as `include:` |
| Same selector published, SPF names no vendor | **Not** found — proves this does not become comprehensive-by-default |
| MX → Mailgun **and** SPF → `include:mailgun.org` | Selector list concatenated once; the `key !== providerKey` skip fires |
| No SPF record | No crash, behavior unchanged |
| Any of the above | `scanMode` still reports `provider-aware`, not comprehensive |

The dedup fixture uses Mailgun deliberately. Zendesk cannot serve — it has no
inbound MX hosting and never appears as an MX-detected provider, confirmed
against `detectEmailProvider()`, which has no Zendesk branch. Google Workspace
and Microsoft 365 cannot serve either without first adding the mappings
`OQ-VIASPF-02` keeps out of scope. Mailgun and SendGrid work with no additions
because the MX detection path and the SPF-include table resolve to the same
catalog key independently.

The suite stood at 489 assertions at release, all passing.

## Acceptance criteria

All met at merge.

1. `slack.com` with default options finds `zendesk1` and `zendesk2`. ✅ — the
   domain moves from B (60) to A+ (75) at **22 selectors tested instead of
   1,677**.
2. Comprehensive mode's results and selector count unchanged. ✅
3. All existing tests pass; the seven new cases pass, dedup included. ✅
4. No new DNS queries beyond the selector probes — the SPF record is reused, not
   re-fetched. ✅
5. A domain whose SPF names no known vendor scans exactly as before. ✅

## Risks

**Scope creep into guessing.** The value of this feature rests entirely on the
`include:` being a deliberate statement by the domain owner. Following the
include chain, or inferring vendors from anything softer, turns a read of
published fact into speculation and would justify the comprehensive scan's DNS
cost without its honesty. The non-goals are the mitigation and are binding on
any extension of this table.

**A mapping hostname going stale.** A vendor changing its documented include
target silently stops the feature working for that vendor. Low harm — the
failure is a missed selector, not a wrong verdict — but the table needs a
periodic check against vendor documentation, unlike the generated catalog beside
it.

## Resolved questions

| Id | Question | Resolution | Resolved in |
| --- | --- | --- | --- |
| `OQ-VIASPF-01` | Should a selector found this way be labelled? | Yes. Optional in the original spec, built anyway: a selector belonging to neither the MX provider nor user input needs to explain itself. Shipped as `viaSpf` in the detail view and the CSV export. | 1.0 |
| `OQ-VIASPF-02` | Add `_spf.google.com` and `spf.protection.outlook.com`? | Not in this release. Both are plausible, and both would change what the dedup test can use as a fixture. A later addition, with its own verification of the hostnames. | 1.0 |
| `OQ-VIASPF-03` | Add Amazon SES? | No. Easy DKIM uses randomized per-identity selector tokens, so static probing yields nothing. The catalog already documents the exclusion. | 1.0 |
| `OQ-VIASPF-04` | Where does the mapping table live? | `js/dns.js`, module-local, beside its consumer. `js/dkim-selectors.js` is generated by `tools/update-dkim-selectors.mjs` and must not carry hand-maintained data. | 1.0 |

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-08-20 | Retrospective record of the shipped 0.2.2 release, reconciled against `1e6a736`. |
