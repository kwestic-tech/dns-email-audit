# Spec: Privacy and security documentation

| Field | Value |
| --- | --- |
| Spec version | 1.0 (Implemented) |
| Target release | 0.2.0 |
| Status | Implemented and released |
| Released in | `v0.2.0`, 2026-08-20 |
| Pull request | [#12](https://github.com/kwestic-tech/dns-email-audit/pull/12) |
| Implementation commit | `f8bfa08` |
| Merge commit | `0e29b1c` |
| Depends on | Nothing |
| Blocks | Every later spec, which inherits the privacy boundary stated here |
| Slug for open questions | `PRIV` |
| Last updated | 2026-08-20 |

> **Retrospective spec.** Written after the work shipped. The **As implemented**
> section records a factual correction made during implementation that the
> original spec had wrong, and that correction is now the boundary every later
> release is measured against.

## Problem

The application's data footprint was minimal and already privacy-respecting —
one `localStorage` key, no cookies, no analytics, no backend — but that story
existed nowhere a user or an auditor would find it.

The in-app strings said *no data stored* without ever saying what the one
exception was, that it is `localStorage` rather than a cookie, or that it has no
expiry. There was no `PRIVACY.md` and no `SECURITY.md` at the repo root. Both
are conventional for open-source projects and closely expected of a security
tool specifically: GitHub surfaces `SECURITY.md` as a distinct *Security policy*
entry in the repository sidebar. And nothing in the application linked to either
document, so even once they existed a user reading only the live interface had
no path to them.

## Scope

1. Add `PRIVACY.md` and `SECURITY.md` at the repo root, in the plain factual
   register the rest of the project's documentation uses.
2. Expand the three in-app strings that already gestured at *no data stored* to
   state the `localStorage` and cookie distinction explicitly.
3. Link to `PRIVACY.md` from the footer, the compact options row and the help
   callout — the three places a user is already looking when they would care.
4. Cross-link both from `README.md`.

## Non-goals

- **No code change.** No new DOM elements, no new CSS, no new i18n keys beyond
  extending existing string values. The diff stays reviewable as documentation
  and copy rather than as a new interface surface.
- **No in-app privacy page.** The GitHub-rendered Markdown is sufficient for a
  project this size.
- **No maintainer email in `SECURITY.md`.** GitHub Security Advisories are the
  only reporting channel, so the document does not need an address baked into
  it. See `OQ-PRIV-02`.
- **No change to what the application stores or transmits.** This release
  documents the footprint; it does not alter it.

## Design

`PRIVACY.md` states what leaves the browser, what is stored on the device, that
no cookies are set, how to clear the one stored value, and where in the source
every claim can be checked — `js/dns.js` and `js/app.js` for the only outbound
calls, `js/i18n.js` for the only `localStorage` call.

`SECURITY.md` states the reporting channel, the scope, the response
expectation, and which versions are supported. In scope: injection through the
sanitizer allowlist or through user-supplied domain names and selectors rendered
into the results table or the exported report, CSP bypasses, any path that sends
data somewhere other than the DoH endpoint, and supply-chain issues in
`tools/*.mjs`. Out of scope: Cloudflare's own service, and whichever static host
the reader deploys to.

Link labels are translated per locale like every other string in the
application. The additions use only the `A` tag, already in the sanitizer
allowlist, so no allowlist change is needed.

## As implemented

**1. The query fan-out was wrong in the spec and corrected in the document.**
The original draft of `PRIVACY.md` said the application sends DoH queries *one
per domain you enter*. That is false. A full audit fans out into roughly 30
queries for a typical domain and 32 in the comprehensive-DKIM example, and
because the SPF `include:` chain is resolved, the **pattern** of those queries
reveals which email and SaaS vendors the audited domain uses — not merely that
someone looked the domain up. The shipped `PRIVACY.md` documents all of this,
including the single `A` query for `example.com` issued before each run as a
connectivity probe.

This is the most important thing in the release. A privacy document that
understates the disclosure is worse than no document, and every later spec that
adds queries is now required to remeasure this number rather than leave it
stale.

**2. Nine locales, not two.** The spec correctly identified that
`locales/index.json` shipped nine locales and enumerated the existing wording
for each rather than leaving a translator to guess. All nine were edited in the
same change.

**3. `SECURITY.md` shipped as written,** with GitHub Security Advisories as the
sole channel and no invented email address.

## Localization impact

No new keys. Three existing values extended per locale — `opt.footer`,
`help.body` and `footer.text` — with the link labels translated: *Privacy* /
*Datenschutz* / *Privacidad* / *Confidentialité* / *Privacy* / プライバシー /
개인정보 / 隐私 / 隱私, and the corresponding *Security* labels in the footer.
Nine locales.

## Testing

`npm test` and `npm run check` must report zero placeholder or key-parity errors
across all nine locales — wording differences are fine, structural mismatches
are a hard CI failure.

Manual verification in a browser for **every shipped language**, not only
English: the options row, the help callout and the footer each render their link
in that language's label, each opens the correct GitHub-rendered file, and
switching the selector through all nine shows correct localized copy each time.
No CSP violations in the console.

Both files verified as rendering on GitHub, with *Security policy* appearing in
the repository sidebar.

## Acceptance criteria

All met at merge.

1. `PRIVACY.md` and `SECURITY.md` exist at the repo root and render on GitHub. ✅
2. GitHub shows a *Security policy* sidebar entry. ✅
3. All nine locales carry translated links in all three places. ✅
4. No code change to what the application stores or transmits. ✅
5. `npm test` and `npm run check` pass. ✅

## Risks

**A privacy document that goes stale is a liability, not an asset.** Mitigated
by the rule stated in `PRIVACY.md` itself: any change to what the application
stores or transmits is reflected in the same pull request as the code change
that causes it. Two later specs — [dmarcbis-tree-walk](dmarcbis-tree-walk.md)
and [dnssec-evidence](dnssec-evidence.md) — increase the query count and
carry that obligation explicitly.

## Resolved questions

| Id | Question | Resolution | Resolved in |
| --- | --- | --- | --- |
| `OQ-PRIV-01` | Does the document describe the fan-out, or only the destination? | The fan-out, in full, including that the query pattern discloses vendor relationships. Corrected during implementation; the original draft undercounted by roughly thirty times. | 1.0 |
| `OQ-PRIV-02` | Does `SECURITY.md` need a maintainer email? | No. GitHub Security Advisories only. An address is a follow-up the maintainer would specify; it must not be invented. | 1.0 |
| `OQ-PRIV-03` | Is a dedicated in-app privacy page needed? | No, not at this size. Revisit only if the footprint ever grows past one `localStorage` key. | 1.0 |

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.0 | 2026-08-20 | Retrospective record of the shipped 0.2.0 change, reconciled against `f8bfa08`. |
