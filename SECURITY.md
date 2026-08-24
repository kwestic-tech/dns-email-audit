# Security Policy

Part of [dns-email-audit](https://github.com/kwestic-tech/dns-email-audit) —
a free, browser-based DNS and email security auditor.

## Reporting a vulnerability

Please report security issues privately rather than opening a public GitHub
issue.

- Preferred: open a
  [GitHub Security Advisory](https://github.com/kwestic-tech/dns-email-audit/security/advisories/new)
  for this repository — private to maintainers until resolved.

Please include a description of the issue and its impact, steps to reproduce
or a proof of concept, and the affected file(s) or commit if known.

## Threat model

There is no session, no credential, no stored user data and no privileged
action here, so script execution on this origin yields an attacker nothing to
steal — which means the failure that actually matters is **output integrity**:
a domain owner being able to make this tool display a false result, suppress a
finding, or render a record so that a reader draws the wrong conclusion.

Deliberately not defended: clickjacking (there is no state and no destructive
action to frame), and anything that requires an attacker who can already
inject markup into the page, since at that point the remaining directives are
not what saves you. Reports about those are welcome but will likely be closed
as working as intended.

## Scope

This is a fully client-side, no-backend application. In-scope examples:

- HTML injection or a markup sink reachable from DNS data — any path that gets
  a DNS-derived value out of a text node and into markup, or any assignment to
  `innerHTML` / `outerHTML` under `js/` that the static scan in `npm test`
  missed
- A rich-text string escaping the twelve-tag allowlist in `sanitizeFragment`
  in `js/i18n.js`
- A malformed record that renders deceptively — a bidirectional override,
  zero-width or control character that reaches the display without its
  sentinel marker, in the interface or in either export, including inside an
  issue message, a tooltip or any other interpolated text
- A CSV cell that a spreadsheet executes as a formula despite the
  neutralization in the export path
- Content-Security-Policy bypasses
- Any path that causes the app to send data somewhere other than
  Cloudflare's DoH endpoint
- Supply-chain issues in the build/tooling scripts (`tools/*.mjs`)

Out of scope: vulnerabilities in Cloudflare's DoH service itself, or in
whichever static host you deploy this to (GitHub Pages, Netlify, Cloudflare
Pages, etc.) — those belong to their respective maintainers.

## Response

This is a small open-source project maintained on a best-effort basis. We aim
to acknowledge reports within 7 days and to ship a fix for confirmed issues
as soon as practical, coordinating disclosure timing with the reporter.

## Supported versions

Only the latest commit on `main` is supported; there are no maintained
release branches.
