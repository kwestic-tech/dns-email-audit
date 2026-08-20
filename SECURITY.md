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

## Scope

This is a fully client-side, no-backend application. In-scope examples:

- XSS or HTML injection via the `sanitizeHTML` allowlist in `js/i18n.js`, or
  via user-supplied domain names / DKIM selectors rendered into the results
  table or exported reports
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
