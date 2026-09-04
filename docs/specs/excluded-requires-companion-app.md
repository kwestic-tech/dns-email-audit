# Spec: Capabilities excluded because they require a companion app

| Field | Value |
| --- | --- |
| Spec version | 0.1 (Draft) |
| Target release | None — this document records an architectural exclusion, not a release |
| Status | Recorded exclusion. Revisited only if a future proposal argues one entry back in. |
| Depends on | Nothing |
| Blocks | Nothing |
| Slug for open questions | `APP` |
| Last updated | 2026-08-24 |

## Position

`dns-email-audit` is, by design, a static page with no session, no account, no
backend, and no persistence beyond one `localStorage` key holding a language
preference. That architecture is what makes every privacy claim in
[`PRIVACY.md`](../../PRIVACY.md) independently verifiable: nothing runs when
the tab is closed, so there is nothing to trust beyond what the page does while
open.

Some genuinely valuable ideas fail against that architecture not because they
cross the privacy boundary [external-intelligence](external-intelligence.md)
protects, but because they need something the architecture cannot provide at
all: state that outlives the tab, or execution that happens without the page
being open. Those ideas are collected here, separately from
`external-intelligence.md`, because the reason for exclusion is different and
should not be conflated. `external-intelligence.md` excludes capabilities that
*could* be built in-page but would disclose the audit to a third party.
This document excludes capabilities that *cannot* be built in-page at all,
regardless of what they would disclose.

Nothing here is scheduled. Nothing here is a target release. This is a parking
lot with a stated reason, so a future proposal is measured against why the
idea landed here rather than re-litigated from nothing, and so an automated
build pipeline reading the roadmap does not accidentally schedule work that
the current architecture cannot deliver.

## Excluded capabilities

| Idea | Why it needs an app | What the core tool does instead |
| --- | --- | --- |
| **Scheduled drift monitoring with alerting** | The highest-value failure mode this tool is positioned to catch is a control disappearing *between* audits — a DMARC record dropped during a migration, a DKIM key rotated to something weaker, an MX record going dangling after a provider change. Catching that requires state (last-known-good result) and unattended execution (a check that runs without a human opening the tab) and a delivery channel (push, email, or similar) — three things a static single-page tool cannot provide by definition. | Manual re-audit. The user re-runs the tool and, once [report-comparison](implemented/report-comparison.md) shipped in 0.9.0, can diff two saved exports by hand to see what changed. |

*This table has one entry as of 2026-08-24, sourced from the async-build spec
evaluation. Add rows here as they surface, rather than opening a new document,
so the "requires an app" exclusion reasoning stays in one place.*

## What is done instead

The pattern is the same one [external-intelligence](external-intelligence.md)
uses for its own deferred capabilities: the core tool stays honest about what
it cannot do, and the gap is named rather than quietly absent from the product.
For drift monitoring specifically, [report-comparison](implemented/report-comparison.md)
(0.8.0) is the load-bearing mitigation — it cannot alert the user
proactively, but it makes a manual "did anything change since last time"
check fast and reliable once the user remembers to run it.

## Conditions if any of these is ever built

Stated in advance, on the same principle
[external-intelligence](external-intelligence.md) uses: a future proposal is
measured against a standard set rather than against whatever seems reasonable
in the moment.

1. **It ships as a distinct product, not a mode of this one.** A scheduler, a
   state store, and a notification channel are a different piece of software
   with a different threat model, different privacy disclosures, and its own
   README. Grafting them onto the static-site architecture described in
   [`docs/specs/README.md`](README.md)'s threat model would invalidate every
   claim that document makes.
2. **The core tool's zero-persistence property is not touched.** Even if a
   companion app exists, `dns-email-audit` itself keeps `localStorage` to
   exactly the one language-preference key. The companion app is opt-in,
   separately installed, and separately documented.
3. **A new privacy disclosure, written before the first line of code.** A
   background job that periodically queries DNS for a saved list of domains
   and stores results is materially different from a one-shot in-browser
   audit, and the user consenting to one must not be read as consenting to
   the other.
4. **No new hard dependency on this product's release cadence.** The
   companion app can iterate independently and must not gate any release in
   `ROADMAP.md`.

Failing any one of these is disqualifying, matching the standard
[external-intelligence](external-intelligence.md) sets for its own
conditions.

## Consequences accepted

Stated plainly so the exclusion is honest about its cost, per the same
convention [external-intelligence](external-intelligence.md) uses.

- A domain owner who fixes their DNS today and never re-audits will not be
  told if it silently regresses six months later.
- The tool's value is front-loaded at the moment someone chooses to run it,
  with no mechanism to bring them back when something breaks.
- Everyone who would benefit most from monitoring — the non-expert owner this
  project's grading weights toward — is also the least likely to remember to
  re-run a manual audit on a schedule.

## Open questions

**OQ-APP-01: Is a companion app in scope for this project at all, or is it a
distinct product under a different name?**
Nothing here commits Kwestic to building a companion app. This document exists
so the idea is recorded with its reasoning rather than lost, and so anyone
proposing it later starts from an informed baseline rather than rediscovering
why it doesn't fit the current architecture. Decide when there's a reason to
decide, not now.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-08-24 | Initial draft. Created from the async-build spec evaluation's "high-value option not yet discussed" note, at Ian's request, to hold scheduled drift monitoring and any future "requires an app" ideas in one place, separate from `external-intelligence.md`. |
