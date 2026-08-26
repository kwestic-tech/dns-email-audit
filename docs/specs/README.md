# Specifications

Each file in this directory specifies one release from [`ROADMAP.md`](../../ROADMAP.md).
A spec exists so that the design argument happens once, in writing, before code
is written, and so that a reviewer can disagree with a decision rather than with
a diff.

A spec that has shipped moves to [`implemented/`](implemented/). It is kept, not
deleted: the reasoning behind a decision is most valuable to whoever inherits it
a year later and wonders why an obvious-looking alternative was rejected.

## Naming and versioning

Specs are named for the capability they describe, not for the release number.
`0.4.0` may become `0.5.0` if the sequence changes; `dns-protocol-depth.md`
stays correct either way.

The spec document itself is versioned in its own header block, not in its
filename:

| Spec version | Meaning |
| --- | --- |
| `0.1 (Draft)` | First complete statement of the design. Open questions unanswered. |
| `0.2`–`0.9` | Revised after a review pass. Each revision records what changed and why. |
| `1.0 (Final)` | Every open question is resolved or explicitly deferred. Implementation may begin. |
| `1.0 (Implemented)` | The release shipped. The document has moved to [`implemented/`](implemented/) and records what was actually built. |

A spec is Final before implementation starts. If implementation discovers that
the spec is wrong, the spec is amended and re-versioned rather than quietly
diverged from.

## Planned

`Target release` below is a version-numbering anchor, kept per the naming rule
in this document — it is not a build-order commitment. **As of 2026-08-24,
the actual implementation order for the automated async build pipeline
follows the priority groups in
[`docs/async-development-handoff.md`](../async-development-handoff.md)**,
derived from an end-user-usefulness evaluation
(`claude/spec-evaluation-results.md` in the project) rather than from release
sequence. Release numbers are unaffected; only the order specs are picked up
for review and implementation changed. See that document for the full
rationale, the dependency map, and the group-by-group execution plan.

| Spec | Target release | Spec version | Status |
| --- | --- | --- | --- |
| [dnssec-evidence](dnssec-evidence.md) | 0.5.0 | 1.4 | **Final — implementation in progress** |
| [findings-and-remediation](findings-and-remediation.md) | 0.6.0 | 0.1 | Draft, awaiting review |
| [local-artifact-validation](local-artifact-validation.md) | 0.7.0 | 0.1 | Draft, awaiting review |
| [report-comparison](report-comparison.md) | 0.8.0 | 0.1 | Draft, awaiting review |
| [external-intelligence](external-intelligence.md) | post-1.0 | 0.1 | Draft, decision pending |

## Captured evidence

Some decisions cannot be made from reasoning about a protocol, only from
looking at what a resolver actually returns. Where a review settles a question
by measurement, the capture is kept beside the spec rather than in the session
that produced it:

| Directory | Holds |
| --- | --- |
| [`fixtures/`](fixtures/) | Captures for specs still being reviewed |
| [`implemented/fixtures/`](implemented/fixtures/) | Captures for specs that have shipped, moved with their spec |

Two of these exist so far, both for the DNS record types 0.4.0 and 0.5.0 add.
`OQ-DEPTH-01` and `OQ-DEPTH-05` were settled this way, and so were four of the
seven questions in [dnssec-evidence](dnssec-evidence.md). A capture states the
date and the resolver it came from, because both go stale.

## Excluded — requires a companion app

Capabilities that do not fit the static, session-free, zero-persistence
architecture this project commits to, regardless of privacy considerations.
Distinct from [external-intelligence](external-intelligence.md), which
excludes capabilities for what they would disclose rather than for what the
architecture cannot provide.

| Spec | Status |
| --- | --- |
| [excluded-requires-companion-app](excluded-requires-companion-app.md) | 0.1, recorded exclusion |

## Implemented

Shipped releases, recorded retrospectively. Each carries the pull request and
merge commit that delivered it, and an **As implemented** section stating where
the shipped code differs from what its spec asked for. Those divergences are the
reason these documents are worth keeping: several of them are now binding
precedent, and one spec was superseded outright during implementation.

| Spec | Released in | PR | Merge commit | Spec version |
| --- | --- | --- | --- | --- |
| [resilient-optional-checks](implemented/resilient-optional-checks.md) | 0.2.0 | [#8](https://github.com/kwestic-tech/dns-email-audit/pull/8) | `e74b47b` | 1.0 (Implemented) |
| [wildcard-txt-depth](implemented/wildcard-txt-depth.md) | 0.2.0 | [#9](https://github.com/kwestic-tech/dns-email-audit/pull/9) | `b41b50d` | 1.0 (Implemented) |
| [unproven-controls-scoring](implemented/unproven-controls-scoring.md) | 0.2.0 | [#10](https://github.com/kwestic-tech/dns-email-audit/pull/10) | `67a2339` | 1.0 (Implemented) |
| [spf-subnet-and-redundancy](implemented/spf-subnet-and-redundancy.md) | 0.2.0 | [#11](https://github.com/kwestic-tech/dns-email-audit/pull/11) | `ef26ca5` | 1.0 (Implemented) |
| [privacy-documentation](implemented/privacy-documentation.md) | 0.2.0 | [#12](https://github.com/kwestic-tech/dns-email-audit/pull/12) | `0e29b1c` | 1.0 (Implemented) |
| [repository-hygiene](implemented/repository-hygiene.md) | 0.2.0 | [#13](https://github.com/kwestic-tech/dns-email-audit/pull/13) | `d1677ff` | 1.0 (Implemented) |
| [locale-translation-pipeline](implemented/locale-translation-pipeline.md) | 0.2.1 | [#14](https://github.com/kwestic-tech/dns-email-audit/pull/14) | `ec1983f` | 1.0 (Implemented, superseding design) |
| [spf-referenced-dkim-selectors](implemented/spf-referenced-dkim-selectors.md) | 0.2.2 | [#15](https://github.com/kwestic-tech/dns-email-audit/pull/15) | `e158020` | 1.0 (Implemented) |
| [rendering-and-robustness](implemented/rendering-and-robustness.md) | 0.2.3 | [#18](https://github.com/kwestic-tech/dns-email-audit/pull/18) | `6bf8bda` | 1.3 (Implemented) |
| [dmarcbis-tree-walk](implemented/dmarcbis-tree-walk.md) | 0.3.0 | [#20](https://github.com/kwestic-tech/dns-email-audit/pull/20) | `8c3a36f` | 1.2 (Implemented) |
| [dns-protocol-depth](implemented/dns-protocol-depth.md) | 0.4.0 | [#22](https://github.com/kwestic-tech/dns-email-audit/pull/22) | `9bda3ad` | 1.2 (Implemented) |

Releases before 0.2.0 predate this process and have no spec. `0.1.0` and the
work merged as PRs #1 through #7 are documented in
[`CHANGELOG.md`](../../CHANGELOG.md) only.

Every spec above was written from an original working specification except
[resilient-optional-checks](implemented/resilient-optional-checks.md), which had
none and is reconstructed from its merged diff. It says so in its own header.

## Document structure

Every spec follows the same section order so a reviewer can compare like with
like across releases:

1. **Header**: spec version, target release, status, dependencies, date.
2. **Problem**: what is wrong or missing today, stated against the current code.
3. **Scope** and **Non-goals**: what this release does and explicitly does not do.
4. **Design**: the actual functions, files, and data shapes to add or change.
5. **Localization impact**: which `locales/en.json` keys are added or changed.
6. **Testing**: the assertions and fixtures that must exist before merge.
7. **Acceptance criteria**: the conditions that make the release done.
8. **Risks**: what could go wrong and what the mitigation is.
9. **Open questions**: numbered, unresolved decisions requiring a human answer.

A spec in [`implemented/`](implemented/) adds one section, **As implemented**,
between Design and Localization impact, and converts Open questions to
**Resolved questions**. Nothing else about the order changes, so a shipped spec
still reads like the planned ones beside it.

## Open question identifiers

Open questions are numbered `OQ-<spec-slug>-NN`, for example `OQ-SEC-03`. The
identifier is stable across spec revisions so review comments stay attached to
the right question after the document is edited. A resolved question is not
deleted; it moves to a **Resolved questions** section with the answer and the
spec version that resolved it. That preserves the reasoning for whoever reads
the spec a year from now and wonders why an obvious-looking alternative was
rejected.

## Review process

Each spec is reviewed independently by at least two reviewers before it is
marked Final. Reviewers are asked to produce four things:

1. A verdict on each numbered open question, with reasoning.
2. Any correctness objection to the design, referenced to the RFC or the file
   and function it contradicts.
3. Anything in the spec that would break the privacy boundary stated in
   [`PRIVACY.md`](../../PRIVACY.md), the CSP, or the localization contract in
   [`AGENTS.md`](../../AGENTS.md).
4. Anything the spec claims about the current codebase that is not true.

Review output is recorded as a pull request against the spec file. The spec
author resolves each item, bumps the spec version, and records the change in a
**Revision history** table at the foot of the document.

## Threat model

Stated once here so that no spec re-derives it and no spec inflates it.

**What this is.** A static website served from GitHub Pages. It takes a list of
domain names, issues DNS-over-HTTPS queries to one resolver, and renders the
answers. There is no backend, no database, no account, no session, no
authentication, no cookie, and no server-side code of any kind. `localStorage`
holds one key, a two-letter language preference. The full source is public, so
the shipped behavior is auditable by anyone.

**What that removes.** The usual reasons to fear script execution do not apply.
There is no credential to steal, no session to ride, no stored user data to
exfiltrate, no privileged action to trigger, and no server to pivot into. Nothing
else under `kwestic.com` shares trust with this origin, so the blast radius of a
compromised page is that page. Clickjacking is not a meaningful threat against a
tool with no state and no destructive action. Cross-site request forgery has no
target. Specs must not propose defenses whose only justification is one of these.

**What remains.** Two things.

*Output integrity.* Every SPF record, DKIM key, MX hostname, CAA value and TXT
string the tool renders was authored by a third party, frequently by the party
being investigated, and displaying large volumes of it is the tool's entire
purpose. Cloudflare is the transport and not a filter: it returns what the
authoritative nameserver published, byte for byte. The failure that matters is a
domain owner being able to make the tool display a false result, suppress a
finding, or render a record so that a reader draws the wrong conclusion. A
bidirectional override inside a hostname is a better example of this than a
`<script>` tag, because it survives correct escaping and changes what a human
reads.

*Cross-domain leakage within one run.* A hostile domain in a 200-domain audit
shares a page with the other 199. This matters to someone auditing a client
estate and to almost nobody else, but it is the one case where script execution
would obtain something the attacker did not already have.

**Consequences for spec authors.** Justify a rendering or parsing control by
output integrity or by maintainability, not by compromise. Do not add a CSP
directive, a header, or a platform mechanism whose stated benefit is confidential
data that does not exist here. Do treat DNS responses and any user-supplied file
as untrusted input, because the volume of attacker-authored content is high even
though the payoff for attacking it is low.

## Constraints every spec inherits

These are not restated in each document. They are binding on all of them.

- **No new network destinations.** The application talks to
  `https://cloudflare-dns.com` and nothing else. Any spec proposing otherwise
  must say so in Non-goals and route the capability to
  [external-intelligence](external-intelligence.md).
- **No persistence beyond the language preference.** `localStorage` holds
  `dns-email-audit-lang`. Audit results, imported reports, and user-supplied
  artifacts live in memory for the lifetime of the page.
- **Localization is part of the change.** A change to `locales/en.json`
  translates all thirteen other locales in the same change, runs
  `npm run build:fallback`, and passes `npm run locale:gate`.
- **`js/dns.js` returns tokens, not English.** Audit logic emits stable
  identifiers and structured data. `js/app.js` turns them into words.
- **Advisory before scoring.** A new check reports its finding for at least one
  release before it affects the grade, and a scoring change is backtested with
  `node tools/backtest.mjs` before it merges.
- **`npm test` and `npm run locale:gate` pass before any pull request opens.**

## Display rules for third-party values

Established by [rendering-and-robustness](implemented/rendering-and-robustness.md) and
binding on every release that renders a DNS record, an imported report, or a
user-supplied file. A spec that adds a new rendered value inherits these without
restating them.

- **No markup sinks.** Nothing under `js/` assigns to `innerHTML` or
  `outerHTML`. Values become text nodes or allowlisted attributes. Reading
  `outerHTML` to serialize a tree is permitted; writing it is not. The allowlist
  is empty and stays empty.
- **Nothing invisible is silently dropped.** Bidirectional controls, zero-width
  characters and C0 or C1 controls are replaced at their exact position by a
  visible sentinel such as `‹RLO›` or `‹ZWSP›`, never stripped and never passed
  through. CSS isolation is applied as well but is not the mechanism: it prevents
  a value reordering its neighbours, not its own contents.
- **Sentinels are never translated.** They name Unicode code points, so two
  auditors reading the same record in different languages must see identical
  evidence.
- **Display caps never reach the data.** 1024 characters per value and 20 items
  per list, with a disclosure control for the remainder. The full value stays in
  the result object and in every export.
- **Unknown is not absent.** A value the tool could not retrieve is rendered as
  unverified, never as missing. This is already the rule in `optionalCheck()` and
  `unprovenPillars()`; it extends to every new observation.
