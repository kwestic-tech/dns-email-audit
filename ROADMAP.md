# Roadmap

This document states where the project is, what is deliberately not built yet,
and the order the remaining work should land in. It is a planning document, not
a promise of dates. Each release below has a corresponding specification under
[`docs/specs/`](docs/specs/) that is reviewed and agreed before implementation
starts.

The organizing constraint is the privacy boundary. This application performs DNS
lookups from the user's browser to a single DNS-over-HTTPS resolver and does
nothing else over the network. Every item below is designed to hold that line,
and the one item that would cross it is deferred past 1.0 behind an explicit
opt-in.

## Where 0.2.2 left the project

Released 0.2.2 consolidated two things that were previously fragile.

The localization pipeline is now mature infrastructure rather than a manual
chore. `locales/en.json` is the source of truth, thirteen locales track it, and
`locales/translation-status.json` records XLIFF 2.1 state per key derived from
file fingerprints rather than trusted from memory. Every release below inherits
the rule in [AGENTS.md](AGENTS.md): a change that touches `locales/en.json`
translates all thirteen locales in the same change, and `npm run locale:gate`
passes before the pull request opens.

DKIM selector discovery improved in a specific, bounded way. Selectors are now
derived from providers named in the audited domain's own SPF record through
literal `include:` and `redirect=` terms, and each finding carries a `viaSpf`
attribution through the results table, the CSV export, and the HTML report. This
is an input to later key analysis, not a licence to guess more selector names.

Verification baseline at the `v0.2.2` tag:

| Signal | State |
| --- | --- |
| `npm test` | 489 assertions passing |
| `npm run locale:gate` | 13/13 translated locales passing strict |
| Working tree | clean at `v0.2.2` |
| Known doc defect | `README.md` still cites 174 assertions; corrected in 0.2.3 |

## Shipped releases and their specs

Every release from 0.2.0 onward has a specification under
[`docs/specs/implemented/`](docs/specs/implemented/), written retrospectively for
the work that shipped before this process existed. Each records what was built,
and — more usefully — where the shipped code diverged from what its spec asked
for. Three of those divergences are now precedent the planned releases inherit:
findings emit tokens rather than English, a new check reports before it scores,
and an unverifiable result is marked rather than hidden.

| Release | Delivered | Spec |
| --- | --- | --- |
| 0.2.0 | A failed optional lookup degrades one check instead of discarding the audit | [resilient-optional-checks](docs/specs/implemented/resilient-optional-checks.md) |
| 0.2.0 | A wildcard TXT record judged at the depth that predicts the harm | [wildcard-txt-depth](docs/specs/implemented/wildcard-txt-depth.md) |
| 0.2.0 | Unproven controls score zero; the floor–ceiling range grade is gone | [unproven-controls-scoring](docs/specs/implemented/unproven-controls-scoring.md) |
| 0.2.0 | SPF authorized-range size and `a`/`mx` redundancy audits, advisory only | [spf-subnet-and-redundancy](docs/specs/implemented/spf-subnet-and-redundancy.md) |
| 0.2.0 | `PRIVACY.md`, `SECURITY.md`, and localized in-app links | [privacy-documentation](docs/specs/implemented/privacy-documentation.md) |
| 0.2.0 | Version corrected to `0.2.0`, community health files, package metadata | [repository-hygiene](docs/specs/implemented/repository-hygiene.md) |
| 0.2.1 | XLIFF-based locale pipeline, thirteen locales complete, five new languages | [locale-translation-pipeline](docs/specs/implemented/locale-translation-pipeline.md) |
| 0.2.2 | DKIM selectors for vendors named in the domain's own SPF record | [spf-referenced-dkim-selectors](docs/specs/implemented/spf-referenced-dkim-selectors.md) |
| 0.5.0 | DNSSEC chain evidence: six states, local DS-to-DNSKEY matching, attributed claims | [dnssec-evidence](docs/specs/implemented/dnssec-evidence.md) |

`0.1.0` and the work merged as PRs #1 through #7 predate the spec process and are
documented in [`CHANGELOG.md`](CHANGELOG.md) only.

## Status of the original eight workstreams

| # | Workstream | State after 0.2.2 | Lands in |
| --- | --- | --- | --- |
| 1 | Rendering correctness and robustness | **Done, and rescoped along the way.** The original framing was CSP and XSS hardening; a static site with no session or stored data has no compromise to defend, so the work that survived is output integrity. Shipped in 0.2.3: no markup sink remains under `js/`, interpolation is single-pass, and every class of malformed record has a decided, tested display behavior. | [0.2.3](docs/specs/implemented/rendering-and-robustness.md), released |
| 2 | RFC 9989 DMARC | **Done.** The bis tag vocabulary, `t=`, `psd=`, inheritance, URI parsing and external report authorization were already implemented; 0.3.0 added the missing half — the RFC 9989 §4.10 DNS Tree Walk, replacing the Public Suffix List for every DMARC decision, with discovery provenance, `psd=` termination, existence-gated `np=`, and misplaced-record diagnosis. | [0.3.0](docs/specs/implemented/dmarcbis-tree-walk.md), released |
| 3 | Anomaly and remediation engine | Not started. Findings are a flat list of localized strings with no severity model, dependencies, or ordering. | [0.6.0](docs/specs/findings-and-remediation.md) |
| 4 | DKIM, MX, CAA and DANE depth | **Done.** 0.4.0 decodes DKIM public keys to algorithm and modulus size, parses CAA into a policy with wildcard semantics, resolves every MX target to find dangling and CNAME hosts, and adds TLSA lookup, reported per host as DNSSEC-authenticated or not on the strength of the resolver's AD bit for that host's own name. 0.5.0 reviewed and **retired** the `qualified` flag rather than completing it: a TLSA record lives in the MX host's zone, which the audited domain's chain evidence says nothing about, and local DS-to-DNSKEY matching never validates RRSIGs and so cannot exceed the resolver's per-host verdict (`OQ-SEC9-07`). Every observation is advisory: zero grade movement. | [0.4.0](docs/specs/implemented/dns-protocol-depth.md), released |
| 5 | DNSSEC depth | **Done.** 0.5.0 queries the child `DNSKEY` set and the parent `DS` set, matches the digests locally with Web Crypto, and replaces the four-state model with six — separating a signed-but-unanchored zone and a DS/DNSKEY mismatch from a zone that was never signed. The resolver's AD flag remains the validation signal, and every claim is attributed to it or to local computation. | [0.5.0](docs/specs/implemented/dnssec-evidence.md), released |
| 6 | Local MTA-STS and BIMI validation | Not started. Both are validated at the TXT record level only. | [0.7.0](docs/specs/local-artifact-validation.md) |
| 7 | Local report comparison | Not started. Exports are CSV and static HTML; nothing can be read back. | [0.8.0](docs/specs/report-comparison.md) |
| 8 | External intelligence | Intentionally deferred. Would cross the privacy boundary. | [post-1.0](docs/specs/external-intelligence.md) |

## Release sequence

The order is not arbitrary. The rendering path is rebuilt first because every
later release pushes more third-party DNS content through it, and retrofitting a
node-building renderer across six releases of new interface costs more than
establishing it once. Protocol correctness comes second because the application
already claims RFC 9989 conformance in its output. The findings engine comes
after the signals it consumes are stable, so the rule set is written once rather
than rewritten each time a new observation lands.

The threat model that governs all of this is stated once in
[`docs/specs/README.md`](docs/specs/README.md). In short: a static site with no
session, no stored user data and no privileged action has no compromise worth
defending, so the thing being protected is the accuracy of what the tool
displays.

### 0.2.3: Rendering correctness and malformed-record robustness — released

Spec: [`docs/specs/implemented/rendering-and-robustness.md`](docs/specs/implemented/rendering-and-robustness.md)

Replaces HTML string construction in `js/app.js` with DOM node building, fixes
re-entrant placeholder interpolation in `js/i18n.js`, returns a fragment from the
rich-text sanitizer, and decides display behavior for every class of malformed
DNS record: oversized values, huge record sets, bidirectional overrides, control
and zero-width characters, and invalid encodings. Adds a dependency-free DOM shim
and a hostile-value regression suite. Narrows `img-src`, replaces the fixed CSP
nonce with a hash. Corrects the stale assertion count in `README.md`.

Exit condition: no DNS-derived value reaches anything but a text node or an
allowlisted attribute, every malformation class has a decided and tested
behavior, and grades are byte-identical to `v0.2.2`.

### 0.3.0: Complete DMARCbis behavior — **released**

Spec: [`docs/specs/implemented/dmarcbis-tree-walk.md`](docs/specs/implemented/dmarcbis-tree-walk.md)

Replaces the two-probe organizational-domain fallback with the RFC 9989 DNS Tree
Walk, records where the applied policy was found and how it was inherited, and
tightens malformed-record diagnosis so a misplaced `v=DMARC1` is reported as
misplaced rather than missing.

Exit condition, met: subdomain, organizational-domain, PSD, malformed-record and
report-authorization fixtures all produce deterministic, RFC-aligned outcomes,
with no network access. No scoring rule changed; the grade movement the release
does produce is discovery-only and is explained domain by domain in the spec's
**Verification** section.

### 0.4.0: DNS-only protocol depth — **released**

Spec: [`docs/specs/implemented/dns-protocol-depth.md`](docs/specs/implemented/dns-protocol-depth.md)

Decodes DKIM public keys to report algorithm and modulus size, parses CAA into
structured fields, resolves MX targets to detect dangling hosts and weak
redundancy, and adds TLSA lookup with syntax validation. Every new observation
retains its raw DNS evidence and makes no claim requiring SMTP, certificate, or
third-party access.

Exit condition: new checks ship advisory first and enter scoring only after a
backtest shows the grade distribution shift is intended.

### 0.5.0: DNSSEC evidence — **released**

Spec: [`docs/specs/implemented/dnssec-evidence.md`](docs/specs/implemented/dnssec-evidence.md)

Queries child DNSKEY and parent DS records, matches DS digests against DNSKEY
material with Web Crypto, and distinguishes secure, insecure delegation,
signed-but-unanchored, mismatch, bogus, and indeterminate. The resolver's AD flag
remains the validation signal; this release adds transparent evidence beside it
rather than claiming the browser is an independent validating resolver.

Exit condition, met: the interface never labels a chain secure solely because
DNSKEY records exist — `servfail.nl` confirms its DS locally and is bogus, which
is why the two axes stay separate — and each conclusion is attributed to the
resolver or to local computation, on screen. `checkTlsa()`'s `qualified` flag
was reviewed and **retired** rather than completed: a TLSA record lives in the
MX host's zone, which the audited domain's chain evidence says nothing about.
Zero grade, score and `dnssec.signed` movement against `v0.4.0`.

### 0.6.0: Anomaly and remediation roadmap

Spec: [`docs/specs/findings-and-remediation.md`](docs/specs/findings-and-remediation.md)

Introduces structured findings separate from localized display strings, with
severity, confidence, evidence, and prerequisite dependencies. Detects
cross-protocol conditions such as BIMI without DMARC enforcement, MTA-STS without
TLS-RPT, and TLSA without usable DNSSEC. Produces an ordered remediation sequence
rather than a flat suggestion list.

Exit condition: every recommendation points at evidence and prerequisites, and
results are identical across all fourteen locales.

### 0.7.0: Private local artifact validators

Spec: [`docs/specs/local-artifact-validation.md`](docs/specs/local-artifact-validation.md)

Adds a visually separate panel accepting pasted or selected MTA-STS policy text
and BIMI SVG material, validated strictly in memory. No MTA-STS, BIMI, or VMC URL
is ever fetched automatically, and user-supplied SVG is never injected into the
application DOM.

Exit condition: artifact analysis produces no new network requests, no
persistence, and no active markup.

### 0.8.0: Stateless report comparison

Spec: [`docs/specs/report-comparison.md`](docs/specs/report-comparison.md)

Defines a versioned JSON report schema, exports normalized evidence with the
scoring rubric version, and compares two reports entirely in memory to show new,
resolved, regressed, and unchanged findings. History is never persisted.

Exit condition: reloading the page discards imported reports, and hostile strings
inside imported JSON render as text only.

### Post-1.0 decision: External intelligence

Spec: [`docs/specs/external-intelligence.md`](docs/specs/external-intelligence.md)

Certificate transparency, blocklist, reputation, SMTP and arbitrary policy-URL
lookups stay outside the core product. If ever introduced, they require a
separate opt-in mode, a distinct network policy, a pre-query disclosure naming
the exact destination, and exclusion from the default score.

## How to use these specs

Specs are named for what they describe, not for the release number, so a
resequenced roadmap does not require renaming files. Each spec carries its own
version in its header, starting at `0.1 (Draft)` and incrementing through review
until it is marked `Final`. A spec is Final before implementation begins, and the
implementing pull request references it by name.

Every spec ends with numbered open questions. Those are the decisions that are
genuinely unsettled, and they are the primary input to review. See
[`docs/specs/README.md`](docs/specs/README.md) for the review process.

## Addendum: build order for the automated async development pipeline (2026-08-24)

The release sequence above (0.2.3 through 0.8.0) states why the work is
*shipped* in that order — grade stability, protocol claims already made, a
findings engine that wants stable inputs. It is kept exactly as written and
still governs version numbers and release notes.

It is **not** the order an automated agentic build pipeline uses to pick up
work. That pipeline follows a separate priority ranking, graded on end-user
usefulness first and build-dependency structure second, worked out in
`claude/spec-evaluation-results.md` (in the Kwestic project) and turned into an
execution plan in
[`docs/async-development-handoff.md`](docs/async-development-handoff.md).

The short version: `findings-and-remediation` (0.6.0) is the single
highest-value spec for the tool's stated non-expert-owner audience, but it is
also the most downstream in the dependency graph — it consumes the output
shapes of `dmarcbis-tree-walk`, `dns-protocol-depth`, and `dnssec-evidence`.
So the *value* ranking and the *build* ranking disagree, and
`docs/async-development-handoff.md` is the document that reconciles them into
an actual sequence, including which specs can be developed in parallel
(`local-artifact-validation` alongside the 0.3.0→0.4.0→0.5.0 chain) and which
cannot.

Nothing about this addendum changes what any spec says, what release number it
targets, or the naming rule above. It changes only the order in which specs
are reviewed to `1.0 (Final)` and implemented. Update this addendum, not the
sequence above, if the build-priority ranking changes.
