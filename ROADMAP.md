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
| 0.2.3 | Rendering correctness and decided malformed-record behavior | [rendering-and-robustness](docs/specs/implemented/rendering-and-robustness.md) |
| 0.3.0 | RFC 9989 DMARC DNS Tree Walk and discovery provenance | [dmarcbis-tree-walk](docs/specs/implemented/dmarcbis-tree-walk.md) |
| 0.4.0 | DKIM, CAA, MX and DNS-published DANE depth | [dns-protocol-depth](docs/specs/implemented/dns-protocol-depth.md) |
| 0.5.0 | DNSSEC chain evidence: six states, local DS-to-DNSKEY matching, attributed claims | [dnssec-evidence](docs/specs/implemented/dnssec-evidence.md) |
| 0.6.0 | ES modules under `src/` bundled to one artifact; a two-member browser API; no behaviour change | [modular-architecture-and-production-build](docs/specs/implemented/modular-architecture-and-production-build.md) |
| 0.7.0 | Stable finding identity, source-bound evidence and dependency-ordered remediation | [findings-and-remediation](docs/specs/implemented/findings-and-remediation.md) |
| 0.8.0 | Private local MTA-STS policy and BIMI SVG validation with user-supplied provenance | [local-artifact-validation](docs/specs/implemented/local-artifact-validation.md) |
| 0.8.1 | Output-integrity hardening for hostile DNS/locale values, audit re-entry and BIMI SVG references | [local-artifact-validation, amended to 1.11](docs/specs/implemented/local-artifact-validation.md) |
| 0.9.0 | A versioned JSON report, and comparison of two of them in memory with per-protocol observability | [report-comparison](docs/specs/implemented/report-comparison.md) |

`0.1.0` and the work merged as PRs #1 through #7 predate the spec process and are
documented in [`CHANGELOG.md`](CHANGELOG.md) only.

## Status of the original eight workstreams

| # | Workstream | State after 0.2.2 | Lands in |
| --- | --- | --- | --- |
| 1 | Rendering correctness and robustness | **Done, and rescoped along the way.** The original framing was CSP and XSS hardening; a static site with no session or stored data has no compromise to defend, so the work that survived is output integrity. Shipped in 0.2.3: no markup sink remains under `js/`, interpolation is single-pass, and every class of malformed record has a decided, tested display behavior. | [0.2.3](docs/specs/implemented/rendering-and-robustness.md), released |
| 2 | RFC 9989 DMARC | **Done.** The bis tag vocabulary, `t=`, `psd=`, inheritance, URI parsing and external report authorization were already implemented; 0.3.0 added the missing half — the RFC 9989 §4.10 DNS Tree Walk, replacing the Public Suffix List for every DMARC decision, with discovery provenance, `psd=` termination, existence-gated `np=`, and misplaced-record diagnosis. | [0.3.0](docs/specs/implemented/dmarcbis-tree-walk.md), released |
| 3 | Anomaly and remediation engine | **Done.** 0.7.0 adds stable finding identity, five-level severity, confidence, source-bound evidence and dependency-ordered remediation while preserving the legacy issue and scoring surfaces. | [0.7.0](docs/specs/implemented/findings-and-remediation.md), released |
| 4 | DKIM, MX, CAA and DANE depth | **Done.** 0.4.0 decodes DKIM public keys to algorithm and modulus size, parses CAA into a policy with wildcard semantics, resolves every MX target to find dangling and CNAME hosts, and adds TLSA lookup, reported per host as DNSSEC-authenticated or not on the strength of the resolver's AD bit for that host's own name. 0.5.0 reviewed and **retired** the `qualified` flag rather than completing it: a TLSA record lives in the MX host's zone, which the audited domain's chain evidence says nothing about, and local DS-to-DNSKEY matching never validates RRSIGs and so cannot exceed the resolver's per-host verdict (`OQ-SEC9-07`). Every observation is advisory: zero grade movement. | [0.4.0](docs/specs/implemented/dns-protocol-depth.md), released |
| 5 | DNSSEC depth | **Done.** 0.5.0 queries the child `DNSKEY` set and the parent `DS` set, matches the digests locally with Web Crypto, and replaces the four-state model with six — separating a signed-but-unanchored zone and a DS/DNSKEY mismatch from a zone that was never signed. The resolver's AD flag remains the validation signal, and every claim is attributed to it or to local computation. | [0.5.0](docs/specs/implemented/dnssec-evidence.md), released |
| 6 | Local MTA-STS and BIMI validation | **Done.** 0.8.0 adds a separate in-memory panel for supplied MTA-STS policy and BIMI SVG material, with strict pre-parse limits, source-bound findings and no network, storage, scoring or logo-rendering path. 0.8.1 hardens output handling and amends the SVG `url()` rule without changing that boundary. | [0.8.0 and 0.8.1](docs/specs/implemented/local-artifact-validation.md), released |
| 7 | Local report comparison | **Done.** 0.9.0 adds a versioned JSON report and compares two of them entirely in memory. The schema is a named projection rather than a dump of the result object, settled by measurement; per-protocol observability means an unobserved protocol is marked with its reason rather than reported as fixed; and an analysis-version or generator-version difference withholds the claim it cannot support instead of the whole diff. Nothing is persisted. | [0.9.0](docs/specs/implemented/report-comparison.md), released |
| 8 | External intelligence | Intentionally deferred. Would cross the privacy boundary. | [post-1.0](docs/specs/external-intelligence.md) |
| 9 | Modular architecture and production build | **Done.** Released as 0.6.0; all six gates met. Spec `1.8`. The application was seven classic scripts loading IIFEs onto `window`, with `js/dns.js` alone at 5,704 lines owning transport, every protocol, scoring and issue construction. It is now ES modules under `src/`, bundled to one artifact, with thirteen owning directories, zero adapters and a two-member browser API. | [0.6.0](docs/specs/implemented/modular-architecture-and-production-build.md), released |
| 10 | 1.0 product contract and release readiness | Not started. The compatibility surface, supported environments, accessibility evidence and graduation gate are now explicit rather than inferred from completing 0.9.0. | [1.0.0](docs/specs/one-zero-readiness.md) |
| 11 | MX host address validity and provider divergence | **0.9.1 next; spec `0.6`, 0.9.1 implemented.** 0.9.2 is blocked on a privacy review and `OQ-MXV-03`. Extends workstream 4, which resolved MX targets but never asked what they resolved *to*: a host answering only loopback or private space still reports as healthy. 0.9.1 adds address-scope classification, address-literal and null-MX-conflict diagnosis at no query cost; 0.9.2 adds forward-confirmed reverse lookups to find a vanity MX that has fallen behind its provider's address set. | [0.9.1 and 0.9.2](docs/specs/mx-host-validity.md) |

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

### 0.6.0: Modular architecture and production build — **released**

Spec: [`docs/specs/implemented/modular-architecture-and-production-build.md`](docs/specs/implemented/modular-architecture-and-production-build.md)

Converted the browser code from `window`-attached IIFEs to ES modules under
`src/`, split `js/dns.js` and `js/app.js` along four boundaries — DNS
transport, protocol evaluation, audit coordination, UI — and introduced esbuild
as the project's first development dependency, producing a single
`dist/app.min.js` that GitHub Pages serves in place of seven source files.

This is the one release in the sequence that ships **no audit or UI behavior
change**, by design. It deliberately retired undocumented legacy JavaScript
globals and replaced them with the two-member supported facade recorded in the
spec. It was scheduled here rather than later because the three
feature releases that follow all read or extend the output shapes that lived in
`js/dns.js`, and establishing the boundaries cost less then than after three
more releases had been layered onto a 5,704-line file.

Exit condition, met: five-surface equivalence against a deterministic fixture
corpus captured at `v0.5.0` — full result, query trace, CSV, HTML report and
DOM, three-way through baseline/source/bundle — reports **zero differences**
across 32 cases, with the contract and state inventories intact, 4,451
assertions reported, `npm run locale:gate` at 13/13, and zero runtime
dependencies. **One clause of it was wrong and is recorded rather than
quietly dropped:** `PRIVACY.md` did need an edit. Driving the app through its
real controls booted the page, which showed a second fixed `example.com` probe
the document had never disclosed: one when the page finishes loading, and one
immediately before each audit run — so a session that runs a single audit sends
two, and a session that never runs one still sends the page-load probe.
Pre-existing behaviour newly measured, not a 0.6.0 change. Spec `1.5` carries
the correction.

### 0.7.0: Anomaly and remediation roadmap — released

Spec: [`docs/specs/implemented/findings-and-remediation.md`](docs/specs/implemented/findings-and-remediation.md)

Introduced structured findings separate from localized display strings, with
severity, confidence, evidence, and prerequisite dependencies. Detects
cross-protocol conditions such as BIMI without DMARC enforcement, MTA-STS without
TLS-RPT, and TLSA without usable DNSSEC. Produces an ordered remediation sequence
rather than a flat suggestion list.

Exit condition met: every recommendation points at source-bound evidence and
prerequisites, and finding/remediation order is identical across all fourteen
locales. Released as `v0.7.0`.

### 0.8.0: Private local artifact validators — released

Spec: [`docs/specs/implemented/local-artifact-validation.md`](docs/specs/implemented/local-artifact-validation.md)

Adds a visually separate panel accepting pasted or selected MTA-STS policy text
and BIMI SVG material, inspected strictly in memory. No MTA-STS, BIMI, or VMC URL
is ever fetched automatically, and user-supplied SVG is never injected into the
application DOM.

Exit condition met: the production-browser instrument observes no analysis
request, persistence or foreign-node insertion; selected and pasted input is
bounded before parsing, and artifact findings remain outside scoring. Released
as `v0.8.0`.

### 0.8.1: Output-integrity hardening — released

Spec amendment: [`docs/specs/implemented/local-artifact-validation.md`](docs/specs/implemented/local-artifact-validation.md)

Closes the output failures found by the post-0.8.0 review: prototype-chain
lookups can no longer turn hostile DNS or locale strings into objects; a failed
row render is contained without deleting a colliding domain's result; the audit
guard is claimed before its connectivity await; DNS-derived provider labels
are sentinelised; and the BIMI SVG `url()` screen distinguishes local fragments,
`data:` profile diagnostics and external security rejections. The footer entity
and the documentation drift found in the same review are corrected as part of
the patch.

Exit condition met: 5,100 assertions pass, all thirteen translated locales pass
strict validation, the real-browser file/security gates pass 22 and 94 checks,
and all 32 deterministic cases remain identical to `v0.8.0` across results,
query traces, CSV, HTML and DOM. Released as `v0.8.1`.

### 0.9.0: Stateless report comparison

Spec: [`docs/specs/implemented/report-comparison.md`](docs/specs/implemented/report-comparison.md) — `1.10 (Implemented, amended)`. Released as `v0.9.0`.

Defines a versioned JSON report schema, exports normalized evidence with an
`analysisVersion`, and compares two reports entirely in memory to show new,
resolved, regressed, and unchanged findings. History is never persisted.

The schema is a named projection of the result object rather than a dump of it.
That was the review's largest correction and it was settled by measurement, not
argument: the draft exported the whole result at a 1000-domain import cap, which
is 8.62 MiB against its own 8 MiB pre-parse limit — a tool emitting files it would
then reject. The projection also keeps two things out of a file people email to
each other: display state, and the apex TXT records that carry a domain's
third-party vendor verification tokens. The import cap becomes `MAX_DOMAINS`,
200, because the application cannot produce a larger report.

`analysisVersion` gates the score delta and nothing else. Finding ids and record
observations are still diffed across releases, but different generator versions
are labelled as `changed` with baseline/current-only findings rather than the
causal claims improved/regressed and new/resolved. Stable ids establish identity,
not unchanged detector semantics. `analysisVersion` is bumped by anything that
can move a score, discovery included, because 0.3.0 is the confirmed instance of
scores moving with the rubric untouched.

Exit condition: reloading the page discards imported reports, hostile strings
inside imported JSON render as text only, a protocol that was unobserved on
either side reports its findings as unknown rather than resolved, and no
user-supplied artifact finding appears in an exported report.

### 0.9.1 and 0.9.2: MX host validity

Spec: [`docs/specs/mx-host-validity.md`](docs/specs/mx-host-validity.md) — `0.2`.

0.4.0 taught the audit to resolve every MX target and report the ones that do
not resolve. Neither it nor anything since asks what a target resolves *to*, so a
host answering `127.0.0.1` or `10.0.0.4` produces `resolves: 'yes'`, raises
nothing, and reads as a correctly configured mail domain while receiving no mail
from the internet. That false negative is why 0.9.1 exists; two adjacent defects
— an address literal in the MX RDATA, and a null MX published beside a real one —
are diagnosed today as dangling hosts, which is the right alarm attached to
remediation the operator cannot carry out.

0.9.2 addresses a quieter failure. A domain that points its MX at a name in its
own zone holding a hand-copied snapshot of a provider's address has forked from
that provider: the copy does not follow renumbering and need not contain every
address the provider publishes. The check identifies the provider by
forward-confirmed reverse DNS and reports the addresses that were never copied.

**The releases split on query cost, not on subject.** 0.9.1 issues no query the
audit does not already make. 0.9.2 adds `PTR` lookups on a path that deep checks
leave enabled by default, which moves published DNS fan-out and therefore
requires the privacy review `AGENTS.md` makes a stop condition. 0.9.1 is not
blocked by that review; 0.9.2 does not begin until it concludes.

Exit condition for 0.9.1: an MX host resolving only into special-purpose address
space is reported as unreachable rather than healthy, the two misdiagnosed
defects raise their own findings and suppress `mx.dangling`, and no score or
grade moves. For 0.9.2: a vanity host missing addresses its forward-confirmed
provider publishes is reported with those addresses named, an equal set reports
nothing, and `PRIVACY.md` carries re-measured fan-out figures.

### 1.0.0: Product contract and release readiness

Spec: [`docs/specs/one-zero-readiness.md`](docs/specs/one-zero-readiness.md)

Graduates the finished product without adding another protocol feature. Defines
the supported 1.x compatibility surfaces, executes a real browser and keyboard
accessibility matrix, verifies clean-checkout and production artifacts, closes
the external-intelligence decision, and reconciles every public behavior claim
with measurements from the finished branch.

Exit condition: the supported facade, finding identities, JSON schema and CSV
rules have explicit compatibility policies; the agreed browser and accessibility
matrix passes; the privacy, storage and network claims match observation; all
maintenance items are dispositioned; and deterministic replay against `v0.9.0`
shows no unintended movement across every published surface.

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

## Addendum: current execution order after the 0.6.0 refactor (2026-08-31)

The earlier async plan allowed 0.8.0 artifact validation to run in parallel
with the protocol chain and reconcile a temporary finding stub later. That did
not happen before the refactor serialized the source tree, and preserving the
old optimization would now create avoidable contract churn.

One release remains:

```text
1.0.0 graduation
```

`0.7.0` froze finding identity and provenance. `0.8.0` consumed that final
shape rather than inventing a stub. `0.9.0` froze the public report
schema around both DNS and user-supplied provenance decisions. `1.0.0` verifies
and documents the compatibility promises made by those releases. The decision
document for external intelligence can be reviewed alongside the feature specs,
but it must be Final before 1.0.0 under the current readiness draft.

[`HANDOFF.md`](HANDOFF.md) carries the current operational review checkpoints.
Release numbers, filenames and stable
`OQ-*` identifiers do not change when implementation scheduling changes.
