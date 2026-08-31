# Spec: Modular architecture and production build

| Field | Value |
| --- | --- |
| Spec version | 1.8 (Implemented) |
| Target release | 0.6.0 |
| Status | **Released as `v0.6.0` on 2026-08-30.** All six gates are met. Originally **Final.** Approved for implementation after three Codex review rounds. Amended to `1.1` during Phase 2 to correct one incomplete enumeration in §11, to `1.2` to correct an overstated evidence claim about how that enumeration is guarded, to `1.3` to add the last ambient primitive the conversion sweep found, and to `1.4` — during Task 2.7 — to state the oracle's provenance once the supported facade replaces the legacy engine global and reclassify the PSL fixture-identity fingerprint as binding-level, to `1.5` at the Gate 2 audit to correct two claims `1.4` overstated, and to `1.6` at Task 3.6 to replace §3's three-name exception-edge row with two separate inventories. See [Revision history](#revision-history). Linux dependency installation was verified on a native Linux runner at Gate 1. |
| Depends on | [dnssec-evidence](dnssec-evidence.md), released as 0.5.0 and used as the behavioral baseline |
| Blocks | [findings-and-remediation](../findings-and-remediation.md), [local-artifact-validation](../local-artifact-validation.md), [report-comparison](../report-comparison.md) — all three are scheduled after it |
| Slug for open questions | `ARCH` |
| Last updated | 2026-08-30 |
| Evidence | [esbuild-legacy-bundle-spike-0.6.0](fixtures/esbuild-legacy-bundle-spike-0.6.0.md) — settles `OQ-ARCH-01`, confirms Phase 1 viability, and demonstrates the fixture-substitution hazard; [gate-0-evidence-0.6.0](fixtures/gate-0-evidence-0.6.0.md) — the Gate 0 conditions, met 2026-08-27; [gate-1-evidence-0.6.0](fixtures/gate-1-evidence-0.6.0.md) — the Gate 1 conditions, including native-Linux `npm ci` and `file://` in a real browser; [gate-2-evidence-0.6.0](fixtures/gate-2-evidence-0.6.0.md) — the Gate 2 conditions, met 2026-08-28, with both compatibility deltas performed and the oracle's two-execution rebuild; [gate-4-evidence-0.6.0](fixtures/gate-4-evidence-0.6.0.md) — every protocol in an owning directory, and the issue-token vocabulary diffed byte-identical against `v0.5.0`; [gate-5-evidence-0.6.0](fixtures/gate-5-evidence-0.6.0.md) — the four Gate 5 conditions, each with the command that produced it, including the runnable `v0.5.0` scoring comparison. Gate 3 has no evidence document; its conditions are carried by the contract suites it created. |
| Reviews | **Three formal spec-review rounds** (Codex, 2026-08-27) produced `0.2`, `0.4` and `1.0`. Two later review cycles amended the spec: the Task-2.7 round produced `1.4`, and its §5 Gate-2 audit produced `1.5`; the Task-3.6 round produced `1.6`. Those five were carried in six **temporary working documents** at the repository root — a request and a follow-up for each — which are deleted; the filenames still named in the Revision history below are **provenance only**, not documents you can open. A further **implementation-review cycle ran across Phases 5 and 6, produced no working document, and amended nothing**. Every durable decision from both sources is folded into [As implemented](#as-implemented). |
| Source | Written from an external proposal, *DNS Email Audit Modular Architecture and Production Build Refactor Specification* (Codex, 2026-08). Section numbers of the form §N below refer to that document. Where this spec diverges from it, the divergence is recorded in [§ Corrections to the source proposal](#corrections-to-the-source-proposal). |

## Problem

The application is seven classic `<script src>` tags loading IIFEs that attach
to `window` in dependency order ([`index.html:187`](../../../index.html)). There is
no module system, no build step for JavaScript, and no way for one file to
declare what it needs from another. The load order in `index.html` *is* the
dependency graph, and it is enforced by three assertions in
[`tools/csp.test.mjs`](../../../tools/csp.test.mjs) rather than by the language.

Two of those files carry almost all of the hand-written code:

| File | Lines | Raw | gzip |
| --- | ---: | ---: | ---: |
| `js/dns.js` | 5,704 | 288,185 | 87,260 |
| `js/app.js` | 1,819 | 83,539 | 24,837 |
| `js/render.js` | 552 | 22,802 | 7,990 |
| `js/i18n.js` | 403 | 16,107 | 5,536 |
| `js/locales-en.js` *(generated)* | 1,186 | 125,172 | 37,678 |
| `js/public-suffixes.js` *(generated)* | 6 | 164,798 | 44,475 |
| `js/dkim-selectors.js` *(generated)* | 6 | 18,596 | 5,691 |
| **Total** | **9,676** | **719,199** | **213,467** |

`js/dns.js` is a single 5,704-line IIFE that owns DNS transport, response
caching, SPF parsing and recursive evaluation, DKIM discovery and key decoding,
DMARC parsing and organizational-domain tree walking, DNSSEC chain evaluation,
MX health, CAA, MTA-STS, TLS-RPT, TLSA, provider detection, scoring, and issue
construction. Every one of those responsibilities shares one lexical scope and
one closing `})(window)`.

The consequences are concrete rather than aesthetic:

**Blast radius is the file, not the concern.** A change to DMARC
organizational-domain discovery and a change to SPF lookup accounting are edits
to the same 288 KB file. Neither a human reviewer nor a coding agent can bound
the effect of one by reading only the part it touched.

**Protocol logic cannot be tested without the whole file.**
[`tools/scoring.test.mjs`](../../../tools/scoring.test.mjs) constructs a `node:vm`
context, evaluates `js/dkim-selectors.js` and all 288 KB of `js/dns.js` into it,
and reaches the functions under test through the object the IIFE assigns to
`window`. There is no way to import `classifySpfSubnet` without also
instantiating the DNSSEC evaluator, the provider catalog and the scoring
weights. The suite works — 2,121 assertions pass — but it tests a monolith
through a keyhole.

**The delivery cost is paid in full on every visit.** The browser fetches seven
uncompressed files totaling 719 KB. Nothing is minified, dead code is not
eliminated, and the 308 KB of generated data tables are served with the same
cache lifetime as the code that changes every release.

**There is no distinction between source and artifact.** What the repository
contains is byte-for-byte what GitHub Pages serves.
[`tools/build-site.mjs`](../../../tools/build-site.mjs) copies seven paths into
`_site/`; it is a file-selection step, not a build. That has been an asset —
the shipped behavior is trivially auditable — and this spec must not spend it
carelessly.

The project is about to add three more releases of protocol surface
([findings-and-remediation](../findings-and-remediation.md),
[local-artifact-validation](../local-artifact-validation.md),
[report-comparison](../report-comparison.md)), each of which reads or extends the
output shapes inside `js/dns.js`. The architectural boundaries are cheaper to
establish now, against a released and backtested 0.5.0 baseline, than after
three more releases have been layered onto the monolith.

### The baseline this refactor is measured against

Captured on `main` at 0.5.0, 2026-08-27:

| Signal | Value |
| --- | --- |
| `npm test` | 2,121 assertions, 0 failed |
| `tools/scoring.test.mjs` | 1,535 assertions — the protocol suite, and 72% of all coverage |
| `tools/render.test.mjs` | 329 assertions |
| `tools/export.test.mjs` | 199 assertions |
| `tools/csp.test.mjs` | 41 assertions |
| `tools/interpolate.test.mjs` | 17 assertions |
| `tools/check-locales.mjs` | passes; reports findings rather than an assertion count |
| `npm run locale:gate` | 13/13 locales strict |
| Browser payload | 7 files, 719,199 bytes raw, 213,467 bytes gzip |
| Runtime npm dependencies | 0 |
| Development npm dependencies | 0 |
| `package-lock.json` | Does not exist; git-ignored at [`.gitignore:3`](../../../.gitignore) |

> The per-suite split above is read from `npm test` output. The authoritative
> total is the sum, 2,121. Any implementation phase that changes this number
> must say why in its commit message.

## Scope

Ordered as the work is done. **The build comes before the module conversion**,
reversed from this spec's 0.1 draft — see
[Corrections from review round 1](#1b-corrections-from-review-round-1), item A.

1. Introduce esbuild as the project's first development dependency and bundle
   the **existing classic scripts unchanged** into `dist/app.min.js`, making the
   built artifact the delivery boundary before anything else moves.
2. Establish the equivalence, parity and artifact tests against that boundary,
   so every later commit is checked against the thing the browser receives.
3. Convert the hand-written browser code from `window`-attached IIFEs to ES
   modules under `src/`, one responsibility at a time behind the stable bundle,
   using explicitly marked adapters where a converted module must still serve a
   classic consumer.
4. Split `js/dns.js` and `js/app.js` along the four responsibility boundaries in
   §4 of the source proposal: DNS transport, protocol evaluation, audit
   coordination, UI.
5. Change the deployed artifact from seven source files to the bundle, without
   changing `index.html` as the public entry point or any public URL.
6. Extend CI to build the bundle, verify the deployment artifact's contents, and
   report bundle size.
7. Prove behavioral equivalence against the 0.5.0 baseline across the complete
   audit result, the DNS query trace, the rendered DOM and both exports —
   executed against `dist/app.min.js`, not only against source.
8. Restructure the tests to mirror module ownership, and remove the `node:vm`
   sandbox where a plain `import` now suffices.
9. Document module ownership in `AGENTS.md` so a coding agent's expected
   modification boundary is stated rather than inferred.

## Non-goals

Inherited unchanged from §3 of the source proposal, and restated here because
they are binding:

- **No audit behavior change.** Same normalized DNS responses in, same statuses,
  findings, severities, scores and explanations out. See
  [Behavioral equivalence](#behavioral-equivalence).
- **No scoring change.** `WEIGHTS`, `PARKED_WEIGHTS` and `GRADE_THRESHOLDS` stay
  byte-identical, asserted directly against `v0.5.0`.
- **No frontend framework**, and no runtime npm dependency. esbuild is a
  development dependency and never reaches the browser.
- **No backend, no server-side processing, no persistence change.** The privacy
  boundary in [`PRIVACY.md`](../../../PRIVACY.md) is untouched: browser →
  `https://cloudflare-dns.com`, `localStorage` holds one key.
- **No new network destination.** `connect-src` stays
  `'self' https://cloudflare-dns.com`.
- **No public URL change.** `index.html` remains the entry point.
- **No UI redesign.**
- **No Web Worker**, no dynamic `import()`, no aggressive code splitting.

And three added by this spec:

- **No finding-identifier redesign.** See
  [Corrections to the source proposal](#corrections-to-the-source-proposal),
  item 2.
- **No localization key change.** `locales/en.json` is not edited by this
  release. See [Localization impact](#localization-impact).
- **No change to the generated-data update tools.**
  `tools/update-psl.mjs` and `tools/update-dkim-selectors.mjs` keep writing the
  same data; only the module wrapper around their output changes.

## Design

### 1. Corrections to the source proposal

The source proposal was checked against the code at 0.5.0. Six of its claims do
not hold, and correcting them changes the work materially. They are recorded
here rather than silently diverged from.

**1. The code is not ES modules, and the proposal never says so.** §5, §13 and
§19 describe moving files into `src/` as though the module graph already exists.
It does not. `js/dns.js` ends `})(window)`; `js/app.js`, `js/render.js` and
`js/i18n.js` follow the same pattern; `js/public-suffixes.js` and
`js/dkim-selectors.js` assign a global. Every consumer — `index.html`,
[`tools/lib/browser-harness.mjs`](../../../tools/lib/browser-harness.mjs),
[`tools/backtest.mjs`](../../../tools/backtest.mjs) and
`tools/scoring.test.mjs` — reaches the code through `window`, and the harness
comment states the design explicitly: *"the files are plain IIFEs that attach to
`window`, so there is nothing to mock and no bundler involved."*

Converting to ESM is therefore not a precondition the proposal assumed; it is
the largest single work item in the refactor, and it invalidates the loading
strategy of four separate tools.

> **Amended in 0.2.** Version 0.1 concluded "this spec makes it Phase 0" — the
> ESM conversion first, the build after. Review round 1 reversed that: the
> conversion is **Phase 2**, behind a bundle established in Phase 1, because
> 0.1's phase ordering could not keep the browser working between its own
> commits. The omission this correction identifies is unchanged and still the
> largest work item; only its position moved. See
> [Corrections from review round 1](#1b-corrections-from-review-round-1), item A.

**2. Findings already have stable machine-readable identifiers.** §31 proposes
introducing them, with examples in the form `SPF_LOOKUP_LIMIT`. This is already
the binding project rule, stated in the header of `js/dns.js` and in
`docs/specs/README.md`: *"`js/dns.js`
returns tokens, not English."* The existing tokens are lowercase-hyphenated —
`'spf-missing'`, `'@none'`, `'noteWildcard'` — and are consumed by
`js/app.js` through the i18n layer and by `locales/en.json` keys of the form
`issue.spf-large-subnet.msg`.

Renaming them to `SCREAMING_SNAKE_CASE` would touch every locale file, every
issue key, and the export formats, for no behavioral gain — and it would violate
§35 of the proposal itself, which forbids moving code and redesigning result
schemas in the same change. **Declined.** The token vocabulary is preserved
byte-for-byte. §31's genuine content — that findings are structured facts and
the UI decides presentation — is already true and is preserved by the module
boundary in [Design §4](#4-protocol-modules).

**3. A shared DNS cache already exists.** §9 asks for one. `dohCache` is a
`Map` with LRU eviction at `js/dns.js:70`, keyed on
`name + type`, with a `noCache` opt-out and — importantly — a deliberate rule
that only `success`, `nodata` and `nxdomain` results are cached, so a transport
failure is never remembered as an answer. §9's last line asks for the cache to be "scoped to the active audit". **That
part is declined.** Page-lifetime reuse is deliberate, tested, and part of a
published privacy figure:

- [`tools/scoring.test.mjs:1888-1891`](../../../tools/scoring.test.mjs) asserts
  exact query counts across two *different* domains — a first DMARC walk issues
  3 queries and a sibling subdomain issues 1, reusing the cached upper steps.
  Per-audit scoping fails that assertion.
- [`js/app.js:1397`](../../../src/main.js) calls `analyzeDomain(domain, opts)` once
  per queued domain from a shared worker pool, with no audit context passed.
  The reuse exists *because* the cache outlives a single domain.
- [`PRIVACY.md:30-33`](../../../PRIVACY.md) publishes the consequence: "roughly 41
  queries for a typical domain", and 61 for `cloudflare.com`. Narrowing the
  cache raises those numbers, which makes it a privacy-facing change, not a
  refactor.

**Accepted as narrowed further than 0.1 stated**: the cache moves to
`src/core/dns/cache.js` behind a factory — an architectural change — and each
audit runtime owns one cache. `src/main.js` constructs exactly one production
runtime for the browser page, preserving page lifetime exactly; tests construct
fresh runtimes and therefore do not share caches accidentally. Eviction policy,
key format and the cacheable-kind rule do not change. Changing the production
runtime's one-per-page lifetime is a separate, later decision requiring
query-count fixtures and a privacy review.

**4. A deployment allowlist already exists.** §40 asks for one.
`tools/build-site.mjs` builds `_site/` from an explicit seven-entry list with a
skip-set that keeps `locales/translation-status.json` out of the published
site. What is missing is a *test*: nothing asserts the allowlist's contents, so
a careless edit to that array could publish `tools/` or `docs/` unnoticed.
**Accepted as narrowed**: the allowlist swaps `js` for `dist`, and gains the
assertion described in [Testing](#testing).

**5. `package-lock.json` does not exist and is git-ignored.** §18 reasons from
*"commit X, package-lock.json, documented Node version"*, and §28 requires that
*"npm development dependencies must be pinned through the lockfile."* Neither is
possible today: [`.gitignore:3`](../../../.gitignore) ignores the lockfile, because
until now the project has had zero dependencies of any kind and the file would
always have been empty.

Adding esbuild makes this the first dependency in the project's history, and the
build system becomes part of its supply chain (§28's own words). The `.gitignore`
entry must be removed and the lockfile committed, or the requirement cannot be
met. Recorded as `OQ-ARCH-02`.

**6. Behavioral equivalence, as specified, cannot be verified.** §23 requires the
refactored implementation to produce equivalent output, and §39 asks CI to verify
*"production build success"*. But every existing test loads **source**, and the
browser will be served the **bundle**. "Build success" means esbuild exited zero;
it says nothing about whether the bundle behaves like the source it was built
from. A minifier bug, a tree-shaking mistake, or a `this`-binding change under
ESM strict mode would pass every gate in the proposal and reach production.
**Corrected**: at least one suite runs against `dist/app.min.js`. See
[Testing](#testing), item 4.

### 1b. Corrections from review round 1

Codex reviewed spec version 0.1 on 2026-08-27 and raised eight findings. **All
eight were verified against the code and all eight were accepted.** They are
recorded here because several reverse decisions 0.1 argued for, and the
reasoning should survive.

| # | What 0.1 said | What was wrong | Where it now lives |
| --- | --- | --- | --- |
| A | ESM conversion is Phase 0, ahead of the build | Phase 0 could not keep the browser working between its own commits: the gate claimed seven scripts still load while the interim note required `index.html` to load a `src/main.js` that did not exist for another commit. esbuild can bundle the existing IIFEs unchanged, so the build can come first and give every later commit a stable delivery boundary. | Scope, Design §6, `OQ-ARCH-07` |
| B | Equivalence observes scores, grades and issue tokens | The Non-goals promise statuses, findings, severities, scores **and explanations**. A refactor could change MX detail, DNSSEC evidence, DKIM key facts, provider detection, warnings, suggestions or export columns and still pass. Query fan-out is not observed at all, and it is a published privacy figure. | Design §8, Testing |
| C | Capture the baseline by checking out `v0.5.0` | The runner being invoked is a new file on this branch. Checking out the tag deletes it. | Design §8 |
| D | Bundle parity "loads the bundle and re-runs the fixtures" | No stated access path to `auditDomain` inside a minified browser entry, and `tools/scoring.test.mjs:21` injects a four-rule `__PUBLIC_SUFFIX_RULES__` table that a static data import would silently replace with the real 165 KB PSL. | Design §6, Testing |
| E | Per-audit cache scoping, "behavior unchanged" | Both halves were wrong. See correction 3 above. | Correction 3, Design §5 |
| F | esbuild has "zero transitive dependencies" | `npm view esbuild` at 0.28.2 reports `postinstall: node install.js` and 26 `@esbuild/*` `optionalDependencies`. Small is not zero, and a postinstall script is exactly what a supply-chain argument must account for. | Risks R3, `OQ-ARCH-01` |
| G | Transport boundary proven by grepping for locale keys | `locales/en.json` is nested, so `issue.spf-large-subnet.msg` never appears as a literal; and the tokens are *values* like `spf-missing`, not keys. The resolver could emit a judgment token and the grep would pass. | Design §3, Testing |
| H | Assertion count `>= 2,121` is a merge gate | A count can stay level while a meaningful assertion is deleted and an unrelated one added. It is an inventory signal, not coverage proof. | Testing, Risks R5 |

Three smaller factual errors were also corrected: `legalComments: 'inline'`
preserves nothing (no file under `js/` contains an `@license`, `@preserve`,
`/*!` or `//!` comment, and the MIT text lives in the separate `LICENSE` file);
`tools/interpolate.test.mjs` has 17 assertions, not 329; and
`src/data/locales-en.js` regenerates when `locales/en.json` is edited, not every
release — which this release explicitly promises not to do.

One item was raised by this spec's author in response and is **open**: the
bundle's output format. See `OQ-ARCH-06`.

### 2. Target source structure

Adapted from §5, with the caution in that section honored: a module exists
because it owns a responsibility, not to make the tree look modular.

**Unit tests live beside the code they test.** The reasoning is in
[Design §9](#9-test-placement); the short version is that §32 of the source
proposal asks for a protocol change to be bounded by one directory, and a test
in a parallel tree puts half the change outside it.

```text
src/
├── main.js                  entry point; wires UI to coordinator
├── runtime.js               side-effect-free createAuditRuntime() composition
├── facade.expected.json     the two supported production exports
│
├── platform/
│   └── browser.js           browser primitives passed into the runtime
│
├── core/
│   ├── dns/
│   │   ├── doh.js           DoH request, timeout, retry, AbortController
│   │   ├── resolver.js      normalization, response-kind classification
│   │   ├── cache.js         runtime-lifetime; production creates one runtime per page
│   │   ├── errors.js        DnsTypeError and dnsError(kind, name, type)
│   │   ├── optional.js      optionalCheck() rethrow/fallback policy
│   │   ├── existence.js     direct-kind name-existence mapping
│   │   ├── contracts.js     ten kinds, retry/cache sets, exception-edge names
│   │   └── *.test.js
│   │
│   ├── spf/                 parse, recursive evaluate, lookup accounting,
│   │                        subnet classification, redundancy
│   ├── dkim/                selector discovery, catalog, key decode
│   ├── dmarc/               parse, tree walk, organizational domain, policy
│   ├── dnssec/              chain evaluation, DS↔DNSKEY matching
│   ├── mx/                  MX health
│   ├── caa/                 CAA policy
│   ├── bimi/                BIMI record validation
│   ├── transport/           mta-sts.js, tls-rpt.js, tlsa.js
│   └── shared/              pure parsing/value helpers; imports nothing
│                            (each protocol directory carries its own *.test.js)
│
├── audit/
│   ├── audit-domain.js      orchestration; which checks run, in what order
│   ├── context.js           per-audit state (NOT the DoH cache — see §5)
│   ├── scoring.js           WEIGHTS, PARKED_WEIGHTS, GRADE_THRESHOLDS
│   ├── issues.js            buildIssues, buildSuggestions
│   └── *.test.js
│
├── providers/detectors.js   + detectors.test.js
│
├── ui/
│   ├── render.js            from js/render.js
│   ├── report.js            exportCSV, exportHTML
│   ├── events.js            DOM wiring
│   └── *.test.js
│
├── i18n/index.js            from js/i18n.js  + index.test.js
│
└── data/                    generated; not hand-edited, not unit-tested
    ├── public-suffixes.js
    ├── dkim-selectors.js
    └── locales-en.js

tests/                       cross-cutting only — no single module owns these
├── lib/                     dom-shim, doh-fixture, harness
├── fixtures/equivalence/    the corpus and its committed baseline
├── contract/                result-algebra and dependency-direction contracts
├── integration/             whole-audit runs through the real transport path
└── build/                   parity, artifact contents, size, CSP
```

**`core/bimi/` is new in 0.2.** Version 0.1's tree omitted BIMI entirely while
the implementation plan filed `validateBimiRecord` under `core/transport/`.
BIMI is brand-indicator validation, not mail transport security; the two
documents disagreed and both were wrong. Codex raised this in round 1.

### 3. DNS transport boundary

`src/core/dns/` owns obtaining DNS information and nothing else.

Version 0.2 proposed a grep for locale keys (vacuous — `en.json` is nested and
the tokens are values). Version 0.3 then replaced it with a single five-member
union that **this codebase does not have**. Both are withdrawn. What follows is
the structure that exists at `v0.5.0`, documented rather than designed.

#### Four processing layers, plus exception edges

Not a five-stage pipeline: layer 5 is a set of deliberate bypasses, not a stage
every query flows through. Round 2 made this correction and it is load-bearing
for the API table and the allowed-edge matrix.

| # | Boundary | Implementation | Returns / raises |
| --- | --- | --- | --- |
| 1 | Raw transport | `dohFetch()` | One of ten kinds (below) |
| 2 | Usability gate | `requireUsable()` `js/dns.js:256` | Passes `success`/`nodata`/`nxdomain`; **throws** `dnsError(kind, …)` for the other seven |
| 3 | Normalized records | `dohQuery()`, `dohAll()` `js/dns.js:281` | Arrays of cleaned strings — **no kind** |
| 4 | Error and cancellation policy | `optionalCheck()` `js/dns.js:247` | Caller's declared unknown; **re-throws** `AbortError` and `DnsTypeError` |
| — | **Exception edges** | See the two inventories below | Read `.kind` directly, deliberately bypassing layer 3 |

> **Amended in 1.6: this row named three sites and conflated two different
> contracts.** Both were found at Task 3.6, whose job is to name and test these
> edges — the same way `1.1`, `1.3` and `1.5` were found by the work that had to
> use them.
>
> The two contracts are:
>
> 1. **Raw-kind readers** — code allowed to inspect a raw resolver response
>    instead of consuming normalized record arrays.
> 2. **Kind propagation paths** — fields in an `analyzeDomain()` result that can
>    retain one of the ten closed transport kinds.
>
> One list cannot serve both. `domainExists()` and `checkConnectivity()` are
> legitimate raw-kind readers and **neither propagates a kind** — one maps to
> `yes`/`no`/`unknown`, the other to a boolean. Conversely a layer-4 fallback can
> propagate a caught `DnsError.kind` without reading a raw resolver response at
> all. Naming three sites answered neither question completely.

#### The raw-kind reader inventory

Organized by **owning function or family**, not by line number, so a move within
an owner does not invalidate it. Anything outside this list and the layer
implementations must consume normalized arrays.

| Owner | Allowed raw-kind consumer | What it exists to preserve |
| --- | --- | --- |
| `core/dns` | `existenceFromResponse()` / `domainExists()` | `nxdomain` versus `nodata`, which is `no` versus `yes` |
| `core/dns` | `checkConnectivity()` | The raw answer as a reachability boolean |
| `core/dmarc` | `checkExternalReportAuth()` | The exact response kind, and the conversion of failed kinds at the protocol boundary |
| `core/dmarc` | `discoverDmarc()` | Each walk step, and a failed walk distinguished from absence |
| `core/dnssec` | `dnssecLookupStatus()` / `checkDNSSEC()` | Lookup completeness, and the validated-`servfail` security signal |
| `audit` | the NS `servfail` DNSSEC preflight in `analyzeDomain()` | The deliberate unchecked retry, before orchestration continues |

**`doh.js` and `requireUsable()` are not exception edges.** They *are* layers 1
and 2. Keeping them out of the allowlist is what stops the term meaning
"anywhere a kind is mentioned".

#### The kind propagation inventory

Derived from **result construction**, then checked against the baseline — not
the other way round. The corpus is coverage evidence; the source is the
contract, and a path the corpus does not currently reach is a corpus finding
rather than permission to omit it.

| Result path | Mechanism |
| --- | --- |
| `dmarcDiscovery.steps[].kind` | `discoverDmarc()` records each step |
| `dmarcDiscovery.error` | `discoverDmarc()` on a failed walk |
| `advanced.dnssec.lookups.ns.kind` | `dnssecLookupStatus()` |
| `advanced.dnssec.lookups.ds.kind` | `dnssecLookupStatus()` |
| `advanced.dnssec.lookups.dnskey.kind` | `dnssecLookupStatus()` |
| `advanced.dnssec.chain[].detail.kind` | `checkDNSSEC()` claims |
| `advanced.dnssec.error` | `checkDNSSEC()` |
| `advanced.reportAuth[].error` | `checkExternalReportAuth()`'s internal `catch` |
| `advanced.reportAuth[].exactKind` | `checkExternalReportAuth()` on an unauthorized destination |
| `advanced.caa.error` | the `checkCAA()` layer-4 fallback |
| `advanced.spfLookups.queryError` | the `countSpfLookups()` layer-4 fallback |

Eleven typed paths, and one **derived presentation copy**: the DMARC walk's kind
is interpolated into the `dmarc-unverified` issue's arguments. That copy is
tested against **its own issue key** and is deliberately **not** added to
`dns.transport.kind`'s `resultPaths` — a bare `issues[].args[]` pattern would let
an unrelated argument that happened to equal `timeout` earn transport coverage,
which is the vacuous credit the measured state matrix exists to remove.

The **thrown** audit `error.kind` is not on this list. It is not a result, and
§12.1 already owns it as a thrown path; mixing it into `resultPaths` would blur
the two.

#### Layer 4 may carry a kind — but `optionalCheck()` does not decide that

`optionalCheck()` is **policy-neutral**. It re-throws `AbortError` and
`DnsTypeError` and otherwise returns whatever the caller declared. Many callers
declare `null`, `[]`, or a shape with no kind at all, and those must never
acquire one implicitly.

**A caller-supplied fallback alone owns the unknown result's shape, and it may
copy `DnsError.kind` deliberately.** Three fallback factories do:

| Fallback | Escapes as |
| --- | --- |
| website resolution | **nothing** — copied to a temporary `website.error`, then collapsed to the `hosting` sentinel `@dns-error` |
| `checkCAA()` | `advanced.caa.error` |
| `countSpfLookups()` | `advanced.spfLookups.queryError` |

`checkExternalReportAuth()` is a fourth kind-copying site and is **not** one of
these: it is an internal `catch`, and its `optionalCheck()` wrapper supplies a
static `[]`. `discoverDmarc()` is a third mechanism again — it records raw
response kinds directly into its walk result. The three are distinct and the
contract tests them as such.

#### Layer 1 — the ten transport kinds

Every one verified at its construction site. This set is **closed** and is
byte-compatible with `v0.5.0`; no member is renamed, merged or added.

| Kind | Origin |
| --- | --- |
| `success` | `responseKind()`, status 0 with answers |
| `nodata` | `responseKind()`, status 0 without answers |
| `nxdomain` | `responseKind()`, status 3 |
| `servfail` | `responseKind()`, status 2 |
| `refused` | `responseKind()`, status 5 |
| `dns-error` | `responseKind()`, any other status |
| `http-error` | `js/dns.js:189` |
| `cancelled` | `js/dns.js:195` |
| `timeout` | `js/dns.js:196` |
| `network-error` | `js/dns.js:196` |

`DnsTypeError` is **thrown** at `js/dns.js:121`, never
returned. It is not a kind and must not become one.

Three cross-cutting rules the contract tests pin, because each is a distinction
a coarser model would flatten:

- **Cacheable ⊂ retry-terminal.** Retry stops on
  `success`/`nodata`/`nxdomain`/**`cancelled`** (`js/dns.js:216`);
  the cache admits only the first three (`js/dns.js:219`).
  `cancelled` is terminal but never cached.
- **`servfail` is a security signal**, not merely a failure: it drives the
  `resolver-bogus` DNSSEC claim at `js/dns.js:4022`.
- **`nxdomain` ≠ `nodata`** at the exception edge: `domainExists()` maps
  `nxdomain` → `'no'`, `success`/`nodata` → `'yes'`, everything else
  → `'unknown'` (`js/dns.js:2202-2205`).

#### The protocol/audit algebras are separate

Accepting the transport model above does not discharge the protocol half.
Protocol modules have their own discriminants — `analyzeSpf().status` is one of
`ok`/`warn`/`present`/`missing`/`softfail`/`permerror`; `checkDNSSEC().state` is
one of `secure`/`insecure`/`bogus`/`unanchored`/`mismatch`/`indeterminate`; DMARC
record diagnosis carries `absent`/`syntax`/`version`/`not-first`/`bad-value`.
These are enumerated per owner in the API table (§12) and every member is mapped
to a suite and a fixture by the state matrix (Testing item 3).

`src/core/dns/` may emit none of them.

### 4. Protocol modules

Each `src/core/<protocol>/` module takes normalized DNS results and a resolver
handle, and returns structured facts using the **existing** token vocabulary.
No module under `src/core/` imports from `src/ui/`. Enforced by test, not by
convention — see [Testing](#testing), item 5.

> **On passing a resolver handle, and the seam this project refuses.**
> `tools/lib/doh-fixture.mjs` states a standing rule: *"`js/dns.js` gets no test
> seam. There is no `__setResolver`, no injected transport and no production
> branch that exists only for tests — this repo has consistently refused those,
> and a resolver stub that bypasses the real request-building code would stop
> testing the part most likely to be wrong."*
>
> A resolver handle passed between protocol modules is not that. The rule
> forbids a seam that exists *only for tests* and that lets a test bypass real
> request construction. Here the handle is the production call path — it is how
> `src/audit/` gives `src/core/spf/` a resolver in the browser, with no
> test-only branch anywhere — and tests keep substituting `fetch` exactly as
> they do today, so the genuine URL construction, `application/dns-json`
> parsing, cache, concurrency limiter and retry loop all stay under test. The
> precedent is preserved, not spent. Any implementation that adds a
> `__setResolver`-shaped export has violated it and must be rejected in review.

### 5. Audit coordinator

`auditDomain(domain, options, context)` owns which checks run, which may run
concurrently, error isolation via the existing `optionalCheck()`, and result
aggregation. It does not parse records.

**The DoH cache is not in that context.** Version 0.1 put it there, following
§9's request that the cache be "scoped to the active audit". That is declined —
see [Corrections](#1-corrections-to-the-source-proposal) item 3. The cache is
constructed by its own module at page scope and the coordinator reuses it, which
is exactly `v0.5.0` behavior. `context.js` carries per-audit state that is
genuinely per-audit: the options in force, the accumulated result, cancellation.
Moving cache ownership into it is a later, separately-authorized change
requiring query-count fixtures and a privacy review.

The concurrency structure that exists today — `Promise.all` over independent
checks, batched DKIM selector scanning at `DKIM_SCAN_BATCH_SIZE = 24` — is
preserved as-is. §8 of the proposal is explicit that the refactor does not
require concurrency changes, only that the architecture stop preventing them.
**Changing concurrency and moving code in the same phase is forbidden** by §35
and by this spec.

### 6. Build

esbuild 0.28.2, exact-pinned, as the sole **direct** development dependency.
Every figure below is measured, not estimated — see
[fixtures/esbuild-legacy-bundle-spike-0.6.0](fixtures/esbuild-legacy-bundle-spike-0.6.0.md).

#### Measured, not assumed

| | Value |
| --- | --- |
| Packages installed on darwin-arm64 | **2** — `esbuild` + `@esbuild/darwin-arm64` |
| Declared optional platform packages | 26, of which 25 resolve UNMET |
| Install scripts | **1** — `postinstall: node install.js`, surfaced by npm's `allowScripts` gate |
| Legacy bundle, raw | 430,750 (from 719,199 — **−40.1%**) |
| Legacy bundle, gzip | 130,256 (from 213,467 — **−39.0%**) |
| Build time | 22 ms |

Two packages and one install script is a small supply chain and esbuild remains
the right choice. It is **not zero**, which `0.1` of this spec claimed twice.
Whether CI allows the install script is an explicit decision, not an implicit
one — see Risks R3.

> **Linux CI is still outstanding.** The spike ran on darwin-arm64 only and the
> footprint is platform-specific by design. Round 2's condition is not fully
> discharged until `npm ci` is confirmed on Linux. Tracked as an acceptance
> criterion, deliberately deferred.

#### Configuration

| Setting | Value | Why |
| --- | --- | --- |
| `bundle` | `true` | One artifact, per §25 |
| `format` | `iife` | §10; keeps `file://`, keeps the CSP shape |
| `globalName` | **omitted in Phase 1**, `DnsAudit` only after the facade exists | §10. See below. |
| `minify` | `true` | The measured 40% |
| `sourcemap` | `linked`, external | `OQ-ARCH-04` |
| `target` | `es2020` + required-API matrix | `OQ-ARCH-03` |
| `splitting` | `false` | §25 |
| `metafile` | `true` | Size reporting **and** the binding co-location proof (Testing item 7) |
| `banner.js` | explicit string | `legalComments` cannot do this — no file under `js/` carries an `@license`, `@preserve`, `/*!` or `//!` comment, and the MIT text is the separate `LICENSE` file |

#### `globalName` does not do what 0.2 claimed

Version 0.2 asserted that `globalName: 'DnsAudit'` would expose *"exactly the
surface the existing harness already reaches"*. It does not: esbuild assigns
**the entry point's exports** to that name, and `src/entry-legacy.js` has none.
In a classic script the generated top-level `var DnsAudit` would have
**overwritten** the real object from `js/dns.js:5601` —
breaking the application on Task 1.6, the commit that moves the delivery
boundary.

The spike confirms the correct approach works: with **no** `globalName`, the
bundled IIFEs create all 24 globals themselves, `DnsAudit` arrives with all 95
members intact, and `WEIGHTS` and `GRADE_THRESHOLDS` are identical to source.

`globalName` is therefore introduced only in §10's stage 3, against a facade
that actually exports something.

`index.html` becomes:

```html
<script src="dist/app.min.js"></script>
```

### 7. Deployment

`tools/build-site.mjs`'s allowlist changes from

```js
['index.html', 'CNAME', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'css', 'js', 'locales']
```

to

```js
['index.html', 'CNAME', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'css', 'dist', 'locales']
```

`npm run build` becomes two steps — bundle, then assemble `_site/` — and
`_site/` must contain no `src/`, no `tools/`, no `docs/`, no `package.json`,
no `node_modules/`, no `*.test.*` from either tree, and no `assets/`. The
allowlist is asserted exactly — presence *and* absence — not assumed. Source
maps ship under `dist/` per `OQ-ARCH-04`.

`dist/` is already git-ignored ([`.gitignore:7`](../../../.gitignore)), which
matches §17: the artifact is generated by CI from the commit being deployed and
never committed.

### 8. Behavioral equivalence

**Five observed surfaces.** Version 0.3 said four and then enumerated only four
in the gate while promising both exports in Scope — HTML report parity had
fallen out. Round 2's R2-F4 caught it. Restored, and counted honestly.

> Given identical fixture DNS responses, the refactored code produces an
> identical canonical projection of the complete `analyzeDomain()` result, an
> equivalent DNS query trace, byte-identical CSV, an equivalent canonical HTML
> report, and an equivalent canonical DOM, compared against `v0.5.0` — and
> `dist/app.min.js` produces the same as `src/`.

| Surface | Compared | Why separate |
| --- | --- | --- |
| Result | Canonical JSON of the whole return | Non-goals promise the whole result, not the grade |
| Query trace | Normalized multiset + order where order is the behavior | Fan-out is published in `PRIVACY.md`; a lost cache hit is invisible in the result |
| CSV | Exact bytes | Positional columns; a reorder silently breaks anyone parsing them |
| HTML report | Canonical tree + exact CSP/stylesheet bytes | The report carries its own security policy |
| DOM | Canonical tree | Where a `this`-binding or escaping change surfaces |

#### Canonicalization rules

Checked in as `tests/fixtures/equivalence/canonicalization.md` **before** the
corpus is captured. Executable, not prose.

**Result.** Recursively sort object keys only. **Preserve array order** —
several are semantically ordered (DMARC walk steps, DNSSEC chain claims, issue
lists). Distinguish an absent property from one present with `undefined`. Encode
non-JSON primitives with tagged wrappers rather than coercing: `BigInt` (used
throughout the SPF subnet arithmetic) becomes `{"$bigint":"…"}`, `NaN` and
`±Infinity` become tagged strings. **No blanket removal of empty values and no
float rounding** — both would hide real changes.

**Query trace.** Gate on the multiset of normalized `(name, type, do, cd)` plus
occurrence count, and on maximum observed concurrency and batch size. Do **not**
gate on global chronology: independent `Promise.all` branches may interleave
differently without any behavioral change, and gating on it would produce
failures that mean nothing. Order **is** asserted, separately and explicitly,
for the two algorithms where sequence is the behavior — the DMARC tree walk and
SPF recursive evaluation.

**CSV.** Exact bytes including header row and column order, under one documented
newline convention.

**HTML report.** Canonical parsed tree, with the embedded
`default-src 'none'; style-src 'unsafe-inline'; img-src data:` policy and the
inlined stylesheet compared as **exact bytes** — those are the parts a
canonicalizer must not be allowed to normalize away.

The runner supplies a fixed instant and a fixed locale formatter through the
platform binding. `report.generated` therefore contains the same formatted
timestamp in the baseline, source and bundle runs. Time is an input, not an
excluded output field; no timestamp wildcard is permitted.

**DOM.** Ordered node and child structure with exact text. Attributes compared
as a sorted name/value map. Properties that are not attributes — `value`,
`checked`, `disabled`, visibility — compared explicitly. **Whitespace text nodes
are not normalized away**; the hygiene sentinels (`‹RLO›`, `‹ZWSP›`) depend on
exact text.

**Exclusions.** One manifest entry per excluded field, each with a reason. **No
wildcard field classes** — an exclusion nobody can enumerate is a hole nobody
can review.

> **Final ruling after round 3.** These rules are
> strict enough that inconsequential differences will surface. That is
> deliberate: a canonicalizer loose enough to never cry wolf is loose enough to
> absorb a real regression. Each tolerance added must name the difference class
> it admits and why that class cannot carry a defect. This strict line is
> accepted; time and locale are controlled inputs rather than broad exclusions.

#### The oracle, and capturing the baseline

Fixtures, never live DNS. `tools/backtest.mjs` queries Cloudflare and is a local
grade-*distribution* check only, never a gate. The oracle is
[`tools/lib/doh-fixture.mjs`](../../../tools/lib/doh-fixture.mjs).

> **Amended in 1.4: the five surfaces are bound to one deterministic CASE, not
> to one runtime.** Through `v0.5.0` and up to Task 2.6 they were both, and the
> distinction never had to be drawn: the runner captured the result surface by
> wrapping `window.DnsAudit.analyzeDomain`, which worked because the global and
> the engine the UI called were the same object.
>
> Stage 3 of §10 ends that, deliberately. `globalName` makes `window.DnsAudit`
> esbuild's export namespace — non-configurable accessors, and **not** the
> engine object `src/main.js` calls. Measured against the built artifact: the
> assignment throws, and the string `window.DnsAudit` occurs zero times in the
> shipped code. That is the namespace boundary working, not a bundler defect,
> and it is the boundary §10's source contract exists to create.
>
> So from stage 3 the runner uses **two isolated executions of the same
> deterministic case**:
>
> 1. a fresh subject and runtime calls the supported facade's `analyzeDomain`
>    for the **result** surface; and
> 2. a separate fresh subject and runtime drives the real UI controls for the
>    **query trace, CSV, HTML report and DOM**.
>
> The result execution has its own DoH fixture and its own trace. That trace is
> **not an exclusion** from the query-trace surface — no exclusion is added, and
> the exclusion manifest stays empty. It belongs to a different instrument
> execution and is not the trace being reported; the emitted query trace is the
> UI execution's complete trace.
>
> Both executions take the same case data profile, options, fixed instant,
> locale and platform profile, and neither warms the other: one runtime, one
> cache, per execution. Because a joined pair is now an assertion rather than a
> fact, the runner asserts **cross-surface binding** so that two accidentally
> different cases cannot be reported under one case id. Within-case domain order
> and the UI's worker behaviour are preserved in the UI execution.
>
> **Corrected in 1.5.** `1.4` named the issue **token set** among the bound
> fields. It is not, and cannot honestly be: the UI renders each issue as
> translated prose through `issueMessage()` and attaches no token attribute, so
> the tokens are not observable on the UI side at all. Adding one for the
> oracle's benefit would be a production test seam, which §11 forbids. The
> fields actually bound, all read structurally from the DOM, are:
>
> | Field | Result execution | UI execution |
> | --- | --- | --- |
> | domain set | `result.domain` | `tr[data-domain]` |
> | grade | `result.score.grade` | `tr[data-grade]` |
> | score | `result.score.pts` | `span.score-total`'s text node |
> | issue count | `result.issues.length` | `div.issue` |
> | suggestion count | `result.suggestions.length` | `div.issue.tip` |
>
> **The issue tokens lose nothing by this.** They are carried in full by the
> **result** surface, which is compared byte for byte against the baseline —
> that is where a changed token is caught, and it always was. What `1.4`
> overclaimed is narrower than it reads: not that the tokens are checked, but
> that they serve as a cross-execution *join key*. They do not, because only one
> execution can see them.
>
> Only fields that **cannot** differ because the code under test changed may be
> bound here. That rule was learned by breaking it: an earlier version read the
> score from the CSV's `Score` column, and the mutation battery's own
> "reorder two CSV columns" case — which must move the `csv` surface and nothing
> else — aborted the run instead of reporting a difference. A binding is not a
> second surface comparison; anything a change could move on one side alone
> belongs in the diff, where it is reported.
>
> **The UI execution boots the page, and 1.5 records what that showed.** The
> driver clicks `#auditBtn`, `#exportCsvBtn` and `#exportHtmlBtn` rather than
> calling the globals Task 2.8 removes, which means it must first fire
> `DOMContentLoaded` — every control is wired inside that listener. Firing it
> runs the boot's own `checkConnectivity()`, and because that call passes
> `noCache: true` it is a genuine second query. So the trace now shows **two**
> fixed `example.com A` probes per run where it showed one: one when the page
> initializes, one before each audit run. Measured across all thirty corpus
> cases, the count is exactly two whether the case audits one domain or nine —
> both are fixed costs, independent of what was entered.
>
> That is **pre-existing behaviour newly measured**, not a 0.6.0 change: the old
> runner called `window.startAudit()` on a page that had never booted, so a real
> visitor always paid the first probe and the trace never showed it.
> `PRIVACY.md` described only the second, and `1.5` corrects it to distinguish
> both. The per-domain fan-out figures it publishes — 41 typical, 61 for
> `cloudflare.com` — come from `tools/backtest.mjs`, which builds the engine
> directly and loads no page, and are unchanged.
>
> What this costs is stated plainly: the result surface and the other four are
> no longer captured from the same process image. What replaces the lost
> guarantee is the binding assertion, which is checked rather than assumed.
> Alternatives were rejected for the reasons recorded in
> `CODEX follow-up review for Facade Contraction and Fixture Identity.md`
> §1: calling `analyzeDomain` directly instead of `startAudit()` leaves the
> application's `results` array empty and blanks three surfaces; auditing twice
> in one runtime doubles the DNS fan-out, which **is** the trace surface; and a
> capture hook inside the application is the test seam §11 forbids.

Each subject is a complete repository or built-artifact root. The runner must
load that subject's own `index.html`, stylesheet, generated English bundle and
JavaScript; it may not pair baseline JavaScript with current-branch assets.
Capture without moving the worktree — the tag does not contain the runner:

```bash
git worktree add ../dea-v050 v0.5.0
node tests/build/equivalence.mjs --subject-root=../dea-v050 --emit \
  > tests/fixtures/equivalence/baseline-v0.5.0.json
git worktree remove ../dea-v050
```

For source parity the subject root is the checkout root with `src/` selected;
for artifact parity it is `_site/`. The baseline is committed; CI regenerates
it from a clean clone and asserts it matches. The baseline manifest records the
commit/tag, Node and ICU versions, fixed instant, locale, and SHA-256 of every
loaded HTML/CSS/locale/script input. A phase that cannot produce a clean
five-surface diff does not merge.

### 9. Test placement

**Unit tests live beside the code they test. Cross-cutting tests do not.**

The argument for co-location is the refactor's own stated goal. §32 of the
source proposal says a task like "correct DMARC organizational-domain
discovery" should primarily affect `src/core/dmarc/` — and then immediately
undercuts itself by naming a second directory, `tests/dmarc/`, that the same
task must also touch. Co-location makes the claim true instead of nearly true:
one directory holds the parser, its evaluator, its findings and the tests that
pin them. Go enforces this (`_test.go` beside the source), Rust puts unit tests
in the same file, and Jest/Vitest projects default to it.

It also closes the drift gap. A test in a parallel tree is a file you can forget
exists; a test in the same directory is one you scroll past every time you open
the module.

**What does not co-locate.** Four kinds of test have no single owning module,
and forcing them into one would be worse than the parallel tree:

| Lives in `tests/` | Why |
| --- | --- |
| `build/` — parity, artifact contents, size, CSP | Observes `dist/app.min.js` and `_site/`, which no module owns |
| `fixtures/equivalence/` — the corpus and baseline | Shared by every module and by the build suite |
| `contract/` — result algebra, dependency direction | Asserts *relationships between* modules |
| `integration/` — whole-audit runs | Spans transport, every protocol, coordination |

So the structure is a deliberate hybrid, not a compromise: `src/**/*.test.js`
for what one module owns, `tests/` for what none does.

**Three costs, and how each is paid.** These are real and the decision should
not be taken without them:

1. **The markup-sink scan's empty allowlist.** `tools/csp.test.mjs` scans every
   `.js` file under `js/` and its comment states the property that makes it
   trustworthy: *"The allowlist is EMPTY. That is what makes this check
   reliable: an empty allowlist has no judgment calls in it."* Test files under
   `src/` would need excluding, and an exclusion is a judgment call — the exact
   erosion that comment warns against.
   **Paid by:** excluding on a mechanical filename suffix (`*.test.js`) rather
   than a per-file list, and by adding a scan of the built artifact. A suffix
   rule has no per-file judgment in it, and the artifact scan proves the
   property on the thing that actually ships. The named-file allowlist stays
   empty and stays empty.
2. **Test code reaching the bundle.** esbuild includes only what the entry point
   transitively imports, so an unreferenced `*.test.js` is never bundled. But
   "should not happen" is not a test.
   **Paid by:** the artifact test asserting a sentinel string present in every
   test file appears nowhere in `dist/app.min.js`, and the size report making an
   accidental inclusion visible.
3. **Test discovery and the assertion inventory.** The current suites are six
   explicit `node tools/X.test.mjs` invocations whose "N passed" output is a
   tracked signal. Globbing changes that.
   **Paid by:** a small `tools/run-tests.mjs` that globs both trees, runs each
   file, and sums the counts. The hand-rolled assertion style and the printed
   totals are preserved; only discovery changes. Migrating to `node:test` is
   explicitly **not** part of this release — that is a schema change wearing a
   tooling costume, and §35 forbids it.

**Naming.** Co-located tests are `*.test.js` (ESM, matching the module beside
them). Cross-cutting suites keep `*.test.mjs`, matching the existing `tools/`
convention. The extension difference is a useful signal about which tree a file
belongs to.

**Decided.** Approved by Ian on 2026-08-27, as `OQ-ARCH-09`. The hybrid is the
layout: `src/**/*.test.js` for unit tests, `tests/` for build, contract,
integration and fixtures.

What remains open is not the decision but **cost 1's mitigation**, because it
touches a security control rather than a layout preference. Round 2 is asked
whether a filename-suffix exclusion is materially different from the per-file
allowlist `tools/csp.test.mjs` warns against, and whether the added artifact
scan carries the weight this spec claims for it. If the answer is no, the
layout stands and the mitigation changes.

### 10. The delivery boundary and the supported facade

Required by round 2's R2-F1. The bundler cannot design this; it has to be
decided and checked in.

#### The global surface today: 24 names, not five

Version 0.2 listed five and called it an inventory. The real count, taken from
every assignment site:

| Owner | Globals | Count |
| --- | --- | ---: |
| `js/app.js` | `startAudit`, `cancelAudit`, `clearAll`, `exportCSV`, `exportHTML`, `filterTable`, `loadExample`, `loadFile`, `openLearnMore`, `setLang`, `showHelp`, `sortTable`, `toggleDetail`, `toggleShowMe` | 14 |
| `js/app.js` | `__APP_TEST__` | 1 |
| `js/i18n.js` | `i18n`, `t`, `tp`, `tRaw` | 4 |
| `js/dns.js` | `DnsAudit` | 1 |
| `js/render.js` | `R` | 1 |
| `js/public-suffixes.js` | `__PUBLIC_SUFFIX_RULES__` | 1 |
| `js/dkim-selectors.js` | `__DKIM_SELECTOR_CATALOG__` | 1 |
| `js/locales-en.js` | `__I18N_EN__` (via `window.`, not `global.`) | 1 |
| | **Total** | **24** |

The spike confirms the bundle reproduces all 24 exactly — none missing, none
extra.

#### Classification — and the finding that shapes the facade

Every name was traced to its actual consumers:

| Class | Names | Disposition |
| --- | --- | --- |
| **Supported API** | `analyzeDomain`, `checkConnectivity` | The facade. These are the **only** two `DnsAudit` members `js/app.js` calls. |
| **Test-only surface** | the other 93 `DnsAudit` members (77 used by `scoring.test.mjs`, 4 by `backtest.mjs`), `__APP_TEST__` (used by `render.test.mjs:21`, `export.test.mjs:17`) | Become **direct ESM imports**. Never frozen into the facade. |
| **Transition inputs** | `__PUBLIC_SUFFIX_RULES__`, `__DKIM_SELECTOR_CATALOG__`, `__I18N_EN__` | Generated data. Global reads/writes only during the legacy-to-ESM transition; replaced by injected bindings (§11). Not facade exports. |
| **Internal wiring** | `i18n`, `t`, `tp`, `tRaw`, `R` | Become imports within the bundle. |
| **Unsupported legacy surface** | all 14 `js/app.js` function globals | Zero repository or documented consumers. Removed deliberately; see below. |

**The 14 function globals have no repository consumer.** `index.html` contains no inline event
handlers — the CSP carries no `'unsafe-inline'`, so it cannot — and its single
textual match for `cancelAudit` is `data-i18n="btn.cancelAudit"`, a locale key.
Nothing in `index.html`, `tools/` or the test suites reads any of the 14.

That proves the application does not need them; it cannot prove that a console
script, extension or embedding page outside this repository never called them.
This project exposes no documented JavaScript API (`package.json` has no
`main`, `exports` or `files`), so those names are declared **unsupported legacy
surface**, not supported compatibility API. Their removal is intentional and is
a **behavior change** in the strict sense that observable globals disappear.
Per §35 it is therefore its own Phase-2 commit, a named allowed delta in the
equivalence manifest, and a compatibility note in `CHANGELOG.md` and the PR
description. A separate commit makes the decision auditable; this paragraph
authorizes it.

**The supported facade is two members.** From a 95-member surface. That is the
answer to round 2's "derive the facade from actual consumers": the application
needs `analyzeDomain` and `checkConnectivity`, and everything else is either
internal or test surface that ESM imports serve better than a global ever did.
The facade is the only supported browser API from 0.6.0 onward.

#### Three stages, in order

Round 2's required transition, made concrete:

**Stage 1 — legacy bundle, no `globalName`.** The unmodified IIFEs create their
own globals; parity reaches `window.DnsAudit` exactly as the current harness
does. Verified by the spike.

**Stage 2 — ESM facade designed and exported.** `src/main.js` exports the
supported API as named exports. The expected member list is checked in as
`src/facade.expected.json` and asserted against **both** the source module's
exports and the built bundle's global.

**Stage 3 — `globalName: 'DnsAudit'` enabled**, and only then, against an entry
that genuinely exports those members. The legacy assignment in `js/dns.js` is
removed in the same commit.

#### The namespace source contract

Asserted over the real import graph, not by grep: **no module under `src/` reads
or writes `window.DnsAudit`, `globalThis.DnsAudit`, or any of the 24 names
above**, except

- the explicitly marked temporary adapters during Phase 2, and
- the generated boundary esbuild produces at stage 3.

This is the condition round 2 attached to accepting IIFE output: a generated
global at the delivery boundary is acceptable *only if* the source graph is
forbidden from using it as an internal dependency. Without this contract, the
IIFE decision does not hold.

### 11. The composition root

Required by round 2's R2-F3, and the spike proved why it is not optional.

#### The hazard, demonstrated

`tools/scoring.test.mjs:21` injects a four-rule public suffix table. Bundle
`js/public-suffixes.js` and load it into that sandbox:

```text
injected before load : 4
in force after load  : 10239
```

The suite then reports **`1535 passed, 0 failed`** — byte-identical to the
source baseline. Nothing failed. Nothing warned. The assertion count did not
move. The suite was green while testing against the wrong public suffix list.

A static `import` of generated data recreates this defect, because the bundle
satisfies the import on its own and no test can intervene. This is also the
final proof of Testing item 1: **a passing count is not a coverage signal.**

#### The factory

One production runtime factory. Generated data and platform primitives are
**passed**, never imported by the modules that consume them:

```js
createAuditRuntime({
  publicSuffixRules,        // from src/data/, or a fixture table
  dkimSelectorCatalog,      // from src/data/, or a fixture catalog
  englishBundle,            // __I18N_EN__ equivalent
  platform,
}) -> { analyzeDomain, checkConnectivity, mount }
```

`src/runtime.js` owns this side-effect-free factory. `src/main.js` imports the
three generated inputs and `src/platform/browser.js`, calls the factory
**once**, calls `mount()`, and exports only the §10 facade. Importing
`src/runtime.js` never touches the DOM or network. Unit and integration tests
call the same factory with fixture data. There is no second construction path
and no production branch that exists only for tests.

The browser platform object names every ambient primitive used by the moved
code: `fetch`, `crypto`, `AbortController`, `URLSearchParams`, `setTimeout`,
`clearTimeout`, `document`, `localStorage`, `navigator`, `open`, `URL`, `Blob`,
`FileReader`, `Intl`, `console`, `now()` and `formatDateTime(date, locale)`.
The last two preserve the current `new Date().toLocaleString(i18n.lang)`
behavior in production while making export parity deterministic. Language
built-ins such as `Promise`, `Map`, `Set` and `BigInt` are required APIs, not
injectable platform services.

> **`open` was added in 1.3, and it is the last one.** `openLearnMore()` builds
> the Learn-more page into a `Blob`, opens it with
> `open(url, '_blank', 'noopener')` and revokes the object URL a minute later.
> Found by the **completed conversion sweep over `js/app.js`** — the only file
> left to convert — which enumerated its full ambient set: eight primitives
> already on this list and this one missing. That is why it is the last: there
> is no further legacy source to sweep. It is **not** evidence that the lexical
> contract in `tests/contract/platform.test.mjs` is exhaustive; that contract
> could not have found it either, for the reasons `1.2` records.
>
> `open` is the first entry here that is a **navigation side effect** rather
> than a data capability, and it is worth naming as such because the platform is
> the security boundary between `src/` and the browser. Splitting page
> construction from navigation is architecturally reasonable and **Phase 5 owns
> it** — `src/ui/` is where that decomposition belongs. Doing it during Task 2.6
> would put a behaviour-shaped change inside a wrapper-only conversion, which
> §35 forbids. Its final UI-facing abstraction is reconsidered then, not now.
>
> **`navigator` was added in 1.1.** Version 1.0 omitted it while claiming the
> list named *every* ambient primitive, which was false: `detectLang()` reads
> `navigator.languages` and `navigator.language` to pick a language before any
> stored preference exists. The omission was found by converting `js/i18n.js`
> in Task 2.2 — where the module stopped being able to reach `window` and every
> ambient dependency had to be named — not by reading the spec. Implementing
> the 1.0 list would have left i18n reading `navigator` ambiently while every
> other primitive was injected, which is the *almost isolated* state that makes
> a later leak invisible. The distinction the list draws is unchanged:
> `navigator` is a host object, and host objects are injected.

The set is **reviewed during conversion, synchronized bidirectionally, and
guarded against the known ambient catalog.** A module that reaches for an
ambient primitive this list does not name is a defect in the list.

What that means precisely, because the distinction is the whole point of this
paragraph:

| Established | How |
| --- | --- |
| This list and `PLATFORM_PRIMITIVES` name the same set | Asserted in **both** directions, so neither can grow past the other |
| Every declared primitive is actually provided | Asserted against a constructed platform |
| No module under `src/` reads a **known** ambient name outside the platform module and the marked adapters | A lexical scan over a named catalog of ambient identifiers |

And what is **not** established. The scan cannot discover an ambient identifier
that is absent from its own catalog — the very omission that produced this
amendment would not have been found by it, only by the conversion work that did
find it. It is a lexical scan, not JavaScript name resolution: it does not model
scope, shadowing, computed member access or aliasing, and it is not a substitute
for reading a module while converting it.

It is **defense in depth against regression**, which is a real and useful thing
to have and a different thing from a proof of completeness. The completeness of
this list rests on the conversion review that produced it. Anything stronger
would need real name-resolution analysis, and this release adds no parser and no
dependency for it — `OQ-ARCH-01` bought exactly one development dependency and
this is not a good reason to spend another.

#### Passed versus imported

| Dependency | Passed | Imported | Why |
| --- | :---: | :---: | --- |
| Public suffix rules | ✓ | | The demonstrated hazard |
| DKIM selector catalog | ✓ | | Same class |
| English bundle | ✓ | | Same class |
| Browser/platform primitives listed above | ✓ | | Tests substitute at the lowest primitive |
| Protocol modules | | ✓ | Pure logic, no ambient state |
| Scoring constants | | ✓ | Immutable, and byte-identity is asserted |

#### Lifetimes, stated

| Scope | Holds | Constructed |
| --- | --- | --- |
| **Runtime/page** | The DoH cache; generated data; resolver; i18n instance | Once per factory call. `src/main.js` makes one production runtime per page. |
| **Audit** | Options in force, accumulated result, cancellation signal | Per `analyzeDomain()` call |
| **Call** | Per-query retry and timeout state | Per resolver call |

**Node's ESM module cache is not a dependency-injection mechanism.** The cache
factory returns a new cache to each runtime. Test isolation comes from
constructing a fresh runtime per suite, never from cache-busted imports or
module-level mutation. Contract tests prove both halves: two audits through one
runtime reuse cached answers, while two runtimes share none.

#### Proving fixture identity behaviorally

The lesson of the spike is that a green run proves nothing. Every suite declares
which generated-data profile it supplies and runs one **behavioral** fingerprint
per binding before any other assertion:

| Binding | Fixture fingerprint | Production counter-result |
| --- | --- | --- |
| PSL | The four-rule fixture resolves `foo.blogspot.com` to `blogspot.com` | The real PSL contains the private `blogspot.com` rule and resolves it to `foo.blogspot.com` |
| DKIM catalog | A fixture-only provider contributes selector `fixtureselector999` | The production catalog does not contain that selector |
| English bundle | `t('doc.title')` returns the fixture value `__fixture_english_title__` | The production bundle returns the shipped English title |

The PSL case is deliberately a rule present in production and absent from the
fixture. `a.b.ck` and `a.www.ck` are not fingerprints: both fixture rules are
also in the real PSL and therefore produce identical results. A test replacing
any one binding while leaving the other two correct must fail its own probe.

> **Amended in 1.4: the PSL fingerprint is a BINDING-LEVEL engine/runtime
> fingerprint, and cannot be an application one.**
>
> `1.0` introduced these three as one uniform class. Two of them are: the DKIM
> catalog and the English bundle are each observed through a real consumer, and
> both survive the facade contraction. The PSL is not, and calling it the same
> kind of thing claimed more than the code delivers — the third time this spec
> has had to correct that shape of overstatement, after `1.2`.
>
> `getOrganizationalDomain()` is the only reader of the public suffix sets
> (`js/dns.js:335-355`), and **nothing in the application calls it.** Measured,
> not argued: zero call sites at `v0.5.0` and zero at `f1a2842`, and
> `result.organizationalDomain` is produced by the RFC 9989 discovery walk in
> `selectOrganizationalDomain()`, which never consults the PSL. No audit result,
> query trace, CSV, report or DOM node depends on the public suffix list.
>
> So the probe stands, unchanged, in the suites that can run it — the unit,
> legacy-contract and runtime suites that supply the binding directly through
> `createAuditRuntime()`, which is the direct-ESM disposition §10 gives the
> test-only surface. It is a fingerprint of the **engine/runtime contract**, and
> that is what it is now called.
>
> An artifact-driven suite is **not** required to claim a behavioural PSL
> fingerprint through the two-member facade, because no such production path
> exists and inventing one would be a test seam. Generated-source identity,
> build-input provenance and the runtime contract remain **separate evidence**;
> input hashes are provenance and are never represented as behavioural
> equivalence, which the runner already states.
>
> The DKIM-catalog fingerprint keeps a real application-level form:
> `dkimStatus.selectors[].uncommon` is `!isRecognizedDkimSelector(sel)`
> (`js/dns.js:1255`), measured `true` under the production catalog and `false`
> under a fixture catalog that contributes the selector. The English
> fingerprint is `t()`, its actual consumer.
>
> **The PSL stays in the release.** It is 160.6 KB of a 422 KB bundle and
> reaches nothing, which is a real finding and a real question — and it is a
> behaviour-and-size decision, not a refactor. Removing it here would be scope
> creep of exactly the kind Risk R8 exists to refuse. Recorded in
> [`docs/maintenance-backlog.md`](../../maintenance-backlog.md) with the measured
> size, and the bundle is not changed in 0.6.0.

### 12. Module APIs and the allowed-edge matrix

Required by round 2's R2-F5. The folder tree in §2 describes ownership; this
describes interfaces and permitted direction.

#### Allowed edges

An edge absent from this matrix is a test failure, not a judgment call.

| From | May import |
| --- | --- |
| `src/main.js` | `runtime.js`, `platform/browser.js`, `data/` |
| `src/runtime.js` | `core/dns/`, `core/shared/`, `audit/`, `ui/`, `i18n/` |
| `src/platform/` | **nothing** |
| `src/ui/` | `ui/` siblings, `i18n/`; event functions receive audit callbacks as arguments |
| `src/audit/` | `core/<protocol>/`, `providers/`, `audit/` siblings; resolver handle is passed |
| `src/core/<protocol>/` | `core/shared/` only; resolver and generated data are passed |
| `src/core/dns/` | `core/dns/` siblings, `core/shared/`; platform is passed |
| `src/core/shared/` | **nothing** |
| `src/providers/` | `core/shared/` only |
| `src/i18n/` | `core/shared/` only; English and platform are passed |
| `src/data/` | **nothing** |

Consequences that follow, each asserted:

- No `src/core/` module imports `src/ui/` or `src/audit/`.
- No protocol module imports a sibling protocol module. Generated data reaches
  its consumer through runtime construction, never by importing `src/data/`
  directly — that would be an implied convenience edge, which the matrix forbids.
- No UI module imports `audit/`; `mount()` receives `analyzeDomain` and
  `checkConnectivity` callbacks from the runtime.
- Only `src/main.js` imports generated data or the browser platform adapter.
- `src/data/` is a sink. A generated file that imports anything has stopped
  being generated data.

#### Cycle rule

The contract test parses the real static import graph and **rejects any strongly
connected component containing more than one module.** Acyclic is necessary but
not sufficient: an acyclic graph can still point the wrong way, which is what the
matrix above catches.

#### Per-directory API table

Each owning directory checks in `API.md` in the same commit that creates the
directory. It records public exports, accepted inputs, result axes, allowed
dependencies and lifetime. The implementation tasks may refine function names,
but not ownership or direction without amending this spec.

| Owner | Public responsibility / API | Inputs | Result and lifetime |
| --- | --- | --- | --- |
| `main.js` | browser entry; exports `analyzeDomain`, `checkConnectivity` | generated modules, browser platform | one mounted runtime per page |
| `runtime.js` | `createAuditRuntime()` | three generated bindings, platform | facade + `mount`; fresh cache/i18n/resolver per call |
| `platform/` | `createBrowserPlatform(window)` | one window, at the composition root only | immutable primitive adapter, one per runtime; provides the §11 set including `navigator` and the navigation capability `open` |
| `core/dns/` | `createResolver`, raw fetch, usable/normalized APIs, errors | platform, runtime cache | ten kinds; page/runtime cache, per-call retry state |
| `core/shared/` | URI, record-field, IP and other genuinely cross-protocol pure helpers | values only | pure, no retained state |
| `core/spf/` | parse/status, lookup count, subnet/redundancy audit | SPF text, domain, resolver | §12.1 SPF axes; call lifetime |
| `core/dkim/` | selector discovery, catalog use, key analysis | domain, selector options, catalog, resolver | §12.1 DKIM axes; call lifetime |
| `core/dmarc/` | parse, tree walk, inheritance, report authorization | domain/records, resolver | §12.1 DMARC axes; call lifetime |
| `core/dnssec/` | record parsing, DS↔DNSKEY evidence, classifier | domain, resolver, crypto | §12.1 DNSSEC axes; call lifetime |
| `core/mx/` | MX health | MX records, domain, resolver | §12.1 MX axes; call lifetime |
| `core/caa/` | CAA parse, inheritance and summary | domain, resolver | §12.1 CAA axes; call lifetime |
| `core/bimi/` | BIMI record validation | record text | valid/declined/advertised/present/unknown axes; pure |
| `core/transport/` | MTA-STS, TLS-RPT and TLSA validation/checks | records or MX hosts, resolver | §12.1 transport axes; call lifetime |
| `providers/` | DNS/email/hosting detection | normalized records | provider token; pure |
| `audit/` | orchestration, scoring, issues | domain/options, resolver, protocol APIs | complete audit result; per-audit context |
| `i18n/` | translation lookup and DOM translation | English bundle, platform | per-runtime language/listeners |
| `ui/` | rendering, reports, events | result data, i18n, injected facade callbacks | mounted DOM state; report builders are pure over supplied data |
| `data/` | generated PSL/catalog/English constants | none | immutable runtime inputs |

#### 12.1 Pre-refactor state and result-shape inventory

This inventory is derived from `v0.5.0` before extraction. It is the minimum
closed vocabulary Gate 0 must place in `tests/state-algebras.json`; Phase 4 does
not get to discover missing members after the equivalence corpus has already
been declared complete.

| Owner / field | Complete members at `v0.5.0` |
| --- | --- |
| DNS `result.kind` | `success`, `nodata`, `nxdomain`, `servfail`, `refused`, `dns-error`, `http-error`, `cancelled`, `timeout`, `network-error`. **`1.6`:** the algebra's `resultPaths` were empty, which said it is not observable in a result. It is, on the eleven typed paths §3 now lists. |
| DNS thrown paths | `DnsTypeError`, `AbortError`, and `DnsError.kind` for the seven kinds rejected by `requireUsable()` |
| Domain existence | `yes`, `no`, `unknown` |
| SPF `status` | `ok`, `warn`, `present`, `missing`, `softfail`, `permerror` |
| SPF subnet `severity` | `LOW`, `MEDIUM`, `HIGH` |
| DKIM `confidence` | `not-checked`, `sampled`, `observed` |
| DKIM `scanMode` | absent when not checked; `provider-aware`, `comprehensive` when checked |
| DKIM selector `type` | `key`, `cname` |
| DKIM key `keyType` | `rsa`, `ed25519`, `unknown` |
| DMARC `status` | `ok`, `warn`, `present`, `missing`, `unknown`, legacy-direct-call `permerror` |
| DMARC tag state | `absent`, `valid`, `invalid`; alignment fields use `absent`, `r`, `s`, `invalid` |
| DMARC record diagnosis | `absent`, `not-first`, `bad-value`, `version`, `syntax` |
| DMARC walk `terminated` | `root`, `error`, `psd-y`, `psd-n` |
| DMARC observation `why` | `at-apex-not-underscore`, `multiple-at-step`, `version-bad-case`, `version-not-first`, `version-absent` |
| External report authorization `state` | `authorized`, `unauthorized`, `unverifiable`, `override-mismatch` |
| External report authorization `exactKind` | `success`, `nodata`, `nxdomain`. **Added in `1.6`**, owned by `core/dmarc`: the field had no algebra at all. Absent on `unverifiable` results and on the name-too-long case. `nxdomain` is reachable because the inline usability gate accepts it and the unauthorized result carries `exactKind: response.kind` — the corpus having observed only two of the three is a corpus finding, not a two-member algebra. |
| External report override reason | `null`, `cross-host`, `malformed` |
| MX host `resolves` | `yes`, `no`, `unknown` |
| MX `ipv6Coverage` | `none`, `some`, `all` |
| DNSSEC `state` | `secure`, `insecure`, `bogus`, `unanchored`, `mismatch`, `indeterminate` |
| DNSSEC chain `claim` | `resolver-ad`, `resolver-bogus`, `resolver-unreachable`, `link-checked`, `lookup-incomplete`, `ds-confirms-dnskey`, `ds-no-matching-key`, `ds-digest-mismatch`, `ds-unverifiable` |
| DNSSEC DS match | `unverifiable`, `unverifiable-digest-type`, `no-matching-key`, `confirmed`, `digest-mismatch` |
| DNSSEC eligibility | `eligible`, `ineligible`, `unknown` |
| DNSSEC key structure | `valid`, `invalid`, `unknown` |
| DNSSEC evidence | `complete`, `partial`, `none` |

Not every meaningful state is a string discriminant. These axes are equally
binding and receive explicit matrix rows:

| Owner | Non-enum result shapes that must be covered |
| --- | --- |
| SPF | lookup `error` / `warning` / `indeterminate` / `unknown`; zero/ten/over-ten counts; void lookup count; cycle present/absent; subnet redundancy known/unknown |
| DKIM | checked versus not checked; `found`; selector sets for missing, failed, duplicated, revoked, unusable and malformed; key `valid`, `revoked`, `appliesToEmail`; `cryptoValidated` = `null` / `true` / `false` |
| DMARC | record absent/present/multiple/malformed; own/inherited/PSD-applied/no-applied policy; walk error before versus after an own record; report destinations checked/omitted; URI valid/invalid |
| CAA | found/absent/unknown; record valid/malformed; issuance and wildcard issuance blocked/open; unknown critical property present/absent |
| MX | no MX, null MX, one/many targets; dangling/CNAME/duplicate-preference/shared-prefix collections; per-host CNAME unknown; overall unknown |
| BIMI | advertised/present/declined/multiple/unknown; validation valid/invalid |
| MTA-STS | advertised/present/multiple/unknown; validation valid/invalid; `policyVerified` false in this release |
| TLS-RPT | advertised/present/multiple/unknown; validation valid/invalid |
| TLSA | per-host present/absent/unknown; `authenticated` = `null` / `true` / `false`; aggregate any/all-authenticated and unknown |
| DNSSEC | each lookup completed/incomplete; DS/DNSKEY empty/non-empty; anchor confirmed/unconfirmed; signed alias true only for `secure` |
| Audit | registered/unregistered; optional check disabled/enabled/unknown; normal result versus thrown cancellation/core transport error; active-mail versus parked scoring |

Parser error-token arrays and issue identifiers are not inferred from a generic
`status` scan. Their exact vocabularies are already consumed by tests and the
UI, so Gate 0 snapshots them separately and the equivalence result surface
compares them byte-for-byte.

`tests/state-algebras.json` is the reviewed source of truth for the rows above.
`tests/state-matrix.json` maps each member or meaningful combination to a unit
or contract suite, an integration fixture where DNS is involved, and an
equivalence fixture for every operator-visible shape. The contract test:

1. rejects matrix rows naming missing suites or fixtures;
2. rejects an algebra member with no coverage row;
3. compares each extracted module's exported state constants with the reviewed
   registry once that module exists; and
4. runs targeted legacy contracts for computed values, thrown paths, booleans,
   nullability and absence until extraction is complete.

It does **not** claim that a static string-literal scan can discover every
state. Computed claims such as `"ds-" + record.match` are expanded explicitly,
and boolean/nullable combinations are reviewed as result shapes. Adding a state
therefore requires an intentional registry, matrix and fixture change; the
five-surface baseline remains the independent proof that the refactor did not
alter an unmodeled value.

## Localization impact

**No key in `locales/en.json` is added, changed or removed by this release.**

That is the point: §30 of the proposal requires the localization contract to
survive, and the cleanest proof is that the source of truth is not touched.
Three mechanical consequences follow anyway:

1. **`js/locales-en.js` becomes `src/data/locales-en.js` and must be emitted as
   an ES module.** `tools/build-fallback.mjs` is changed to write
   `export const LOCALE_EN = {...}` instead of a global assignment. Its
   *content* — the key set and the values — is unchanged, so
   `tools/check-locales.mjs`'s drift check still compares like with like.
2. **`tools/check-locales.mjs` must be updated in the same commit** as the
   fallback generator, since it asserts the generated file matches `en.json`.
   These two changing out of step is the failure mode `npm test` exists to
   catch, and it will catch it.
3. **`npm run locale:gate` must report 13/13 at every phase boundary**, not
   only at the end. A refactor that silently breaks the i18n lookup path would
   otherwise surface as English-looking output long after the phase that caused
   it.

The interpolation suite (`tools/interpolate.test.mjs`, **17** assertions — 0.1
of this spec said 329, which is the render suite's count) is the canary here and
runs unchanged apart from its import mechanism.

## Testing

Layout per [Design §9](#9-test-placement), settled as the hybrid.

**1. The gate is a contract inventory, not an assertion count.** The spike
settles this empirically rather than by argument: the scoring suite reported
`1535 passed, 0 failed` while running against a public suffix list that had been
silently swapped underneath it. The count was identical to the correct baseline.

`tests/inventory.json` names every suite and the contract areas it covers. Gates:
every inventory area has a passing suite; the total is **reported** and any
decrease must name the removed assertions and where the property moved; no entry
is deleted without a stated replacement.

**2. Five-surface equivalence** per Design §8 — result, query trace, CSV, HTML
report, DOM — three-way across `v0.5.0`, `src/` and `dist/app.min.js`. The
release's primary gate. From §10 stage 3 the five are bound to one deterministic
case captured by **two isolated executions**, with the cross-surface binding
asserted rather than assumed; §8 states why and what it costs.

**3. The state matrix**, `tests/state-matrix.json`, required by round 2's R2-F6.
It replaces the prose corpus list as the Gate 0 proof of coverage.

Every discriminant in the codebase maps to three things:

| Column | Meaning |
| --- | --- |
| State | One member of one owner's closed set |
| Unit/contract suite | Where the state is asserted in isolation |
| Integration fixture | Where it is reached through the real transport path, where applicable |
| Equivalence fixture | At least one, for every operator-visible result shape |

It is complete at Gate 0 from the pre-refactor inventory in §12.1, including
computed DNSSEC claims and non-string result axes. It is not deferred until the
modules are extracted.

`tests/contract/state-matrix.test.mjs` enforces the four rules in §12.1. The
reviewed registry, targeted legacy contracts and later exported state constants
work together; no static literal extractor is represented as an exhaustive
proof.

**4. Bundle parity.** Loads the real `dist/app.min.js`. In stage 1 it reaches
`window.DnsAudit` as the current harness does; from stage 3 it asserts the
facade's exported members against `src/facade.expected.json` on **both** the
source module and the bundle. A test-only bundle proves nothing about the
shipped artifact and is not an acceptable substitute.

**5. Contract tests** in `tests/contract/`:

- The ten transport kinds are exhaustive; `cancelled` is retry-terminal and
  never cached; `DnsTypeError` is thrown and is not a kind.
- No resolver return carries a finding, severity, score or locale reference.
- The allowed-edge matrix (§12) holds, and no SCC has more than one module.
- The namespace contract (§10): no `src/` module reads or writes any of the 24
  globals outside a marked adapter.
- **Fixture identity** (§11): separate divergent PSL, DKIM-catalog and English
  fingerprints run first according to the suite's declared data profile. As of
  `1.4` the PSL fingerprint is **binding-level** — it belongs to suites that
  supply the binding through `createAuditRuntime()`, because nothing in the
  application reads the public suffix list. The DKIM-catalog and English
  fingerprints stay behavioural through their real consumers.
- Runtime lifetime: sibling audits through one runtime reuse the cache; two
  independently constructed runtimes do not share it.

**6. Deployment artifact test.** Exact top-level allowlist —
`index.html`, `CNAME`, `LICENSE`, `THIRD_PARTY_NOTICES.md`, `css/`, `dist/`,
`locales/`, nothing else. Every `<script src>`, `<link href>` and source-map link
resolves inside `_site/`. Absent: `src/`, `tools/`, `tests/`, `docs/`,
`node_modules/`, `package.json`, `AGENTS.md`, `*.test.*`,
`locales/translation-status.json`, `assets/`.

**7. Co-location safety is bound to the metafile, not a sentinel.** Round 2's
R2-F7: a sentinel can be tree-shaken, renamed, duplicated, or simply omitted
from a new test file. The binding checks are:

- no `*.test.*` path appears in `metafile.inputs`;
- no `*.test.*` path appears in the source map's `sources`;
- the built artifact passes the markup-sink scan; and
- `_site/` contains no source or test path.

The sentinel remains as defence in depth and carries no acceptance criterion.

**8. `tools/csp.test.mjs` amended, not weakened.** Section 3's filename and
ordering assertions become: exactly one `<script src>`, it is
`dist/app.min.js`, same-origin. Every section-1 policy assertion is preserved
byte-for-byte. The markup-sink scan covers `src/` excluding `*.test.js` — a
mechanical suffix rule, never a per-file list — **and** `dist/app.min.js`.

**9. Bundle size** from the metafile: raw, gzip, per-input composition. Reported,
never enforced. Baseline: 719,199 / 213,467 across seven files; measured legacy
bundle 430,750 / 130,256.

## Acceptance criteria

Structural:

- [ ] All hand-written browser code lives under `src/` as ES modules. `js/` is gone.
- [ ] Every adapter removed; a test asserts none remain.
- [ ] The ten transport kinds are preserved byte-for-byte; `cancelled` is retry-terminal and never cached; `DnsTypeError` is thrown, not returned.
- [ ] §3's **two** exception inventories both hold: no raw-kind reader exists outside the named owners and the layer implementations, and every typed propagation path carries only closed transport kinds. The derived `dmarc-unverified` issue copy is tested against its own key, never as a bare `issues[].args[]` pattern.
- [ ] No resolver return carries a finding, severity, score or locale reference.
- [ ] SPF, DKIM, DMARC, DNSSEC, MX, CAA, BIMI, MTA-STS, TLS-RPT and TLSA each have an owning directory and a checked-in API table.
- [ ] The allowed-edge matrix holds; no SCC contains more than one module.
- [ ] `src/runtime.js` is side-effect-free; importing it neither mounts the UI nor performs network I/O.
- [ ] The browser platform provides the §11 primitive set, `navigator` and `open` included. The spec list and the platform module's published set agree in both directions, every declared primitive is provided, and a lexical scan over a named catalog of ambient identifiers rejects a bare read outside the platform module and the marked adapters. The scan is defense in depth against regression, **not** exhaustive name-resolution analysis: completeness of the list rests on the conversion review, and the scan cannot find an identifier absent from its own catalog.
- [ ] The namespace contract holds: no `src/` module touches any of the 24 globals outside a marked adapter.
- [ ] `src/facade.expected.json` matches both the source exports and the bundle global.
- [ ] Removal of unsupported legacy globals is one named compatibility delta with a manifest entry and release note.
- [ ] `AGENTS.md` documents module ownership and the modification boundary for a protocol change.

Equivalence:

- [ ] Five-surface, three-way equivalence — result, query trace, CSV, HTML report, DOM — across `v0.5.0`, `src/` and `dist/app.min.js`, clean or every difference documented and deliberate. From §10 stage 3 the surfaces come from two isolated executions of one case, bound by an asserted cross-surface identity and with no exclusion added.
- [ ] `canonicalization.md` is checked in **before** the corpus is captured.
- [ ] The baseline binds complete subject roots, input hashes, fixed time, locale, Node and ICU; it regenerates from a clean clone in CI and matches the committed file.
- [ ] Every §12.1 member and meaningful non-enum shape has a state-matrix row naming a suite and fixture, enforced by `state-matrix.test.mjs`.
- [ ] The PSL, DKIM-catalog and English fixture-identity checks pass independently in every suite supplying those bindings. The PSL check is binding-level (§11, `1.4`); an artifact-driven suite is not required to claim a behavioural one.
- [ ] `WEIGHTS`, `PARKED_WEIGHTS`, `GRADE_THRESHOLDS` byte-identical to `v0.5.0`.
- [ ] Issue-token vocabulary unchanged; no `locales/en.json` key added, changed or removed.
- [ ] DNS query fan-out per fixture unchanged, so `PRIVACY.md`'s figures still hold.
- [ ] Every contract area in `tests/inventory.json` has a passing suite.
- [ ] `npm run locale:gate` reports 13/13.

Build and deployment:

- [ ] `npm run build` produces `dist/app.min.js` from `src/` with no network access.
- [ ] Zero `dependencies`; exactly one direct `devDependency`, exact-pinned.
- [ ] `package-lock.json` committed; the resolved footprint recorded as measured, never described as zero.
- [ ] **`npm ci` confirmed on Linux CI** — the spike covered darwin-arm64 only.
- [ ] The `postinstall` script's treatment under npm's `allowScripts` gate is an explicit, recorded CI decision.
- [ ] `dist/` remains git-ignored and is never committed.
- [ ] `_site/` matches the exact allowlist; no `*.test.*` in `metafile.inputs` or source-map `sources`.
- [ ] Bundle raw, gzip and per-input composition in CI output.
- [ ] `index.html` still the entry point; no public URL changed.
- [ ] A clean clone runs `npm ci && npm test && npm run build` from documented instructions.
- [ ] `v0.5.0` can still be checked out and served, unmodified.

Preserved properties:

- [ ] CSP `connect-src` exactly `'self' https://cloudflare-dns.com`; every section-1 assertion byte-identical.
- [ ] Markup-sink named-file allowlist still empty; scan covers `src/` and `dist/app.min.js`.
- [ ] DoH cache retains runtime/page lifetime; `tools/scoring.test.mjs:1891` still passes and two runtimes are proved isolated.
- [ ] **`file://` still works** — `js/locales-en.js` exists to support it and its comments stay.
- [ ] `PRIVACY.md` distinguishes the **two** fixed `example.com A` probes the query-trace surface proves — one at page initialization, one before each audit run — and its per-domain fan-out figures are unchanged. Confirmed by the trace rather than assumed; `1.4` concluded no edit was needed and `1.5` corrects that.
- [ ] No runtime third-party JavaScript reaches the browser.
- [ ] GitHub Actions remain SHA-pinned.

## Risks

| # | Risk | Mitigation |
| --- | --- | --- |
| R1 | **Silent behavior change during extraction.** 5,704 lines moving between files. | Five-surface equivalence at every commit, through the bundle; one responsibility per commit; the delivery boundary established in Phase 1 so every move is checked against the shipped artifact. |
| R2 | **The bundle differs from the source that was tested.** | Parity against the real `dist/app.min.js`; facade members asserted on both surfaces from stage 3. |
| R3 | **First supply-chain dependency.** Measured: 2 packages on darwin-arm64, 1 `postinstall`, 25 unmet optional platform packages. | Exact pin; committed lockfile; `npm ci` only; an explicit recorded decision on npm's `allowScripts` gate; Linux confirmation outstanding. |
| R4 | **ESM strict-mode semantics.** Top-level `this` is `undefined`; `var` no longer creates a global — and `js/dns.js` uses `var` throughout while 24 globals depend on that behavior. | One file per commit behind a working bundle; adapters for classic consumers; the namespace contract catches a missed conversion. |
| R5 | **Coverage lost quietly, invisibly to the count.** Demonstrated, not hypothesised: 1,535 assertions passed against the wrong PSL. | Contract inventory plus the reviewed §12.1 registry and state matrix are the gate; targeted contracts cover computed and non-string shapes. |
| R6 | **Generated data silently substituted.** The demonstrated hazard, and it generalizes to `__DKIM_SELECTOR_CATALOG__` and `__I18N_EN__`. | Composition root (§11): passed, never imported by consumers. One divergent fingerprint per binding, not one proxy and not a count — behavioural through the real consumer for the DKIM catalog and the English bundle, binding-level for the PSL, which no application code reads (`1.4`). |
| R7 | **Deploy publishes source or tests**, now that non-shipping files live under `src/`. | Exact-allowlist artifact test; `metafile.inputs` and source-map `sources` as the binding proof. |
| R8 | **Scope creep.** Every phase surfaces something. The 14 unsupported legacy globals are the first example. | Their removal is the one authorized compatibility delta: its own commit, manifest entry and release note. Every other found behavior change is filed separately unless it blocks the phase. |
| R9 | **Cold-start regression.** One artifact replaces seven cacheable files. | Measured −40% raw / −39% gzip; metafile composition reporting; `OQ-ARCH-05` holds the split for later. |
| R10 | **Cache-scope drift.** Easy to narrow accidentally once behind a factory; invisible in output; changes published privacy figures. | Query-trace surface; sibling reuse within one runtime; isolation between two runtimes; one production runtime per page. |
| R11 | **Canonicalization absorbs a real regression** while tolerating noise it was written to tolerate. | Every tolerance names the difference class it admits and why that class cannot carry a defect; exclusions are per-field with reasons, no wildcards; timestamp and locale are fixed inputs. |

## Resolved questions

All nine design questions are resolved. Linux `npm ci` remains measured work at
Gate 1 and does not alter any answer below.

| ID | Question | Answer | Resolved |
| --- | --- | --- | --- |
| `OQ-ARCH-01` | Bundler | **esbuild**, on measured evidence: 2 packages on this platform, 1 install script, −40% raw / −39% gzip, 22 ms build, legacy IIFEs bundle with an identical 24-global surface | Round 1 conditionally; [spike](fixtures/esbuild-legacy-bundle-spike-0.6.0.md) 2026-08-27 |
| `OQ-ARCH-02` | Commit `package-lock.json` | **Yes.** Exact pin + lockfile + `npm ci` | Round 1 |
| `OQ-ARCH-03` | Browser target | **`es2020` syntax**, plus a separate required-API matrix for `AbortController`, `BigInt`, `Intl.PluralRules`, Web Crypto. No polyfills | Round 1 |
| `OQ-ARCH-04` | Source maps | **Ship linked external maps.** Excluded from the transfer-size figure | Round 1 |
| `OQ-ARCH-05` | Bundle split | **One bundle for 0.6.0.** Report metafile composition; revisit with measured repeat-visit data | Round 1 |
| `OQ-ARCH-06` | Bundle output format | **IIFE.** Keeps `file://`, keeps the CSP shape, gives parity an access path. `globalName` only from §10 stage 3 | Round 2, conditional on R2-F1 and R2-F5 |
| `OQ-ARCH-07` | `js/` transition | **No duplicate tree; marked adapters**, deleted as their last consumer migrates | Round 1 |
| `OQ-ARCH-08` | Strict locale gate in CI | **Add it** | Round 1 |
| `OQ-ARCH-09` | Test co-location | **Hybrid.** `src/**/*.test.js` for unit tests; `tests/` for build, contract, integration, fixtures | Ian, 2026-08-27 |

`OQ-ARCH-06`'s conditions are discharged by §10 (staged facade, namespace
contract) and §12 (allowed-edge matrix, SCC rule). The `file://` answer is
reinforced by evidence rather than argument: `js/locales-en.js` states in its own
generated header that English is inlined *"so the app works when index.html is
opened directly from disk"*, and that file is 125,172 bytes — about 18% of the
current payload. `file://` support was bought and paid for.

## As implemented

Written at Task 6.7, from the finished branch. **The spec's text above is
preserved exactly as it was approved**; everything built differently from it is
recorded here, and the review logs that produced these decisions are folded in
below rather than left as separate root documents.

### What was built as specified

Six phases. **All six gates are met**; Task 6.9's release commit cut Gate 6 and
shipped this as `v0.6.0`. **Thirteen owning directories** under `src/`, each with its own
`API.md` — `audit/`, eight protocol owners, `core/dns/`, `core/shared/`,
`providers/` and `ui/` — and **30 co-located test modules** among them.
`src/ui/` is the one owning directory with no co-located test, and it is not
untested: `tools/render.test.mjs` and `tools/export.test.mjs` are its
established suites and kept their assertion counts through the refactor. One
delivery boundary
(`dist/app.min.js`); the two-member facade as the only supported browser API;
the five-surface equivalence oracle reporting **zero differences** at every gate
against the `v0.5.0` baseline; the empty exclusion manifest never touched.

### Where the implementation differs from the spec

| # | Spec said | Built | Why |
| --- | --- | --- | --- |
| 1 | §2's tree names `core/shared/` with four modules | **Five** — `record-selection.js` was added at Task 5.2a | Gate 5 requires the coordinator to hold no parsing rule. Moving record selection to the protocol owners gave `startsWithCI`, `versionCandidates` and `leadingVersionMatches` two protocol readers each, which is §12's admission test met on its own terms. Task 4.0 had rejected all three **correctly**: their second reader was then `audit`, which has no edge to `core/shared/`. The premise changed, not the rule, and **the matrix was not amended**. |
| 2 | §2's tree names `audit/audit-domain.js` as the audit's composition | **`audit/create-audit.js` is a separate composition boundary** | Deleting `js/dns.js` at Task 6.1 needed a home for the protocol construction. §12 gives `runtime.js` the `core/dns/` edge and `audit/` the `core/<protocol>/` edge, and neither can do the other's job — so the split is structural: the runtime builds the resolver, `create-audit.js` builds every check over it, and `audit-domain.js` remains the coordinator. |
| 3 | Task 6.1 deletes `js/` | Done — and **the 95-member engine surface survives as `tools/lib/legacy-engine.mjs`** | `tools/lib/legacy-engine.mjs` reconstructs all 95 members from the ESM owners, and `tools/scoring.test.mjs` reaches them by name with its **1,535 assertions unmoved through six phases** — the strongest single piece of evidence that no behaviour did. Rewriting it during the refactor would have retired the instrument measuring the refactor. The file is a test harness: nothing under `src/` imports it and it is not in the bundle. |
| 4 | §8's second fixture-identity probe form reads the generated-data globals | **Reads the artifact text** | Those globals went with the last adapter at Task 6.2. Same discriminators — the private `blogspot.com` rule, the fixture DKIM selector, the fixture English title — observed where they are now observable. The form is recorded in each subject's manifest, so a run still cannot read as stronger evidence than it was. |

**Phase 6 retired the transitional adapters, as specified.** `OQ-ARCH-07`
answered the `js/` transition with "marked adapters, deleted as their last
consumer migrates", and §12's Phase 6 requires none to remain. Task 6.2 removed
both and the nine globals they published, and `state-matrix.test.mjs` and
`namespace.test.mjs` now assert the count is exactly zero. **That is not a third
compatibility delta**, and `tests/fixtures/equivalence/compatibility-deltas.json`
says so explicitly: the two authorized deltas are the facade contraction and the
fourteen function globals, and adapter retirement is recorded separately —
finished work on an adapter whose ESM owner now exists, not a change to a
supported surface. The manifest records, per group, what each retired name's
consumer actually was.

### Rulings made during implementation that the spec did not anticipate

- **The derived-fact boundary.** Phase 4 injected two cross-protocol
  collaborators into the wrong owners — SPF's `spfReferencedCatalogKeys` into
  `core/dkim/`, MX's `isNullMx` into `providers/` — because the layer that
  should compose them did not exist yet. Task 5.2 retired both: `src/audit/`
  derives each fact and passes it. The observed legacy signatures survive as
  thin compatibility wrappers, and `tools/scoring.test.mjs`'s count did not
  move.
- **What `audit/` may read.** `audit/scoring.js` and `audit/issues.js` consume
  protocol FACTS — including `spfStatus.warnings` — and never record contents.
  `spfRecords` is the instructive case: its CARDINALITY is evidence for
  `spf-multiple-records`, and its contents are never consulted. Asserted in
  each module's contract, deliberately **not** in the parsing-owner inventory:
  a weight table is not a parsing rule, and widening that inventory to mean
  "anything that reads a protocol value" would leave it protecting nothing.
- **Fourteen issue keys are invisible to a literal scan.** 92 of the 106 are
  written as `key: '…'`; the rest arrive through the DKIM confidence ternary,
  the `DIAGNOSIS_KEYS` table, `pushKeyFinding()`, and forwarding from the
  closed `spf.warnings` algebra. That forwarding is a **compositional
  precondition, not a property of `buildIssues()`** — it does not filter, and
  an arbitrary fabricated token would be forwarded verbatim. Both halves are
  asserted.
- **`result()` isolates at the top level only.** Nested values are shared by
  identity with the audit, deliberately: deep-cloning would change legacy
  identities and value types. Both halves are asserted so nobody later
  "hardens" it into serialization.

### Findings recorded and deliberately not fixed

Neither is a 0.6.0 regression; both predate the branch.

- **`retries` never reaches the transport from `analyzeDomain()`.** Roughly
  twenty `tools/scoring.test.mjs` calls pass it; the per-query options have
  always been `{ signal }` alone, so the factory default applies. Behaviour,
  not plumbing — changing it would alter retry behaviour and the published DNS
  fan-out.
- **`checks-unverified` carries an untranslated noun.** Its argument joins
  `'BIMI'`, `'SPF'`, `'MX'`, `'TLSA'` and `'Website'`. The first four are
  protocol names that must never be translated; "Website" is an ordinary
  English noun that should be. The fix adds an `en.json` key, which under
  `AGENTS.md` means thirteen translations in the same change — a localization
  change, not a refactor.

### What the review rounds established

Two separate sources, and they should not be conflated.

**Six temporary working documents** at the repository root carried the three
formal spec-review rounds and the two later amending cycles — a request and a
follow-up for each. They are deleted; what survives from them is folded here.

**The Phase 5–6 implementation review was separate**, produced no working
document, and amended nothing. What it caught is recorded in the last row.

| Cycle | What it changed |
| --- | --- |
| Spec rounds 1–3 | Recorded in the `0.2`, `0.4` and `1.0` revision rows above — the bundler evidence, the four-boundary transport model, the allowed-edge matrix, the two-member facade, the state matrix. |
| Facade contraction and fixture identity | Produced `1.4` and `1.5`: the oracle's two-execution provenance, the PSL fingerprint reclassified as binding-level, and the **second `example.com` probe** that `PRIVACY.md` had never disclosed. |
| Transport exception edges | Produced `1.6`: two inventories rather than one three-name row — raw-kind readers and typed propagation paths are different questions and one list could not serve both. |
| Phase 5–6 implementation review | **No spec amendment.** They caught, in order: a coordinator that broke Gate 5 by holding seven parsing rules; a concurrency instrument that could hang instead of failing; four dead compatibility wrappers calling a function their module did not import; a harness mode that documented a global it could not produce; and repeated current-state claims that outlived the code they described. |

**The pattern across the review cycles is one shape**, and it is the most
transferable thing this branch produced: **a check that is green because
nothing reaches it.** A wrapper nobody calls, a scan over a deleted path, a
race with no deadline, a mode with no caller, a claim nothing asserts. None was
visible to 4,451 assertions, five equivalence surfaces or a real browser,
because a green suite is exactly what they produce. The controls that caught
them are the negative case (`§1`'s third rule), the caller count, and the
comment strip — a scan asking "does this file do X" must strip comments,
because the file most likely to discuss X is the one that just stopped doing it.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 1.8 | 2026-08-30 | **Released as `v0.6.0`.** Gate 6 cut by Task 6.9's release commit, which touches no source file: the version bump, `CHANGELOG.md`'s promoted `0.6.0` section and compare links, the `README.md` figures, and the status fields in this document, its implementation plan, the spec index, `ROADMAP.md` and the async handoff. The `1.7` row below is the implementation-complete record and is preserved as written. **No spec text, acceptance criterion, surface or threshold changed at the release** — the release gates were re-run against the released tree and report the same figures Gate 5 recorded: 4,451 assertions across 46 suites, both equivalence subjects at 32 cases and five surfaces with zero differences, 430 of 430 registry rows covered, and 13/13 locales at 771/771 keys. |
| 1.7 | 2026-08-30 | **Implementation complete; release pending.** Moved to `docs/specs/implemented/` with its fixtures, and the **As implemented** section added above: four documented divergences, four rulings the spec did not anticipate, two findings recorded and deliberately not fixed, and what each review cycle established. The spec's approved text is unchanged. The six temporary review documents are folded into that section and removed from the repository root; the filenames still named in the rows below are provenance only. **Gates 0–5 are met and Gate 6 is not** — Task 6.9 cuts the release and flips the status field, the tag reference and the index row. All nine open questions resolved; both equivalence subjects report zero differences across 32 cases and five surfaces. |
| 1.6 | 2026-08-28 | **Amended during Phase 3, Task 3.6 — §3's exception-edge row named three sites and conflated two contracts.** Found by the task whose job is to name and test those edges, which is how `1.1`, `1.3` and `1.5` were found too. **(a) Two inventories, not one.** A **raw-kind reader** inspects a raw resolver response instead of a normalized array; a **propagation path** is a result field that retains a closed transport kind. One list could not serve both: `domainExists()` and `checkConnectivity()` are legitimate readers and propagate nothing, while a layer-4 fallback can propagate a caught `DnsError.kind` without reading a raw response at all. The reader inventory is now six entries organized by owning function or family — `core/dns` twice, `core/dmarc` twice, `core/dnssec`, `audit` — and `doh.js` and `requireUsable()` are expressly excluded, because they ARE layers 1 and 2 and an allowlist that includes them stops meaning anything. **(b) Eleven typed propagation paths, derived from result construction and then checked against the baseline, not the reverse.** The Task-3.6 request proposed the eleven the corpus had been observed to produce; that set was a lower bound and one of its members was not a typed field. `advanced.spfLookups.queryError` is source-reachable through the `countSpfLookups()` fallback and the corpus did not reach it when the defect was found — a corpus finding, not permission to omit the path. Task 3.6 closed that gap with the `spf-lookup-query-error` case; the path was listed on source-reachability alone, before any corpus observation existed for it. The DMARC walk's kind copied into the `dmarc-unverified` issue's arguments is a **derived presentation copy**, tested against its own issue key and deliberately kept out of `resultPaths`: a bare `issues[].args[]` pattern would let an unrelated argument equal to `timeout` earn transport coverage, which is the vacuous credit the measured matrix exists to remove. The thrown audit `error.kind` stays a thrown path under §12.1 and is not mixed into `resultPaths`. **(c) Layer 4's rule stated precisely.** `optionalCheck()` is policy-neutral: it re-throws `AbortError` and `DnsTypeError` and otherwise returns what the caller declared, and many callers declare `null` or `[]`. A caller-supplied fallback alone owns the unknown's shape and MAY copy `DnsError.kind` deliberately. Exactly three fallback factories do — website resolution, which collapses to the `@dns-error` hosting sentinel and escapes nothing; `checkCAA()`; and `countSpfLookups()`. `checkExternalReportAuth()` is an internal `catch` under a static `[]` fallback, and `discoverDmarc()` records raw kinds directly: three distinct mechanisms, tested as such. **(d) Registry corrections.** `dns.transport.kind.resultPaths` was empty, which asserted the algebra is not observable in a result; it now names the eleven typed paths. A three-member algebra for `advanced.reportAuth[].exactKind` — `success`, `nodata`, `nxdomain` — is added under `core/dmarc`, a field that previously had no owner. Both change the Gate-0 inventory totals, recorded as an explicit post-Gate-0 addendum rather than by rewriting the historical claim. No runtime behaviour, phase ordering or acceptance threshold changed. Recorded in `CODEX follow-up review for Transport Exception Edges.md`. |
| 1.5 | 2026-08-28 | **Corrects two claims `1.4` overstated. Found by the Gate 2 audit, not by the implementation — which was right both times.** **(a) The cross-execution binding does not include issue tokens, §8.** `1.4` named them among the bound fields. The UI renders each issue as translated prose through `issueMessage()` and attaches no token attribute, so they are not observable on that side at all, and manufacturing one for the oracle would be the production test seam §11 forbids. The fields actually bound — domain set, grade, score, issue count, suggestion count — are now named, with the DOM node each is read from. **The tokens lose no coverage**: they are carried in full by the result surface, compared byte for byte against the baseline, which is where a changed token has always been caught. What was overclaimed is narrower than it reads — not that the tokens are checked, but that they serve as a cross-execution join key, which they cannot, because only one execution can see them. The rule that decides what may be bound is recorded with it: only fields that cannot differ because the code under test changed, learned by breaking it. **(b) `PRIVACY.md` did need an edit, §8 and the acceptance criteria.** `1.4`'s driver change fires `DOMContentLoaded`, which runs the boot's `checkConnectivity()`; because that call passes `noCache: true` it is a genuine second query. The trace proves **two** fixed `example.com A` probes per run — one at page initialization, one before each audit run — and the count is exactly two across all thirty corpus cases whether one domain is audited or nine. `1.4` concluded the document needed no edit; it described only the second probe, so a browser session sent one more query than it disclosed. **Pre-existing behaviour newly measured, not a 0.6.0 behaviour change**: the old runner drove a page that had never booted. The per-domain figures — 41 typical, 61 for `cloudflare.com` — come from `tools/backtest.mjs`, which loads no page, and are unchanged. `PRIVACY.md`, plan Task 6.6 and the Gate 2 capture are corrected to distinguish both probes. No runtime code, baseline, surface, exclusion or acceptance threshold changed; the empty exclusion manifest and the strict canonicalization line are untouched. The `1.4` row above is preserved exactly as written. Recorded in `CODEX follow-up review for Facade Contraction and Fixture Identity.md` §5. |
| 1.4 | 2026-08-27 | **Amended during Phase 2, Task 2.7 — two corrections, both about what the instrument proves.** **(a) Oracle provenance, §8.** Stage 3 of §10 makes `window.DnsAudit` esbuild's export namespace: non-configurable accessors, and **not** the engine object `src/main.js` calls. Measured against the artifact — the assignment throws, and `window.DnsAudit` occurs zero times in shipped code. The runner captured the result surface by wrapping that global, so the five surfaces can no longer all come from one runtime. They are now bound to one deterministic **case** captured by two isolated executions: the facade's `analyzeDomain` for the result, the real UI controls for trace, CSV, report and DOM, with the same data profile, options, instant, locale and platform, neither warming the other. The result execution's trace is a different instrument execution, **not an exclusion** — no exclusion is added and the manifest stays empty. Cross-surface binding on domain, score, grade and issue tokens is asserted so two different cases cannot be joined under one id. The rejected alternatives, and why, are recorded. **(b) The PSL fingerprint is binding-level, §11.** `getOrganizationalDomain()` is the only reader of the public suffix sets and **no application code calls it** — zero call sites at `v0.5.0` and at `f1a2842`; `result.organizationalDomain` comes from the RFC 9989 walk. So `1.0`'s claim of a behavioural fingerprint per binding was true for the DKIM catalog and the English bundle and not for the PSL, the same shape of overstatement `1.2` corrected. The probe is unchanged and stays in the suites that supply the binding through `createAuditRuntime()`, reclassified as an engine/runtime fingerprint; an artifact-driven suite is not required to claim one through the two-member facade. The unused 160.6 KB PSL payload **stays in 0.6.0** — removing shipped data is a behaviour-and-size decision, Risk R8 — and is filed in `docs/maintenance-backlog.md` with its measured size. No architecture, phase ordering or acceptance threshold is reopened; the five surfaces, the strict canonicalization line and the empty exclusion manifest are unchanged. Recorded in `CODEX follow-up review for Facade Contraction and Fixture Identity.md` §1–§2. |
| 1.3 | 2026-08-27 | **Added `open` to §11's primitive set.** `openLearnMore()` opens the generated Learn-more page with `open(url, '_blank', 'noopener')` (`js/app.js:385`), and the list did not name it. Found by the **completed conversion sweep over `js/app.js`**, the last unconverted file, which enumerated its full ambient set — eight already listed, this one missing. It is the last such finding because there is no further legacy source to sweep, and it is expressly **not** evidence that the lexical contract is exhaustive: that contract could not have found it either, per `1.2`. Implemented as `win.open.bind(win)`, with a receiver-sensitive contract asserting the exact `url`, `_blank` and `noopener` arguments; the 60-second `revokeObjectURL` timeout and every other behaviour are unchanged. Recorded as the first **navigation side-effect** capability on the list; its final UI-facing abstraction is a **Phase 5** question and is not redesigned now. Added to §11, §12's platform API row, the acceptance criteria, `PLATFORM_PRIMITIVES`, `SPEC_11` and the known-ambient catalog. No architecture or implementation decision reopened. Recorded in `CODEX follow-up review for Modular Refactor.md` §18. |
| 1.2 | 2026-08-27 | **Evidence correction, no design change.** `1.1` said §11's primitive set was "exhaustive by contract, not by inspection". It is not, and the phrasing claimed more than the check delivers — the same shape of overstatement this project has corrected twice before, in a paragraph written to correct an overstatement. `tests/contract/platform.test.mjs` establishes three things: the spec list and `PLATFORM_PRIMITIVES` agree bidirectionally, every declared primitive is provided, and a lexical scan over a **named catalog** of ambient identifiers rejects a bare read outside the platform module and the marked adapters. It cannot discover an ambient identifier absent from that catalog — the `navigator` omission `1.1` fixed would not have been caught by it — and a regex is not scope analysis. Replaced with "reviewed during conversion, synchronized bidirectionally, and guarded against the known ambient catalog", stated the scan as defense in depth against regression, and adjusted the acceptance criterion to match. No parser and no dependency added; no architecture or implementation decision reopened. Recorded in `CODEX follow-up review for Modular Refactor.md` §17. |
| 1.1 | 2026-08-27 | **Amended during Phase 2, Task 2.4.** §11's exact platform list omitted `navigator` while claiming to name *every* ambient primitive the moved code uses — false, because `detectLang()` reads `navigator.languages` and `navigator.language`. Found by converting `js/i18n.js`, where the module stopped being able to reach `window` and every dependency had to be named; four of its five ambient primitives were on the list. Added to §11, to §12's `platform/` API row, and to the acceptance criteria, with the completeness now asserted against the platform module's own published set rather than by inspection. Framework §6 trigger 5: a Final spec found wrong is amended and re-versioned, never quietly diverged from. The finding and Ian's decision are recorded in `CODEX follow-up review for Modular Refactor.md` §16. **Narrow by design:** an omission from one enumeration. No design decision, phase ordering, acceptance threshold or behaviour changed, and nothing else in `1.0` is reopened. |
| 1.0 | 2026-08-27 | **Final after Codex review round 3.** Replaced the ineffective `a.b.ck` fixture check with independently divergent PSL, DKIM-catalog and English-bundle fingerprints. Made cache ownership consistently per runtime, with one production runtime per page and cross-runtime isolation. Added a side-effect-free `runtime.js`, browser-platform adapter, complete allowed-edge rows and per-owner API contracts. Replaced the unsound static-extractor promise with a complete pre-refactor inventory covering computed DNSSEC claims, thrown paths, booleans, nullability and absence; the state matrix is complete before Gate 0. Bound equivalence subjects to complete roots with input hashes and fixed time/locale inputs. Declared the two-member facade the only supported 0.6.0 browser API and recorded removal of legacy globals as an intentional compatibility delta. Synchronized the implementation plan with the no-`globalName` legacy phase and the real four-boundary resolver model. Linux `npm ci` remains a Gate 1 measurement. |
| 0.4 | 2026-08-27 | Revised after review round 2 and against measured evidence. **The `OQ-ARCH-01` spike ran** ([capture](fixtures/esbuild-legacy-bundle-spike-0.6.0.md)): the seven unmodified IIFEs bundle to an identical 24-global surface, `DnsAudit` intact at 95 members, −40.1% raw / −39.0% gzip, 22 ms — Phase 1 is confirmed viable, and esbuild's real footprint (2 packages, 1 `postinstall`) replaces the false "zero dependencies" claim. **`globalName` corrected**: it exports the entry's exports, so 0.2's claim was wrong and would have clobbered `window.DnsAudit` on the delivery-boundary commit; the facade is now staged in three steps (§10). **The global inventory was 24, not five** — `js/app.js` alone assigns 14, all of them **dead** (no consumer; `index.html` has no inline handlers). **The supported facade is two members**, `analyzeDomain` and `checkConnectivity`, the only ones `js/app.js` calls out of 95; the other 93 plus `__APP_TEST__` become direct ESM imports. **The transport model is four layers plus exception edges**, not a five-member union — the ten real kinds are enumerated with the cacheable ⊂ retry-terminal rule. **Composition root specified** (§11), justified by the spike demonstrating a bundled PSL silently replacing a fixture while 1,535 assertions still passed. **Allowed-edge matrix, SCC rejection and API tables added** (§12). **HTML report parity restored** to the gate — it had fallen out — making five surfaces, with executable canonicalization rules. **State matrix added**, self-policing via a test that fails on any discriminant lacking a row. **Co-location proof bound to `metafile.inputs`** rather than a sentinel. All nine open questions now resolved. |
| 0.3 | 2026-08-27 | `OQ-ARCH-09` decided by Ian: unit tests co-locate as `src/**/*.test.js`, with `tests/` retained for build, contract, integration and fixture suites. The layout is settled; the markup-sink exclusion that pays for it remains a round-2 review item because it touches a security control rather than a convention. `OQ-ARCH-06` is now the only open question. |
| 0.2 | 2026-08-27 | Revised after review round 1 (Codex). All eight findings verified against the code and accepted. **Build now precedes ESM conversion** — 0.1's Phase 0 could not keep the browser working between its own commits. **Equivalence expanded from score/grade/token to four surfaces** — full result projection, DNS query trace, CSV bytes, canonical DOM. **Per-audit cache scoping declined**: page lifetime is tested at `scoring.test.mjs:1891` and underwrites `PRIVACY.md`'s published fan-out. **esbuild's dependency footprint corrected** — `postinstall` plus 26 platform optional dependencies, not zero. **Transport-boundary grep withdrawn as vacuous**, replaced by a closed result algebra plus import-graph direction. **Assertion count demoted** from merge gate to reported tripwire, with a contract inventory as the gate. Baseline capture moved to `git worktree`. `core/bimi/` added. `legalComments`, interpolation-count and `locales-en.js` claims corrected. Two new items opened: `OQ-ARCH-06` reopened to propose an **IIFE bundle** (keeps `file://`, resolves F3's access path), and `OQ-ARCH-09` added for **test co-location**. Seven questions resolved. |
| 0.1 | 2026-08-27 | First draft, written from the Codex proposal of 2026-08 and checked against `main` at 0.5.0. Six claims in the source proposal corrected (ESM conversion omitted; finding identifiers already exist; DNS cache already exists; deployment allowlist already exists; no lockfile to pin against; behavioral equivalence unverifiable as specified). ESM conversion added as Phase 0. Bundle-parity testing added. Finding-identifier redesign declined. Eight open questions recorded. |
