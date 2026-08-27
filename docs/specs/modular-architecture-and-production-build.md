# Spec: Modular architecture and production build

| Field | Value |
| --- | --- |
| Spec version | 0.2 (Draft) |
| Target release | 0.6.0 |
| Status | Revised after review round 1; awaiting round 2 |
| Depends on | [dnssec-evidence](implemented/dnssec-evidence.md), released as 0.5.0 and used as the behavioral baseline |
| Blocks | [findings-and-remediation](findings-and-remediation.md), [local-artifact-validation](local-artifact-validation.md), [report-comparison](report-comparison.md) — all three are scheduled after it |
| Slug for open questions | `ARCH` |
| Last updated | 2026-08-27 |
| Reviews | Round 1 (Codex, 2026-08-27) recorded in [`CODEX follow-up review for Modular Refactor.md`](../../CODEX%20follow-up%20review%20for%20Modular%20Refactor.md); this spec's responses in [`CODEX Review Modular Refactor.md`](../../CODEX%20Review%20Modular%20Refactor.md) |
| Source | Written from an external proposal, *DNS Email Audit Modular Architecture and Production Build Refactor Specification* (Codex, 2026-08). Section numbers of the form §N below refer to that document. Where this spec diverges from it, the divergence is recorded in [§ Corrections to the source proposal](#corrections-to-the-source-proposal). |

## Problem

The application is seven classic `<script src>` tags loading IIFEs that attach
to `window` in dependency order ([`index.html:187`](../../index.html)). There is
no module system, no build step for JavaScript, and no way for one file to
declare what it needs from another. The load order in `index.html` *is* the
dependency graph, and it is enforced by three assertions in
[`tools/csp.test.mjs`](../../tools/csp.test.mjs) rather than by the language.

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
[`tools/scoring.test.mjs`](../../tools/scoring.test.mjs) constructs a `node:vm`
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
[`tools/build-site.mjs`](../../tools/build-site.mjs) copies seven paths into
`_site/`; it is a file-selection step, not a build. That has been an asset —
the shipped behavior is trivially auditable — and this spec must not spend it
carelessly.

The project is about to add three more releases of protocol surface
([findings-and-remediation](findings-and-remediation.md),
[local-artifact-validation](local-artifact-validation.md),
[report-comparison](report-comparison.md)), each of which reads or extends the
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
| `package-lock.json` | Does not exist; git-ignored at [`.gitignore:3`](../../.gitignore) |

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
  boundary in [`PRIVACY.md`](../../PRIVACY.md) is untouched: browser →
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
[`tools/lib/browser-harness.mjs`](../../tools/lib/browser-harness.mjs),
[`tools/backtest.mjs`](../../tools/backtest.mjs) and
`tools/scoring.test.mjs` — reaches the code through `window`, and the harness
comment states the design explicitly: *"the files are plain IIFEs that attach to
`window`, so there is nothing to mock and no bundler involved."*

Converting to ESM is therefore not a precondition the proposal assumed; it is
the largest single work item in the refactor, and it invalidates the loading
strategy of four separate tools. This spec makes it Phase 0.

**2. Findings already have stable machine-readable identifiers.** §31 proposes
introducing them, with examples in the form `SPF_LOOKUP_LIMIT`. This is already
the binding project rule, stated in the header of `js/dns.js` and in
[`docs/specs/README.md`](README.md#constraints-every-spec-inherits): *"`js/dns.js`
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
`Map` with LRU eviction at [`js/dns.js:70`](../../js/dns.js), keyed on
`name + type`, with a `noCache` opt-out and — importantly — a deliberate rule
that only `success`, `nodata` and `nxdomain` results are cached, so a transport
failure is never remembered as an answer. §9's last line asks for the cache to be "scoped to the active audit". **That
part is declined.** Page-lifetime reuse is deliberate, tested, and part of a
published privacy figure:

- [`tools/scoring.test.mjs:1888-1891`](../../tools/scoring.test.mjs) asserts
  exact query counts across two *different* domains — a first DMARC walk issues
  3 queries and a sibling subdomain issues 1, reusing the cached upper steps.
  Per-audit scoping fails that assertion.
- [`js/app.js:1397`](../../js/app.js) calls `analyzeDomain(domain, opts)` once
  per queued domain from a shared worker pool, with no audit context passed.
  The reuse exists *because* the cache outlives a single domain.
- [`PRIVACY.md:30-33`](../../PRIVACY.md) publishes the consequence: "roughly 41
  queries for a typical domain", and 61 for `cloudflare.com`. Narrowing the
  cache raises those numbers, which makes it a privacy-facing change, not a
  refactor.

**Accepted as narrowed further than 0.1 stated**: the cache moves to
`src/core/dns/cache.js` behind a factory — an architectural change — and the
factory is invoked **once at module scope**, preserving page lifetime exactly.
Eviction policy, key format and the cacheable-kind rule do not change. Changing
who owns the instance is a separate, later decision requiring query-count
fixtures and a privacy review.

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
possible today: [`.gitignore:3`](../../.gitignore) ignores the lockfile, because
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
│
├── core/
│   ├── dns/
│   │   ├── doh.js           DoH request, timeout, retry, AbortController
│   │   ├── resolver.js      normalization, response-kind classification
│   │   ├── cache.js         the existing LRU; page-lifetime instance
│   │   ├── errors.js        transport-failure vs absent vs invalid
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
│   └── transport/           mta-sts.js, tls-rpt.js, tlsa.js
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

`src/core/dns/` owns obtaining DNS information and nothing else. It must not be
able to express an opinion about whether a configuration is secure.

Version 0.1 proposed proving this by grepping for `locales/en.json` keys inside
`src/core/dns/`. **That test was vacuous** and is withdrawn: `en.json` is
nested, so a full key such as `issue.spf-large-subnet.msg` never appears as a
literal string anywhere, and the tokens the code actually emits are *values*
like `spf-missing` and `@none`, not keys. A resolver could emit a judgment token
and the grep would pass.

The boundary is enforced two ways instead, neither of which is a text scan:

**A closed result algebra.** The resolver's public result is a discriminated
union over a fixed, enumerated set of kinds — the five-way distinction shipped
by [resilient-optional-checks](implemented/resilient-optional-checks.md):
absent, invalid, transport failure, unsupported, indeterminate — plus record
data. A contract test asserts that every value the resolver can return inhabits
that set, and that no returned object carries a finding, a severity, a score or
a locale reference. This tests behavior, not spelling.

**Dependency direction.** No module under `src/core/dns/` imports from
`src/i18n/`, `src/ui/`, `src/audit/`, or any `src/core/<protocol>/`. Asserted by
walking the real import graph, not by grepping paths.

A static token scan may be kept as a secondary tripwire. It may not be cited as
the proof of this boundary.

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

esbuild, pinned, as the sole **direct** development dependency. Its real
dependency footprint is stated honestly in `OQ-ARCH-01` and Risks R3: at 0.28.2
the package declares `postinstall: node install.js` and 26 platform-specific
`@esbuild/*` `optionalDependencies`, of which npm installs one. That is a small
supply chain. It is not zero, and 0.1 of this spec claimed it was.

```text
src/main.js ──► esbuild ──► dist/app.min.js
```

| Setting | Value | Why |
| --- | --- | --- |
| `bundle` | `true` | One artifact, per §25 |
| `format` | **`iife`** | See below. Changed from `esm` in 0.2. |
| `globalName` | `DnsAudit` | The single delivery-boundary export |
| `minify` | `true` | The delivery win |
| `sourcemap` | `linked`, external | `OQ-ARCH-04`, answered: ship it |
| `target` | `es2020` + a required-API matrix | `OQ-ARCH-03` |
| `splitting` | `false` | §25; revisit only against a measurement |
| `external` | *(empty)* | Nothing is external; there are no runtime dependencies |
| `metafile` | `true` | Feeds the size report and shows bundle composition |
| `banner.js` | explicit string | esbuild's `legalComments` cannot do this job — see below |

#### Why `iife` and not `esm`

Version 0.1 specified `format: 'esm'` with
`<script type="module" src="dist/app.min.js">`, for symmetry with ESM source.
That symmetry is aesthetic, not a requirement, and it was generating three
separate problems. ESM **source** compiled to an **IIFE bundle** is the ordinary
library-bundle pattern and removes all three:

1. **`file://` keeps working.** `type="module"` is fetched with CORS semantics
   and fails from the filesystem. A classic script does not. `OQ-ARCH-06` — "is
   losing `file://` acceptable" — stops being a question that needs an answer.
2. **Bundle parity gets an access path.** This was Codex's F3: a browser entry
   does not normally re-export the functions a test needs, and tree shaking may
   remove APIs only tests use. `globalName: 'DnsAudit'` makes the built artifact
   expose exactly the surface the existing `node:vm` harness already reaches
   today via `window.DnsAudit`. The parity test loads `dist/app.min.js` in place
   of `js/dns.js` and changes almost nothing else.
3. **The CSP story does not change shape.** `tools/csp.test.mjs` keeps asserting
   one same-origin `<script src>`; no new module semantics enter the policy.

The global exists only at the delivery boundary and is generated by the bundler.
Modules inside the bundle communicate by `import`, so invariant 8
("build-time dependencies do not become runtime dependencies") and the
no-shared-namespace goal are both intact. This is a change to what 0.1 proposed
and to what round 1 assumed, so it is put back to the reviewer as `OQ-ARCH-06`.

#### The banner is not a legal comment

Version 0.1 said `legalComments: 'inline'` "preserves the MIT header". Both
halves were wrong, and Codex caught it. esbuild only treats a comment as legal
if it contains `@license` or `@preserve` or begins `//!` or `/*!`; **no file
under `js/` contains any of those**, and none carries MIT text — the licence is
the separately published `LICENSE` file, which the deployment allowlist already
ships. The descriptive headers in `js/*.js` are ordinary block comments and
esbuild will strip them, correctly.

If a banner is wanted in the artifact, it is set explicitly via `banner.js` and
asserted by the artifact test. It is a provenance note, not a licence notice.

`index.html` changes from seven tags to one:

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

`dist/` is already git-ignored ([`.gitignore:7`](../../.gitignore)), which
matches §17: the artifact is generated by CI from the commit being deployed and
never committed.

### 8. Behavioral equivalence

Version 0.1 defined equivalence over scores, grades and issue tokens. That was
too narrow: the Non-goals promise statuses, findings, severities, scores **and
explanations**, and a refactor could have changed MX detail, DNSSEC evidence,
DKIM key facts, DMARC discovery provenance, provider detection, warnings,
suggestions or export columns while passing. It also observed no DNS query
counts, which are a published privacy figure. Codex raised both in round 1.

The binding definition:

> Given identical fixture DNS responses, the refactored code produces a
> byte-identical **canonical projection of the complete `analyzeDomain()`
> result**, a byte-identical **DNS query trace**, byte-identical **CSV export**,
> and an equivalent **rendered DOM**, compared against `v0.5.0` — and
> `dist/app.min.js` produces the same as `src/`.

Four observed surfaces, not one:

| Surface | What is compared | Why it is separate |
| --- | --- | --- |
| **Result** | Canonical JSON of the whole `analyzeDomain()` return: every status, record, evidence field, warning, suggestion, issue token and score component, with ordered arrays preserved. Any excluded field is listed in the manifest with a reason. | The promise in Non-goals is the whole result, not the grade. |
| **Query trace** | Exact query names, types and counts issued per fixture. | Fan-out is published in [`PRIVACY.md`](../../PRIVACY.md). Output equality does not prove request equality — a lost cache hit is invisible in the result and visible in the trace. |
| **Export** | Byte-identical CSV columns and values; HTML report canonicalized only for genuinely nondeterministic values. | `exportCSV` writes positional columns; a reordering is a silent breaking change for anyone parsing them. |
| **Render** | Canonical DOM tree for the same corpus. | A rendering difference is where a `this`-binding or escaping change surfaces, and it is invisible to all three surfaces above. |

**The oracle is fixtures, never live DNS.** `tools/backtest.mjs` queries
Cloudflare — its own header says it *"requires outbound network access, so run
it locally rather than in CI"* — so two runs differ because someone else's
records changed. It is demoted to a local grade-*distribution* sanity check and
is never a gate. The oracle is
[`tools/lib/doh-fixture.mjs`](../../tools/lib/doh-fixture.mjs), which already
underpins the 1,535-assertion scoring suite and defaults unmatched queries to
NXDOMAIN so a missing fixture fails loudly.

**Capturing the baseline.** Version 0.1 said `git checkout v0.5.0`, then run a
test file that exists only on this branch — the checkout deletes the runner.
Instead the branch's harness is pointed at tag content extracted without moving
the worktree:

```bash
git worktree add ../dea-v050 v0.5.0
node tests/build/equivalence.mjs --source-root=../dea-v050/js --emit \
  > tests/fixtures/equivalence/baseline-v0.5.0.json
git worktree remove ../dea-v050
```

The baseline is committed. CI regenerates it from a clean clone and asserts it
matches, so it cannot drift unnoticed.

**One fixture-harness hazard, called out because it is easy to miss.**
[`tools/scoring.test.mjs:21`](../../tools/scoring.test.mjs) injects a
deliberately tiny public-suffix table — `['com','co.uk','*.ck','!www.ck']` —
through `window.__PUBLIC_SUFFIX_RULES__`, and replaces the sandbox `fetch`
repeatedly. A static `import` of `src/data/public-suffixes.js` would silently
substitute the real 165 KB PSL, and Node's module cache plus a process-global
`fetch` would change the second control. **The suite would still report 1,535
passing assertions while testing something else.** Generated data must therefore
be reachable through an injectable binding at the composition root, and the
parity harness must install and restore DOM, `fetch`, crypto and generated-data
inputs around a cache-busted load.

A phase that cannot produce a clean four-surface diff does not merge.

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

Recorded as `OQ-ARCH-09` because it changes a test-suite layout the reviewer has
already commented on, and because cost 1 touches a security control.

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

Existing suites are migrated, not rewritten (§21). Layout follows
[Design §9](#9-test-placement).

**1. The gate is a checked-in contract inventory, not an assertion count.**
Version 0.1 made `>= 2,121` a merge gate. Codex is right that it cannot be one:
a refactor can delete a meaningful assertion and add an unrelated one while the
total holds, and replacing three filename assertions with four bundle
assertions moves the number without saying whether the original property is
still covered.

`tests/inventory.json` names every suite and the contract areas it covers. The
gates are:

- Every contract area in the inventory has at least one passing suite.
- The assertion total is **reported** on every run, and a decrease requires the
  commit message to name the removed assertions and where the property moved.
- No inventory entry is deleted without a stated replacement.

The count stays visible because it is a good tripwire. It stops being proof.

**2. Four-surface equivalence**, per Design §8: result projection, query trace,
CSV bytes, canonical DOM — three-way across `v0.5.0`, `src/` and
`dist/app.min.js`. This is the release's primary gate.

**3. Contract tests** in `tests/contract/`:

- The resolver's result inhabits the closed kind set and carries no finding,
  severity, score or locale reference (Design §3).
- Import-graph direction: nothing under `src/core/dns/` imports `src/i18n/`,
  `src/ui/`, `src/audit/` or a sibling protocol; nothing under `src/core/`
  imports `src/ui/`. Asserted over the real graph, not by path grep.

**4. Bundle parity**, `tests/build/parity.test.mjs`. Loads the actual
`dist/app.min.js` — reachable because `format: 'iife'` with
`globalName: 'DnsAudit'` exposes the same surface the current harness uses —
installs and restores DOM, `fetch`, crypto and generated-data inputs, and runs
the equivalence corpus against it. A separate test-only bundle would prove
nothing about the shipped artifact and is not permitted as a substitute.

**5. Deployment artifact test**, `tests/build/artifact.test.mjs`. Runs
`npm run build` and asserts on `_site/`:

- Exact top-level allowlist: `index.html`, `CNAME`, `LICENSE`,
  `THIRD_PARTY_NOTICES.md`, `css/`, `dist/`, `locales/` — nothing else.
- Every `<script src>` and `<link href>` in `_site/index.html` resolves to a
  file present in `_site/`; the source-map link resolves too.
- `dist/app.min.js` is non-empty and contains no test sentinel.
- `src/`, `tools/`, `tests/`, `docs/`, `node_modules/`, `package.json`,
  `AGENTS.md` and every `*.test.*` are absent.
- `locales/translation-status.json` is absent.
- `assets/` is absent — it holds only `.gitkeep` and nothing references it.

**6. `tools/csp.test.mjs` amended, not weakened.** Its section 3 asserts script
filenames and load order, which a single bundle makes meaningless. Replaced by:
exactly one `<script src>`, it is `dist/app.min.js`, it is same-origin. Every
policy assertion in section 1 is preserved byte-for-byte. The markup-sink scan
covers `src/` excluding `*.test.js`, **and** `dist/app.min.js`. Source-map and
reference-resolution checks go in the artifact suite rather than overloading
this one.

**7. Bundle size reported** from the esbuild metafile: raw, gzip, and per-input
composition, so an accidental generated-data or test inclusion is visible.
Reported, not enforced. The 0.5.0 comparison point is 719,199 raw / 213,467
gzip across seven files. The source map is not counted — a normal visit does not
fetch it.

**8. `node tools/backtest.mjs --sample`** is a local grade-distribution sanity
check at each phase boundary. Live DNS; never a gate.

## Acceptance criteria

Structural:

- [ ] All hand-written browser code lives under `src/` as ES modules. `js/` is gone.
- [ ] Every temporary adapter is removed; a test asserts none remain.
- [ ] DNS transport returns a closed result algebra carrying no finding, severity, score or locale reference, proven by contract test.
- [ ] Each of SPF, DKIM, DMARC, DNSSEC, MX, CAA, BIMI, MTA-STS, TLS-RPT and TLSA has an identifiable owning directory.
- [ ] Import-graph direction holds: no `src/core/` module imports `src/ui/`.
- [ ] `AGENTS.md` documents module ownership and the expected modification boundary for a protocol change.

Equivalence:

- [ ] Four-surface, three-way equivalence — result projection, query trace, CSV bytes, canonical DOM — across `v0.5.0`, `src/` and `dist/app.min.js`, clean, or every difference documented and deliberate.
- [ ] The baseline regenerates from a clean clone in CI and matches the committed file.
- [ ] `WEIGHTS`, `PARKED_WEIGHTS` and `GRADE_THRESHOLDS` byte-identical to `v0.5.0`.
- [ ] Issue-token vocabulary unchanged; no `locales/en.json` key added, changed or removed.
- [ ] DNS query fan-out per fixture unchanged, so `PRIVACY.md`'s published figures still hold.
- [ ] Every contract area in `tests/inventory.json` has a passing suite; assertion total reported, and any decrease accounted for.
- [ ] `npm run locale:gate` reports 13/13.

Build and deployment:

- [ ] `npm run build` produces `dist/app.min.js` from `src/` with no network access.
- [ ] `package.json` has zero `dependencies` and exactly one direct `devDependency`, exact-pinned.
- [ ] `package-lock.json` is committed, and the resolved package footprint is recorded rather than described as zero.
- [ ] `npm ci` reproduces the build on macOS and Linux CI.
- [ ] `dist/` remains git-ignored and is never committed.
- [ ] CI builds the bundle, runs the full suite, and gates deployment on both.
- [ ] `_site/` matches the exact allowlist, asserted by test, with no `src/`, `tools/`, `tests/` or `*.test.*`.
- [ ] Bundle raw, gzip and per-input composition appear in CI output.
- [ ] `index.html` is still the entry point and no public URL changed.
- [ ] A clean clone runs `npm ci && npm test && npm run build` from documented instructions.
- [ ] The `v0.5.0` tag can still be checked out and served, unmodified.

Preserved properties:

- [ ] CSP `connect-src` still exactly `'self' https://cloudflare-dns.com`; every section-1 policy assertion byte-identical.
- [ ] The markup-sink named-file allowlist is still empty, and the scan covers `src/` and `dist/app.min.js`.
- [ ] The DoH cache retains page lifetime; the sibling-reuse assertion at `tools/scoring.test.mjs:1891` still passes.
- [ ] `PRIVACY.md` needs no edit — confirmed by the query-trace surface, not assumed.
- [ ] No runtime third-party JavaScript reaches the browser.
- [ ] GitHub Actions remain SHA-pinned.

## Risks

| # | Risk | Mitigation |
| --- | --- | --- |
| R1 | **Silent behavior change during extraction.** 5,704 lines moving between files is the highest-probability failure in the release. | Four-surface equivalence at every commit; one responsibility per commit; the build boundary established first so every move is checked against the shipped artifact. |
| R2 | **The bundle differs from the source that was tested.** | Parity runs against the real `dist/app.min.js`, reachable via `globalName`. A test-only bundle is not accepted as a substitute. |
| R3 | **First-ever supply-chain dependency.** esbuild 0.28.2 declares `postinstall: node install.js` and 26 `@esbuild/*` optional dependencies, of which npm installs one. This is small, not zero — 0.1 of this spec wrongly claimed zero. | Exact pin; committed lockfile; `npm ci` only; record the resolved package count and installed-binary provenance from the `OQ-ARCH-01` spike rather than describing the graph from memory. |
| R4 | **ESM strict-mode semantics.** Module top-level `this` is `undefined` rather than the global, and `var` no longer creates a global. `js/dns.js` uses `var` throughout. | Convert one file per commit behind the stable bundle, with adapters for classic consumers; the DOM shim surfaces a `this`-binding error immediately. |
| R5 | **Test harness rewrite loses coverage quietly**, and the assertion count will not catch it. | The contract inventory is the gate; the count is a reported tripwire. Migrate one suite per commit, naming moved properties. |
| R6 | **The fixture harness silently stops testing what it claims.** `scoring.test.mjs:21` injects a four-rule PSL; a static data import would substitute the real 165 KB list and the suite would still report 1,535 passing. | Generated data reaches modules through an injectable binding at the composition root; a contract test asserts the fixture PSL is the one in force during the suite. |
| R7 | **Deploy publishes something it should not**, now that non-shipping files live under `src/`. | Exact-allowlist artifact test asserting presence *and* absence, plus a test-sentinel scan of the bundle. |
| R8 | **Scope creep.** Every phase surfaces a bug worth fixing. | §3 and §35: a behavior fix found during the refactor is filed and shipped separately unless it blocks the phase. Recorded in the commit message either way. |
| R9 | **Cold-start regression.** One artifact replaces seven cacheable files. | Metafile size reporting; `OQ-ARCH-05` carries the measurement for a later split. |
| R10 | **Cache-scope drift.** The page-lifetime cache is easy to narrow by accident once it is behind a factory, and the result is invisible in output while changing published privacy figures. | The query-trace equivalence surface; the sibling-reuse assertion; an explicit acceptance criterion. |

## Open questions

Round 1 answered eight. Two remain open and one is new.

### Open

**`OQ-ARCH-06` — bundle output format: `iife` or `esm`?** *(reopened in 0.2)*
Round 1 answered the question 0.1 asked — "is losing `file://` acceptable" —
with "accepted and documented". This spec now argues the loss is avoidable:
compiling ESM source to an **IIFE** bundle with `globalName: 'DnsAudit'` keeps
`file://` working, keeps `index.html` on a plain `<script src>`, and gives the
parity test a documented access path to the shipped artifact, which was round
1's F3. The cost is one bundler-generated global at the delivery boundary;
modules inside still communicate by `import`.
*Recommendation:* `iife`. Put back to the reviewer because it reverses an answer
already given and it interacts with F3's resolution.

**`OQ-ARCH-09` — do unit tests live beside the code?** *(new in 0.2)*
Full argument in [Design §9](#9-test-placement). Co-location makes §32's
blast-radius claim literally true, at three costs: a filename-suffix exclusion
in the markup-sink scan whose allowlist is deliberately empty; a need to prove
test code never reaches the bundle; and a glob runner replacing six explicit
invocations.
*Recommendation:* co-locate unit tests as `src/**/*.test.js`; keep `tests/` for
build, contract, integration and fixtures. Pay cost 1 with a mechanical suffix
rule plus an artifact scan rather than a per-file allowlist.

### Resolved in round 1

| ID | Question | Answer | Notes |
| --- | --- | --- | --- |
| `OQ-ARCH-01` | Bundler | **esbuild, conditional on a spike** | Spike must bundle the unmodified IIFEs, run the exact artifact under the fixture harness, work on macOS and Linux from `npm ci`, and record the real lockfile footprint. Permitted before Final; it is research, not refactoring. |
| `OQ-ARCH-02` | Commit `package-lock.json` | **Yes** | Exact direct pin + committed lockfile + `npm ci`. `.gitignore:3` entry removed when the first package lands. |
| `OQ-ARCH-03` | Browser target | **Split syntax from platform support** | `target: ['es2020']` for syntax; a separate required-API matrix for `AbortController`, `BigInt`, `Intl.PluralRules`, Web Crypto — esbuild does not polyfill these, so "last two versions" proves nothing on its own. No polyfills. |
| `OQ-ARCH-04` | Source maps | **Ship linked external maps** | Assert the map exists and its link resolves; exclude it from the transfer-size figure, since a normal visit never fetches it. |
| `OQ-ARCH-05` | Bundle split | **One bundle for 0.6.0** | Report metafile composition; defer splitting until repeat-visit and cache-header behavior are measured. |
| `OQ-ARCH-07` | `js/` transition | **No duplicate tree; adapters required** | 0.1 offered a false choice between two complete trees and no transition mechanism. One source of truth per responsibility, small marked adapters behind the stable bundle, each deleted as its last classic consumer migrates. |
| `OQ-ARCH-08` | Strict locale gate in CI | **Add it** | Enforces an existing repository contract; not a behavioral expansion. |

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-08-27 | First draft, written from the Codex proposal of 2026-08 and checked against `main` at 0.5.0. Six claims in the source proposal corrected (ESM conversion omitted; finding identifiers already exist; DNS cache already exists; deployment allowlist already exists; no lockfile to pin against; behavioral equivalence unverifiable as specified). ESM conversion added as Phase 0. Bundle-parity testing added. Finding-identifier redesign declined. Eight open questions recorded. |
| 0.2 | 2026-08-27 | Revised after review round 1 (Codex). All eight findings verified against the code and accepted. **Build now precedes ESM conversion** — 0.1's Phase 0 could not keep the browser working between its own commits. **Equivalence expanded from score/grade/token to four surfaces** — full result projection, DNS query trace, CSV bytes, canonical DOM. **Per-audit cache scoping declined**: page lifetime is tested at `scoring.test.mjs:1891` and underwrites `PRIVACY.md`'s published fan-out. **esbuild's dependency footprint corrected** — `postinstall` plus 26 platform optional dependencies, not zero. **Transport-boundary grep withdrawn as vacuous**, replaced by a closed result algebra plus import-graph direction. **Assertion count demoted** from merge gate to reported tripwire, with a contract inventory as the gate. Baseline capture moved to `git worktree`. `core/bimi/` added. `legalComments`, interpolation-count and `locales-en.js` claims corrected. Two new items opened: `OQ-ARCH-06` reopened to propose an **IIFE bundle** (keeps `file://`, resolves F3's access path), and `OQ-ARCH-09` added for **test co-location**. Seven questions resolved. |
