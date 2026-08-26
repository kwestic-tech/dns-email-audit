# Spec: Modular architecture and production build

| Field | Value |
| --- | --- |
| Spec version | 0.1 (Draft) |
| Target release | 0.6.0 |
| Status | Awaiting review |
| Depends on | [dnssec-evidence](implemented/dnssec-evidence.md), released as 0.5.0 and used as the behavioral baseline |
| Blocks | [findings-and-remediation](findings-and-remediation.md), [local-artifact-validation](local-artifact-validation.md), [report-comparison](report-comparison.md) — all three are scheduled after it |
| Slug for open questions | `ARCH` |
| Last updated | 2026-08-27 |
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

1. Convert the hand-written browser code from `window`-attached IIFEs to ES
   modules under `src/`.
2. Split `js/dns.js` and `js/app.js` along the four responsibility boundaries
   in §4 of the source proposal: DNS transport, protocol evaluation, audit
   coordination, UI.
3. Introduce esbuild as the project's first development dependency, producing
   `dist/app.min.js`.
4. Change the deployed artifact from seven source files to one built bundle,
   without changing `index.html` as the public entry point or any public URL.
5. Extend CI to build the bundle, verify the deployment artifact's contents,
   and report bundle size.
6. Prove behavioral equivalence against the 0.5.0 baseline, including at least
   one suite executed against the built bundle rather than against source.
7. Restructure `tools/*.test.mjs` to mirror module ownership, and remove the
   `node:vm` sandbox where a plain `import` now suffices.
8. Document module ownership in `AGENTS.md` so a coding agent's expected
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
failure is never remembered as an answer. What is actually missing is the
scoping §9 asks for in its last line: the cache is module-global for the page's
lifetime, not scoped to one audit. **Accepted with the scope corrected**: the
cache moves to `src/core/dns/cache.js` unchanged in behavior, and is
*instantiated* by the audit coordinator so its lifetime becomes explicit. The
eviction policy, the key format and the cacheable-kind rule do not change.

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

### 2. Target source structure

Adapted from §5, with the caution in that section honored: a module exists
because it owns a responsibility, not to make the tree look modular. Concrete
line counts from the 0.5.0 monolith are given so the split is a plan rather
than an aspiration.

```text
src/
├── main.js                  entry point; wires UI to coordinator
│
├── core/
│   ├── dns/
│   │   ├── doh.js           DoH request, timeout, retry, AbortController
│   │   ├── resolver.js      normalization, response-kind classification
│   │   ├── cache.js         the existing LRU, instantiated per audit
│   │   └── errors.js        transport-failure vs absent vs invalid
│   │
│   ├── spf/                 parse, recursive evaluate, lookup accounting,
│   │                        subnet classification, redundancy
│   ├── dkim/                selector discovery, catalog, key decode
│   ├── dmarc/               parse, tree walk, organizational domain, policy
│   ├── dnssec/              chain evaluation, DS↔DNSKEY matching
│   ├── mx/                  MX health
│   ├── caa/                 CAA policy
│   └── transport/           mta-sts.js, tls-rpt.js, tlsa.js
│
├── audit/
│   ├── audit-domain.js      orchestration; which checks run, in what order
│   ├── context.js           per-audit shared state, cache instance
│   ├── scoring.js           WEIGHTS, PARKED_WEIGHTS, GRADE_THRESHOLDS
│   └── issues.js            buildIssues, buildSuggestions
│
├── providers/detectors.js
│
├── ui/
│   ├── render.js            from js/render.js
│   ├── report.js            exportCSV, exportHTML
│   └── events.js            DOM wiring
│
├── i18n/index.js            from js/i18n.js
│
└── data/                    generated; not hand-edited
    ├── public-suffixes.js
    ├── dkim-selectors.js
    └── locales-en.js
```

`js/` is deleted at the end of Phase 6, not before.

### 3. DNS transport boundary

`src/core/dns/` owns obtaining DNS information and nothing else. It must not
be able to express an opinion about whether a configuration is secure. The
operational test for a leak: **no string in `src/core/dns/` is a token that
appears as a key in `locales/en.json`.** A grep enforcing that is cheap and is
added to the test suite.

The resolver's existing five-way distinction — absent, invalid, transport
failure, unsupported, indeterminate — is a shipped guarantee from
[resilient-optional-checks](implemented/resilient-optional-checks.md) and
survives the move unchanged. §10 of the proposal restates it correctly.

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

The concurrency structure that exists today — `Promise.all` over independent
checks, batched DKIM selector scanning at `DKIM_SCAN_BATCH_SIZE = 24` — is
preserved as-is. §8 of the proposal is explicit that the refactor does not
require concurrency changes, only that the architecture stop preventing them.
**Changing concurrency and moving code in the same phase is forbidden** by §35
and by this spec.

### 6. Build

esbuild, pinned, as the sole development dependency.

```text
src/main.js ──► esbuild ──► dist/app.min.js
```

| Setting | Value | Why |
| --- | --- | --- |
| `format` | `esm` | Matches the source; no IIFE wrapper needed |
| `bundle` | `true` | One artifact, per §25 |
| `minify` | `true` | The delivery win |
| `sourcemap` | *see `OQ-ARCH-04`* | A `//# sourceMappingURL` comment and a `.map` file are a deployment-allowlist question, not a build question |
| `target` | *see `OQ-ARCH-03`* | §27 requires the compatibility target be explicit and documented |
| `splitting` | `false` | §25; revisit only against a measurement |
| `external` | *(empty)* | Nothing is external; there are no runtime dependencies |
| `legalComments` | `inline` | Preserves the MIT header |

`index.html` changes from seven tags to one:

```html
<script type="module" src="dist/app.min.js"></script>
```

`type="module"` is required for an ESM bundle and carries one behavior change
worth stating: module scripts are deferred and are fetched with CORS semantics,
so **opening `index.html` directly from the filesystem stops working**. It works
today. `npm start` already serves the site over HTTP
([`tools/serve.mjs`](../../tools/serve.mjs)), so the development path is
unaffected, but the change is real and belongs in `CONTRIBUTING.md`. Recorded as
`OQ-ARCH-06`.

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
no `node_modules/`, and no `*.test.mjs`. Asserted, not assumed.

`dist/` is already git-ignored ([`.gitignore:7`](../../.gitignore)), which
matches §17: the artifact is generated by CI from the commit being deployed and
never committed.

### 8. Behavioral equivalence

The binding definition, stricter than §23:

> Given identical fixture DNS responses, `src/` at any phase boundary produces
> byte-identical `calcScore()` output, an identical issue-token list in
> identical order, and an identical `gradeFor()` result to `js/` at the `v0.5.0`
> tag — and `dist/app.min.js` produces the same as `src/`.

**`tools/backtest.mjs` cannot be that mechanism.** It queries live DNS over
Cloudflare — its own header says it *"requires outbound network access, so run it
locally rather than in CI"* — so two runs a day apart differ because someone
else's records changed, not because the refactor did. A non-deterministic oracle
cannot prove byte-equality.

The oracle is [`tools/lib/doh-fixture.mjs`](../../tools/lib/doh-fixture.mjs),
which already exists and is already the basis of the 1,535-assertion scoring
suite. It replaces the sandbox's `fetch` with a programmable map and defaults
unmatched queries to NXDOMAIN, deliberately, so that a missing fixture entry
fails loudly instead of silently reaching the network. Equivalence is therefore
proven the same way correctness already is.

Two tiers:

| Tier | Mechanism | Deterministic | Runs | Gate? |
| --- | --- | --- | --- | --- |
| **Equivalence** | Fixture-corpus replay through `dohFixture`, three-way: `v0.5.0` `js/`, refactored `src/`, built `dist/app.min.js` | Yes | Every commit, in CI | **Yes.** Any diff blocks the merge. |
| **Sanity** | `node tools/backtest.mjs --sample` grade histogram | No — live DNS | Each phase boundary, locally | No. A *distribution* shift is investigated; a per-domain difference is expected and means nothing. |

The equivalence corpus is a new artifact: a fixture set broad enough to reach
every protocol module, captured once at the start of the refactor and version
controlled beside the tests. It is the single most valuable thing built in
Phase 0, because everything after it is measured against it.

A phase that cannot produce a clean three-way fixture diff does not merge.

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

The interpolation suite (`tools/interpolate.test.mjs`, 329 assertions) is the
canary here and runs unchanged apart from its import mechanism.

## Testing

Existing suites are migrated, not rewritten (§21). Five things are added.

**1. Test layout mirrors module ownership.**

```text
tools/                       build and locale tooling (unchanged)
tests/
├── lib/                     from tools/lib/
├── core/dns/  spf/  dkim/  dmarc/  dnssec/  mx/  caa/  transport/
├── audit/                   scoring, issues, coordination
├── ui/                      render, export, csp
└── build/                   bundle parity, artifact contents, size
```

The 2,121 existing assertions are redistributed, not reduced. **The total
assertion count must not fall at any phase boundary.** A phase that reduces it
has lost coverage and must say which assertion it dropped and why.

**2. Protocol tests import directly.** After Phase 0, a test for SPF subnet
classification is `import { classifySpfSubnet } from '../../src/core/spf/...'`,
not a 288 KB `vm.runInContext`. `tools/lib/browser-harness.mjs` survives only
for the UI suites that genuinely need a DOM.

**3. Boundary tests.** Three greps, each an assertion:

- No file under `src/core/` imports from `src/ui/` or `src/audit/`.
- No file under `src/core/dns/` contains a string that is a key in
  `locales/en.json` — the transport-does-not-judge rule from Design §3.
- No file under `src/` other than `src/i18n/` and `src/ui/` reads a locale
  string.

**4. Bundle parity.** `tests/build/parity.test.mjs` builds `dist/app.min.js`,
loads it, and re-runs the scoring fixtures against it, asserting identical
output to the same fixtures run against `src/`. This is the gap in §23/§39
identified above, and it is the single most important new test in the release.

**5. Deployment artifact test.** `tests/build/artifact.test.mjs` runs
`npm run build` and asserts on `_site/`:

- `index.html`, `CNAME`, `css/`, `locales/`, `dist/app.min.js` are present.
- `dist/app.min.js` is non-empty.
- Every `<script src>` and `<link href>` in `_site/index.html` resolves to a
  file that exists in `_site/`.
- `src/`, `tools/`, `tests/`, `docs/`, `node_modules/`, `package.json`,
  `AGENTS.md` and `*.test.mjs` are absent.
- `locales/translation-status.json` is absent — the existing skip-set rule,
  now asserted.

**6. `tools/csp.test.mjs` is amended, not weakened.** Its section 3 currently
asserts filenames and load ordering that a single bundle makes meaningless.
Those three assertions are replaced by: exactly one `<script src>`, it is
`dist/app.min.js`, it is same-origin, and it carries `type="module"`. The
markup-sink scan (section 4) is retargeted from `js/` to `src/` **and
additionally run over `dist/app.min.js`**, so the artifact that ships is proven
free of markup sinks rather than only the source it came from. The empty
allowlist stays empty.

**7. Bundle size is reported.** CI prints raw and gzip size for
`dist/app.min.js` on every run (§26). It does not fail on an increase; it makes
one visible in review. The 0.5.0 comparison point is 719,199 raw / 213,467 gzip
across seven files.

**8. Three-way fixture replay is the equivalence gate**, per Design §8, and
runs in CI. `node tools/backtest.mjs --sample` is run locally at each phase
boundary as a grade-distribution sanity check only — it is live-DNS and must
never be a merge gate.

## Acceptance criteria

Structural:

- [ ] All hand-written browser code lives under `src/` as ES modules. `js/` is gone.
- [ ] DNS transport is a module that emits no locale token, proven by test.
- [ ] Each of SPF, DKIM, DMARC, DNSSEC, MX, CAA, MTA-STS, TLS-RPT and TLSA has an identifiable owning directory.
- [ ] Audit orchestration is separate from UI rendering; no `src/core/` file imports from `src/ui/`.
- [ ] `AGENTS.md` documents module ownership and the expected modification boundary for a protocol change.

Equivalence:

- [ ] Three-way backtest — `v0.5.0` `js/`, refactored `src/`, built `dist/app.min.js` — is byte-identical, or every difference is documented and deliberate.
- [ ] `WEIGHTS`, `PARKED_WEIGHTS` and `GRADE_THRESHOLDS` are byte-identical to `v0.5.0`.
- [ ] The issue-token vocabulary is unchanged; no `locales/en.json` key is added, changed or removed.
- [ ] `npm test` passes with **no fewer than 2,121 assertions**.
- [ ] `npm run locale:gate` reports 13/13.

Build and deployment:

- [ ] `npm run build` produces `dist/app.min.js` from `src/` with no network access.
- [ ] `package.json` has zero `dependencies` and exactly one `devDependency`, pinned.
- [ ] `package-lock.json` is committed *(pending `OQ-ARCH-02`)*.
- [ ] `dist/` remains git-ignored and is never committed.
- [ ] CI builds the bundle, runs the full suite, and gates deployment on both.
- [ ] `_site/` contains only the allowlisted production paths, asserted by test.
- [ ] Bundle raw and gzip size appear in CI output.
- [ ] `index.html` is still the entry point and no public URL changed.
- [ ] A clean clone can run `npm ci && npm test && npm run build` using only documented instructions.
- [ ] The `v0.5.0` tag can still be checked out and served, unmodified.

Preserved properties:

- [ ] CSP `connect-src` is still exactly `'self' https://cloudflare-dns.com`.
- [ ] The markup-sink allowlist is still empty, and the scan covers `src/` *and* `dist/`.
- [ ] `PRIVACY.md` needs no edit, because nothing it describes changed.
- [ ] No runtime third-party JavaScript reaches the browser.
- [ ] GitHub Actions remain SHA-pinned.

## Risks

| # | Risk | Mitigation |
| --- | --- | --- |
| R1 | **Silent behavior change during extraction.** 5,704 lines moving between files is the highest-probability failure in the release. | Three-way deterministic fixture replay at every commit; assertion count may not fall; one responsibility extracted per commit. |
| R2 | **The bundle differs from the source that was tested.** The gap §23/§39 leaves open. | The bundle-parity test (Testing item 4) is a merge gate, not a nice-to-have. |
| R3 | **First-ever supply-chain dependency.** esbuild pulls a platform-specific binary. A compromised release would run with write access to the deploy artifact. | Pin exact version; commit the lockfile; `npm ci` only; esbuild has zero transitive dependencies, which is much of why it is chosen over the alternatives. Revisit under `OQ-ARCH-01`. |
| R4 | **ESM strict mode changes semantics.** IIFE bodies with `'use strict'` are already strict, but module top-level `this` is `undefined` rather than the global, and `var` no longer creates a global. `js/dns.js` uses `var` throughout. | Convert one file per commit with the suite green after each; the DOM shim will surface a `this`-binding error immediately. |
| R5 | **Test harness rewrite loses coverage quietly.** Moving off `node:vm` touches every suite. | Assertion count is a merge gate. Migrate a suite in its own commit, with the count recorded in the message. |
| R6 | **`type="module"` breaks `file://` opening.** Works today. | Documented in `CONTRIBUTING.md`; `npm start` is the supported path. `OQ-ARCH-06`. |
| R7 | **Deploy publishes something it should not.** The allowlist is one array, edited by hand. | Artifact test asserts both presence and absence. |
| R8 | **Refactor scope creep.** Every phase surfaces a bug worth fixing. | §3 and §35: a behavior fix found during the refactor is filed and shipped separately unless it blocks the phase. Recorded in the phase's commit message either way. |
| R9 | **Bundle regresses cold-start performance.** One 213 KB gzip artifact replaces seven cacheable files. | Size reporting in CI; `OQ-ARCH-05` carries the measurement and the split option. |

## Open questions

**`OQ-ARCH-01` — Is esbuild the right tool, and is one dependency acceptable at all?**
The proposal names esbuild "unless implementation research identifies a
materially better option" (§11). The alternatives worth weighing are rollup
(more plugins, more transitive dependencies), and *no bundler at all* — native
ESM served directly, which needs no dependency and keeps the audit-by-reading
property, at the cost of ~40 HTTP requests and no minification. This is the
first dependency in the project's history and the decision deserves a stated
answer rather than an assumed one. **Recommendation:** esbuild. It has zero
transitive dependencies, which is the property that matters most here.

**`OQ-ARCH-02` — Commit `package-lock.json`?**
[`.gitignore:3`](../../.gitignore) ignores it. §28 requires pinning through it.
These are incompatible. **Recommendation:** remove the ignore and commit the
lockfile. A build system in the supply chain that is not pinned is worse than no
pinning policy at all, because it claims a control it does not have — the same
reasoning `tools/csp.test.mjs` records for replacing the published CSP nonce
with a hash.

**`OQ-ARCH-03` — What is the browser compatibility target?**
§27 requires it be explicit and documented, and nothing states it today. The
code already uses `async`/`await`, `AbortController`, `BigInt`, optional
chaining and `Intl.PluralRules`, so the *de facto* floor is roughly ES2020.
**Recommendation:** `target: ['es2020']` with a stated support policy of the
last two versions of Chrome, Firefox, Safari and Edge, and no polyfills.

**`OQ-ARCH-04` — Ship source maps to production?**
A source map makes the deployed bundle debuggable and preserves some of the
audit-by-reading property the current unbundled deployment has for free. It also
publishes `src/` to Pages in a second form and adds roughly the source's own
size to the artifact. **Recommendation:** yes, and add `dist/*.map` to the
deployment allowlist. The project's threat model has no confidentiality
interest in its own source — it is public — and transparency is closer to this
project's stated values than a smaller artifact is.

**`OQ-ARCH-05` — One bundle, or split the generated data out?**
§25 says one bundle unless a measurement justifies otherwise. The measurement:
`public-suffixes.js` and `dkim-selectors.js` total 183,394 raw / 50,166 gzip and
change only when `npm run update:psl` or `npm run update:dkim-selectors` is run
— roughly monthly, and independently of application code. Bundled together, a
returning visitor re-downloads 50 KB gzip of unchanged data tables on every
release. Split, they cache across releases. `locales-en.js` is *not* a candidate:
it is regenerated whenever `locales/en.json` changes, which the localization
contract makes every release. **Recommendation:** ship one bundle for 0.6.0 as
§25 directs, let the CI size report accumulate real numbers, and decide the
split in a later release with data rather than now with an estimate.

**`OQ-ARCH-06` — Is losing `file://` support acceptable?**
`type="module"` requires HTTP. Opening `index.html` from disk works today and
will not after this change. `npm start` and the deployed site are unaffected.
**Recommendation:** accept it and document it. The alternative — an IIFE-format
bundle — keeps `file://` working but reintroduces a global namespace at the one
boundary this refactor exists to remove.

**`OQ-ARCH-07` — Does `js/` get a deprecation period?**
The proposal's §36 permits temporary adapters. A period where both `js/` and
`src/` exist makes each phase independently revertable, at the cost of two
copies of the truth and a real chance of an edit landing in the wrong one.
**Recommendation:** no parallel tree. Convert in place, one responsibility per
commit, `js/` shrinking as `src/` grows, with the suite green at every commit.
The `v0.5.0` tag is the rollback, and it is a better one than a stale duplicate.

**`OQ-ARCH-08` — Should `npm run locale:gate` join CI?**
[`.github/workflows/ci.yml`](../../.github/workflows/ci.yml) runs `npm test`,
which invokes `check-locales.mjs` **non-strict**. The strict gate that
`AGENTS.md` requires before every PR is enforced by convention only. §39 asks
CI to verify "localization validation". **Recommendation:** add it. It is one
line and it closes a gap between the stated contract and the enforced one — but
it is a policy change beyond the refactor's scope, so it needs an explicit yes.

## Revision history

| Version | Date | Change |
| --- | --- | --- |
| 0.1 | 2026-08-27 | First draft, written from the Codex proposal of 2026-08 and checked against `main` at 0.5.0. Six claims in the source proposal corrected (ESM conversion omitted; finding identifiers already exist; DNS cache already exists; deployment allowlist already exists; no lockfile to pin against; behavioral equivalence unverifiable as specified). ESM conversion added as Phase 0. Bundle-parity testing added. Finding-identifier redesign declined. Eight open questions recorded. |
