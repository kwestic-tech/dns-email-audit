# Review request — modular architecture and production build refactor

**Spec under review:** [`docs/specs/modular-architecture-and-production-build.md`](docs/specs/modular-architecture-and-production-build.md) — `0.1 (Draft)`, slug `ARCH`
**Implementation plan:** [`Modular Architecture, Production Build Refactor Implementation.md`](Modular%20Architecture,%20Production%20Build%20Refactor%20Implementation.md)
**Branch:** `spec/modular-architecture-production-build`, commit `285ac40`
**Source proposal:** *DNS Email Audit Modular Architecture and Production Build Refactor Specification* (Codex, 2026-08). `§N` below refers to it.
**Baseline:** `main` at `v0.5.0`
**Prepared:** 2026-08-27
**Asked for:** verdicts, not approval

---

## What this document is

The source proposal was turned into a project-format spec and checked against
the code at `v0.5.0`. **Six of its claims did not hold, and one of its design
requests was declined outright.** Those changes are material enough that they
should not stand on one reader's judgment.

This is the inverse of the usual `CODEX review for PR#N.md`: rather than Codex
reviewing an implementation, the author of the source proposal is asked to
review the corrections made to it, and to render verdicts on eight open
questions — three of which block any code being written.

Per the review process in [`docs/specs/README.md`](docs/specs/README.md),
four things are requested:

1. A verdict on each numbered open question, with reasoning.
2. Any correctness objection to the design, referenced to the RFC or the file
   and function it contradicts.
3. Anything that would break the privacy boundary in
   [`PRIVACY.md`](PRIVACY.md), the CSP, or the localization contract in
   [`AGENTS.md`](AGENTS.md).
4. Anything the spec claims about the current codebase that is not true.

**Item 4 cuts both ways.** Every claim below was verified against the tree at
`v0.5.0` and is cited to a file and line. If any citation is wrong, say so —
that is the most useful thing this review can produce.

---

## Verified baseline

Captured on `main` at `v0.5.0`, 2026-08-27. Every number below is from a real
run, not from memory.

| Signal | Value |
| --- | --- |
| `npm test` | **2,121 assertions**, 0 failed |
| `tools/scoring.test.mjs` | 1,535 — the protocol suite, 72% of all coverage |
| `tools/render.test.mjs` | 329 |
| `tools/export.test.mjs` | 199 |
| `tools/csp.test.mjs` | 41 |
| `tools/interpolate.test.mjs` | 17 |
| `tools/check-locales.mjs` | passes; reports findings, not an assertion count |
| `npm run locale:gate` | 13/13 strict |
| Browser payload | 7 files, 719,199 bytes raw, 213,467 gzip |
| Runtime npm dependencies | 0 |
| Development npm dependencies | 0 |

Per-file:

| File | Lines | Raw | gzip |
| --- | ---: | ---: | ---: |
| `js/dns.js` | 5,704 | 288,185 | 87,260 |
| `js/app.js` | 1,819 | 83,539 | 24,837 |
| `js/render.js` | 552 | 22,802 | 7,990 |
| `js/i18n.js` | 403 | 16,107 | 5,536 |
| `js/locales-en.js` *(generated)* | 1,186 | 125,172 | 37,678 |
| `js/public-suffixes.js` *(generated)* | 6 | 164,798 | 44,475 |
| `js/dkim-selectors.js` *(generated)* | 6 | 18,596 | 5,691 |

---

## Part 1 — Corrections to the source proposal

Eight in total: six factual, two methodological. Each states the evidence and
the decision taken. **A verdict is requested on each.**

### C1 — The code is not ES modules, and the proposal does not mention it

**Severity: this is the largest omission and it changes the shape of the work.**

§5, §13 and §19 describe moving files into `src/` as though a module graph
already exists. It does not.

- [`index.html:187-193`](index.html) loads **seven classic `<script src>` tags**
  in hand-maintained dependency order. No `type="module"` anywhere.
- [`js/dns.js:15`](js/dns.js) opens `(function (global) {` and
  [ends](js/dns.js) `})(window);` — an IIFE assigning an export object to
  `window`. `js/app.js`, `js/render.js` and `js/i18n.js` follow the same
  pattern.
- `js/public-suffixes.js` and `js/dkim-selectors.js` assign globals;
  [`js/dns.js:20`](js/dns.js) reads
  `global.__DKIM_SELECTOR_CATALOG__ || { providers: {}, … }`.
- [`tools/lib/browser-harness.mjs`](tools/lib/browser-harness.mjs) states the
  design in its own header: *"the files are plain IIFEs that attach to
  `window`, so there is nothing to mock and no bundler involved."*

The load order in `index.html` **is** the dependency graph, and it is enforced
by three assertions in [`tools/csp.test.mjs`](tools/csp.test.mjs) §3 rather
than by the language.

Converting to ESM is therefore not a precondition the proposal could assume; it
is the single largest work item, and it invalidates the loading strategy of
four separate tools — `browser-harness.mjs`, `backtest.mjs`,
`scoring.test.mjs`, and `index.html` itself.

**Decision taken:** ESM conversion added as **Phase 0**, ahead of the build
system. Phase 1 of the proposal (build infrastructure first) is not reachable
until it is done.

> **Verdict requested.** Is Phase 0 correctly placed and correctly scoped? Is
> there an argument for bundling the IIFEs as-is first — esbuild can consume
> classic scripts — and converting to ESM afterwards?

### C2 — Findings already have stable machine-readable identifiers

§31 proposes introducing them, with examples of the form `SPF_LOOKUP_LIMIT`,
`DKIM_RSA_KEY_TOO_SHORT`, `DMARC_POLICY_NONE`.

This is already the binding project rule. [`js/dns.js:1-13`](js/dns.js) states
it in the file header:

> *"This file is deliberately free of user-facing English. Anything a person
> reads is represented here as a stable identifier — `'@none'`,
> `'spf-missing'`, `'noteWildcard'` — and turned into words by `js/app.js` via
> the i18n layer."*

[`docs/specs/README.md`](docs/specs/README.md) repeats it under *Constraints
every spec inherits*: **"`js/dns.js` returns tokens, not English."** The tokens
are lowercase-hyphenated and are consumed by `locales/en.json` keys of the form
`issue.spf-large-subnet.msg`, by both export formats, and by all fourteen
locales.

Renaming them to `SCREAMING_SNAKE_CASE` would touch every locale file, every
`issue.*` key and both exports, for **no behavioral gain** — and would violate
§35 of the proposal itself, which forbids moving code and redesigning result
schemas in the same change.

**Decision taken: declined.** The token vocabulary is preserved byte-for-byte
and a diff in it is treated as a defect, not progress. §31's genuine content —
that protocol modules emit structured facts and the UI decides presentation —
is already true and is preserved by the module boundary.

> **Verdict requested.** Confirm the decline, or state what §31 was asking for
> that the existing token scheme does not already provide.

### C3 — A shared DNS cache already exists

§9 asks for one. [`js/dns.js:70-88`](js/dns.js) is a `Map` with LRU eviction
bounded by `MAX_DOH_CACHE_ENTRIES`, keyed on `name + type`, with a `noCache`
opt-out at [`js/dns.js:208`](js/dns.js).

It is also **more careful than §9 asks for**: [`js/dns.js:219`](js/dns.js)
caches only `success`, `nodata` and `nxdomain` results, so a transport failure
is never remembered as an answer. §9 does not mention this rule, and an
implementation that reads §9 literally would lose it.

What is genuinely missing is the scoping §9 requests in its final line: the
cache is module-global for the page's lifetime, not scoped to one audit.

**Decision taken: accepted, narrowed.** The cache moves to
`src/core/dns/cache.js` with **behavior unchanged** — same key format, same
eviction, same cacheable-kind rule — and is instantiated by the audit
coordinator so its lifetime becomes explicit.

> **Verdict requested.** Confirm that per-audit scoping is what §9 intended,
> and that the cacheable-kind rule is understood as load-bearing rather than
> incidental.

### C4 — A deployment allowlist already exists

§40 asks for one. [`tools/build-site.mjs:9`](tools/build-site.mjs) builds
`_site/` from an explicit list:

```js
const files = ['index.html', 'CNAME', 'LICENSE', 'THIRD_PARTY_NOTICES.md', 'css', 'js', 'locales'];
```

with a skip-set keeping `locales/translation-status.json` out of the published
site. What is missing is a **test**: nothing asserts the array's contents, so a
careless edit could publish `tools/` or `docs/` unnoticed.

**Decision taken: accepted, narrowed.** The allowlist swaps `js` for `dist`,
and gains an artifact test asserting both presence and absence.

One note on §40's own recommended allowlist, which lists
`index.html / CNAME / css/ / assets/ / locales/ / dist/`: **`assets/` should not
be on it.** The directory contains exactly one file, `.gitkeep`, and nothing in
`index.html` or `css/` references it. Publishing it would ship an empty
directory. The current seven-entry list is right to omit it, and §40's list
would have quietly added it back.

> **Verdict requested.** Any path genuinely missing from the production
> allowlist? Note that `LICENSE` and `THIRD_PARTY_NOTICES.md` are currently
> published and §40's list drops both — deliberate, or an oversight? They are
> not browser assets, but a static site that ships its own licence text is
> making a claim worth keeping.

### C5 — `package-lock.json` does not exist and is git-ignored

§18 reasons from *"commit X, package-lock.json, documented Node version"*. §28
requires that *"npm development dependencies must be pinned through the
lockfile."*

Neither is possible. [`.gitignore:3`](.gitignore) ignores `package-lock.json`,
because the project has had **zero dependencies of any kind** and the file
would always have been empty.

Adding esbuild makes this the **first dependency in the project's history**,
and by §28's own words the build system becomes part of the supply chain. The
ignore entry must be removed and the lockfile committed, or §28's requirement
claims a control it does not have.

**Decision taken:** recorded as `OQ-ARCH-02` and marked blocking.

> **Verdict requested.** See `OQ-ARCH-02` in Part 2.

### C6 — Behavioral equivalence, as specified, cannot be verified

§23 requires equivalent output. §39 asks CI to verify *"production build
success"*.

But **every existing test loads source, and the browser will be served the
bundle.** "Build success" means esbuild exited zero; it says nothing about
whether the bundle behaves like the source it was built from. A minifier bug, a
tree-shaking mistake, or a `this`-binding change under ESM strict mode passes
every gate in the proposal and reaches production.

**Decision taken:** a bundle-parity test is a merge gate. At least one suite
runs against `dist/app.min.js`, asserting identical output to the same fixtures
run against `src/`.

> **Verdict requested.** Is parity on the scoring corpus sufficient, or should
> the render and export suites also run against the bundle? The render suite is
> where a DOM-construction difference would surface.

### C7 — `tools/backtest.mjs` cannot be the equivalence oracle *(methodological)*

The spec initially named it as the mechanism. It is not fit for the purpose.
[`tools/backtest.mjs:23`](tools/backtest.mjs) says so directly: *"Requires
outbound network access, so run it locally rather than in CI."* It queries live
domains over Cloudflare. **Two runs a day apart differ because a stranger
edited a TXT record, not because the refactor did.** A non-deterministic oracle
cannot prove byte-equality.

The correct oracle already exists:
[`tools/lib/doh-fixture.mjs`](tools/lib/doh-fixture.mjs), the basis of the
1,535-assertion scoring suite. It replaces the sandbox's `fetch` and defaults
unmatched queries to NXDOMAIN deliberately, so a missing fixture fails loudly
rather than silently reaching the network.

**Decision taken:** two tiers. Deterministic fixture replay is the merge gate
and runs in CI; `backtest.mjs --sample` is a local grade-*distribution* sanity
check and is never a gate. Building the equivalence corpus is Task 0.4 and is
the highest-value artifact in the refactor.

> **Verdict requested.** Is the proposed corpus coverage sufficient? It is
> listed in Task 0.4.a of the implementation plan.

### C8 — The resolver handle vs. the seam this repo refuses *(methodological)*

§7 and §6.1 propose protocol modules receiving a resolver. This brushes against
a standing refusal recorded in
[`tools/lib/doh-fixture.mjs:6-11`](tools/lib/doh-fixture.mjs):

> *"`js/dns.js` gets no test seam. There is no `__setResolver`, no injected
> transport and no production branch that exists only for tests — this repo has
> consistently refused those, and a resolver stub that bypasses the real
> request-building code would stop testing the part most likely to be wrong."*

**Decision taken:** the handle is permitted, and the spec records why. The rule
forbids a seam existing *only for tests* that lets a test bypass real request
construction. A resolver handle passed between production modules is the actual
call path in the browser, with no test-only branch, and tests keep substituting
`fetch` exactly as they do today — so URL construction, `application/dns-json`
parsing, the cache, the concurrency limiter and the retry loop all stay under
test. **Any implementation that adds a `__setResolver`-shaped export has
violated the rule and must be rejected in review.**

> **Verdict requested.** Confirm this distinction holds, or state where a
> resolver handle would in practice let a test bypass code that matters.

---

## Part 2 — Open questions

Eight. **Three block Phase 0 and must be answered before any code is written**,
because each changes what the work is. Recommendations are the spec author's
and carry no weight in this review.

### Blocking

**`OQ-ARCH-01` — esbuild, another bundler, or no bundler at all?**
§11 names esbuild *"unless implementation research identifies a materially
better option"*. Alternatives: rollup (more plugins, more transitive
dependencies); or **no bundler** — native ESM served directly, needing no
dependency and keeping the audit-by-reading property, at the cost of ~40 HTTP
requests and no minification.
*Recommendation:* esbuild, because it has zero transitive dependencies — the
property that matters most for a project whose first dependency this is.
*If the answer is "no bundler", Phase 1 becomes a different phase and the
release's premise changes.*

**`OQ-ARCH-02` — commit `package-lock.json`?**
Per C5, `.gitignore:3` and §28 are incompatible.
*Recommendation:* remove the ignore and commit the lockfile. A build system in
the supply chain that is not pinned is worse than no pinning policy, because it
claims a control it does not have — the same reasoning `tools/csp.test.mjs`
records for replacing the published CSP nonce with a hash.

**`OQ-ARCH-07` — does `js/` get a deprecation period?**
§36 permits temporary adapters. A period where both trees exist makes each
phase independently revertable, at the cost of two copies of the truth and a
real chance of an edit landing in the wrong one.
*Recommendation:* no parallel tree. Convert in place, one responsibility per
commit, `js/` shrinking as `src/` grows, suite green at every commit. The
`v0.5.0` tag is the rollback and is a better one than a stale duplicate.

### Non-blocking

**`OQ-ARCH-03` — browser compatibility target?**
§27 requires it be explicit and documented; nothing states it today. The code
already uses `async`/`await`, `AbortController`, `BigInt`, optional chaining
and `Intl.PluralRules`, so the de facto floor is ~ES2020.
*Recommendation:* `target: ['es2020']`, last two versions of Chrome, Firefox,
Safari, Edge, no polyfills.

**`OQ-ARCH-04` — ship source maps to production?**
A map keeps some of the audit-by-reading property the current unbundled
deployment has for free; it also publishes `src/` to Pages in a second form.
*Recommendation:* yes, and add `dist/*.map` to the allowlist. The threat model
has no confidentiality interest in source that is already public.

**`OQ-ARCH-05` — one bundle, or split the generated data out?**
§25 says one bundle unless a measurement justifies otherwise. The measurement:
`public-suffixes.js` + `dkim-selectors.js` are **183,394 raw / 50,166 gzip** and
change only when `npm run update:psl` or `update:dkim-selectors` runs — roughly
monthly, independently of application code. Bundled, a returning visitor
re-downloads 50 KB gzip of unchanged tables every release. `locales-en.js` is
**not** a candidate: the localization contract regenerates it every release.
*Recommendation:* one bundle for 0.6.0 as §25 directs; let CI size reporting
accumulate real numbers; decide the split later with data.

**`OQ-ARCH-06` — is losing `file://` acceptable?**
`type="module"` requires HTTP. Opening `index.html` from disk works today and
will not after. `npm start` and the deployed site are unaffected.
*Recommendation:* accept and document. The alternative — an IIFE-format bundle
— keeps `file://` working but reintroduces a global namespace at the one
boundary this refactor exists to remove.

**`OQ-ARCH-08` — should `npm run locale:gate` join CI?**
[`.github/workflows/ci.yml`](.github/workflows/ci.yml) runs `npm test`, which
invokes `check-locales.mjs` **non-strict**. The strict gate `AGENTS.md` requires
before every PR is enforced by convention only. §39 asks CI to verify
"localization validation".
*Recommendation:* add it — one line, closing a gap between the stated contract
and the enforced one. But it is a policy change beyond the refactor's scope and
needs an explicit yes.

---

## Part 3 — Scheduling

The refactor was placed at **0.6.0**, displacing three feature specs by one
release number each: `findings-and-remediation` → 0.7.0,
`local-artifact-validation` → 0.8.0, `report-comparison` → 0.9.0. Spec
filenames, `OQ-*` identifiers and dependency structure are unchanged, per the
naming rule in `docs/specs/README.md`.

**The constraint worth challenging:** the refactor is a serialization point. It
renames every source file, and
[`docs/async-development-handoff.md`](docs/async-development-handoff.md)
schedules `local-artifact-validation` as a *parallel* track. Either that track
merges before Phase 3½ starts, or it rebases onto `src/` afterwards. Landing
them concurrently means resolving a rename of the entire source tree by hand.

> **Verdict requested.** Is 0.6.0 the right slot given that cost? A defensible
> alternative is to let the parallel track finish first and refactor at 0.7.0,
> trading a later refactor against a cheaper merge.

---

## Part 4 — Specific objections invited

Beyond the open questions, four areas where an objection would be most valuable:

1. **Phase 3 extraction order** — CAA → MX → transport → DNSSEC → DMARC → DKIM
   → SPF, simplest first. Is DNSSEC correctly placed before DMARC given that
   0.5.0 is the newest code and its coupling is least understood?
2. **`src/core/dns/` emits no locale token**, enforced by a grep asserting no
   string in that directory is a key in `locales/en.json`. Is that test
   sufficient to hold the transport-does-not-judge boundary, or does it have
   obvious false negatives?
3. **The assertion count as a merge gate** (2,121, may not fall). Is a count a
   meaningful coverage proxy across a restructuring that redistributes suites,
   or does it mostly create pressure to pad?
4. **`tools/csp.test.mjs` §3** currently asserts script filenames and load
   ordering. A single bundle makes those meaningless and they are replaced by
   four narrower assertions. Does anything of value get lost?

---

## What is not being asked

The spec is `0.1 (Draft)`. It is **not** asking for approval to implement, and
no code has been written — the branch contains documentation only. It is asking
for the four review outputs above so the spec can reach `1.0 (Final)`, which
`docs/specs/README.md` requires before implementation begins.

Reviewer output is recorded in this file as a dated section below, and each
resolution moves to the spec's **Resolved questions** with the spec version that
resolved it. Declined findings get a one-line reason, per the same rule the
pull-request process uses.
