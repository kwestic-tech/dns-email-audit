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

---

# Round 1 response — 2026-08-27

**Reviewed:** [`CODEX follow-up review for Modular Refactor.md`](CODEX%20follow-up%20review%20for%20Modular%20Refactor.md), disposition *Changes requested before the spec reaches 1.0*
**Spec:** `0.1 (Draft)` → **`0.2 (Draft)`**
**Response:** **All eight findings verified and accepted. No finding declined.**
**Two items returned:** `OQ-ARCH-06` (bundle output format) and `OQ-ARCH-09` (test co-location)

## How the findings were checked

Every finding was reproduced against the tree before being folded in, per the
verify-before-folding rule in [`AGENTS.md`](AGENTS.md). This project's history
includes a reviewer citing functions that do not exist, so the check was for
that specifically. **Nothing of the kind was found — eleven of eleven claims
held**, including the three that contradicted this spec's own text.

| Finding | How it was verified | Result |
| --- | --- | --- |
| F1 | Read the plan's Gate 0.C against its own interim note | Direct self-contradiction, confirmed |
| F2 (recipe) | Task 0.4.c checks out `v0.5.0`, then runs a file that exists only on this branch | Confirmed |
| F2 (scope) | Compared the oracle's projection against the Non-goals text | Confirmed — "explanations" was promised and unobserved |
| F3 | `grep __PUBLIC_SUFFIX_RULES__` → [`tools/scoring.test.mjs:21`](tools/scoring.test.mjs) injects `['com','co.uk','*.ck','!www.ck']` | Confirmed, and sharper than stated |
| F4 | [`tools/scoring.test.mjs:1888-1891`](tools/scoring.test.mjs) asserts 3 queries then 1; [`js/app.js:1397`](js/app.js) passes no context; [`PRIVACY.md:30-33`](PRIVACY.md) publishes 41 and 61 | Confirmed |
| F5 | `npm view esbuild version scripts optionalDependencies` → 0.28.2, `postinstall: node install.js`, 26 `@esbuild/*` | Confirmed empirically |
| F6 | `head locales/en.json` (nested); `grep -c 'issue.spf-large-subnet.msg'` → 0 | Confirmed |
| F7.1 | `grep -c '@license\|@preserve\|/\*!\|//!\|MIT'` across all four hand-written files → 0 on every pattern | Confirmed |
| F7.2 | Spec line 90 said 17, line 448 said 329 | Confirmed, self-contradiction |
| F7.3 | Read against this release's own no-`en.json`-edit promise | Confirmed |
| BIMI | Spec tree omits BIMI; plan Task 3.3 filed it under `core/transport/` | Confirmed, both wrong |

**F5 is the one worth naming.** "Zero transitive dependencies" was asserted
twice and carried the entire `OQ-ARCH-01` recommendation. It was recall where
verification cost one command. The standing rule adopted from it: **no
external-tooling claim enters either document without a command behind it.**
Task 0.2 of the plan now requires the spike's numbers rather than a restatement.

## Disposition of each finding

| # | Disposition | Where it landed in `0.2` |
| --- | --- | --- |
| F1 | **Accepted; phases reversed** | Scope; plan Phase 1 (build) now precedes Phase 2 (ESM), with adapters and a stable boundary from the first commit |
| F2 | **Accepted** | Design §8 — four surfaces; `git worktree` baseline capture; plan Tasks 0.4.a–c |
| F3 | **Accepted** | Design §6 and Testing item 4; plan Task 1.9 and the Task 2.1 hazard note; Risks R6 |
| F4 | **Accepted; per-audit scoping withdrawn** | Corrections item 3, Design §5, plan Task 3.2, Risks R10, acceptance criterion |
| F5 | **Accepted** | Design §6, Risks R3, `OQ-ARCH-01`; plan Task 0.2 |
| F6 | **Accepted; grep withdrawn** | Design §3 — closed result algebra plus import-graph direction; plan Task 3.5 |
| F7 | **Accepted, all three** | Design §6 (`banner.js`), Localization impact (17), `OQ-ARCH-05` |
| F8 | **Accepted** | Testing item 1 — `tests/inventory.json` is the gate, count is a reported tripwire; plan Task 0.5 |

The eight required changes in §6 of the review are all applied. Verdicts on
C1–C8 and on the eight original open questions are recorded in the spec's
Revision history and Resolved-questions table; none is disputed.

## Returned item 1 — `OQ-ARCH-06`: the bundle should be IIFE, not ESM

**This reverses an answer round 1 already gave**, which is why it is returned
rather than decided.

Round 1 answered the question `0.1` asked — *"is losing `file://` acceptable"* —
with *"loss accepted and documented"*. That answer is correct for the question.
But the question only exists because `0.1` specified `format: 'esm'`, and that
choice was aesthetic: symmetry with ESM source. It is not a requirement, and
following round 1's own reordering exposes it as the cause of three separate
problems.

**Proposal: ESM source, IIFE output.** `format: 'iife'`,
`globalName: 'DnsAudit'`, `<script src="dist/app.min.js">` with no
`type="module"`. The ordinary library-bundle pattern.

1. **`file://` never breaks.** The loss round 1 accepted is avoidable rather
   than inherent. `OQ-ARCH-06` stops needing an answer instead of getting one.
2. **It resolves F3.** Round 1's objection was that a browser entry does not
   normally re-export what a test needs and tree shaking may remove
   test-only APIs — so *"load the bundle and re-run the fixtures"* had no stated
   access path. `globalName` gives the artifact exactly the surface the existing
   `node:vm` harness already reaches through `window.DnsAudit`. The parity test
   loads `dist/app.min.js` where it loads `js/dns.js` today and changes little
   else. This is the first of the two honest choices round 1 offered — a
   deliberately exported audit API — but obtained from the bundler rather than
   hand-designed, so there is no second API surface to keep correct.
3. **The CSP story keeps its shape.** `csp.test.mjs` keeps asserting one
   same-origin `<script src>`; no module semantics enter the policy.

**The cost, stated plainly:** one bundler-generated global at the delivery
boundary. Modules inside the bundle still communicate by `import`, so invariant
8 and the no-shared-namespace goal hold. The global is the same shape as
today's `window.DnsAudit`, so it is not a new concept in this codebase.

> **Verdict requested.** Does IIFE output undermine anything round 1 was
> protecting? The specific worry worth testing: does keeping a global at the
> boundary make it easier for a later change to reintroduce cross-module global
> coupling, and is the import-graph contract test enough to prevent that?

## Returned item 2 — `OQ-ARCH-09`: unit tests beside the code — **DECIDED**

> **Resolved by Ian, 2026-08-27: the hybrid is approved.** The layout is
> settled and is not a question for round 2. What remains for review is cost 1's
> mitigation, at the end of this section — it weakens a security control, which
> is a different kind of question from a layout preference.

**Proposal: hybrid.** Unit tests co-located as `src/**/*.test.js`; a top-level
`tests/` for what no single module owns — `build/` (parity, artifact, size,
CSP), `fixtures/equivalence/`, `contract/`, `integration/`.

**The argument is §32's own.** The source proposal says a task like "correct
DMARC organizational-domain discovery" should primarily affect
`src/core/dmarc/` — then names a second directory, `tests/dmarc/`, that the same
task must also touch. Co-location makes the claim true rather than nearly true.
Go, Rust and most Jest/Vitest projects work this way.

**Three costs, and how each is paid:**

1. **The markup-sink scan's empty allowlist.**
   [`tools/csp.test.mjs`](tools/csp.test.mjs) scans every `.js` under `js/`, and
   its own comment states the property that makes it trustworthy: *"The
   allowlist is EMPTY. That is what makes this check reliable: an empty
   allowlist has no judgment calls in it."* Test files under `src/` need
   excluding, and an exclusion is a judgment call — the exact erosion that
   comment warns against.
   *Paid by:* a mechanical filename-suffix rule (`*.test.js`), which contains no
   per-file judgment, plus a scan of the built artifact — which proves the
   property on what actually ships. The named-file allowlist stays empty.
2. **Test code reaching the bundle.** esbuild includes only what the entry
   transitively imports, so an unreferenced `*.test.js` is never bundled — but
   "should not happen" is not a test.
   *Paid by:* the artifact test asserting a per-test-file sentinel appears
   nowhere in `dist/app.min.js`, plus metafile composition reporting.
3. **Discovery and the assertion inventory.** Six explicit
   `node tools/X.test.mjs` invocations become a glob.
   *Paid by:* a small `tools/run-tests.mjs` that globs both trees and sums the
   printed counts. The hand-rolled assertion style and the totals survive;
   only discovery changes. **Migrating to `node:test` is explicitly out of
   scope** — that is a schema change wearing a tooling costume, and §35 forbids
   it in a move.

> **Verdict requested — on the mitigation, not the layout.** Two things.
> Is a mechanical filename-suffix exclusion materially different from the
> per-file allowlist `csp.test.mjs` warns against, or is that a distinction
> without a difference? And does co-location interact badly with the deployment
> allowlist in a way the artifact test would not catch? A "no" to the first
> does not reopen the layout — it changes how the scan is written.

## What round 2 should look at

Round 1 proposed the next round cover module API shapes, import-graph cycle
risk, and per-protocol failure-state algebra. Agreed, with two additions from
this round:

1. **The composition root.** F3's PSL hazard means generated data must reach
   modules through an injectable binding rather than a static import. Where that
   binding lives, and how a contract test proves the fixture table is the one in
   force during a suite, is unspecified and load-bearing.
2. **The four-surface canonicalization rules.** Which fields of the full
   `analyzeDomain()` result are legitimately nondeterministic, and how the DOM
   and HTML report are canonicalized without canonicalizing away the differences
   the surface exists to catch.

---

# Round 2 request — 2026-08-27

**Spec:** `docs/specs/modular-architecture-and-production-build.md`, **`0.3 (Draft)`**
**Plan:** `Modular Architecture, Production Build Refactor Implementation.md`
**Branch:** `spec/modular-architecture-production-build`
**Round 1:** all eight findings verified and accepted; disposition table above
**Still true:** no code written. The branch is documentation only.

## State of the eight open questions

| ID | Status | Answer |
| --- | --- | --- |
| `OQ-ARCH-01` | Resolved, round 1 | esbuild, conditional on the spike |
| `OQ-ARCH-02` | Resolved, round 1 | Commit the lockfile |
| `OQ-ARCH-03` | Resolved, round 1 | `es2020` syntax + a separate required-API matrix |
| `OQ-ARCH-04` | Resolved, round 1 | Ship linked external source maps |
| `OQ-ARCH-05` | Resolved, round 1 | One bundle for 0.6.0 |
| `OQ-ARCH-06` | **OPEN** | Proposed: IIFE output. Reverses a round-1 answer. |
| `OQ-ARCH-07` | Resolved, round 1 | No duplicate tree; marked adapters |
| `OQ-ARCH-08` | Resolved, round 1 | Add the strict locale gate to CI |
| `OQ-ARCH-09` | **Decided by Ian, 2026-08-27** | Hybrid co-location. Layout not under review. |

## What round 2 is asked for

**1. `OQ-ARCH-06` — the only thing blocking implementation.**
ESM source compiled to an IIFE bundle with `globalName: 'DnsAudit'`, rather than
ESM output with `type="module"`. It keeps `file://` working, gives the parity
test a documented access path to the shipped artifact (round 1's F3), and leaves
the CSP shape unchanged. It reverses round 1's "loss accepted and documented"
answer, which is why it needs a ruling rather than a decision. Full argument in
*Returned item 1* above. The specific worry to test: does a bundler-generated
global at the delivery boundary make it easier for a later change to reintroduce
cross-module global coupling, and is the import-graph contract test enough?

**2. The markup-sink mitigation under co-location.** The layout is settled. The
question is narrower and is a security question: `tools/csp.test.mjs` derives
its trustworthiness from an empty named-file allowlist, and co-location requires
excluding `*.test.js`. Is a mechanical suffix rule plus a scan of
`dist/app.min.js` an adequate substitute for the property being given up?

**3. The two items round 1 named for this round**, both unspecified and both
load-bearing:

- **The composition root.** F3's PSL hazard means generated data must reach
  modules through an injectable binding, not a static import — otherwise
  `tools/scoring.test.mjs` swaps a four-rule fixture table for the real 165 KB
  PSL and still reports 1,535 passing assertions. Where that binding lives, and
  how a contract test proves the fixture table is the one in force during a
  suite, is not yet written down.
- **Four-surface canonicalization.** Which fields of the full `analyzeDomain()`
  result are legitimately nondeterministic, and how the DOM and HTML report are
  canonicalized without canonicalizing away the very differences the surface
  exists to catch.

**4. Round 1's own proposed agenda:** module API shapes, cycle risk in the
proposed import graph, and whether the expanded fixture corpus covers each
protocol's failure-state algebra.

## Two things worth checking hard

Both are places where this spec could be confidently wrong.

**The phase reversal may have moved a risk rather than removed it.** Building
first means `src/entry-legacy.js` bundles seven IIFEs that communicate through
`window`. esbuild will treat each as a module with side effects; the globals
still resolve at runtime because `window` is real. That reasoning has not been
executed — it is Task 0.2's spike. If it is wrong, Phase 1 does not exist in the
form described and the ordering question reopens.

**The four-surface oracle may be too strict to be usable.** Byte-identical CSV
and canonical DOM across a 5,704-line restructuring will surface differences
that are genuinely inconsequential — key ordering, whitespace, float formatting.
If the canonicalization rules end up absorbing those, they may absorb real
regressions with them. A judgment on where that line sits is more useful now
than after the corpus is built.
