# Modular Architecture and Production Build Refactor — Implementation

**Spec:** [`docs/specs/modular-architecture-and-production-build.md`](docs/specs/modular-architecture-and-production-build.md)
**Target release:** 0.6.0
**Baseline:** `v0.5.0` — 2,121 assertions, 13/13 locales, 719,199 bytes raw / 213,467 gzip
**Written:** 2026-08-27

This document turns the spec into an ordered work plan. The spec argues the
design; this one says what to type, in what order, and what must be true before
moving on. Where they disagree, the spec wins.

---

## 0. Before anything is written

The spec is **`1.0 (Final)`**, approved after three Codex review rounds, with
the `OQ-ARCH-01` spike run and captured. Implementation may begin.

All nine design questions are resolved. One platform measurement remains at
Gate 1:

| Item | Blocks | State |
| --- | --- | --- |
| `OQ-ARCH-01` spike | Phase 1 | **Done** — [capture](docs/specs/fixtures/esbuild-legacy-bundle-spike-0.6.0.md). Legacy IIFEs bundle to an identical 24-global surface; −40.1% raw. |
| Linux `npm ci` | Gate 1 | **Outstanding.** The spike covered darwin-arm64 only and the footprint is platform-specific. |
| Round 3 verdict | `1.0 (Final)` | **Done** — findings resolved directly in the final spec and this plan. |

**Task 0.1** — Confirm `npm ci` on Linux CI and fold the footprint into the
spike capture. This runs immediately after Tasks 1.1–1.2 create the dependency
and lockfile, and must complete before Gate 1; it does not block Gate 0.

**Task 0.2 — complete.** The `OQ-ARCH-01` spike established the following; the
checked-in capture is the evidence:

- bundled the **unmodified** IIFEs from `js/` and confirmed the artifact runs;
- ran that exact artifact under the fixture harness;
- recorded the darwin-arm64 package count, platform-package identity and
  postinstall behavior; and
- left Linux installation explicitly to Task 0.1 rather than generalizing the
  macOS result.

Fold the numbers into spec Risks R3 and `OQ-ARCH-01`. **Do not restate the
dependency graph from memory** — that is the error round 1 caught (F5).

**Task 0.3 — complete.** Spec `1.0 (Final)`, revision history and
[`docs/specs/README.md`](docs/specs/README.md) are synchronized.

**Task 0.4** — Build the equivalence corpus. The single most valuable artifact
here; everything after is measured against it. It must be **deterministic**,
which rules out `tools/backtest.mjs` (live DNS). The oracle is
[`tools/lib/doh-fixture.mjs`](tools/lib/doh-fixture.mjs).

- **0.4.a** — `tests/fixtures/equivalence/`: broad enough to reach every
  protocol module. Signed and unsigned domains; all six DNSSEC states; parked
  domains; `p=none`/`quarantine`/`reject`; SPF under, at and over the lookup
  limit; `include:` and `redirect=` chains; a circular SPF reference; with and
  without DKIM; CAA present and absent; MTA-STS, TLS-RPT and BIMI valid and
  malformed; at least one record carrying a bidirectional control, for the
  hygiene sentinels; **and the sibling-subdomain pair that exercises cache
  reuse**, so the query trace pins it.
- **0.4.b** — `tests/fixtures/equivalence/canonicalization.md` **first**, then
  `tests/build/equivalence.mjs`. The runner replays the corpus through a complete
  subject root and emits the **five surfaces** — canonical full-result JSON, DNS
  query trace, CSV bytes, canonical HTML report, canonical DOM. HTML had fallen
  out of the 0.3 gate (round 2, R2-F4). Rules are checked in **before** the
  corpus is captured, not derived from it afterwards. Excluded fields go in a
  manifest one at a time, with reasons; no wildcard classes. Freeze the instant
  and locale formatter through the platform binding. Record SHA-256 for every
  loaded HTML, CSS, locale and script input plus Node and ICU versions.
- **0.4.c** — Capture the baseline **without moving the worktree**. Version 0.1
  said `git checkout v0.5.0` and then ran a file that only exists on this
  branch:

  ```bash
  git worktree add ../dea-v050 v0.5.0
  node tests/build/equivalence.mjs --subject-root=../dea-v050 --emit \
    > tests/fixtures/equivalence/baseline-v0.5.0.json
  git worktree remove ../dea-v050
  ```

  These run in sequence. Commit the baseline; CI regenerates it from a clean
  clone and asserts it matches.

**Task 0.5** — `tests/inventory.json`: every suite and the contract areas it
covers. The coverage gate; the assertion total is a reported tripwire beside it,
not proof. The spike settled this empirically — 1,535 assertions passed against
the wrong PSL.

**Task 0.6** — Create `tests/state-algebras.json`, `tests/state-matrix.json` and
`tests/contract/state-matrix.test.mjs` from spec §12.1 **in full before corpus
capture**. Include all nine DNSSEC chain claims, computed values, thrown paths,
boolean and nullable axes, and absence-based result shapes. The contract rejects
uncovered registry members and missing suite/fixture references, compares later
module state constants to the registry, and runs targeted legacy contracts. It
must not claim a static string scan exhausts JavaScript behavior.

**Task 0.7** — Add the three generated-data identity profiles from spec §11:
the divergent `foo.blogspot.com` PSL result, fixture-only DKIM selector
`fixtureselector999`, and fixture English `doc.title`. Each affected suite runs
the probes for the bindings it supplies before any other assertion.

> **Gate 0.** Spec `1.0 (Final)`. Spike numbers recorded. Full §12.1 state
> registry/matrix and all three identity profiles exist. Corpus, five-surface
> runner and committed baseline reproduce from a clean clone. **No file under
> `js/` has been edited.**

---

## The rule every phase below obeys

```text
suite green
    ↓
extract exactly one responsibility
    ↓
suite green, contract inventory intact
    ↓
five-surface equivalence clean, through the bundle
    ↓
commit
```

**One responsibility per commit.** Not one file — one responsibility. A commit
that moves SPF parsing *and* renames its tokens is two commits that were not
separated.

**Never in the same commit as a move:** a protocol semantics change, a result
schema change, a scoring change, a concurrency change, a cache-scope change, or
a UI behavior change. Spec §35, and it is the difference between a revertable
refactor and an unrevertable one.

**The browser must work at every commit.** This is what round 1's F1 broke in
the previous plan. From Phase 1 onward there is exactly one delivery boundary —
`dist/app.min.js` — and every commit either leaves it working or is not a
commit.

---

## Phase 1 — Build first, on the unmodified source

*Reversed from the previous plan, per round 1 F1. The build lands before
anything moves, so every later commit is checked against the artifact the
browser actually receives.*

esbuild bundles the existing classic scripts unchanged: an entry file that
imports the seven current files for side effects, in their existing
`index.html` order, still assigning to `window` exactly as today.

**Task 1.1** — `npm install --save-exact --save-dev esbuild`. Exact pin. First
dependency in the project's history.

**Task 1.2** — Remove `package-lock.json` from [`.gitignore:3`](.gitignore) and
commit the lockfile.

**Task 1.3** — `src/entry-legacy.js`: seven side-effect imports in load order.
No code moves. This file is temporary and is deleted in Phase 6.

**Task 1.4** — `tools/build-bundle.mjs`, config per spec Design §6 —
`format: 'iife'`, **no `globalName`**, `metafile: true`, linked external source
map, `target: 'es2020'`, and explicit `banner.js`. `globalName` is forbidden in
the legacy phase: the spike proved the IIFEs create their own 24 globals, while
an early `globalName: 'DnsAudit'` overwrites the real object. **Not
`legalComments`**: no file under `js/` carries an
`@license`, `@preserve`, `/*!` or `//!` comment, so it would preserve nothing
(round 1, F7).

**Task 1.5** — `package.json`: `build:bundle`, and `build` becomes
bundle-then-assemble. Confirm `dependencies` is absent or empty.

**Task 1.6** — `index.html`: seven tags → one. **This is the commit where the
delivery boundary moves**, and the five-surface equivalence must be clean
through it before anything else proceeds.

**Task 1.7** — [`tools/build-site.mjs`](tools/build-site.mjs): allowlist `js` →
`dist`, plus source maps.

**Task 1.8** — Amend [`tools/csp.test.mjs`](tools/csp.test.mjs) §3: exactly one
`<script src>`, it is `dist/app.min.js`, same-origin. **Preserve every §1 policy
assertion byte-for-byte.** Retarget the markup-sink scan to cover the source
tree *and* `dist/app.min.js`.

> **The named-file allowlist stays empty — that is the property being
> protected.** Co-location (`OQ-ARCH-09`) puts `*.test.js` under `src/`, so the
> scan later needs an exclusion, and the file's own comment warns that *"an empty
> allowlist has no judgment calls in it."* The exclusion must be a **mechanical
> filename-suffix rule**, never a list of specific files, and the artifact scan
> of `dist/app.min.js` must land in the same commit — it is what proves the
> property on the code that actually ships. Round 2 accepted this mitigation;
> `metafile.inputs`, source-map `sources`, the artifact scan and `_site/`
> absence are the binding proof. The sentinel is defense in depth only.

**Task 1.9** — `tests/build/parity.test.mjs`. Loads the real
`dist/app.min.js` and runs the corpus against it. Install and restore DOM,
`fetch`, crypto and generated-data inputs around a cache-busted load. **A
test-only bundle proves nothing about the shipped artifact and is not an
acceptable substitute** (round 1, F3).

**Task 1.10** — `tests/build/artifact.test.mjs`: the exact top-level allowlist,
every `<script src>`/`<link href>`/source-map link resolving inside `_site/`,
bundle non-empty, no test sentinel, and the absence list — `src/`, `tools/`,
`tests/`, `docs/`, `node_modules/`, `package.json`, `AGENTS.md`, `*.test.*`,
`locales/translation-status.json`, `assets/`.

**Task 1.11** — Size reporting from the metafile: raw, gzip, per-input
composition. Reported, never enforced. Source map excluded from the transfer
figure.

**Task 1.12** — CI: `npm ci`, `npm test`, `npm run build`, then upload. Add
`npm run locale:gate` (`OQ-ARCH-08`, answered yes). Every action stays
SHA-pinned.

> **Gate 1.** The site is served from one built artifact and behaves
> identically. Parity, artifact and five-surface equivalence all green. Zero
> runtime dependencies. **No application code has moved yet.**

---

## Phase 2 — ES modules, behind the bundle

*Every commit here is validated against a delivery boundary that already exists.
That is the whole reason this phase is second.*

Where a converted ESM module must still serve a classic consumer, add a small
adapter that re-exposes the existing global **from the single ESM source**.
One source of truth per responsibility — this is not a parallel tree
(`OQ-ARCH-07`). Mark every adapter with a grep-able sentinel.

**Task 2.1** — Generated data → `src/data/*.js` as ESM. Update
`tools/update-psl.mjs`, `tools/update-dkim-selectors.mjs` and
`tools/build-fallback.mjs` to emit modules; update
[`tools/check-locales.mjs`](tools/check-locales.mjs) **in the same commit** as
the fallback generator.

> **The PSL injection hazard.** [`tools/scoring.test.mjs:21`](tools/scoring.test.mjs)
> injects a four-rule `__PUBLIC_SUFFIX_RULES__` table. A static import would
> silently substitute the real 165 KB list and **the suite would still report
> 1,535 passing assertions while testing something else** (round 1, F3).
> Generated data must reach modules through an injectable binding at the
> composition root, and a contract test must assert the fixture table is the one
> in force.

**Task 2.2** — `js/i18n.js` → `src/i18n/index.js`; `js/render.js` →
`src/ui/render.js`. English and platform are constructor arguments, never data
imports. Adapters keep `js/app.js` working.

**Task 2.3** — `js/dns.js` → ESM. Wrapper only; **no code moves between files in
this commit.** 5,704 lines changing their wrapper is reviewable; 5,704 lines
changing wrapper and home is not. Watch: top-level `this` is `undefined`; `var`
no longer creates a global.

**Task 2.4** — Add `src/platform/browser.js` with the exact primitive set in
spec §11. No other source module reads browser globals directly. Production
`now()` and `formatDateTime()` preserve `new Date().toLocaleString(locale)`;
fixtures freeze them.

**Task 2.5** — Add side-effect-free `src/runtime.js` and
`createAuditRuntime()`. It constructs a new cache, resolver and i18n instance
per call, then returns `{ analyzeDomain, checkConnectivity, mount }`. Importing
the module performs no network or DOM work. Prove cache reuse within one runtime
and isolation between two runtimes.

**Task 2.6** — `js/app.js` → `src/main.js`. It imports the three generated
modules and browser platform, constructs one runtime, calls `mount()`, and
exports named `analyzeDomain` and `checkConnectivity`. Retire
`src/entry-legacy.js`.

**Task 2.7** — Check in `src/facade.expected.json`, assert the two named exports
on source and bundle, then enable `globalName: 'DnsAudit'` and remove the legacy
`window.DnsAudit` assignment **in the same commit**. The namespace-source
contract must be green before this commit lands.

**Task 2.8** — Remove the 14 unsupported `js/app.js` function globals and the
remaining unsupported `DnsAudit` members as the one authorized compatibility
delta. Land it as one commit and one equivalence-manifest entry, and record the
decision in the review log. Include the compatibility note when the changelog
and PR description are written once from the finished branch; do not describe
absence of repository consumers as proof of no external consumer.

**Task 2.9 — PARTIALLY COMPLETE as of Task 2.3 (2026-08-27).** Not to be
redone. Converting `js/dns.js` to an ES module forced its consumers off
`node:vm` in the same commit, because a sandbox cannot evaluate a module.
Already migrated: **interpolate**, **export**, **render** (via
`tools/lib/browser-harness.mjs`, which now constructs the ESM layers and
injects the generated data), **scoring** (builds the engine directly, keeping a
holder object so all 69 `sandbox.fetch` swaps work unchanged), and
`tests/contract/legacy-shapes.test.mjs`. What remains of this task is the
`js/app.js` half, which Task 2.6 carries.

Original text — Migrate the suites off `node:vm` where a plain `import`
suffices, smallest first: interpolate (17) → export (199) → render (329) → scoring
(1,535). One suite per commit, each naming its inventory entries.
`tools/lib/browser-harness.mjs` keeps the DOM shim and loses
`vm.runInContext`; **rewrite its header comment**, which currently describes the
IIFE design as fact.

**Task 2.10 — COMPLETE as of Task 2.3 (2026-08-27).** Not to be redone.
`tools/backtest.mjs` builds the engine directly with the production tables and
the real `fetch`. It keeps its live-DNS grade-distribution job and did **not**
become the equivalence oracle.

> **Gate 2.** All source is ESM. Adapter sentinels counted and shrinking. Test layout follows the
> settled `OQ-ARCH-09` hybrid. Five-surface equivalence clean through the
> bundle.

---

## Phase 3 — DNS transport

**Task 3.1** — `src/core/dns/doh.js`: request, `AbortController`, timeout,
retry — around [`js/dns.js:177-220`](js/dns.js).

**Task 3.2** — `src/core/dns/cache.js`: the LRU from
[`js/dns.js:70-88`](js/dns.js), **behavior unchanged**. Same key format, same
eviction, same rule that only `success`/`nodata`/`nxdomain` are cached and a
transport failure never is. Export a factory. `createAuditRuntime()` invokes it
once per runtime; `src/main.js` creates one runtime for the page.

> **Do not scope this per audit.** [`tools/scoring.test.mjs:1888-1891`](tools/scoring.test.mjs)
> asserts a first DMARC walk issues 3 queries and a sibling issues 1, and
> [`PRIVACY.md:30-33`](PRIVACY.md) publishes the resulting fan-out — "roughly 41
> queries for a typical domain", 61 for `cloudflare.com`. Narrowing the cache
> changes a published privacy figure (round 1, F4). The runtime lifetime
> preserves reuse without using Node's ESM cache as dependency injection.

**Task 3.3** — `src/core/dns/errors.js`: `DnsTypeError` and
`dnsError(kind, name, type, detail)`. `DnsTypeError` and `AbortError` remain
thrown paths, never transport kinds.

**Task 3.4** — `src/core/dns/resolver.js`: `requireUsable()`, `dohQuery()` and
`dohAll()`. Preserve the boundary: usable raw results pass, seven kinds throw,
and normalized APIs return cleaned string arrays with no kind.

**Task 3.5** — `src/core/dns/optional.js`: `optionalCheck()` catches to the
caller's declared unknown result and rethrows `AbortError` and `DnsTypeError`.
`src/core/dns/existence.js` owns `yes` / `no` / `unknown` mapping.

**Task 3.6** — Name and test the direct-kind exception edges. Connectivity and
name existence may read raw kinds; DNSSEC receives the raw resolver handle so
its `servfail` security path remains possible. No normalized API may flatten
those paths.

**Task 3.7** — `tests/contract/`: the ten-kind raw algebra; cacheable and
retry-terminal sets; seven usability throws; normalized arrays; optional-check
rethrow set; named exception edges; no resolver result carrying a finding,
severity, score or locale reference; and import-graph direction. The locale-key
grep from the old plan remains withdrawn as vacuous.

> **Gate 3.** Result-algebra and direction contracts pass. Query trace
> unchanged. Sibling-reuse assertion still green.

---

## Phase 4 — Protocol extraction

Simplest first, so the pattern is proven on a module small enough to hold in
one head before it meets a hard one.

**Task 4.0** — Establish `core/shared/` before the owner extractions. Move only
pure helpers used by two or more protocol owners, keep the directory
import-free, and reject convenience dumping. If no helper meets that test,
omit the directory and update the target tree and edge table in the same
commit; review protocol-local duplication explicitly rather than hiding it
behind a false abstraction.

| # | Module | Extract | Notes |
| --- | --- | --- | --- |
| 4.1 | `core/caa/` | `checkCAA` | Smallest. Proves the pattern. |
| 4.2 | `core/mx/` | MX health, host resolution | |
| 4.3 | `core/bimi/` | `validateBimiRecord` | **Its own directory.** Brand-indicator validation is not mail transport security; the previous plan filed it under `core/transport/` and the spec tree omitted it (round 1). |
| 4.4 | `core/transport/` | `validateMtaStsRecord`, `validateTlsRptRecord`, TLSA | |
| 4.5 | `core/dnssec/` | Chain evaluation, DS↔DNSKEY matching | Newest code; 0.5.0 is its baseline. |
| 4.6 | `core/dmarc/` | Parse, tree walk, org domain, `DMARC_TAGS_RFC9989` | Imports the PSL. Tree-walk coupling. |
| 4.7 | `core/dkim/` | Discovery, catalog, key decode | `DKIM_SCAN_BATCH_SIZE = 24` moves **unchanged**. |
| 4.8 | `core/spf/` | Parse, recursive evaluate, lookup accounting, subnets, redundancy | Hardest, most resolver-coupled. Last. |

Each: extract → check in that directory's `API.md` from spec §12 → add/update
its state constants and matrix rows → its tests → full suite → five-surface
equivalence → commit. The Gate-0 inventory is refined into module constants,
not completed for the first time here. Eight commits minimum.

**Task 4.9** — `providers/detectors.js`.

> **Gate 4.** Every protocol has an owning directory. **Token vocabulary
> byte-identical** — diff issue tokens against `v0.5.0` explicitly.

---

## Phase 5 — Audit coordination and UI

**Task 5.1** — `src/audit/context.js`: options in force, accumulated result,
cancellation. **Not the DoH cache** — see Task 3.2.

**Task 5.2** — `src/audit/audit-domain.js`. Preserve the existing `Promise.all`
structure exactly. **No concurrency change in this release.**

**Task 5.3** — `src/audit/scoring.js`: `calcScore`, `calcDmarcScore`,
`calcSpfScore`, `gradeFor`, `WEIGHTS`, `PARKED_WEIGHTS`, `GRADE_THRESHOLDS`,
`POLICY_RANK`. Assert byte-identical to `v0.5.0`.

**Task 5.4** — `src/audit/issues.js`: `buildIssues`, `buildSuggestions`.

**Task 5.5** — `src/ui/report.js`: `exportCSV`
([`js/app.js:1560`](src/main.js)), `exportHTML`
([`js/app.js:1634`](src/main.js)). The report's own
`default-src 'none'; style-src 'unsafe-inline'; img-src data:` policy is
asserted by `csp.test.mjs` §5 and must survive.

**Task 5.6** — `src/ui/events.js`: DOM wiring. `src/main.js` reduces to
composition.

Every Phase-5 owner receives or updates its `API.md` in the same commit as its
public exports. UI event wiring receives facade callbacks; it never imports
`audit/`.

> **Gate 5.** Weights byte-identical. Coordinator holds no parsing rule. No
> protocol interpretation under `src/ui/`. Markup-sink allowlist still empty.

---

## Phase 6 — Cleanup, documentation, release

**Task 6.1** — Delete `js/` and `src/entry-legacy.js`.

**Task 6.2** — Remove every adapter; assert zero sentinels remain.

**Task 6.3** — `AGENTS.md`: the module-ownership table. Acceptance criterion,
not a nicety — §32's argument is that a DMARC task should be boundable to
`src/core/dmarc/`. Write the table that makes it true.

**Task 6.4** — `CONTRIBUTING.md`: `npm ci`, `npm test`, `npm run build`,
`npm start`; the test layout; and the `file://` status per `OQ-ARCH-06`.

**Task 6.5** — `README.md`: build commands, the source/artifact distinction, and
the assertion count **read out of a real `npm test` run**.

**Task 6.6** — `PRIVACY.md`: confirm in writing that no edit is needed, citing
the query-trace surface rather than assuming it.

**Task 6.7** — Move the spec to `docs/specs/implemented/` by the five-step
procedure in `AGENTS.md`: `git mv`, re-depth every link, fix inbound references
repo-wide, link-check every markdown file, add **As implemented**, convert Open
questions to **Resolved questions**, bump to `1.0 (Implemented)`, add the
Revision history row.

**Task 6.8** — `CHANGELOG.md`, in the voice of the finished thing.

**Task 6.9** — **Cut the release as its own commit, over its own file set.**
Last commit on the branch; touches **no code**:

| File | Change |
| --- | --- |
| `package.json` | version → `0.6.0` |
| `CHANGELOG.md` | `## [Unreleased]` promoted, compare links added |
| `README.md` | assertion count, build commands, behaviour statements |
| `docs/specs/implemented/modular-architecture-and-production-build.md` | status → released |
| `docs/specs/README.md` | row moves to the Implemented table |
| `ROADMAP.md` | 0.6.0 marked released |
| `docs/async-development-handoff.md` | Phase 3½ marker → RELEASED |

**If a commit touches both a file above and a file under `src/`, it is two
commits.** Over six phases the temptation to slip a CHANGELOG line in beside a
code change is constant, and a version bump buried in a commit that also moves
5,000 lines is illegible in `git log` and impossible to revert alone.

**Task 6.10** — `pr-description.md`, structured like
[PR #4](https://github.com/kwestic-tech/dns-email-audit/pull/4), with real
numbers: before/after payload, contract inventory, five-surface diff.

**Task 6.11** — Push once. Open the PR. Stop. **The merge is Ian's call.** Tag
`v0.6.0` annotated on the squashed commit after he merges.

> **Gate 6 — release.** Every box in the spec's Acceptance criteria ticked.

---

## Standing verification

Run at every phase boundary:

```bash
npm ci
npm test                      # contract inventory intact; total reported
npm run locale:gate           # 13/13
npm run build                 # dist/app.min.js + _site/
node tests/build/equivalence.mjs --subject-root=. --entry=src
node tests/build/equivalence.mjs --subject-root=_site
```

**Order matters for the last four and only those four.** Both equivalence runs
compare against the committed `baseline-v0.5.0.json`, and the `dist` run reads
what `npm run build` just produced, so the build must precede it. `npm ci`
precedes everything once Phase 1 has landed. The locale gate is
order-independent with respect to the rest.

Locally, additionally:

```bash
node tools/backtest.mjs --sample
```

Live DNS. Read it for a *distribution* shift and nothing finer. Never a gate.

**Any equivalence diff on any of the five surfaces is a stop.** Not a note in
the PR description — a stop, until it is explained or reverted. A query-trace
diff with an identical result is still a stop: it means cache or concurrency
behavior moved, and that is a published privacy figure.

## What this plan deliberately does not do

Each of these is a thing the architecture makes possible and the release does
not spend. Spec §46: *"None of these capabilities should be implemented merely
because the refactor makes them possible."*

- **No concurrency change.** The coordinator makes it possible; measure first.
- **No request deduplication beyond today's cache.**
- **No change to existing audit cancellation behavior.** `AbortController`,
  the UI cancel path and the `optionalCheck()` rethrow rule all remain.
- **No Web Worker.**
- **No finding-schema redesign.** Explicitly declined in the spec.
- **No bundle splitting.** `OQ-ARCH-05` carries the measurement for later.
- **No resolver comparison.** That is
  [external-intelligence](docs/specs/external-intelligence.md).
- **No protocol fixes found in passing** — filed separately, noted in the
  phase's commit message.

---

## Risk index

Spec risks, mapped to where they are actually mitigated.

| Risk | Where |
| --- | --- |
| R1 silent behavior change | Every gate: five-surface equivalence, through the bundle |
| R2 bundle ≠ tested source | Task 1.9, and the boundary existing from Phase 1 |
| R3 supply chain | Tasks 0.2, 1.1, 1.2 — spike numbers, not recollection |
| R4 ESM strict-mode semantics | Tasks 2.3–2.7 — one responsibility per commit, behind a working bundle |
| R5 harness rewrite loses coverage | Tasks 0.5–0.6 inventory/state matrix; count reported, not gating |
| R6 fixture harness silently stops testing | Tasks 0.7 and 2.1 — independent PSL/catalog/English fingerprints |
| R7 deploy publishes too much | Task 1.10 exact allowlist, presence and absence |
| R8 scope creep | "What this plan deliberately does not do" |
| R9 cold-start regression | Task 1.11 metafile reporting, `OQ-ARCH-05` |
| R10 cache-scope drift | Tasks 2.5 and 3.2 — within-runtime reuse, cross-runtime isolation, query trace |
| R11 canonicalization hides change | Task 0.4.b — strict rules, full subject roots, fixed time/locale and input hashes |

---

## Round 1 changes to this plan

Recorded so the reversal is not re-litigated. All from
[`CODEX follow-up review for Modular Refactor.md`](CODEX%20follow-up%20review%20for%20Modular%20Refactor.md),
verified against the code before folding in.

| Was | Now | Why |
| --- | --- | --- |
| Phase 0 = ESM, Phase 1 = build | Phase 1 = build, Phase 2 = ESM | The old Phase 0 could not keep the browser working between its own commits — Gate 0.C claimed seven scripts still loaded while the interim note required a `src/main.js` that did not exist for another commit (F1) |
| Baseline via `git checkout v0.5.0` | `git worktree add` | The checkout deleted the runner the next command invoked (F2) |
| Equivalence = score, grade, tokens | Five surfaces | The old oracle could not see MX detail, DNSSEC evidence, provider detection, exports, rendering or query fan-out; round 2 restored HTML export as the fifth surface |
| Cache instantiated per audit | One cache per runtime, one production runtime per page | `scoring.test.mjs:1891` asserts sibling reuse; `PRIVACY.md` publishes the fan-out; tests need isolated runtimes |
| Transport proven by locale-key grep | Result algebra + import direction | `en.json` is nested; tokens are values, not keys — the grep was vacuous (F6) |
| Assertion count ≥ 2,121 as gate | Contract inventory as gate, count as tripwire | A count holds level while a real assertion is swapped for an unrelated one (F8) |
| BIMI under `core/transport/` | `core/bimi/` | Brand-indicator validation is not mail transport security; plan and spec disagreed |
| `legalComments: 'inline'` | Explicit `banner.js` | No file under `js/` has an `@license`, `@preserve`, `/*!` or `//!` comment (F7) |
