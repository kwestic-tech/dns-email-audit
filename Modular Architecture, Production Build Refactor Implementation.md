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

The spec is **`0.2 (Draft)`**, revised after review round 1 and awaiting round
2. [`docs/specs/README.md`](docs/specs/README.md) requires `1.0 (Final)` before
implementation begins.

Round 1 resolved seven of the original eight open questions. Ian decided
`OQ-ARCH-09` on 2026-08-27. **One remains, and it changes the work:**

| Question | Blocks | Why it must be answered first |
| --- | --- | --- |
| `OQ-ARCH-06` | Phase 1 | `iife` vs `esm` output decides the `index.html` tag, whether `file://` survives, and how the parity test reaches the bundle. |

**Settled, and binding on every phase below:**

| Question | Answer | Decided by |
| --- | --- | --- |
| `OQ-ARCH-09` | **Hybrid.** Unit tests co-locate as `src/**/*.test.js`; `tests/` keeps build, contract, integration and fixture suites. | Ian, 2026-08-27 |

The layout is settled. Its one open consequence is the markup-sink exclusion in
Task 1.8 — a security control, not a convention — which round 2 reviews. If that
mitigation is rejected, the layout stands and the mitigation changes.

**Task 0.1** — Answer `OQ-ARCH-06`. Argued in the spec and put to the reviewer
in [`CODEX Review Modular Refactor.md`](CODEX%20Review%20Modular%20Refactor.md).

**Task 0.2** — Run the `OQ-ARCH-01` spike. Round 1 made esbuild conditional on
it, and it is research rather than refactoring, so it is permitted before Final:

- bundle the **unmodified** IIFEs from `js/` and confirm the artifact runs;
- run that exact artifact under the fixture harness;
- `npm ci` on macOS **and** Linux CI;
- record the real resolved package count, the postinstall behavior, and the
  installed binary's provenance.

Fold the numbers into spec Risks R3 and `OQ-ARCH-01`. **Do not restate the
dependency graph from memory** — that is the error round 1 caught (F5).

**Task 0.3** — Move both questions to **Resolved questions**, bump the spec to
`1.0 (Final)`, add the Revision history row, update
[`docs/specs/README.md`](docs/specs/README.md).

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
- **0.4.b** — `tests/build/equivalence.mjs`: replays the corpus through a given
  source root and emits the **four surfaces** — canonical full-result JSON, DNS
  query trace, CSV bytes, canonical DOM. Not score/grade/tokens; that was round
  1's F2. Any deliberately excluded field goes in a manifest with a reason.
- **0.4.c** — Capture the baseline **without moving the worktree**. Version 0.1
  said `git checkout v0.5.0` and then ran a file that only exists on this
  branch:

  ```bash
  git worktree add ../dea-v050 v0.5.0
  node tests/build/equivalence.mjs --source-root=../dea-v050/js --emit \
    > tests/fixtures/equivalence/baseline-v0.5.0.json
  git worktree remove ../dea-v050
  ```

  These run in sequence. Commit the baseline; CI regenerates it from a clean
  clone and asserts it matches.

**Task 0.5** — `tests/inventory.json`: every suite and the contract areas it
covers. This is the coverage gate; the assertion total is a reported tripwire
beside it, not proof (round 1, F8).

> **Gate 0.** Spec `1.0 (Final)`. Spike numbers recorded. Corpus, four-surface
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
four-surface equivalence clean, through the bundle
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
`format` per `OQ-ARCH-06`, `globalName: 'DnsAudit'`, `metafile: true`, explicit
`banner.js`. **Not `legalComments`**: no file under `js/` carries an
`@license`, `@preserve`, `/*!` or `//!` comment, so it would preserve nothing
(round 1, F7).

**Task 1.5** — `package.json`: `build:bundle`, and `build` becomes
bundle-then-assemble. Confirm `dependencies` is absent or empty.

**Task 1.6** — `index.html`: seven tags → one. **This is the commit where the
delivery boundary moves**, and the four-surface equivalence must be clean
through it before anything else proceeds.

**Task 1.7** — [`tools/build-site.mjs`](tools/build-site.mjs): allowlist `js` →
`dist`, plus source maps.

**Task 1.8** — Amend [`tools/csp.test.mjs`](tools/csp.test.mjs) §3: exactly one
`<script src>`, it is `dist/app.min.js`, same-origin. **Preserve every §1 policy
assertion byte-for-byte.** Retarget the markup-sink scan to cover the source
tree *and* `dist/app.min.js`.

> **The named-file allowlist stays empty — that is the property being
> protected.** Co-location (`OQ-ARCH-09`) puts `*.test.js` under `src/`, so the
> scan needs an exclusion, and the file's own comment warns that *"an empty
> allowlist has no judgment calls in it."* The exclusion must be a **mechanical
> filename-suffix rule**, never a list of specific files, and the artifact scan
> of `dist/app.min.js` must land in the same commit — it is what proves the
> property on the code that actually ships. Round 2 is reviewing whether this
> mitigation is adequate; if it is not, the layout stands and this task changes.

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
> identically. Parity, artifact and four-surface equivalence all green. Zero
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
`src/ui/render.js`. Adapters keep `js/app.js` working.

**Task 2.3** — `js/dns.js` → ESM. Wrapper only; **no code moves between files in
this commit.** 5,704 lines changing their wrapper is reviewable; 5,704 lines
changing wrapper and home is not. Watch: top-level `this` is `undefined`; `var`
no longer creates a global.

**Task 2.4** — `js/app.js` → `src/main.js`, with `src/entry-legacy.js` retired
in favour of it.

**Task 2.5** — Migrate the suites off `node:vm` where a plain `import` suffices,
smallest first: interpolate (17) → export (199) → render (329) → scoring
(1,535). One suite per commit, each naming its inventory entries.
`tools/lib/browser-harness.mjs` keeps the DOM shim and loses
`vm.runInContext`; **rewrite its header comment**, which currently describes the
IIFE design as fact.

**Task 2.6** — `tools/backtest.mjs` off `vm`. It keeps its live-DNS
grade-distribution job and does **not** become the equivalence oracle.

> **Gate 2.** All source is ESM. Adapter sentinels counted and shrinking. Test layout follows the
> settled `OQ-ARCH-09` hybrid. Four-surface equivalence clean through the
> bundle.

---

## Phase 3 — DNS transport

**Task 3.1** — `src/core/dns/doh.js`: request, `AbortController`, timeout,
retry — around [`js/dns.js:177-220`](js/dns.js).

**Task 3.2** — `src/core/dns/cache.js`: the LRU from
[`js/dns.js:70-88`](js/dns.js), **behavior unchanged**. Same key format, same
eviction, same rule that only `success`/`nodata`/`nxdomain` are cached and a
transport failure never is. Export a factory, then **invoke it once at module
scope**. Page lifetime is preserved.

> **Do not scope this per audit.** [`tools/scoring.test.mjs:1888-1891`](tools/scoring.test.mjs)
> asserts a first DMARC walk issues 3 queries and a sibling issues 1, and
> [`PRIVACY.md:30-33`](PRIVACY.md) publishes the resulting fan-out — "roughly 41
> queries for a typical domain", 61 for `cloudflare.com`. Narrowing the cache
> changes a published privacy figure (round 1, F4). Moving the cache behind a
> factory is architectural; changing who owns the instance is a separate,
> separately-authorized decision.

**Task 3.3** — `src/core/dns/errors.js`: the five-way distinction from
[resilient-optional-checks](docs/specs/implemented/resilient-optional-checks.md).

**Task 3.4** — `src/core/dns/resolver.js`: normalization and response-kind
classification.

**Task 3.5** — `tests/contract/`: the **closed result algebra** — every resolver
return inhabits the enumerated kind set and carries no finding, severity, score
or locale reference — plus **import-graph direction**. The locale-key grep from
the previous plan is withdrawn as vacuous (round 1, F6): `en.json` is nested and
the tokens are values, not keys.

> **Gate 3.** Result-algebra and direction contracts pass. Query trace
> unchanged. Sibling-reuse assertion still green.

---

## Phase 4 — Protocol extraction

Simplest first, so the pattern is proven on a module small enough to hold in
one head before it meets a hard one.

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

Each: extract → its tests → full suite → four-surface equivalence → commit.
Eight commits minimum.

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
([`js/app.js:1560`](js/app.js)), `exportHTML`
([`js/app.js:1634`](js/app.js)). The report's own
`default-src 'none'; style-src 'unsafe-inline'; img-src data:` policy is
asserted by `csp.test.mjs` §5 and must survive.

**Task 5.6** — `src/ui/events.js`: DOM wiring. `src/main.js` reduces to
composition.

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
numbers: before/after payload, contract inventory, four-surface diff.

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
node tests/build/equivalence.mjs --source-root=src
node tests/build/equivalence.mjs --source-root=dist
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

**Any equivalence diff on any of the four surfaces is a stop.** Not a note in
the PR description — a stop, until it is explained or reverted. A query-trace
diff with an identical result is still a stop: it means cache or concurrency
behavior moved, and that is a published privacy figure.

## What this plan deliberately does not do

Each of these is a thing the architecture makes possible and the release does
not spend. Spec §46: *"None of these capabilities should be implemented merely
because the refactor makes them possible."*

- **No concurrency change.** The coordinator makes it possible; measure first.
- **No request deduplication beyond today's cache.**
- **No audit cancellation.**
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
| R1 silent behavior change | Every gate: four-surface equivalence, through the bundle |
| R2 bundle ≠ tested source | Task 1.9, and the boundary existing from Phase 1 |
| R3 supply chain | Tasks 0.2, 1.1, 1.2 — spike numbers, not recollection |
| R4 ESM strict-mode semantics | Tasks 2.3, 2.4 — one file per commit, behind a working bundle |
| R5 harness rewrite loses coverage | Task 0.5 inventory; count reported, not gating |
| R6 fixture harness silently stops testing | Task 2.1 — the PSL injection hazard |
| R7 deploy publishes too much | Task 1.10 exact allowlist, presence and absence |
| R8 scope creep | "What this plan deliberately does not do" |
| R9 cold-start regression | Task 1.11 metafile reporting, `OQ-ARCH-05` |
| R10 cache-scope drift | Task 3.2, plus the query-trace surface at every gate |

---

## Round 1 changes to this plan

Recorded so the reversal is not re-litigated. All from
[`CODEX follow-up review for Modular Refactor.md`](CODEX%20follow-up%20review%20for%20Modular%20Refactor.md),
verified against the code before folding in.

| Was | Now | Why |
| --- | --- | --- |
| Phase 0 = ESM, Phase 1 = build | Phase 1 = build, Phase 2 = ESM | The old Phase 0 could not keep the browser working between its own commits — Gate 0.C claimed seven scripts still loaded while the interim note required a `src/main.js` that did not exist for another commit (F1) |
| Baseline via `git checkout v0.5.0` | `git worktree add` | The checkout deleted the runner the next command invoked (F2) |
| Equivalence = score, grade, tokens | Four surfaces | The old oracle could not see MX detail, DNSSEC evidence, provider detection, exports, rendering or query fan-out (F2) |
| Cache instantiated per audit | Page lifetime preserved | `scoring.test.mjs:1891` asserts sibling reuse; `PRIVACY.md` publishes the fan-out (F4) |
| Transport proven by locale-key grep | Result algebra + import direction | `en.json` is nested; tokens are values, not keys — the grep was vacuous (F6) |
| Assertion count ≥ 2,121 as gate | Contract inventory as gate, count as tripwire | A count holds level while a real assertion is swapped for an unrelated one (F8) |
| BIMI under `core/transport/` | `core/bimi/` | Brand-indicator validation is not mail transport security; plan and spec disagreed |
| `legalComments: 'inline'` | Explicit `banner.js` | No file under `js/` has an `@license`, `@preserve`, `/*!` or `//!` comment (F7) |
