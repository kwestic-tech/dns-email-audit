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

The spec is **0.1 (Draft), awaiting review**, and
[`docs/specs/README.md`](docs/specs/README.md) requires a spec to reach
`1.0 (Final)` before implementation begins. Eight open questions are unresolved,
and **three of them change the work itself** rather than merely documenting it:

| Question | Blocks | Why it must be answered first |
| --- | --- | --- |
| `OQ-ARCH-01` | Phase 1 | If not esbuild — or no bundler at all — Phase 1 is a different phase. |
| `OQ-ARCH-02` | Phase 1 | Whether `package-lock.json` is committed decides whether `npm ci` is even possible in CI. |
| `OQ-ARCH-07` | Phase 0 | Parallel `js/` tree vs. convert-in-place changes every commit in the refactor. |

`OQ-ARCH-03` (compatibility target), `-04` (source maps), `-05` (bundle split),
`-06` (`file://`) and `-08` (locale gate in CI) can be answered during their own
phase without reordering anything.

**Task 0.1** — Circulate the spec for review. Two reviewers, per the process in
`docs/specs/README.md`. Ask each for the four things that section requires: a
verdict per open question, correctness objections cited to file and function,
anything that breaks the privacy/CSP/localization contracts, and anything the
spec claims about the codebase that is not true.

**Task 0.2** — Resolve every `OQ-ARCH-*`. Move each to a **Resolved questions**
section with the answer and the spec version that resolved it. Never renumber.

**Task 0.3** — Bump the spec to `1.0 (Final)`, add the Revision history row,
update the Planned table in `docs/specs/README.md`.

**Task 0.4** — Build the equivalence corpus **before** touching any code. This
is the most valuable artifact in the whole refactor and everything after it is
measured against it.

It must be **deterministic**, which rules out `tools/backtest.mjs`: that tool
queries live DNS, and two runs a day apart differ because a stranger edited a
TXT record, not because the refactor did. The oracle is
[`tools/lib/doh-fixture.mjs`](tools/lib/doh-fixture.mjs) — already the basis of
the 1,535-assertion scoring suite, already defaulting unmatched queries to
NXDOMAIN so a gap fails loudly.

- **0.4.a** — `tests/fixtures/equivalence/`: a fixture set broad enough to reach
  every protocol module. Signed and unsigned domains; each of the six DNSSEC
  states; parked domains; `p=none`, `p=quarantine`, `p=reject`; SPF under, at
  and over the lookup limit; `include:` and `redirect=` chains; a circular SPF
  reference; domains with and without DKIM; CAA present and absent; MTA-STS and
  TLS-RPT valid and malformed; and at least one record carrying a bidirectional
  control, so the hygiene sentinels are covered too.
- **0.4.b** — `tests/build/equivalence.test.mjs`: replay the corpus through a
  given source root and emit a canonical JSON of scores, grades and issue-token
  lists.
- **0.4.c** — Capture the baseline from the tag:

  ```bash
  git checkout v0.5.0
  node tests/build/equivalence.test.mjs --source-root=js --emit > tests/fixtures/equivalence/baseline-v0.5.0.json
  git checkout spec/modular-architecture-production-build
  ```

  Commit that baseline. It is the contract.

`node tools/backtest.mjs --sample` still has a job — a grade-distribution sanity
check, run locally at each phase boundary. It is **never** a merge gate, and a
per-domain difference in its output means nothing.

> **Gate 0.** Spec is `1.0 (Final)`. The fixture corpus and
> `baseline-v0.5.0.json` are committed and reproducible. No source file under
> `js/` has been edited.

---

## The rule every phase below obeys

```text
suite green
    ↓
extract exactly one responsibility
    ↓
suite green, assertion count not lower
    ↓
three-way fixture replay clean
    ↓
commit
```

**One responsibility per commit.** Not one file, not one directory — one
responsibility. A commit that moves SPF parsing *and* renames its tokens is two
commits that were not separated.

**Never in the same commit as a move:** a protocol semantics change, a result
schema change, a scoring change, a concurrency change, or a UI behavior change.
Spec §35, and it is the difference between a revertable refactor and an
unrevertable one.

**Assertion count is a merge gate.** 2,121 at every phase boundary, or the
commit message names the assertion that was dropped and why.

---

## Phase 0 — ES modules

*The largest phase and the one the source proposal omitted entirely. Everything
else depends on it.*

The code today is seven classic scripts loading IIFEs that attach to `window`,
ordered by `index.html:187–193`. Nothing can be split until there is a module
graph to split along.

### 0.A — Generated data files first

They are the leaves of the graph and the safest thing to convert.

**Task 0.A.1** — `tools/update-psl.mjs` emits `export const PUBLIC_SUFFIXES = …`
instead of a global assignment. Regenerate to `src/data/public-suffixes.js`.

**Task 0.A.2** — Same for `tools/update-dkim-selectors.mjs` →
`src/data/dkim-selectors.js`. Note `js/dns.js:20` reads
`global.__DKIM_SELECTOR_CATALOG__` with a `|| { providers: {}, generic: [], … }`
fallback; the import replaces both the read and the fallback.

**Task 0.A.3** — `tools/build-fallback.mjs` emits
`export const LOCALE_EN = …` → `src/data/locales-en.js`.

**Task 0.A.4** — `tools/check-locales.mjs` parses the new format. **Same commit
as 0.A.3** — these two drifting apart is exactly what that check exists to catch.

> **Gate 0.A.** `npm test` 2,121. `npm run locale:gate` 13/13.
> `npm run build:fallback` is a no-op on a clean tree.

### 0.B — Leaf modules

**Task 0.B.1** — `js/i18n.js` → `src/i18n/index.js`. Named exports; drop the
IIFE. It imports `LOCALE_EN` from `src/data/locales-en.js`.

**Task 0.B.2** — `js/render.js` → `src/ui/render.js`. Same shape.

**Task 0.B.3** — Migrate `tools/interpolate.test.mjs` (17 assertions) off
`loadApp({files:[…]})` to a plain `import`. This is the smallest suite and the
proof that the harness can be retired incrementally.

> **Gate 0.B.** Two suites now import directly. `vm` still loads the rest.

### 0.C — The monolith becomes a module

**Task 0.C.1** — Delete the `(function (global) { … })(window)` wrapper from
`js/dns.js`. Convert the trailing assignment object into named `export`s. Add
the two data imports. **No code is moved between files in this commit** — it is
5,704 lines changing wrapper only, which is what makes it reviewable.

Watch for four things that ESM changes:
- top-level `this` is `undefined`, not `window`
- `var` no longer creates a global; anything reached via `window.X` breaks
- modules are always strict, but these IIFEs already declare `'use strict'`
- hoisting across what used to be one scope now crosses module boundaries

**Task 0.C.2** — Same for `js/app.js` → `src/main.js`.

**Task 0.C.3** — Rewrite `tools/lib/browser-harness.mjs`. It keeps the DOM shim,
which is still needed, and loses `vm.runInContext`. Its own header comment
("plain IIFEs that attach to `window` … no bundler involved") becomes false and
must be rewritten, not left.

**Task 0.C.4** — Migrate `tools/scoring.test.mjs` (1,535 assertions — 72% of all
coverage) to direct imports. Highest-value and highest-risk migration in the
refactor. The count is the check.

**Task 0.C.5** — Migrate `render.test.mjs` (329) and `export.test.mjs` (199).

**Task 0.C.6** — `tools/backtest.mjs` off `vm`. It keeps its live-DNS,
grade-distribution job; it does **not** become the equivalence oracle. The
`--source-root` flag belongs on `tests/build/equivalence.test.mjs` from Task
0.4.b, which is the instrument the refactor is actually measured with.

> **Gate 0.C.** No `vm.runInContext` remains outside a suite that documents why.
> Equivalence replay — `v0.5.0` `js/` vs `src/` — clean.
> **`index.html` still loads seven scripts and the site still works.** Phase 0
> changes source only; delivery is Phase 1.

*Interim `index.html` note:* between 0.C.1 and Phase 1 the page needs
`<script type="module" src="src/main.js">`. This temporarily makes native ESM the
delivery mechanism (~10 requests) and temporarily breaks `file://` — both are
resolved in Phase 1. `tools/csp.test.mjs` section 3 needs an interim amendment;
do not delete those assertions, adjust them, or the CSP loses a real control for
the duration of the refactor.

---

## Phase 1 — Build infrastructure

*Gated on `OQ-ARCH-01` and `OQ-ARCH-02`.*

**Task 1.1** — `npm install --save-exact --save-dev esbuild`. Exact pin, no
caret. This is the project's first dependency.

**Task 1.2** — Remove `package-lock.json` from `.gitignore:3` and commit the
lockfile *(assuming `OQ-ARCH-02` resolved as recommended)*.

**Task 1.3** — `tools/build-bundle.mjs`. Config per spec Design §6. `target`
from `OQ-ARCH-03`, `sourcemap` from `OQ-ARCH-04`, `splitting: false`.

**Task 1.4** — `package.json`: `"build:bundle"`, and `"build"` becomes
bundle-then-assemble. Verify `dependencies` is absent or empty.

**Task 1.5** — `index.html`: seven tags → one
`<script type="module" src="dist/app.min.js"></script>`.

**Task 1.6** — `tools/build-site.mjs`: allowlist `js` → `dist`. Add
`dist/*.map` if `OQ-ARCH-04` says yes.

**Task 1.7** — Amend `tools/csp.test.mjs` section 3 per spec Testing item 6:
exactly one `<script src>`, it is `dist/app.min.js`, same-origin,
`type="module"`. Retarget the markup-sink scan from `js/` to `src/`, **and add
`dist/app.min.js` to it**. Keep the allowlist empty.

**Task 1.8** — `tests/build/parity.test.mjs`. **The most important new test in
the release.** Build the bundle, run the scoring fixtures against it, assert
identical output to the same fixtures against `src/`. This closes the gap where
tests read source and users get the bundle.

**Task 1.9** — `tests/build/artifact.test.mjs`. Run `npm run build`; assert every
presence and absence in spec Testing item 5 — including that
`locales/translation-status.json` is absent, which is the existing skip-set rule
finally asserted.

**Task 1.10** — Size reporting: raw and gzip for `dist/app.min.js`, printed, not
enforced.

**Task 1.11** — `.github/workflows/pages.yml`: `npm ci`, `npm test`,
`npm run build`, then upload. `.github/workflows/ci.yml`: add the build. Keep
every action SHA-pinned. Add `npm run locale:gate` if `OQ-ARCH-08` says yes.

> **Gate 1.** `dist/app.min.js` builds offline. Parity test passes. `_site/`
> contains no `src/`, `tools/`, `tests/`, `docs/`, `package.json` or
> `node_modules/`. Size is in CI output. Equivalence replay clean through
> `dist/` as well as `src/`. Zero runtime dependencies, one pinned dev
> dependency.

---

## Phase 2 — DNS transport

**Task 2.1** — `src/core/dns/doh.js`: the DoH request, `AbortController`,
timeout, retry. Around `js/dns.js:177–220`.

**Task 2.2** — `src/core/dns/cache.js`: the existing LRU from `js/dns.js:70–88`,
**behavior unchanged** — same key format, same eviction, same rule that only
`success`/`nodata`/`nxdomain` are cached and a transport failure never is.
Export a factory so lifetime becomes explicit rather than module-global. Do not
change what it caches in this commit.

**Task 2.3** — `src/core/dns/errors.js`: the five-way distinction (absent,
invalid, transport failure, unsupported, indeterminate) that
[resilient-optional-checks](docs/specs/implemented/resilient-optional-checks.md)
shipped and that spec §10 requires survive.

**Task 2.4** — `src/core/dns/resolver.js`: normalization and response-kind
classification. The public surface protocol modules see.

**Task 2.5** — The transport-does-not-judge test: no string in
`src/core/dns/` is a key in `locales/en.json`. Cheap grep, real boundary.

**Task 2.6** — `tests/core/dns/`.

> **Gate 2.** DNS transport emits no locale token, proven. Equivalence clean.

---

## Phase 3 — Protocol extraction

Order is deliberate: simplest first, so the pattern is proven on a module small
enough to fully understand before it is applied to a hard one.

| # | Module | Extract | Notes |
| --- | --- | --- | --- |
| 3.1 | `core/caa/` | `checkCAA` | Smallest. Proves the pattern. |
| 3.2 | `core/mx/` | MX health, host resolution | |
| 3.3 | `core/transport/` | `validateMtaStsRecord`, `validateTlsRptRecord`, TLSA, `validateBimiRecord` | |
| 3.4 | `core/dnssec/` | Chain evaluation, DS↔DNSKEY matching | Newest code; 0.5.0 is its baseline. |
| 3.5 | `core/dmarc/` | Parse, tree walk, org domain, `DMARC_TAGS_RFC9989` | Imports the PSL. Watch the tree-walk coupling. |
| 3.6 | `core/dkim/` | Discovery, catalog, key decode | `DKIM_SCAN_BATCH_SIZE = 24` moves **unchanged**. |
| 3.7 | `core/spf/` | Parse, recursive evaluate, lookup accounting, subnets, redundancy | Hardest. Most coupled to the resolver. Last. |

Each is: extract → its own `tests/core/<protocol>/` → full suite → equivalence →
commit. Seven commits minimum, not one.

**Task 3.8** — Boundary test: no file under `src/core/` imports from `src/ui/`
or `src/audit/`.

**Task 3.9** — `providers/detectors.js`.

> **Gate 3.** Every protocol has an owning directory. Boundary test passes.
> Assertion count >= 2,121. Equivalence clean. **Token vocabulary
> byte-identical** — diff the issue tokens against `v0.5.0` explicitly.

---

## Phase 4 — Audit coordination

**Task 4.1** — `src/audit/context.js`: per-audit state, holding the cache
instance from Task 2.2. This is where §9's scoping request is finally satisfied.

**Task 4.2** — `src/audit/audit-domain.js`: orchestration. Preserve the existing
`Promise.all` structure exactly. **No concurrency change in this phase.**

**Task 4.3** — `src/audit/scoring.js`: `calcScore`, `calcDmarcScore`,
`calcSpfScore`, `gradeFor`, `WEIGHTS`, `PARKED_WEIGHTS`, `GRADE_THRESHOLDS`,
`POLICY_RANK`. Assert byte-identical to `v0.5.0`.

**Task 4.4** — `src/audit/issues.js`: `buildIssues`, `buildSuggestions`.

**Task 4.5** — `tests/audit/`.

> **Gate 4.** Weights byte-identical. Coordinator holds no parsing rule.
> Equivalence clean.

---

## Phase 5 — UI separation

**Task 5.1** — `src/ui/report.js`: `exportCSV` (`js/app.js:1560`), `exportHTML`
(`js/app.js:1634`). The exported report's own
`default-src 'none'; style-src 'unsafe-inline'; img-src data:` policy is asserted
by `csp.test.mjs` section 5 and must survive the move.

**Task 5.2** — `src/ui/events.js`: DOM wiring.

**Task 5.3** — `src/main.js` reduced to composition: wire UI to coordinator,
nothing else.

**Task 5.4** — `tests/ui/`.

> **Gate 5.** No protocol interpretation under `src/ui/`. Markup-sink allowlist
> still empty, scan covers `src/` and `dist/`.

---

## Phase 6 — Cleanup, documentation, release

**Task 6.1** — Delete `js/`. Only now, and only with the three-way equivalence
replay clean. Re-point the `baseline-v0.5.0.json` capture instructions at the
tag, since `js/` no longer exists on the branch.

**Task 6.2** — Remove every temporary adapter. Spec §36 permits them; it also
requires they be marked for removal. Grep for the marker and confirm zero.

**Task 6.3** — `AGENTS.md`: a module-ownership section. This is an acceptance
criterion, not a nicety — spec §32's whole argument is that "correct DMARC
organizational-domain discovery" should be a task an agent can bound to
`src/core/dmarc/` and `tests/core/dmarc/`. Write the table that makes that true.

**Task 6.4** — `CONTRIBUTING.md`: `npm ci`, `npm test`, `npm run build`,
`npm start`; the new test layout; **and that `file://` no longer works**
(`OQ-ARCH-06`).

**Task 6.5** — `README.md`: build commands, the source/artifact distinction, and
the assertion count **read out of a real `npm test` run** — it drifted from 174
to 489 unnoticed once already.

**Task 6.6** — `PRIVACY.md`: re-read and confirm no edit is needed. If the
refactor was done correctly, nothing it describes changed. Confirming that in
writing is the point.

**Task 6.7** — Move the spec to `docs/specs/implemented/`, following the
five-step procedure in `AGENTS.md` — `git mv`, re-depth every link, fix inbound
references repo-wide, run a link check over every markdown file, add the
**As implemented** section, convert Open questions to **Resolved questions**,
bump to `1.0 (Implemented)`, add the Revision history row.

**Task 6.8** — `CHANGELOG.md`, in the voice of the finished thing.

**Task 6.9** — Cut the release as the last commit on the branch: bump
`package.json` to `0.6.0`, promote `## [Unreleased]`, add compare links, set
released status in the spec header, `docs/specs/README.md`, `ROADMAP.md` and the
phase marker in `docs/async-development-handoff.md`.

**Task 6.10** — `pr-description.md`, structured like
[PR #4](https://github.com/kwestic-tech/dns-email-audit/pull/4), with real
numbers: before/after payload, assertion count, equivalence diff.

**Task 6.11** — Push once. Open the PR. Stop. **The merge is Ian's call.**
Tag `v0.6.0` annotated on the squashed commit after he merges.

> **Gate 6 — release.** Every box in the spec's Acceptance criteria ticked.

---

## Standing verification

Run at every phase boundary:

```bash
npm test                      # >= 2,121 assertions, 0 failed
npm run locale:gate           # 13/13
npm run build                 # dist/app.min.js + _site/
node tests/build/equivalence.test.mjs --source-root=src              # vs baseline
node tests/build/equivalence.test.mjs --source-root=dist             # vs baseline
```

**Order matters for the last three and only those three:** both equivalence runs
compare against the committed `baseline-v0.5.0.json`, and the `dist` run reads
what `npm run build` just produced, so the build must precede it. The first two
commands are order-independent with respect to everything else.

Locally, at each phase boundary, additionally:

```bash
node tools/backtest.mjs --sample
```

Live DNS, so read it for a *distribution* shift and nothing finer. Never a gate.

Any equivalence diff is a stop. Not a note in the PR description — a stop, until
it is explained or reverted.

---

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
| R1 silent behavior change | Every gate: three-way fixture replay (Task 0.4) |
| R2 bundle ≠ tested source | Task 1.8 |
| R3 supply chain | Tasks 1.1, 1.2, `OQ-ARCH-01` |
| R4 ESM strict-mode semantics | Tasks 0.C.1, 0.C.2 — one file per commit |
| R5 harness rewrite loses coverage | Assertion count at every gate |
| R6 `file://` breaks | Task 6.4, `OQ-ARCH-06` |
| R7 deploy publishes too much | Task 1.9 |
| R8 scope creep | "What this plan deliberately does not do" |
| R9 cold-start regression | Task 1.10, `OQ-ARCH-05` |
