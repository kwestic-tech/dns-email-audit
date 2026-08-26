# Codex follow-up review — modular architecture and production build, round 1

**Reviewed:** 2026-08-27

**Branch:** `spec/modular-architecture-production-build`

**Reviewed head:** `71068a2`

**Prior handoff:** `CODEX Review Modular Refactor.md`

**Spec:** `docs/specs/modular-architecture-and-production-build.md`, `0.1 (Draft)`

**Implementation plan:** `Modular Architecture, Production Build Refactor Implementation.md`

**Disposition:** **Changes requested before the spec reaches 1.0**

This is a separate follow-up decision log. It does not replace the review
request or either specification. I checked their claims against `v0.5.0` and
the current branch, traced the classic-script and test-harness loading paths,
and checked the bundler-specific claims against esbuild's own documentation and
package metadata.

No production or specification file was changed during this review. The only
new artifact is this document. The untracked `skills-lock.json` was present at
the start of the review and was left untouched.

## 1. Executive assessment

The architectural destination is right: protocol ownership, audit
coordination, UI composition, generated data and the DNS resolver should stop
sharing two lexical scopes. The corrections concerning stable finding tokens,
the deployment allowlist, lockfile pinning, live-DNS backtests and resolver
handles also mostly hold.

The implementation order does not yet hold. The plan makes ESM conversion a
prerequisite for the build, but esbuild can bundle the existing side-effect
scripts first. Doing that first is safer and resolves three problems at once:

- the deployed artifact and its parity test exist before the riskiest changes;
- every ESM migration commit can remain runnable behind one stable bundle
  entry; and
- temporary compatibility adapters can be removed incrementally without
  maintaining two copies of the implementation.

As written, Phase 0 breaks the browser between its own commits, its baseline
capture command cannot run after checking out `v0.5.0`, and its equivalence
contract observes only scores, grades and issue tokens even though the spec
promises preservation of the complete audit result and exported reports.
Those are specification blockers, not implementation details to discover
later.

## 2. Findings

### F1 — P1 — Phase 0 cannot keep the application runnable as written

**Locations:** implementation plan lines 121–196; spec Design §2 and open
question `OQ-ARCH-07`.

Tasks 0.A.1–0.A.3 move the generated globals from `js/` to ESM exports under
`src/data/`. Tasks 0.B.1–0.B.2 then move `js/i18n.js` and `js/render.js` out of
the paths `index.html` still loads. Task 0.C.1 turns `js/dns.js` into a module,
while `js/app.js` remains a classic consumer until the next commit.

That cannot satisfy Gate 0.C's simultaneous claims that `index.html` still
loads seven scripts and the site still works. The following “interim” note says
the opposite: `index.html` must load `src/main.js` as a module from 0.C.1 onward,
but `src/main.js` does not exist until 0.C.2. Gate 0.A and Gate 0.B have the same
unaddressed path problem earlier.

**Required change:** reverse the first two phases.

1. Add esbuild, the lockfile, artifact assembly and bundle parity around the
   current classic scripts. Use one ordered side-effect entry that loads the
   generated globals, i18n, renderer, DNS and app in their existing order.
2. Point `index.html` at that built artifact and make it the stable delivery
   boundary.
3. Convert one leaf or responsibility at a time behind the bundle. Where a
   converted ESM module must still serve a classic consumer, add a small,
   explicitly marked adapter that exposes the existing global from the single
   ESM source. This is not a parallel implementation tree.
4. Remove each adapter as its last consumer migrates, and assert that none
   remain at cleanup.

If the author keeps ESM first, the plan instead needs an exact, commit-by-commit
loader matrix showing which files exist, which tags load them, and which
adapter keeps every legacy consumer working. The current “convert in place”
language is not enough.

### F2 — P1 — The equivalence oracle is both too narrow and not reproducible by the stated command

**Locations:** implementation plan Tasks 0.4.b–0.4.c; spec Design §8, Testing
items 4 and 8, and Acceptance criteria.

The spec's non-goal promises the same normalized DNS responses, statuses,
findings, severities, scores and explanations. Task 0.4.b records only scores,
grades and issue-token lists. A refactor could change MX details, DNSSEC
evidence, DKIM key facts, DMARC discovery, provider detection, warnings,
suggestions, export fields or issue metadata and still pass that oracle.

The capture recipe also checks out `v0.5.0` and then runs
`tests/build/equivalence.test.mjs`. That test does not exist at the tag; it is a
new artifact on this branch. Checking out the tag removes the very runner the
next command invokes.

**Required change:**

- Define a canonical projection of the **complete `analyzeDomain()` result**,
  including query-kind/status evidence and ordered details, with an explicit
  list of any fields deliberately excluded and why.
- Add render and export parity. At minimum, compare canonical DOM/report trees
  and byte-identical CSV column/value output for the same corpus. HTML may be
  canonicalized only for values that are genuinely nondeterministic.
- Record exact DNS query names, types and counts for fixtures that exercise
  cache, tree-walk and concurrency-sensitive behavior. Output equality alone
  does not preserve privacy fan-out.
- Capture the tag from a separate worktree or run the branch's harness against
  files obtained from `git archive`/`git show`. Do not switch the active
  implementation worktree to the tag, and prove regeneration from a clean
  clone in CI.

### F3 — P1 — Bundle parity has no executable access path to the shipped bundle

**Locations:** implementation plan Task 1.8 and standing verification; spec
Testing item 4.

`dist/app.min.js` is specified as the bundle of `src/main.js`. A browser entry
normally imports the audit functions for its own use but does not re-export
them. Tree shaking may also remove APIs used only by tests. “Load the bundle and
re-run the scoring fixtures” therefore does not state how the test reaches
`auditDomain`, `calcScore` or the protocol primitives in the exact artifact the
browser receives.

There is a second ambiguity: today's scoring suite injects a small public
suffix table through `window.__PUBLIC_SUFFIX_RULES__` and repeatedly replaces
the VM context's `fetch`. Direct static imports of generated data remove the
first control, while Node's ESM module cache and process-global `fetch` change
the second. The count cannot prove that the same fixtures are still being run.

**Required change:** specify one concrete parity contract before finalizing the
spec. Two honest choices are:

- `src/main.js` deliberately exports a supported audit API, the production
  bundle preserves those exports, and the Node harness installs/restores DOM,
  `fetch`, crypto and generated-data inputs before a cache-busted dynamic
  import; or
- a browser-level test drives the exact built `index.html` through its real UI
  and observes the rendered and exported outputs.

A separate test-only bundle is useful for unit tests but is not proof about
`dist/app.min.js`. Whichever choice is made must retain the real DoH URL
construction path described in `tools/lib/doh-fixture.mjs`.

### F4 — P1 — Per-audit cache scoping is a behavior and privacy-fan-out change

**Locations:** review request C3; spec Corrections item 3, Design §§2 and 5;
implementation plan Tasks 2.2 and 4.1.

The existing cache is intentionally page-scoped. `tools/scoring.test.mjs` has a
specific regression proving that a second sibling DMARC walk reuses upper-tree
answers cached by the first. `startAudit()` calls `analyzeDomain()` separately
for each queued domain and does not currently pass a shared audit context.

Instantiating a cache “per audit” is therefore ambiguous:

- if “audit” means one domain, the sibling reuse test fails and a 200-domain
  run issues more DNS queries;
- if it means one batch, the application must create one context in
  `startAudit()` and pass it to every worker; and
- either definition discards reuse between two batches in the same page,
  unlike `v0.5.0`.

The current documents call this behavior unchanged and also say `PRIVACY.md`
cannot need an edit. Both claims are premature because request count is part of
the published privacy story.

**Required change:** preserve page-lifetime scope in 0.6.0, or explicitly make
cache lifetime a permitted behavior change with query-count fixtures,
before/after fan-out measurements and a privacy review. Moving the cache behind
a factory is architectural; changing who owns the factory instance is a
separate decision.

### F5 — P1 — The esbuild supply-chain decision rests on a false dependency claim

**Locations:** spec Risks R3 and `OQ-ARCH-01`; review request `OQ-ARCH-01`.

The spec repeatedly recommends esbuild because it has “zero transitive
dependencies.” Its current package metadata declares a postinstall script and
platform-specific `@esbuild/*` optional dependencies. npm installs the package
for the current platform and records the platform packages in the lockfile.
That may still be a small and reasonable supply chain, but it is not zero.

Primary evidence:

- esbuild's package metadata:
  <https://github.com/evanw/esbuild/blob/main/npm/esbuild/package.json>
- esbuild's own installation code describing the platform optional dependency:
  <https://github.com/evanw/esbuild/blob/main/lib/npm/node-platform.ts>

**Required change:** compare tools using direct packages, lockfile package
count, install scripts, installed executable provenance, maintenance model and
cross-platform CI behavior. If esbuild still wins—and it probably does—record
the real reason. Keep “exactly one direct `devDependency`” as a
`package.json` criterion, but do not describe the resolved dependency graph as
one package or zero transitive packages.

### F6 — P2 — The transport boundary grep does not prove the stated boundary

**Locations:** spec Design §3, Testing item 3 and Acceptance criteria;
implementation plan Task 2.5.

The proposed test says no string under `src/core/dns/` may be a key in
`locales/en.json`. The locale file is nested, so a full key such as
`issue.spf-large-subnet.msg` does not appear as one literal string. The current
protocol tokens are values such as `spf-missing`, `@none` and `noteWildcard`,
not locale JSON keys. A resolver could emit one of those judgment tokens and
the grep would still pass.

**Required change:** enforce dependency direction mechanically, and test the
resolver's public result algebra directly. DNS transport may emit record data
and a closed set of transport/response kinds; it may not emit any protocol
finding, severity, score or locale lookup. A static token scan can be a
secondary tripwire, but it cannot be the proof claimed by the acceptance
criterion.

### F7 — P2 — Three build/test claims are factually wrong

**Locations:** spec Build §6 and Localization impact; spec `OQ-ARCH-05`.

1. `legalComments: 'inline'` does not preserve the existing file headers.
   esbuild only treats comments containing `@license`/`@preserve` or beginning
   `//!`/`/*!` as legal comments. The headers in `js/*.js` are ordinary block
   comments, and none is an MIT header. The MIT text is the separately
   published `LICENSE` file. See the
   [esbuild legal-comments documentation](https://esbuild.github.io/api/#legal-comments).
2. `tools/interpolate.test.mjs` has 17 assertions, not 329. The baseline table
   and implementation plan state 17 correctly; the Localization section does
   not.
3. `src/data/locales-en.js` is a legitimate future split candidate. The
   localization contract regenerates it **after an `en.json` edit**, not every
   release. This release explicitly promises no such edit.

**Required change:** correct all three claims. If preserving a banner inside
the bundle is desired, define an esbuild `banner` or change the source notice to
a qualifying legal comment and assert it in the artifact test. Do not call the
current descriptive headers licence notices.

### F8 — P2 — Assertion count is an inventory signal, not a merge gate

**Locations:** implementation plan lines 84–108; spec Testing item 1, Risks R5
and Acceptance criteria.

A refactor can delete a meaningful assertion and add an unrelated one while
remaining above 2,121. Conversely, replacing three filename/order assertions
with four bundle-boundary assertions changes the count without telling whether
the original behavior is covered. The proposed equivalence manifest and named
contract tests are the gates; the raw count is only a useful review signal.

**Required change:** report the total and require every removed assertion to be
accounted for, but do not treat `>= 2,121` as proof of preserved coverage. Gate
on a checked-in inventory of named suites/contract areas plus the full-result,
render, export, query-trace and built-artifact parity described above.

## 3. Verdicts on the eight corrections

### C1 — ESM omission

**Verdict: correction accepted; phase placement declined.** ESM conversion is
large and was omitted. It is not a prerequisite to bundling the IIFEs. Build
and bundle parity should precede ESM conversion for the reasons in F1.

### C2 — Finding identifiers

**Verdict: decline confirmed.** Preserve the existing token vocabulary. A
case-style rename is schema churn with no architectural gain.

### C3 — Shared DNS cache

**Verdict: cacheable-kind rule confirmed; per-audit scope not confirmed.** The
current page-scoped reuse is deliberate and tested. Preserve it in a
behavior-neutral refactor or authorize and measure the change separately.

### C4 — Deployment allowlist

**Verdict: correction accepted.** Keep `LICENSE` and
`THIRD_PARTY_NOTICES.md`; omit the empty `assets/` directory. Add an exact
top-level allowlist assertion and reference-resolution checks.

### C5 — Lockfile

**Verdict: accepted.** Remove the ignore rule and commit
`package-lock.json` when the first package is added.

### C6 — Behavioral equivalence

**Verdict: correction accepted, proposed parity scope insufficient.** Scoring
parity alone does not cover the promised result schema, DOM rendering or
exports. Apply F2 and F3.

### C7 — Live backtest as oracle

**Verdict: accepted.** A live DNS sample is not deterministic and cannot gate
equivalence. The proposed fixture topics are a good start, but the observed
projection must expand beyond score/grade/tokens and include query traces.

### C8 — Resolver handle

**Verdict: distinction confirmed with a constraint.** A resolver passed along
the production call path is not a test-only seam. Tests must still exercise
the actual URL builder, response parser, cache, limiter and retry behavior. A
pure protocol unit test may use normalized records, but it cannot replace the
transport integration corpus.

## 4. Verdicts on the open questions

### `OQ-ARCH-01` — Bundler

**Answer: esbuild, conditional on correcting F5 and passing a small spike.**
The spike must bundle the unmodified IIFEs, run the exact artifact under the
fixture harness, work on macOS and Linux CI from `npm ci`, and record the real
lockfile/package footprint. This is implementation research permitted before
the spec is final; it is not production refactoring.

### `OQ-ARCH-02` — Lockfile

**Answer: commit it.** Exact direct pin plus committed lockfile plus `npm ci`.

### `OQ-ARCH-03` — Browser target

**Answer: split syntax from platform support.** `target: ['es2020']` is an
acceptable conservative syntax target, but “last two versions” is a separate,
moving support policy and does not prove support for `AbortController`,
`BigInt`, `Intl.PluralRules` or other APIs esbuild does not polyfill. Document
both and add a short required-API matrix; no polyfills is acceptable.

### `OQ-ARCH-04` — Source maps

**Answer: ship linked external source maps.** Source is already public and the
debuggability benefit is real. Assert the `.map` is present, its link resolves,
and `_site/` contains only the intended `dist` files. Do not count the map in
the browser transfer size because it is not fetched during a normal visit.

### `OQ-ARCH-05` — Bundle split

**Answer: one bundle for 0.6.0.** Correct the `locales-en.js` claim, report the
esbuild metafile composition, and defer splitting until actual cache headers
and repeat-visit behavior are measured.

### `OQ-ARCH-06` — `file://`

**Answer: loss accepted and documented.** `npm start` becomes the supported
local path. Remove stale source comments that continue promising `file://`
fallback behavior.

### `OQ-ARCH-07` — `js/` transition

**Answer: no duplicate implementation tree; temporary adapters are required.**
The current question presents a false choice between two complete trees and no
transition mechanism. Use one source of truth per responsibility and small
marked adapters behind the stable bundle, then delete each adapter when its
last classic consumer is gone.

### `OQ-ARCH-08` — Strict locale gate in CI

**Answer: add it.** This enforces an existing repository contract. It is not a
behavioral expansion of the application.

## 5. Other requested verdicts

### Scheduling

**Keep the refactor at 0.6.0.** It should remain the serialization point before
the three blocked feature specs. Any already-started local-artifact work should
either land before the first source move or pause until the new module paths are
final; concurrent source-tree work is not worth the merge cost.

### Phase 3 extraction order

**Accepted with one correction.** CAA → MX → mail transport → DNSSEC → DMARC →
DKIM → SPF is a reasonable increasing-coupling order. BIMI does not belong in
`core/transport/`; give it `core/bimi/` or state a broader responsibility name
that actually includes brand-indicator validation. The target tree and Task
3.3 currently disagree about BIMI.

### Transport-does-not-judge test

**Declined as sufficient.** See F6.

### Assertion count

**Declined as a merge gate.** Preserve and report it, but gate named behavior
and parity. See F8.

### CSP assertions

**The replacement is directionally sound.** Filename ordering no longer has
value after bundling. Preserve the exact CSP policy assertions, exact one-script
same-origin/module assertions, source scan and built-artifact scan. Add source
map and artifact reference-resolution checks under the artifact suite rather
than overloading the CSP suite.

## 6. Required next revision

Before the spec moves to `1.0 (Final)`:

1. Reorder build establishment before ESM conversion and write the transitional
   adapter/loader strategy.
2. Replace the baseline recipe with one that works from a clean clone without
   checking the active worktree away from the branch.
3. Expand equivalence to the complete audit result, query traces, rendering and
   exports, and specify how the exact production bundle is loaded.
4. Preserve page-scoped cache behavior or explicitly authorize and measure a
   cache-scope change.
5. Correct the esbuild dependency model and record the spike results.
6. Replace the vacuous transport-token grep with a result-algebra contract.
7. Correct the legal-comment, interpolation-count and generated-English claims.
8. Treat assertion count as a reported inventory signal, not coverage proof.

This is intentionally a foundational first round. Once these changes land, the
next review should focus on the concrete module API shapes, cycle risks in the
proposed import graph, and whether the expanded fixture corpus covers each
protocol's failure-state algebra.
