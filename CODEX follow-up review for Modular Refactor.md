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

---

# Round 2 follow-up — 2026-08-27

**Reviewed head:** `ae394df`

**Spec reviewed:** `0.3 (Draft)`

**Round 1 response:** all eight findings accepted

**Disposition:** **IIFE output accepted in principle; changes still requested
before `1.0 (Final)`**

## 7. Round 2 executive assessment

Round 1 was folded in accurately. The build now precedes the ESM conversion,
the page-lifetime cache is preserved, equivalence observes substantially more
than the grade, and the vacuous token grep and assertion-count gate are gone.
The separate BIMI owner, explicit banner, lockfile treatment and hybrid test
layout are also sound corrections.

The proposed IIFE delivery format is acceptable and preferable here. ESM
source does not require ESM output, and preserving the existing classic-script
boundary avoids spending `file://` compatibility for no product benefit. A
single generated global does not recreate internal global coupling **if** the
source graph is forbidden from reading or writing it.

The current text does not yet establish that condition. It also attributes a
behavior to esbuild's `globalName` that the option does not have: it exports the
entry point's exports, not an unrelated object that an imported side-effect
script assigned to `window`. The composition root, exported facade,
canonicalization rules, full dependency DAG and protocol failure-state matrix
remain unspecified. The spec should not become Final until those contracts are
written down.

## 8. Round 2 findings

### R2-F1 — P1 — `globalName` does not expose the legacy `window.DnsAudit` API automatically

**Locations:** spec Design §6, “Why `iife` and not `esm”; Testing item 4;
implementation plan Tasks 1.3, 1.4 and 1.9.

esbuild defines `globalName` as the variable that receives **the exports from
the entry point**. `src/entry-legacy.js` is currently specified as seven
side-effect imports and no exports. Meanwhile `js/dns.js` independently assigns
its API to `window.DnsAudit` during bundle evaluation.

Those are not the same operation. With `globalName: 'DnsAudit'`, the generated
outer assignment can overwrite the `window.DnsAudit` value created inside the
bundle with the entry module's empty export object. Even when it does not
collide, `globalName` cannot infer or mirror the legacy object's members. The
claim that this gives “exactly the surface the existing harness already
reaches” is therefore unsupported.

Primary documentation:
<https://esbuild.github.io/api/#global-name>. It states that the configured
global stores the exports from the entry point.

**Required change:** define the boundary in two explicit stages.

1. During the legacy-bundle phase, omit `globalName` (or use a non-conflicting
   temporary name). The unmodified `js/dns.js` continues to create
   `window.DnsAudit`, and parity reaches that existing surface.
2. Before the legacy assignment is removed, add a deliberate ESM facade whose
   named exports are the supported audit API. Then, and only then, compile that
   entry with `globalName: 'DnsAudit'`.
3. Check in the expected facade member names and assert both source and bundle
   expose exactly that set. Do not expose `__APP_TEST__` as production API just
   because the old harness used it.
4. Add a source contract forbidding reads or writes of `window.DnsAudit`,
   `globalThis.DnsAudit` or the chosen namespace anywhere except the temporary
   legacy adapter and final generated boundary.

This is still the first honest parity option from round 1—a supported exported
facade—but it must be designed. The bundler cannot design it on the project's
behalf.

### R2-F2 — P1 — The proposed resolver algebra does not describe the current resolver

**Locations:** spec Design §3, Testing item 3 and Acceptance criteria;
implementation plan Tasks 3.3–3.5.

The revised spec says the resolver returns a discriminated union over the
five-way distinction “absent, invalid, transport failure, unsupported,
indeterminate.” That is not the algebra in `v0.5.0`.

`dohFetch()` currently returns these raw kinds:

```text
success, nodata, nxdomain, servfail, refused, dns-error,
http-error, cancelled, timeout, network-error
```

An unsupported record type throws `DnsTypeError`; it is not a returned kind.
“Invalid” is normally a record-parser conclusion, and “indeterminate” is a
protocol/audit conclusion. `resilient-optional-checks.md` guarantees that a
failed optional lookup becomes a declared unknown and that cancellation is
re-thrown; it does not redefine the raw resolver response into the five labels
the new spec names.

Collapsing these layers during a move could erase distinctions that DNSSEC,
DMARC discovery, `domainExists()`, retry, cacheability and cancellation use
today.

**Required change:** specify separate closed algebras:

- raw DoH result kinds, byte-for-byte compatible with `dohFetch()`;
- thrown programmer/cancellation errors and which layer may catch each;
- normalized record/absence results exposed to protocol modules; and
- protocol-level `invalid`/`unknown`/`indeterminate` conclusions.

The contract tests must enumerate every member, preserve `nodata` versus
`nxdomain`, prove only `success`/`nodata`/`nxdomain` are cacheable, and prove
`cancelled` never becomes an optional-check fallback.

### R2-F3 — P1 — The composition root is still a requirement, not a design

**Locations:** spec Design §§4, 6 and 8; Risks R6; implementation plan Task
2.1.

The documents now correctly say generated data must be injectable at the
composition root. They do not define the root, its factory, the lifetime of the
objects it creates, or how the same runtime becomes both the browser's facade
and the unit/integration test subject.

That omission is load-bearing. Static imports recreate the PSL defect. Module
singletons make fixture selection and cache isolation depend on Node's ESM
cache. A factory that injects a normalized resolver can accidentally create the
test-only bypass `tools/lib/doh-fixture.mjs` forbids.

**Required change:** add a concrete composition contract. One viable shape is:

```js
createAuditRuntime({
  publicSuffixRules,
  dkimSelectorCatalog,
  englishBundle,
  platform
}) -> { auditDomain, scoring, reporting, mount }
```

The production entry imports generated data and browser platform primitives,
calls the factory once, mounts the UI, and exports the supported facade from
R2-F1. Unit tests call the same factory with the four-rule PSL and fixture
catalog. Transport integration tests replace only the lowest `fetch` primitive
while still exercising URL construction, response parsing, retry, limiter and
cache. A normalized resolver substitute may be used for a pure protocol unit
test, but never as the only coverage of the transport path.

The spec need not use that exact name, but it must state:

- which dependencies are passed versus imported;
- which instances are page-scoped, audit-scoped and call-scoped;
- how the fixture proves its PSL/catalog identity behaviorally; and
- how globals are installed and restored without relying on ESM cache-busting
  as the state-isolation mechanism.

### R2-F4 — P1 — “Four-surface equivalence” is internally inconsistent and lacks canonicalization rules

**Locations:** spec Scope item 7, Design §8, Testing item 2 and Acceptance
criteria; implementation plan Tasks 0.4.b and standing verification.

The scope promises both exports. The Design §8 table mentions byte-identical
CSV and canonicalized HTML. But the binding definition, acceptance criterion
and Task 0.4.b list only result, query trace, CSV and DOM. HTML report parity has
fallen out of the actual gate.

The remaining surfaces are named but not defined. “Canonical JSON” does not say
whether absent and present-with-`undefined` are distinct, how `BigInt` is
encoded, or whether object keys and arrays are reordered. “Exact query trace”
overfits global chronology: independent `Promise.all` branches may interleave
differently without changing query set, fan-out or protocol semantics. “Canonical
DOM” does not say how attributes, DOM properties, text nodes or event behavior
are treated.

**Required change:** add a checked-in canonicalization specification before the
corpus is captured:

- **Result:** recursively sort object keys only; preserve array order, property
  presence, `undefined` and non-JSON primitives with tagged encodings. No
  blanket removal of empty values or float rounding.
- **Queries:** gate on the multiset of normalized
  `(name, type, do, cd, count)` plus maximum active concurrency/batch metrics.
  Preserve ordered assertions separately for algorithms where order is the
  behavior, such as DMARC tree walk and SPF recursion. Do not gate unrelated
  parallel branches on scheduler chronology.
- **CSV:** exact bytes, including header and column order, under one documented
  newline convention.
- **DOM:** ordered node/child structure and exact text; attributes compared as
  a sorted name/value map; relevant properties such as `value`, `checked`,
  `disabled` and visibility compared explicitly. Do not normalize whitespace
  text away.
- **HTML report:** restore it to the gate. Compare a canonical parsed tree while
  separately asserting CSP and stylesheet bytes that must remain exact.
- **Exclusions:** one manifest entry per excluded field, with a reason. No
  wildcard field classes.

The result, query, render and export categories may still be called four
surfaces, but “export” must actually include CSV **and** HTML everywhere the
gate is enumerated.

### R2-F5 — P1 — The import contracts do not yet prevent cycles or renewed global coupling

**Locations:** spec Design §§2–5, Testing item 3 and Acceptance criteria;
implementation plan Tasks 3.5 and 4.9.

The proposed graph assertions constrain `core/dns` and forbid `core → ui`.
They still permit protocol-to-protocol cycles, `audit ↔ providers`,
`ui ↔ i18n`, or a protocol reading a shared global instead of importing its
dependency. An acyclic graph can also point in the wrong architectural
direction.

**Required change:** add the target DAG before files move. At minimum it should
name allowed edges among:

```text
entry/composition → ui, audit, i18n, generated data, platform
ui                → i18n and rendering/report primitives
audit             → protocol modules, providers, resolver contracts
protocol modules  → resolver contracts and explicitly named pure shared data
resolver          → DNS transport/cache/platform only
generated data    → nothing
```

Exceptions such as DMARC's PSL dependency must appear as injected data or an
explicit allowed edge, not an implied convenience. The contract test must:

- parse the real static import graph;
- reject every strongly connected component containing more than one module;
- reject any edge absent from the allowed-layer matrix; and
- enforce the global-namespace rule from R2-F1.

Also add a small API table per owning directory: public exports, accepted
inputs, returned discriminants, allowed dependencies and state lifetime. The
current folder tree describes ownership but not interfaces.

### R2-F6 — P1 — The equivalence corpus list does not cover the protocols' failure-state algebras

**Locations:** implementation plan Task 0.4.a; spec Design §8 and Risks R1/R6.

The revised corpus adds useful happy, absent, malformed and DNSSEC-state cases,
but it still does not demonstrate every protocol's failure-state boundary. It
does not name transport failures per optional check, cancellation, HTTP failure,
NODATA versus NXDOMAIN, duplicate/conflicting records, external-report
authorization, wildcard behavior, provider detection, DKIM partial scan
failure, DMARC walk termination modes, deep-check suppression, or TLSA's
per-host weakest-link cases.

The existing 1,535-assertion suite covers many of these individually. That does
not make them part of the new end-to-end baseline automatically.

**Required change:** add a state-matrix manifest. For each DNS layer and
protocol owner, list every returned discriminant and each error/unknown path,
then map it to:

- a unit or contract suite;
- an integration fixture through the real resolver path where applicable; and
- at least one four-surface equivalence fixture for every operator-visible
  result shape.

The matrix, not a prose list of representative domains, is the Gate 0 proof
that the corpus reaches what the refactor promises to preserve.

### R2-F7 — P2 — The co-location mitigation is acceptable, but the sentinel is not the primary proof

**Locations:** spec Design §9, Testing items 5–7 and Risk R7; implementation
plan Tasks 1.8, 1.10 and 1.11.

A mechanical `*.test.js` exclusion is materially safer than a named-file
allowlist: it contains no per-file exception and is reviewable as one category.
Combined with scanning the exact production bundle, it adequately preserves
the markup-sink control. Co-location does not otherwise weaken deployment
because `src/` is absent from `_site/`.

The proposed per-test sentinel is weaker than the esbuild metafile. A sentinel
can be tree-shaken, renamed, duplicated or omitted from a new test. The metafile
already records every input that contributes to the bundle.

**Required change:** make these the binding checks:

- no `*.test.*` path appears in `metafile.inputs`;
- no `*.test.*` path appears in the linked source map's `sources`;
- the exact built artifact passes the markup-sink scan; and
- `_site/` contains no source or test path.

The sentinel may remain as defense in depth, but it should not carry the
acceptance criterion.

### R2-F8 — P2 — The round-two documents have small state drift

**Locations:** implementation plan §0; spec header, Open questions and Revision
history.

- The plan says the spec is `0.2`; the reviewed spec and round-two request say
  `0.3`.
- Task 0.3 says “move both questions” although `OQ-ARCH-09` is already recorded
  as decided and only `OQ-ARCH-06` is open.
- The Revision history is ordered `0.1`, `0.3`, `0.2`.
- The spec's early Correction 1 still ends “This spec makes it Phase 0,” even
  though round 1 reversed that decision and the build is now Phase 1.

**Required change:** correct these before the next handoff so a reader does not
have to infer which statement is current.

## 9. Requested round 2 verdicts

### `OQ-ARCH-06` — IIFE or ESM output

**Verdict: choose IIFE output, conditional on R2-F1 and R2-F5.** A generated
global at the delivery boundary does not undermine ESM internals. The import
graph test alone is not enough; the source must also be forbidden from using
that global as an internal dependency. Preserve the legacy surface without a
colliding `globalName`, then replace it with an explicit supported ESM facade.

### Co-located test exclusion

**Verdict: the mechanical suffix exclusion is adequate.** It is materially
different from a named-file allowlist because adding a new exception does not
silently widen it. The scan of the exact built artifact is the decisive second
control. Strengthen accidental-inclusion detection with metafile and source-map
input assertions per R2-F7.

### Composition root

**Verdict: not yet specified.** Use one production runtime factory with
explicit generated-data and platform bindings, defined lifetimes, and one
supported facade. Do not use process-global ESM state as dependency injection.

### Four-surface canonicalization

**Verdict: not yet usable as a gate.** Apply R2-F4, particularly restoring HTML
export parity and replacing global query chronology with a normalized multiset
plus targeted order/concurrency assertions.

### Module API shapes and cycle risk

**Verdict: not yet specified.** The ownership tree is good; it needs the API
table, allowed-edge matrix, SCC rejection and global-namespace rule in R2-F5.

### Failure-state coverage

**Verdict: insufficient as listed.** Convert the prose corpus list into the
state-to-suite/fixture matrix required by R2-F6.

## 10. Required next revision

Before `1.0 (Final)`:

1. Correct the IIFE facade and legacy-to-ESM boundary transition.
2. Replace the invented five-way resolver algebra with the actual layered
   transport, error, normalized-record and protocol algebras.
3. Specify the composition factory, dependency bindings and lifetimes.
4. Make canonicalization executable and restore HTML report parity.
5. Define the complete allowed import DAG and supported module APIs.
6. Add the per-protocol failure-state coverage matrix.
7. Bind the co-location safety proof to metafile/source-map inputs and the
   built-artifact scan.
8. Correct the document-version and stale-phase text.

The next review can then test the API/DAG and state matrices for omissions. The
esbuild spike remains a separate Gate 0 requirement: an accepted IIFE design is
not evidence that the unmodified legacy bundle has actually run on both target
platforms.

---

## 11. Round 3 readiness response — 2026-08-27

**Reviewed branch head:** `9108f58` (`Answer review round 2 and scope the next
spec revision`)

**Artifact status:** there is no revision `0.4` or round 3 review request on the
branch yet. The new material is the author's response to round 2 and a proposed
sequence for writing `0.4`; the spec remains `0.3 (Draft)`. This section answers
the explicit verdict request and clears that drafting work. It is **not** an
approval of an as-yet unwritten `0.4`.

### Verdict on the R2-F2 refinement

**Accepted. Document the existing boundaries; do not introduce a new resolver
normalization layer.** R2-F2 asked the spec to distinguish the algebras that the
current implementation already exposes. Introducing a new result model during
the modular move would enlarge the change and make behavioral equivalence harder
to prove.

The table in the response is faithful to the code, with one terminology
correction: it describes **four processing layers plus direct-kind consumers**,
not a five-layer sequential stack.

1. `dohFetch()` returns the ten transport kinds.
2. `requireUsable()` admits `success`, `nodata` and `nxdomain`, and throws for
   the other seven.
3. `dohQuery()` and `dohAll()` return cleaned string arrays with no result kind.
4. `optionalCheck()` is an outer policy boundary that converts failures to each
   caller's declared unknown result while rethrowing `AbortError` and
   `DnsTypeError`.
5. `domainExists()`, `checkConnectivity()` and the DNSSEC `servfail` path bypass
   the normalized-record path deliberately. They are exception edges, not a
   fifth stage through which every query flows.

Revision `0.4` should preserve that distinction in its diagram, API table and
allowed-edge matrix. It must still specify the protocol/audit result algebras
(`invalid`, `unknown`, `indeterminate` and protocol-specific states) in the
state-to-fixture matrix; accepting the transport refinement does not remove
that half of R2-F2 or R2-F6.

### One correction to carry into the facade inventory

The response correctly establishes that a single esbuild `globalName` cannot
reproduce the legacy surface, but its inventory is not complete enough to use
as the checked-in contract. In addition to the five rows it lists:

- `js/i18n.js` also assigns `tRaw` beside `i18n`, `t` and `tp`;
- `js/locales-en.js` assigns `__I18N_EN__`;
- `js/public-suffixes.js` assigns `__PUBLIC_SUFFIX_RULES__`; and
- `js/dkim-selectors.js` assigns `__DKIM_SELECTOR_CATALOG__`.

The last three are generated-data inputs rather than supported application API,
but they are still global reads/writes during the legacy-to-ESM transition and
must be represented in the source contract. The final production facade should
be derived from actual consumers. Test-only internals, including
`__APP_TEST__`, should move to direct ESM imports instead of being frozen into
that facade.

### Authorization and next handoff

Code is clear to produce revision `0.4` using the accepted sequencing in the
round 2 response, with these conditions:

- run and record the `OQ-ARCH-01` legacy IIFE spike before presenting build
  behavior as verified;
- use the four-layers-plus-exception-edges model above;
- inventory generated-data globals as transition inputs, not facade exports;
- enumerate the final facade members and prove both source and bundle surfaces;
- specify the runtime factory, bindings and state lifetimes;
- provide the complete API/allowed-edge tables and SCC rejection rule;
- define four-surface canonicalization, including HTML export; and
- map every transport and protocol state to suites and equivalence fixtures.

Once those artifacts exist, round 3 can review their completeness and internal
consistency. There is no value in another permission cycle before Code writes
them.

---

## 12. Round 3 review — 2026-08-27

**Reviewed branch head:** `569c9df` (`Prepare the round three review handoff`)

**Reviewed artifacts:** spec `0.4 (Draft)`, the revised implementation plan,
the esbuild legacy-bundle spike capture, and the current `v0.5.0` code and test
harnesses cited by them.

**Disposition:** **changes requested before `1.0 (Final)`.** Revision `0.4` is
a substantial improvement: the measured spike supports the build-first phase,
the four-boundary transport model is faithful, HTML report parity is restored,
and the metafile/source-map checks correctly carry the co-location acceptance
criterion. The remaining findings are not requests for another architecture
reset. They are contradictions and proof gaps in the mechanisms meant to make
the refactor safe.

### R3-F1 — P0 — The fixture-identity assertion cannot detect the substitution it is meant to catch

**Locations:** spec Design §11 and Testing item 5; implementation plan Task
2.1; [`tools/scoring.test.mjs:21`](tools/scoring.test.mjs) and lines 485–487.

The proposed behavioral fingerprint says that with the four-rule fixture table,
`getOrganizationalDomain('a.b.ck')` produces a result the real 10,239-rule PSL
cannot produce. That claim is false. The fixture contains `*.ck` and `!www.ck`
because those are real PSL rules. I loaded `js/dns.js` once with the fixture and
once with `js/public-suffixes.js` and reproduced:

```text
                         four-rule fixture     real PSL
a.b.ck                   a.b.ck                a.b.ck
a.www.ck                 www.ck                www.ck
```

The proposed contract therefore stays green when the real PSL replaces the
fixture — exactly the failure it is supposed to make loud.

A discriminator using a rule present in the real list and absent from the
fixture does work. For example, on the reviewed commit:

```text
foo.blogspot.com         blogspot.com          foo.blogspot.com
x.github.io              github.io             x.github.io
```

There is a second gap: one PSL assertion does not establish the identities of
the DKIM selector catalog and English bundle. The spec says all three generated
inputs receive the same treatment, but specifies no behavioral fingerprint for
the latter two.

**Required change:** replace the PSL probe with at least one verified divergent
case and record both expected results. Define a separate behavioral identity
probe for every generated binding a suite supplies. The contract should fail
when any one of the PSL, selector catalog or English bundle is silently replaced
while the other two remain correct.

### R3-F2 — P0 — The implementation plan still enables the colliding `globalName` in Phase 1

**Locations:** implementation plan Task 1.4; spec Design §6 and §10.

Spec `0.4` correctly says Phase 1 must omit `globalName`; the spike verified
that configuration. The plan still instructs the implementer to configure
`globalName: 'DnsAudit'` in Task 1.4, before a facade exists. As the spec itself
explains, that generated assignment overwrites the real object created by
`js/dns.js` and breaks the application on the delivery-boundary commit.

The sentence “where they disagree, the spec wins” is not a mitigation in a
document whose stated purpose is to say what to type and in what order.

**Required change:** Task 1.4 must say `globalName` is omitted. Add explicit
Phase-2 tasks for facade creation, source-and-bundle member assertions, enabling
`globalName`, and removing the legacy `DnsAudit` assignment in that order.

### R3-F3 — P1 — The state matrix is incomplete and cannot be self-policing by the stated extraction rule

**Locations:** spec Design §12, Testing item 3 and Acceptance criteria;
implementation plan Task 0.6.

The seed already demonstrates the extractor problem. It claims seven DNSSEC
chain claims, but the current code has nine. Two are computed at
[`js/dns.js:4077`](js/dns.js):

```js
'ds-' + record.match
```

with reachable values `ds-no-matching-key` and `ds-digest-mismatch`. Neither is
in the seven-member list. Other current algebras are not seeds at all, including
external-report authorization's `authorized` / `unauthorized` /
`unverifiable` / `override-mismatch` states and DMARC's operator-visible status
set. Boolean, nullable and absence-based result shapes cannot be discovered by
extracting string discriminants.

Deferring DKIM, CAA, MX, BIMI and transport-family enumeration until Phase 4 is
also circular. Gate 0's corpus is supposed to prove the refactor covers the
existing behavior before extraction begins; it cannot do that if its state
inventory becomes complete only while the code is being extracted.

**Required change:** inventory every current owner and result shape before Gate
0 corpus capture and before any application move. Define what the extractor can
soundly recognize. Computed members must be expanded explicitly; thrown errors,
nullable states, boolean axes and meaningful combinations need named rows or
targeted schema contracts. A static literal scan may be defense in depth, but it
cannot be called proof of exhaustiveness. The partial Phase-4 placeholders must
not remain in `1.0 (Final)`.

### R3-F4 — P1 — Cache construction has two incompatible ownership models

**Locations:** spec Correction 3 and Design §11; implementation plan Task 3.2.

Correction 3 and Task 3.2 say the cache factory is invoked once at ESM module
scope. Design §11 says the cache is constructed by `createAuditRuntime()`, that
tests obtain isolation by constructing a fresh runtime, and that a suite needing
different generated data calls the factory again. Both cannot be true: a
module-scope cache is shared by every runtime in the process and makes a fresh
runtime only superficially fresh.

Page lifetime does not require module-global ownership. It requires the browser
composition root to create one production runtime for the page.

**Required change:** the cache factory returns a new cache per runtime; the
production `src/main.js` constructs one runtime once, while each suite can
construct its own. Assert both properties: sibling audits through one runtime
reuse the cache, and two runtimes do not share it.

### R3-F5 — P1 — The composition root and allowed-edge matrix are not yet implementable as a complete graph

**Locations:** spec target tree, Design §11 and §12; implementation plan Phase
2.

The factory is load-bearing but has no owning file in the target tree and no
task that creates it. `src/main.js` is said to call `createAuditRuntime()`, but
the plan only converts `js/app.js` into `src/main.js`. This leaves it unclear
whether importing the source facade in a test also mounts the browser UI as a
side effect.

The edge table also contradicts the injection contract: it allows
`src/i18n/` to import `src/data/locales-en.js`, while §11 says the English
bundle is passed and never imported by its consumer. `providers/` has no row;
the platform binding has no location; and the UI-to-audit relationship is not
specified as an import or injected callback. The platform shape omits primitives
the present resolver uses directly — `setTimeout`, `clearTimeout` and
`URLSearchParams` — while including an unused `now` binding.

**Required change:** add the runtime/composition module to the tree and plan,
state whether it is side-effect-free, and give it an API row. Complete the
matrix for `providers`, platform, composition and UI event wiring. Remove the
i18n-to-data edge if English is injected, or revise the injection claim and its
fixture proof. Enumerate the actual platform primitives and who receives them.
The per-directory API tables also need an explicit creation/update task in each
extraction phase; an acceptance criterion alone will not produce them.

### R3-F6 — P1 — The five-surface baseline does not bind all baseline inputs or nondeterminism

**Locations:** spec Design §8; implementation plan Tasks 0.4.b–c.

The capture command supplies only `../dea-v050/js` as the baseline root. The
HTML surface embeds stylesheet bytes from `css/style.css`, the DOM begins with
`index.html`, and localization uses generated English data. Unless the runner
binds those assets to the tag as well, the “v0.5.0” observation can silently be
a mixture of baseline JavaScript and current-branch HTML, CSS or locale data.

The HTML export also includes `new Date().toLocaleString(i18n.lang)`. Exact text
comparison needs a frozen clock and locale environment, or a specific manifest
exclusion; the current rules name neither. A generated timestamp will otherwise
make the supposedly deterministic baseline differ on every run.

**Required change:** make each subject a repository/artifact root, not merely a
JavaScript directory, and record exactly where its HTML, CSS, locale data and
source map come from. Freeze clock and locale-dependent formatting for the
runner, or enumerate the timestamp as a narrowly justified exclusion. Keep the
strict canonicalization policy otherwise; its refusal to round floats, reorder
arrays or normalize security-sensitive bytes is appropriate.

### R3-F7 — P1 — The plan still carries the resolver model that `0.4` withdrew

**Locations:** spec target tree and Design §3; implementation plan Tasks
3.3–3.5 and “What this plan deliberately does not do.”

Task 3.3 still instructs extraction of *“the five-way distinction from
resilient-optional-checks”*. The target tree likewise describes
`core/dns/errors.js` as “transport-failure vs absent vs invalid.” Both repeat
the layer confusion `0.4` explicitly corrects. Task 3.5 then tests one closed
resolver algebra without assigning the usability gate, normalized-record API,
optional-check policy and direct-kind exception edges to files and contracts.

The same section says “No audit cancellation,” although cancellation already
exists through `AbortController` and `optionalCheck()` deliberately rethrows it.
Read literally, that is a behavior regression, not a non-goal.

**Required change:** rewrite Phase 3 around the four processing boundaries plus
named exception edges, including the retry/cache and rethrow contracts. Change
the non-goal to **no change to existing audit cancellation behavior**. Remove
the stale “five-way” language everywhere, including the target-tree comment.

### R3-F8 — P2 — The two-member facade is valid for repository consumers, not proof that the removed globals have no consumers

**Locations:** spec Design §10 and Risk R8.

The call-site inventory supports a two-member facade for the application in
this repository. It cannot establish that the 14 `js/app.js` globals or the
other 93 `DnsAudit` members have no external consumer: a static site can be
driven by console scripts, browser extensions or embedding pages that do not
exist in this checkout. “No repository consumer” is verified; “dead” is a
compatibility policy.

The proposed two-member facade is therefore acceptable only if the project
explicitly declares the legacy globals unsupported. Their removal should be a
named, deliberate compatibility delta in the equivalence manifest, changelog
and release notes. If compatibility is intended, retain an adapter for the
documented transition instead. A separate commit makes the delta reviewable but
does not itself authorize it.

## 13. Requested round 3 verdicts

### API and allowed-edge tables

**Not complete yet.** Apply R3-F5. The no-sibling-protocol rule and SCC rejection
are good, but the graph lacks owners and contradicts the generated-data binding
contract.

### State matrix

**Static extraction is not sufficient as specified, and the enumerations must
be complete before Gate 0.** Apply R3-F3. The computed DNSSEC claims are a
concrete counterexample, not a hypothetical limitation.

### Composition contract

**Directionally correct, internally inconsistent.** Injection through the real
production path is the right design. Resolve cache ownership, give the factory
an owning module, and provide a behavioral identity check per generated input.

### Facade

**Two members are sufficient for known repository consumers.** Treat removal of
the legacy surface as an explicit compatibility decision, not as a fact proved
by grep.

### Canonicalization

**The strictness is appropriate.** It is safer to surface noise and justify a
narrow tolerance than to begin with broad normalization. Bind every baseline
asset to `v0.5.0` and control the timestamp/locale inputs per R3-F6 before the
rules can serve as an executable gate.

## 14. Required next revision

Before `1.0 (Final)`:

1. Replace the ineffective fixture fingerprints and cover all three generated
   bindings.
2. Reconcile the implementation plan with the no-`globalName` legacy phase and
   the four-boundary resolver model.
3. Complete the pre-refactor state/result-shape inventory and define a sound
   enforcement strategy.
4. Make cache ownership consistently per-runtime, with one runtime per browser
   page.
5. Give the runtime factory, platform, providers and UI wiring explicit homes,
   APIs and allowed edges.
6. Bind the equivalence runner to complete subject roots and deterministic time
   and locale inputs.
7. Record the compatibility policy for removing the legacy global surface.

After those corrections, the design is close to final. Linux `npm ci` remains
a Gate 1 requirement, as the round-three request states; this review does not
reinterpret the darwin-arm64 spike as cross-platform evidence.

---

## 15. Round 3 resolution and final approval — 2026-08-27

At Ian's direction, Codex applied the round-three findings directly rather than
returning them for another author/reviewer cycle.

| Finding | Resolution in spec `1.0` and the synchronized plan |
| --- | --- |
| R3-F1 | Replaced `a.b.ck` with the verified divergent `foo.blogspot.com` PSL probe; added independent fixture-only DKIM-catalog and English-bundle fingerprints. |
| R3-F2 | Phase 1 now explicitly omits `globalName`; Phase 2 contains the ordered facade, assertion, boundary-enable and legacy-assignment removal tasks. |
| R3-F3 | Added the complete pre-refactor §12.1 inventory, including nine DNSSEC claims, thrown paths, computed values, booleans, nullability and absence. Removed the claim that static extraction is exhaustive and prohibited Phase-4 deferral. |
| R3-F4 | Cache ownership is per runtime; `src/main.js` constructs one runtime per page. Tests assert reuse within a runtime and isolation between runtimes. |
| R3-F5 | Added side-effect-free `runtime.js`, `platform/browser.js`, full platform primitives, missing edge rows, UI callback direction and per-owner `API.md` tasks. English is injected rather than imported by i18n. |
| R3-F6 | Equivalence subjects are complete roots with input hashes, Node/ICU metadata and fixed time/locale inputs. The strict canonicalization ruling is retained. |
| R3-F7 | Phase 3 now implements the ten-kind raw layer, usability gate, normalized records, optional-check policy and named direct-kind edges. The stale five-way model is gone; cancellation is explicitly preserved. |
| R3-F8 | The two-member facade is the supported 0.6.0 browser API. Legacy globals are declared unsupported, and their removal is an authorized manifest/changelog/PR compatibility delta in its own commit. |

**Final disposition:** **approved for implementation as `1.0 (Final)`.** Linux
`npm ci`, the lockfile footprint and postinstall policy remain mandatory Gate 1
evidence. They do not reopen the design and were not fabricated on a macOS
machine.

---

## 16. Implementation finding — §11's primitive set is incomplete — 2026-08-27

**Raised during Phase 2, Task 2.4. Framework §6 trigger 5: a spec defect.**
A Final spec found wrong is amended and re-versioned, never quietly diverged
from (`docs/specs/README.md`).

### The finding

Spec `1.0 (Final)` §11 states:

> The browser platform object names every ambient primitive used by the moved
> code: `fetch`, `crypto`, `AbortController`, `URLSearchParams`, `setTimeout`,
> `clearTimeout`, `document`, `localStorage`, `URL`, `Blob`, `FileReader`,
> `Intl`, `console`, `now()` and `formatDateTime(date, locale)`.

**`navigator` is missing, and it is genuinely required.** `detectLang()` in the
i18n layer reads it three times to pick a language before any stored preference
exists:

```js
var preferred = (navigator.languages && navigator.languages.length)
  ? navigator.languages
  : [navigator.language || DEFAULT_LANG];
```

The claim "names **every** ambient primitive used by the moved code" is
therefore false as written. This was not found by reading the spec — it was
found by converting `js/i18n.js` in Task 2.2, where the module stopped being
able to reach `window` and every ambient dependency had to be named. Nineteen
call sites needed `document`, `localStorage`, `fetch`, `console` and
`navigator`; four of those five were on the list.

### Why it matters rather than being a typo

The list is not decoration. It is the enumeration §11 rests on, and two
acceptance criteria depend on it being complete:

- *"`src/runtime.js` is side-effect-free; importing it neither mounts the UI nor
  performs network I/O"* — a module reaching for an unlisted ambient primitive
  is exactly the leak that criterion forbids;
- *"The namespace contract holds: no `src/` module touches any of the 24 globals
  outside a marked adapter"* — the same shape of rule, one layer down.

Implementing the incomplete list would have left i18n reading `navigator`
ambiently while every other primitive was injected: a module that is *almost*
isolated, which is the state that makes a later leak invisible.

### Decision — approved by Ian, 2026-08-27

**`navigator` belongs in the injected browser platform. i18n must not read it
ambiently. The implementation is NOT to be altered to match the incomplete 1.0
list.** The spec is amended to `1.1 (Final)`.

The implementation already does the right thing: `src/platform/browser.js`
provides `navigator`, `PLATFORM_PRIMITIVES` declares it, and
`src/i18n/index.js` destructures it from `platform` rather than reaching for it.
`tests/contract/platform.test.mjs` asserts the set is complete against the
module's own declaration, so the spec and the code cannot drift again without a
test saying so.

### Scope of the amendment

Narrow, and deliberately so. This corrects an omission from an enumeration; it
changes no design decision, no phase ordering, no acceptance threshold and no
behaviour. Nothing else in `1.0` is reopened.

| Changed | Not changed |
| --- | --- |
| §11's exact primitive list gains `navigator` | Every other §11 rule |
| §12's `platform/` API row names it | The allowed-edge matrix |
| Acceptance criteria gain the completeness check | Every other criterion |
| Header version, revision history, spec index | The plan's task ordering |

Language built-ins remain required APIs rather than injectable services —
`navigator` is a host object, which is precisely the distinction §11 draws.

---

## 17. Evidence correction — "exhaustive by contract" overstated the check — 2026-08-27

**Raised by Ian against the `1.1` amendment itself. Spec `1.2 (Final)`.**

### The finding

§11 as amended in `1.1` said:

> The set is **exhaustive by contract**, not by inspection.

It is not, and the phrasing claims more than `tests/contract/platform.test.mjs`
delivers. What the contract actually establishes:

| Established | Not established |
| --- | --- |
| The spec list and `PLATFORM_PRIMITIVES` name the same set, asserted in both directions | That the set is complete |
| Every declared primitive is provided by a constructed platform | — |
| No module under `src/` reads a **known** ambient name outside the platform module and the marked adapters | That no module reads an **unknown** one |

Two limits, both real:

1. **The `AMBIENT` catalog is hand-written and bounded.** The scan can only
   reject names it already knows to look for. The `navigator` omission that
   produced the `1.1` amendment would **not** have been caught by it — that was
   found by converting `js/i18n.js`, where the module stopped being able to
   reach `window` and every dependency had to be named.
2. **A regex is not scope analysis.** It does not model scope, shadowing,
   computed member access or aliasing.

### Why this matters more than the wording

It is the same shape of error this project has now corrected three times: a
check described as stronger than it is. The spike's `1535 passed, 0 failed`
against a swapped public suffix list; the `a.b.ck` probe that would have passed
under the substitution it existed to catch; and now a completeness claim in a
paragraph written *to correct a completeness failure*. The correction is worth
making precisely because the sentence was in the amendment.

### Decision — approved by Ian, 2026-08-27

Keep the test; it is genuine defense in depth against regression. Stop calling
it exhaustive proof.

- §11 now reads "reviewed during conversion, synchronized bidirectionally, and
  guarded against the known ambient catalog", with a table of what is and is not
  established.
- The lexical scan is stated as defense in depth, **not** exhaustive JavaScript
  name-resolution analysis, and the completeness of the list is attributed to
  the conversion review that produced it.
- The acceptance criterion is reworded to match.
- Test comments adjusted so the file does not claim in code what the spec no
  longer claims in prose.

**No parser and no dependency added.** `OQ-ARCH-01` bought exactly one
development dependency and this is not a good reason to spend another. No
architecture or implementation decision is reopened, and no behaviour changes.

---

## 18. `window.open` — the last ambient found by the conversion sweep — 2026-08-27

**Raised before Task 2.6. Spec `1.3 (Final)`.**

### The finding

`js/app.js:385`, in `openLearnMore()`:

```js
var url = URL.createObjectURL(new Blob([html], { type: 'text/html' }));
global.open(url, '_blank', 'noopener');
setTimeout(function () { URL.revokeObjectURL(url); }, 60000);
```

`window.open` is an ambient primitive the moved code uses, and §11 did not name
it. One call site.

### Found by sweeping, not by tripping over it

`1.2` recorded that the completeness of §11's list rests on the conversion
review rather than on the lexical contract. So `js/app.js` — the only
unconverted file left — was swept **before** Task 2.6 began, enumerating its
full ambient set rather than discovering omissions one at a time:

| Used by `js/app.js` | On the §11 list |
| --- | --- |
| `document`, `fetch`, `setTimeout`, `Blob`, `FileReader`, `URL`, `AbortController`, `Intl` | all eight |
| `open` | **missing** |

**This is the last such finding, because there is no further legacy source to
sweep.** That is a statement about the source tree being exhausted, and
explicitly **not** a claim that the lexical contract in
`tests/contract/platform.test.mjs` is exhaustive — that contract could not have
found `open` either, for exactly the reasons `1.2` records.

### Decision — approved by Ian, 2026-08-27

`window.open` is a browser capability and belongs in the injected platform for
this phase.

- Added to §11, §12's platform API row, the acceptance criteria,
  `PLATFORM_PRIMITIVES`, `SPEC_11` and the known-ambient catalog.
- Implemented as `win.open.bind(win)`. A bare `open` lifted off `window` throws
  `Illegal invocation` in a browser, as `fetch` and `setTimeout` do.
- A receiver-sensitive contract asserts it works when destructured off the
  platform, and that the **exact** `url`, `_blank` and `noopener` arguments
  reach the window in order. `noopener` is the one that matters: without it the
  opened page holds a reference back through `window.opener`, and no other
  assertion in the suite would have noticed it being dropped.
- The 60-second `revokeObjectURL` timeout and every other behaviour are
  unchanged.

### Recorded for Phase 5

`open` is the first entry on §11's list that is a **navigation side effect**
rather than a data capability, and the platform is the security boundary
between `src/` and the browser. Splitting page construction from navigation is
architecturally reasonable, and **Phase 5 owns that decomposition** — `src/ui/`
is where it belongs. Doing it during Task 2.6 would put a behaviour-shaped
change inside a wrapper-only conversion, which §35 forbids. Its final UI-facing
abstraction is reconsidered then; it is not redesigned now.

### A consequence worth noting

Adding a primitive means every window a platform is constructed from must
provide it. Four test sandboxes had to gain `open` — and they failed **loudly**,
at construction, with `Cannot read properties of undefined (reading 'bind')`,
rather than degrading silently. That is the binding discipline from Task 2.4
paying for itself: a platform that tolerated a missing primitive would have
produced a runtime that worked until someone clicked "Learn more".
