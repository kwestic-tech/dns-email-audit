# Capture: Gate 1 evidence

| Field | Value |
| --- | --- |
| For | [modular-architecture-and-production-build](../modular-architecture-and-production-build.md) |
| Records | The Gate 1 conditions: the site is served from one built artifact and behaves identically |
| Captured | 2026-08-27 |
| Local platform | macOS (darwin arm64), Node v26.7.0, ICU 78.3, Unicode 17.0 |
| CI platform | Ubuntu 24.04.4 LTS, `Linux 6.17.0-1022-azure x86_64`, Node v26.7.0, npm 11.19.0 |
| CI run | [33058521236](https://github.com/kwestic-tech/dns-email-audit/actions/runs/33058521236) — all four jobs green |
| Baseline | `v0.5.0`, commit `5c08364cc3270101f07c2d1b925a6d584e551527` |

## Gate 1, as the plan states it

> The site is served from one built artifact and behaves identically. Parity,
> artifact and five-surface equivalence all green. Zero runtime dependencies.
> **No application code has moved yet.**

## Result

| Condition | Evidence |
| --- | --- |
| Served from one artifact | `index.html` has one `<script src>`: `dist/app.min.js` |
| Behaves identically | 30 cases, 5 surfaces, **0 differences**, on macOS and on Linux, against both the working tree and `_site/` |
| Parity | `tests/build/parity.test.mjs`, 34 assertions |
| Artifact | `tests/build/artifact.test.mjs`, 43 assertions |
| Zero runtime dependencies | `"dependencies"` is absent; one exact-pinned `devDependency` |
| No application code moved | `git diff main...HEAD -- js/` is empty |
| Linux `npm ci` | Native Ubuntu runner, no `--os` substitution |
| `file://` | Real headless Chrome 151, 21 assertions |

## 1. Native Linux `npm ci` — the outstanding Gate 1 measurement

The `OQ-ARCH-01` spike measured darwin-arm64 only, and the dependency footprint
is platform-specific by design. `npm ci --os=linux --cpu=x64` on a Mac proves
the lockfile *resolves*; it proves nothing else, and it is not what this
records. **This ran on a real Linux runner with no platform substitution.**

```text
uname:  Linux 6.17.0-1022-azure x86_64
distro: Ubuntu 24.04.4 LTS
node:   v26.7.0
npm:    11.19.0
arch:   linux-x64
```

| Measure | Result |
| --- | --- |
| `npm ci` | `added 2 packages, and audited 3 packages in 545ms` |
| Platform packages installed | **exactly 1**, and it is `@esbuild/linux-x64` |
| Total packages in the tree | 3 (`esbuild`, `@esbuild/linux-x64`, the root) |
| `allowScripts` | `esbuild denied, as recorded` — asserted from `package.json`, not trusted |
| esbuild executes | `esbuild 0.28.2 ran with its install script denied` |
| Test suite | 11 suites, **2,514 assertions**, 0 failed |
| Production build | succeeded |
| Deployment artifact test | 43 passed |
| Locale gate | 13/13 |

**The install script never runs, on any platform, and the build works anyway.**
That is the strongest available position for a first dependency: the binary
comes from the optional platform package, and `install.js` is not needed to
obtain it. The decision is recorded as `"allowScripts": { "esbuild": false }`
and CI asserts the setting is still what it claims.

Spec Risk R3 and `OQ-ARCH-01` are discharged: the darwin-arm64 result and the
Linux result agree — 2 packages, 1 install script, 26 declared optional platform
packages, exactly one of them resolved per platform.

### The declared engines floor

`package.json` declares `engines: node >=18`. A separate job runs `npm ci`,
`npm test` and `npm run build` on **Node 20**: 11 suites green, build
successful. Kept separate so a floor problem reads as itself rather than as a
supply-chain failure.

## 2. `file://` in a real browser

`js/locales-en.js` states in its own generated header that English is inlined
"so the app works when index.html is opened directly from disk (file://), where
fetching `locales/*.json` is blocked by the browser". `OQ-ARCH-06` chose an IIFE
bundle over an ES module for the same reason: a module script is fetched with
CORS, which `file://` refuses outright.

**Structural reasoning was not accepted as evidence for this.** The check drives
a real browser engine at a real `file://` URL over the DevTools Protocol, using
Node's built-in `WebSocket` so no dependency is added — the release ships
exactly one. It **refuses to skip** when no browser is present: a `file://`
check that quietly passes without running is worth less than none.

Verified locally (Chrome on macOS) and on CI (`Google Chrome 151.0.7922.137`,
`/usr/bin/google-chrome`), 21 assertions each:

| Asserted | Result |
| --- | --- |
| The page is really on `file://` | `location.protocol === 'file:'` |
| One classic script | `dist/app.min.js`, and **no** `type="module"` |
| The application initialised | 12 probed globals, `DnsAudit` at 95 members, 10,239 PSL rules |
| Scoring weights intact | identical to source |
| i18n resolved **with no network** | `t('doc.title')` returns the real product name, the document title was translated in place, the audit button reads "Run Audit", and 20+ nodes carry `data-i18n` |
| Real computation ran | the PSL-reading org-domain walk and the DER key walk, both correct |

`--allow-file-access-from-files` is deliberately **not** passed. The point is
that the app works under a browser's ordinary `file://` restrictions, not that
it works when they are lifted.

## 3. Parity — the artifact behaves like its source

Spec correction 6: every pre-existing test loads *source* and the browser is
served the *bundle*. "Build success" means esbuild exited zero.

`tests/build/parity.test.mjs` loads the real `dist/app.min.js` — asserted to be
the file `index.html` names and `_site/` publishes, not a test-only build — and
compares it with the seven sources:

| Compared | Source | Bundle |
| --- | ---: | ---: |
| Globals created | 24 | **24**, identical set |
| `DnsAudit` members | 95 | **95**, identical |
| `__APP_TEST__` members | 30 | **30**, identical |
| `WEIGHTS`, `PARKED_WEIGHTS`, `GRADE_THRESHOLDS`, `POLICY_RANK` | — | byte-identical |
| Public suffix rules | 10,239 | 10,239 |
| Inlined English bundle | present | present |

Behaviour is compared too, not just names: `getOrganizationalDomain` reads the
bundled PSL and `analyzeDkimKey` runs the DER walk, both of which would break
quietly under a tree-shaking or minification fault while every name still
matched.

**The bundle introduced no global of its own**, which is the assertion that
would have caught the mistake spec version 0.2 nearly shipped — `globalName` is
omitted until §10 stage 3 precisely because esbuild assigns the *entry point's
exports* to it, and an entry with none would have emitted a `var DnsAudit` that
overwrote the real object.

Negative control: an altered artifact fails the constants comparison, and an
extra global is caught.

## 4. The deployment artifact

`tests/build/artifact.test.mjs`, both directions:

- `_site/` holds **exactly** `CNAME`, `LICENSE`, `THIRD_PARTY_NOTICES.md`,
  `css/`, `dist/`, `index.html`, `locales/` — asserted as a set;
- absent: `src/`, `tools/`, `tests/`, `docs/`, `node_modules/`, `js/`,
  `assets/`, `package.json`, `package-lock.json`, `AGENTS.md`, `CLAUDE.md`;
- absent by pattern at any depth: test files, stray source maps, markdown
  beyond the notice, `locales/translation-status.json`, JSON outside `locales/`;
- every `<script src>`, `<link href>` and the source-map link resolves inside
  `_site/`;
- **co-location safety is bound to `metafile.inputs` and the source map's
  `sources`**, not to a sentinel (round 2, R2-F7). The inputs are exactly the
  entry point and the seven legacy scripts; nothing under `tests/`, `tools/` or
  `node_modules/` appears in either.

It found two things on its first run, which is what it is for:

1. **The build metafile was being published.** `dist/` is copied wholesale into
   `_site/`, so writing `dist/metafile.json` shipped a size manifest listing
   source paths. It moved to `.build/`, so `dist/` now contains only the two
   files that ship and the deploy allowlist needs no per-file skip entry — a
   judgment call kept out of the place this project keeps them out of.
2. **A source-map assertion assumed a 1:1 correspondence with inputs.**
   `src/entry-legacy.js` contributes no code, so esbuild leaves it out of
   `sources`. The real invariant is that every mapped source is an input.

## 5. Five-surface equivalence

Against the committed `v0.5.0` baseline, **30 cases, 5 surfaces, 0 differences**,
in four configurations:

| Subject | Platform | Result |
| --- | --- | --- |
| Working tree | macOS | 0 differences |
| `_site/` | macOS | 0 differences |
| Working tree | Linux CI | 0 differences |
| `_site/` | Linux CI | 0 differences |

And the committed baseline **regenerates byte-identically on Linux** from a
`v0.5.0` worktree — so it is reproducible across platforms, not just repeatable
on the machine that made it.

Subject-input hashes are reported as **provenance**, never counted as
differences. The subject under test is by definition not the one the baseline
was captured from: Task 1.6 replaced seven script inputs with one, and every
Phase 2 commit will change them again. Gating on them would have produced a
permanent false stop from the delivery-boundary commit onward. What is asserted
instead is that the manifest is *complete* — every script, stylesheet and
`index.html` hashed, and nothing else — that re-reading one subject produces
identical hashes, and that a one-byte change to an input moves exactly one.

### The oracle still validates something

From the delivery-boundary commit onward the runner loads the artifact, so a
validator that mutated `js/` without rebuilding would be measuring an artifact
the mutation never reached — every mutation reporting "moves nothing", a green
run proving nothing. `tests/build/equivalence.validate.mjs` now **builds every
root it makes**, and carries the negative control that keeps that honest:

- a mutation that is **not** rebuilt moves **no** surface;
- the same mutation, rebuilt, moves the result surface.

All seven mutations are still caught on exactly the surfaces they should be and
on no others, now through the shipped artifact.

## 6. Bundle size — reported, never enforced

| | v0.5.0 | 0.6.0 | Change |
| --- | ---: | ---: | ---: |
| Files fetched | 7 | **1** | −6 |
| Raw | 719,199 | **431,102** | **−40.1%** |
| gzip | 213,467 | **130,417** | **−38.9%** |

Composition, by contribution to the output:

| Bytes | Share | Input |
| ---: | ---: | --- |
| 160.7 KB | 38.2% | `js/public-suffixes.js` |
| 112.8 KB | 26.8% | `js/locales-en.js` |
| 79.0 KB | 18.8% | `js/dns.js` |
| 38.8 KB | 9.2% | `js/app.js` |
| 17.8 KB | 4.2% | `js/dkim-selectors.js` |
| 6.1 KB | 1.5% | `js/render.js` |
| 5.5 KB | 1.3% | `js/i18n.js` |
| 0.0 KB | 0.0% | `src/entry-legacy.js` |

Two thirds of the artifact is generated data. That is the measurement
`OQ-ARCH-05` will want when the bundle split is revisited, and it is why the
split was deferred rather than guessed at.

Build time: 55 ms on Linux, 639 ms cold on macOS. The source map is 1,015.7 KB
and is **excluded from the transfer figure** per `OQ-ARCH-04` — it is fetched
only when a developer opens the tools.

> **The raw size is a property of the artifact; the gzip size is not.** Raw is
> byte-identical across platforms at 431,102. gzip measured 130,466 on macOS and
> **130,417** on Linux — a 49-byte difference from the local zlib, not from the
> bundle. Size is reported and never enforced, and this is one concrete reason
> why: an assertion on the gzip figure would fail across platforms while nothing
> about the shipped bytes had changed.

## 7. Why Tasks 1.6, 1.7 and 1.8 landed together

Framework §2 says the delivery-boundary commit should be "that change and
nothing else. No config tweak riding along." Framework §1 rule 1 says the
browser works at **every** commit. Here the two pull apart, and rule 1 wins:

- **1.6 alone breaks the deployed site.** `tools/build-site.mjs` still copied
  `js/` and not `dist/`, so `_site/index.html` would reference a file the
  assemble never produced — a published site whose only script 404s.
- **1.6 without 1.8 leaves the suite red.** `tools/csp.test.mjs` §3 asserts what
  the markup says, and it said seven scripts.

The three are one responsibility — moving the delivery boundary — and §2's
warning is about *unrelated* changes riding along. Approved after the fact by
Ian, 2026-08-27, and recorded here rather than left in a commit message:
keeping the browser and the suite functional at every commit is the stronger
invariant, and the three changes form one atomic transition.

Section 1's policy assertions, section 2's JSON-LD hash and section 5's exported
report policy in `tools/csp.test.mjs` are **byte-identical** — verified by
diffing them against the previous commit, not by intending it.

## 8. The assertion inventory

| Suite | v0.5.0 | Gate 1 |
| --- | ---: | ---: |
| `tools/check-locales.mjs` | findings | findings |
| `tools/scoring.test.mjs` | 1,535 | 1,535 |
| `tools/interpolate.test.mjs` | 17 | 17 |
| `tools/render.test.mjs` | 329 | 329 |
| `tools/export.test.mjs` | 199 | 199 |
| `tools/csp.test.mjs` | 41 | **49** |
| `tests/contract/legacy-shapes.test.mjs` | — | 125 |
| `tests/contract/canonicalization.test.mjs` | — | 108 |
| `tests/contract/state-matrix.test.mjs` | — | 22 |
| `tests/build/parity.test.mjs` | — | 34 |
| `tests/build/artifact.test.mjs` | — | 43 |
| `tests/build/equivalence.validate.mjs` | — | 53 |
| **`npm test`** | **2,121** | **2,514** |
| `tests/build/file-url.test.mjs` (own job) | — | 21 |

Nothing was removed. `tools/csp.test.mjs` gained 8 and its §1, §2 and §5 are
unchanged. Every area is recorded in `tests/inventory.json` and enforced by
`npm run inventory`, which also asserts that `npm test` runs exactly the suites
the inventory names.

## 9. Carried forward

- **No application code has moved.** `js/` is byte-identical to `v0.5.0`, and
  `src/` holds one file: seven side-effect imports with no exports of its own,
  asserted so by `state-matrix.test.mjs` — which is the property that keeps
  omitting `globalName` safe.
- **The legacy-globals compatibility delta is still ahead**, in Phase 2 Task
  2.8. Removing the 14 `js/app.js` function globals proves *no repository
  consumer*, not *no consumer*. It is an authorized decision needing its own
  commit, a named entry in the equivalence manifest, and a note in the changelog
  and the PR body. Framework §9 records it as the item most likely to be quietly
  forgotten; recording it here too.
- **A repository-hygiene note, out of scope for this release.** GitHub now warns
  that `actions/checkout` and `actions/setup-node` at their pinned v4 SHAs
  target the deprecated Node 20 action runtime and are being forced onto Node
  24. The pins are correct and the actions still run; moving to v5 SHAs is a
  separate change, and this release does not make it.
