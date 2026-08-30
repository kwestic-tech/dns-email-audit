# Capture: esbuild legacy-bundle spike

| Field | Value |
| --- | --- |
| For | [modular-architecture-and-production-build](../modular-architecture-and-production-build.md) |
| Settles | `OQ-ARCH-01`, and the round-2 condition that the spike run before build behavior is presented as verified |
| Captured | 2026-08-27 |
| Platform | macOS (darwin arm64), Node v26.7.0, npm with `allowScripts` gating |
| esbuild | 0.28.2, exact-pinned |
| Baseline | `main` at `v0.5.0`, seven classic scripts |

Captures go stale. This one states its platform and tool versions because both
are load-bearing: the dependency footprint is platform-specific by design, and
esbuild's behavior is version-specific.

## Question

Can esbuild bundle the seven **unmodified** IIFEs — which communicate through
`window` and have no imports or exports — into one classic script that behaves
identically? Phase 1 of the implementation plan assumes yes. Until this ran, that
was reasoning, not evidence.

## Method

`entry-legacy.js` containing seven side-effect imports in `index.html` load
order, bundled with `--bundle --format=iife --minify --target=es2020`. No
`globalName` (per R2-F1). Both the seven source files and the bundle were then
loaded into a `node:vm` context backed by `tools/lib/dom-shim.mjs`, and their
global surfaces compared.

## Result 1 — the legacy bundle works

| Measure | Source | Bundle | |
| --- | --- | --- | --- |
| Globals created | 24 | 24 | identical set; none missing, none extra |
| `DnsAudit` members | 95 | 95 | identical |
| `WEIGHTS` | — | — | identical |
| `GRADE_THRESHOLDS` | — | — | identical |
| `__PUBLIC_SUFFIX_RULES__` | 10,239 | 10,239 | present |

Build time: 22 ms.

**Phase 1 is viable as specified.** The side-effect imports are preserved, the
`window` assignments still run, and no `globalName` collision occurs because
none was requested.

## Result 2 — the delivery win, measured

| | Raw | gzip |
| --- | ---: | ---: |
| Seven files at `v0.5.0` | 719,199 | 213,467 |
| One minified bundle | 430,750 | 130,256 |
| **Change** | **−40.1%** | **−39.0%** |

Seven requests become one. These are the numbers the spec should quote; the
0.5.0 figures were previously stated against an unmeasured target.

## Result 3 — the dependency footprint, measured

`OQ-ARCH-01` was recommended in spec `0.1` on the claim that esbuild has "zero
transitive dependencies". That was false, as round 1 found. The true footprint:

| Measure | Value |
| --- | --- |
| Direct dependencies | 1 (`esbuild`) |
| Packages actually installed on this platform | **2** — `esbuild` + `@esbuild/darwin-arm64` |
| Declared optional platform packages | 26, of which 25 resolve UNMET |
| Install scripts | **1** — `esbuild@0.28.2` runs `postinstall: node install.js` |

npm surfaced the postinstall itself:

```text
npm warn install-scripts 1 package has install scripts not yet covered by allowScripts:
npm warn install-scripts   esbuild@0.28.2 (postinstall: node install.js)
```

Two packages and one install script is a small supply chain, and esbuild remains
the right choice. It is not zero, and the spec must not say so. The `allowScripts`
gate is worth an explicit decision in CI rather than an implicit allow.

## Result 4 — the PSL hazard is real, and silent

Round 2's F3 predicted that a bundled `public-suffixes.js` would overwrite the
four-rule fixture table `tools/scoring.test.mjs:21` injects, and that **the suite
would still report 1,535 passing assertions while testing something else**.

Reproduced exactly:

```text
injected before load : 4
in force after load  : 10239
```

And the suite, run against the bundle with the real 10,239-rule list silently
substituted:

```text
1535 passed, 0 failed
```

Identical to the source baseline. **Nothing failed. Nothing warned.** The
assertion count was unchanged, which is the clearest possible demonstration that
a count is not a coverage signal — round 2's F8, and round 1's F3, both
confirmed by measurement rather than argument.

This is the single most important result here. It means:

- generated data must reach modules through an injectable binding at the
  composition root, never a static import that a bundle can satisfy on its own;
- a contract test must assert **behaviorally** that the fixture table is the one
  in force during a suite — a count or a green run proves nothing; and
- the same class of hazard applies to any generated input, so
  `__DKIM_SELECTOR_CATALOG__` and `__I18N_EN__` need the same treatment.

## Result 5 — `file://` is a deliberate, paid-for property

Not the question asked, but it settles `OQ-ARCH-06` more firmly than the
argument did. The header of the generated `js/locales-en.js` states:

> *"English is inlined here so the app works when index.html is opened directly
> from disk (`file://`), where fetching `locales/*.json` is blocked by the
> browser."*

125,172 bytes — 37,678 gzip, roughly 18% of the current payload — exist for no
other reason. `file://` support is not incidental; it was bought and paid for.

Round 1 answered `OQ-ARCH-06` "loss accepted and documented", which would have
discarded that investment while continuing to ship the file that funds it. IIFE
output keeps both. The comments round 1 proposed deleting as "stale promises of
`file://` fallback" are not stale, and must stay.

## Consequences for the spec

1. `OQ-ARCH-01` resolves to esbuild on measured evidence. Risks R3 takes the
   two-package/one-install-script figures.
2. Phase 1 is confirmed viable; the phase order stands.
3. Design §6 takes the −40% / −39% figures.
4. The composition-root section (R2-F3) is not optional — Result 4 is what it
   exists to prevent.
5. `OQ-ARCH-06` resolves to IIFE, now with Result 5 behind it.
6. Linux CI verification is still outstanding: this ran on darwin-arm64 only,
   and the footprint is platform-specific.

---

## Addendum, 2026-08-27 — the dependency as installed

Task 0.2 asks for the spike's footprint to be folded in once the dependency
actually exists. It now does. Every figure below was reproduced by installing
it, not carried over from the spike.

| Measure | Spike | As installed |
| --- | --- | --- |
| Packages on darwin-arm64 | 2 | **2** — `esbuild`, `@esbuild/darwin-arm64` |
| Declared optional platform packages | 26 | **26** |
| Install scripts | 1 | **1** — `postinstall: node install.js` |
| Vulnerabilities reported | — | 0 |

### The `allowScripts` decision, recorded

Spec acceptance criterion: *"The `postinstall` script's treatment under npm's
`allowScripts` gate is an explicit, recorded CI decision."*

npm 11.19.0 does not run the script by default. It warns:

```text
npm warn install-scripts 1 package has install scripts not yet covered by allowScripts:
npm warn install-scripts   esbuild@0.28.2 (postinstall: node install.js)
```

**esbuild works with the script denied.** Verified, not assumed: with the
postinstall never having run, `require('esbuild').version` reports `0.28.2` and
`buildSync` produces correct output. The platform binary comes from the optional
package `@esbuild/darwin-arm64`, and `install.js` is not needed to obtain it.

So the decision is **deny**, recorded in `package.json`:

```json
"allowScripts": { "esbuild": false }
```

A subsequent `npm ci` is then clean — no warning, 2 packages, esbuild functional.
This is the strongest available position for a first dependency: the install
script never executes, on any machine, and the build still works.

### The lockfile

`package-lock.json` is committed as of this release and removed from
`.gitignore`. Version 3, **27 entries**, integrity hash on every one, and all
**26** platform packages present — so `npm ci` on any platform resolves its own
binary from a pinned, verifiable entry.

### Cross-platform resolution — what is and is not proven

`npm ci --os=linux --cpu=x64` against this lockfile resolves
**`@esbuild/linux-x64`**, 2 packages, same footprint as darwin-arm64, no
`allowScripts` warning.

**That proves the lockfile resolves for Linux. It does not prove `npm ci` on
Linux.** No container runtime was available on the capture machine, so nothing
here executed esbuild on Linux. Running the binary, and the footprint a real
Linux runner reports, remain **Gate 1 evidence from CI** — the spike's
darwin-arm64 result must not be presented as cross-platform, and neither must
this.
