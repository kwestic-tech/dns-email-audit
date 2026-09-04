# Maintenance backlog

Work that is real, that is not part of any release's spec, and that must not be
folded into one just because it was noticed while that release was in progress.

A release spec is a design argument with a scope. Slipping unrelated repair into
it makes the diff harder to review, the revert harder to reason about, and the
spec's own claims harder to check. Anything found in passing is filed here with
enough detail to act on without re-deriving it, per spec Risks R8.

Each entry records what was observed, verbatim where possible, and what was
deliberately **not** changed.

---

## GitHub Actions: pinned actions target the deprecated Node 20 runtime

**Found:** 2026-08-27, during the 0.6.0 Gate 1 CI run
([33058521236](https://github.com/kwestic-tech/dns-email-audit/actions/runs/33058521236)).
**Status:** open. **Deliberately not changed in 0.6.0.**

Every job in that run emitted this annotation:

```text
Node.js 20 is deprecated. The following actions target Node.js 20 but are being
forced to run on Node.js 24: actions/checkout@11d5960a326750d5838078e36cf38b85af677262,
actions/setup-node@49933ea5288caeca8642d1e84afbd3f7d6820020. For more information see:
https://github.blog/changelog/2025-09-19-deprecation-of-node-20-on-github-actions-runners/
```

### The pins, as they stand

| Action | Pinned SHA | Tag | Used by |
| --- | --- | --- | --- |
| `actions/checkout` | `11d5960a326750d5838078e36cf38b85af677262` | v4 | `.github/workflows/ci.yml`, `.github/workflows/pages.yml` |
| `actions/setup-node` | `49933ea5288caeca8642d1e84afbd3f7d6820020` | v4 | `.github/workflows/ci.yml`, `.github/workflows/pages.yml` |
| `actions/configure-pages` | `983d7736d9b0ae728b81ab479565c72886d7745b` | v5 | `.github/workflows/pages.yml` |
| `actions/upload-pages-artifact` | `56afc609e74202658d3ffba0e8f6dda462b719fa` | v3 | `.github/workflows/pages.yml` |
| `actions/deploy-pages` | `d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e` | v4 | `.github/workflows/pages.yml` |

### What this is and is not

It is **a warning, not a failure**. The runner forces these actions onto Node 24
and they work: all four jobs in that run were green, including a native Linux
`npm ci`, the full test suite and the production build.

The pins are also **correct as pins**. SHA-pinning third-party actions is a
security control this project keeps (`GitHub Actions remain SHA-pinned` is a
0.6.0 acceptance criterion), and the warning is about the action's declared
runtime, not about the pin.

### What to do

Move `actions/checkout` and `actions/setup-node` to their v5 SHAs, which declare
the `node24` runtime. That is a supply-chain change to CI: it needs the new SHAs
verified against the upstream release tags, and it should land on its own so the
diff is reviewable as what it is.

**Not folded into 0.6.0.** The refactor's CI changes are about the build and the
supply chain of `esbuild`; re-pinning unrelated actions in the same release
would mix an unreviewed supply-chain change into a diff nobody would expect to
find one in.

---

## `tools/lib/dom-shim.mjs` exports a `createWindow()` nobody calls

**Found:** 2026-08-27, during 0.6.0 Task 2.6, while removing `node:vm` from the
browser harness. **Status:** open. **Deliberately not changed in 0.6.0.**

[`tools/lib/dom-shim.mjs`](../tools/lib/dom-shim.mjs) exports `createWindow(extra)`
alongside `createDocument()`. Nothing imports it. Verified against the commit
this was found at, so it is not something the refactor stranded:

```console
$ git grep -n 'createWindow' 21c46ac -- '*.mjs' '*.js'
21c46ac:tools/lib/dom-shim.mjs:497:export function createWindow(extra = {}) {
```

One hit, and it is the declaration. Every consumer that needs a window builds
its own — `tools/lib/browser-harness.mjs`, `tests/lib/subject.mjs` and
`tests/build/parity.test.mjs` each construct one, because each needs a different
set of substituted primitives.

Its doc comment is stale in a way that would mislead: it describes building a
global "for loading `js/render.js`, `js/i18n.js` and `js/app.js` into a
`node:vm` sandbox". None of those files exists after Task 2.6, and no suite
loads the application through `node:vm` any more.

### What to do

Delete the function and its comment. It is a two-line removal with no consumer,
but it is dead code that predates this release and removing it inside a
wrapper-only conversion would put an unrelated deletion in a diff whose whole
claim is that nothing moved. The three real window builders stay as they are:
they differ on purpose, and collapsing them into one helper would give the
equivalence subject and the unit harness the same substitutions, which is the
opposite of what each needs.

---

## The public suffix list is shipped and read by nothing

**Found:** 2026-08-27, during 0.6.0 Task 2.7, while trying to carry spec §11's
PSL fixture-identity fingerprint across the facade contraction.
**Status:** open. **Deliberately not changed in 0.6.0.**

`getOrganizationalDomain()` is the only reader of the public suffix sets
(`js/dns.js:335-355`), and no application code calls it.
Measured at two commits, not inferred:

```console
$ grep -c 'getOrganizationalDomain(' js/dns.js          # declaration only
1
$ git show v0.5.0:js/app.js | grep -c 'getOrganizationalDomain'
0
```

The audit result's `organizationalDomain` field is produced by
`selectOrganizationalDomain()`, which walks the RFC 9989 discovery chain and
never consults the PSL. So no audit result, query trace, CSV export, HTML report
or DOM node depends on the public suffix list.

### What it costs

| | |
| --- | --- |
| `src/data/public-suffixes.js` in the bundle | **160.6 KB**, the largest single input |
| Share of a 422 KB artifact | **38.1%** |
| Rules carried | 10,239 |

Every visitor downloads it. It is the single biggest thing in the payload.

### Why it stays in 0.6.0

Removing shipped data is a **behaviour and size decision, not a refactor**. This
release's contract is five-surface equivalence against `v0.5.0`, and its Risk R8
exists to refuse exactly this kind of in-passing change: "every other found
behavior change is filed separately unless it blocks the phase". It does not
block the phase.

There is also a live question underneath it, and it should be answered before
the data is removed rather than after: `getOrganizationalDomain()` implements
the PSL algorithm correctly and three suites assert it. Is the RFC 9989 walk the
right substitute in every case, or is the absence of a PSL call site a **latent
defect** — somewhere the organizational domain should have been computed from
the public suffix list and instead falls back to discovery? That is a protocol
question for [findings-and-remediation](specs/implemented/findings-and-remediation.md) or
[report-comparison](specs/implemented/report-comparison.md) to answer.

### What to do

Answer the protocol question first. Then either delete the table, its generator
`tools/update-psl.mjs` and `getOrganizationalDomain()` together — a ~38% payload
cut, with its own equivalence run and release note — or wire the function to its
missing call site. Do not do half of it: shipping the table without a reader and
keeping a function nobody calls is the state this entry exists to end.
