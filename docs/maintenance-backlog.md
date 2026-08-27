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
