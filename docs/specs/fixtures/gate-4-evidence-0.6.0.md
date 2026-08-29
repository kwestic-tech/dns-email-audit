# Gate 4 evidence — 0.6.0

**Captured:** 2026-08-28, at `3ea55ea`, on the
`spec/modular-architecture-production-build` branch.

Gate 4 as the implementation plan states it: *"Every protocol has an owning
directory. **Token vocabulary byte-identical** — diff issue tokens against
`v0.5.0` explicitly."*

Both halves below. The second is an explicit comparison against the `v0.5.0`
tag, **not** an inference from a green equivalence run — equivalence proves the
32 corpus cases produce identical output, which is a different claim from the
vocabulary being unchanged.

---

## 1. Every protocol has an owning directory

| Directory | Task | Injected capabilities |
| --- | --- | --- |
| `src/core/shared/` | 4.0 | none — imports nothing, siblings included |
| `src/core/caa/` | 4.1 | `dohFetch`, `requireUsable` |
| `src/core/mx/` | 4.2 | `dohQuery`, `optionalCheck` |
| `src/core/bimi/` | 4.3 | none — no lookup, no factory |
| `src/core/transport/` | 4.4 | `tlsa.js` only: `dohFetch`, `requireUsable`, `optionalCheck`, `cleanAnswerData` |
| `src/core/dnssec/` | 4.5 | `matching.js`: `crypto`. `chain.js`: `dohFetch`, `cleanAnswerData`, `matchDsSet` |
| `src/core/dmarc/` | 4.6 | `org-domain.js`: `publicSuffixRules`. `tree-walk.js` and `report-auth.js`: resolver |
| `src/core/dkim/` | 4.7 | resolver, `crypto`, `dkimSelectorCatalog`, and the transitional `spfReferencedCatalogKeys` |
| `src/core/spf/` | 4.8 | `dohQuery`, `dohFetch`, `requireUsable`, `cleanAnswerData` |
| `src/providers/` | 4.9 | `isNullMx` |

`js/dns.js` fell from **5,527 lines at Gate 3 to 1,494**, and now holds only
the scoring model, issue and suggestion construction, and `analyzeDomain()` —
all of which belong to Phase 5.

Every directory carries its own `API.md` and co-located tests.

## 2. Token vocabulary, diffed against `v0.5.0`

Read out of the tag with `git show v0.5.0:locales/en.json` and compared as
sorted key lists, with values compared by serialized content:

```text
v0.5.0 issue tokens: 106
HEAD    issue tokens: 106
added:   (none)
removed: (none)
byte-identical key list: true
tokens whose English content moved: (none)
registry algebra matches HEAD: true
registry algebra matches v0.5.0: true
```

All three agree: the 106 tokens in `v0.5.0`, the 106 in `HEAD`, and the 106 the
reviewed registry's `audit.issue.key` algebra records.

> **A defect in the first run of this check, recorded because it is the kind
> that reads as a finding.** The comparison initially reported all 106 tokens
> as having changed content. The tokens had not moved; the script compared
> `en.json`'s issue OBJECTS with `!==`, which is reference identity. Fixed to
> compare serialized content. A byte-for-byte gate that produces a false
> positive on every entry is worth writing down, because the temptation is to
> conclude something about the code rather than about the instrument.

## 3. Full gate run

| Check | Result |
| --- | --- |
| `npm test` | **4,090**, 0 failed |
| `npm run inventory` | **215** passed |
| `node tests/build/equivalence.mjs --subject-root=.` | 32 cases, 5 surfaces, **0 differences** |
| `node tests/build/equivalence.mjs --subject-root=_site` | 32 cases, 5 surfaces, **0 differences** |
| `npm run coverage` | 32 cases, 430 rows, **430 covered, 0 uncovered** |
| `npm run locale:gate` | 13/13 |
| `npm run test:file-url` | 28 passed, real Chrome |
| Raw-kind readers | 6 entries across 4 owners; only the audit preflight remains in `js/dns.js` |
| Kind propagation | 11 typed paths + 1 derived issue mirror |
| Marked adapters | 2 |
| Documentation | 53 tracked Markdown files, 0 broken links |

## 4. Two transitional cross-protocol collaborators, carried into Phase 5

Neither is an allowed-edge violation — both are injected by the composition
root — and neither is the target shape.

| Collaborator | Owner | Injected into | Retired by |
| --- | --- | --- | --- |
| `spfReferencedCatalogKeys` | `core/spf/` | `createDkimCheck()` | Phase 5, replaced by audit-derived catalog keys |
| `isNullMx` | `core/mx/` | `createDetectors()` | Phase 5, replaced by the audit-derived boolean |

Both wait on the same thing: there is no `src/audit/` yet to derive a fact in.
Phase 5 creates it and retires both with one move.
